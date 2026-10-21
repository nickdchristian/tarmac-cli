"""A run that changes nothing must say so: reads before writes, UNCHANGED outcomes and quiet handled errors."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, WaiterError

from tarmac.core.aws_audit import DRY_RUN_ALLOWED, is_benign_error
from tarmac.core.config_schema import Contact, ContactsConfig
from tarmac.core.exceptions import DeploymentError
from tarmac.services.accounts import AccountService
from tarmac.services.cloudformation import CloudFormationService
from tarmac.services.identity import IdentityService
from tarmac.services.organization import DEFAULT_TRUSTED_SERVICES, OrganizationService


def _events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [r.data for r in caplog.records if getattr(r, "event", None) == "audit"]  # type: ignore[attr-defined]


def _outcomes(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [e["outcome"] for e in _events(caplog)]


@pytest.fixture(autouse=True)
def _info(caplog):
    caplog.set_level(logging.INFO, logger="tarmac.audit")


def _org_service() -> tuple[OrganizationService, MagicMock, MagicMock, MagicMock]:
    mgr = MagicMock()
    org, account, iam = MagicMock(), MagicMock(), MagicMock()
    mgr.get_client.side_effect = lambda svc, **kw: {"organizations": org, "account": account, "iam": iam}[svc]
    return OrganizationService(mgr), org, account, iam


def _contact(label: str) -> Contact:
    return Contact(
        name=f"{label} Team", title=label, email=f"{label.lower()}@example.com", phone="+15555550100"
    )


def test_alternate_contacts_already_set_are_unchanged_and_not_rewritten(caplog):
    svc, _, account, _ = _org_service()
    contacts = ContactsConfig(
        billing=_contact("Billing"), operations=_contact("Operations"), security=_contact("Security")
    )

    def current(AlternateContactType: str) -> dict[str, Any]:
        contact = {"BILLING": contacts.billing, "OPERATIONS": contacts.operations}.get(AlternateContactType)
        if contact is None:  # SECURITY differs from the declared one
            return {"AlternateContact": {"Name": "Someone Else", "Title": "x", "EmailAddress": "o@x.io"}}
        return {
            "AlternateContact": {
                "Name": contact.name,
                "Title": contact.title,
                "EmailAddress": contact.email,
                "PhoneNumber": contact.phone,
            }
        }

    account.get_alternate_contact.side_effect = current

    assert svc.set_account_contacts(contacts) == ["SECURITY"]
    assert _outcomes(caplog) == ["unchanged", "unchanged", "succeeded"]
    assert account.put_alternate_contact.call_count == 1


def test_trusted_services_already_enabled_are_unchanged(caplog):
    svc, org, _, _ = _org_service()
    already = DEFAULT_TRUSTED_SERVICES[:-1]
    org.get_paginator.return_value.paginate.return_value = [
        {"EnabledServicePrincipals": [{"ServicePrincipal": sp} for sp in already]}
    ]

    assert svc.enable_trusted_services() == DEFAULT_TRUSTED_SERVICES
    assert _outcomes(caplog) == ["unchanged"] * len(already) + ["succeeded"]
    org.enable_aws_service_access.assert_called_once_with(ServicePrincipal=DEFAULT_TRUSTED_SERVICES[-1])


def test_unreadable_service_access_falls_back_to_enabling_everything(caplog):
    svc, org, _, _ = _org_service()
    org.get_paginator.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "List")

    svc.enable_trusted_services(["a.amazonaws.com"])

    org.enable_aws_service_access.assert_called_once_with(ServicePrincipal="a.amazonaws.com")
    assert _outcomes(caplog) == ["succeeded"]


def test_root_access_features_already_on_are_unchanged(caplog):
    svc, org, _, iam = _org_service()
    org.get_paginator.return_value.paginate.return_value = [
        {"EnabledServicePrincipals": [{"ServicePrincipal": "iam.amazonaws.com"}]}
    ]
    iam.list_organizations_features.return_value = {
        "EnabledFeatures": ["RootCredentialsManagement", "RootSessions"]
    }
    config = MagicMock(
        enabled=True,
        enable_root_credentials_management=True,
        enable_root_sessions=True,
        delegated_admin_account=None,
    )

    result = svc.configure_root_access(config)

    assert result["root_credentials_management"]
    assert result["root_sessions"]
    assert result["iam_trusted_access"]
    assert _outcomes(caplog) == ["unchanged", "unchanged", "unchanged"]
    iam.enable_organizations_root_credentials_management.assert_not_called()
    iam.enable_organizations_root_sessions.assert_not_called()
    org.enable_aws_service_access.assert_not_called()


def _identity() -> tuple[IdentityService, MagicMock]:
    mgr = MagicMock()
    sso = MagicMock()
    mgr.get_client.side_effect = lambda svc, **kw: sso if svc == "sso-admin" else MagicMock()
    svc = IdentityService(mgr)
    svc.get_instance_details = MagicMock(return_value=("arn:inst", "d-1"))  # type: ignore[method-assign]
    svc.sso_client = sso
    return svc, sso


def test_existing_group_assignment_is_unchanged_and_not_recreated(caplog):
    svc, sso = _identity()
    sso.get_paginator.return_value.paginate.return_value = [
        {"AccountAssignments": [{"PrincipalType": "GROUP", "PrincipalId": "g-1"}]}
    ]

    assert svc.assign_group_to_accounts("g-1", "Admins", "arn:ps", ["111122223333"]) == 1

    assert _outcomes(caplog) == ["unchanged"]
    sso.create_account_assignment.assert_not_called()


def test_missing_group_assignment_is_created(caplog):
    svc, sso = _identity()
    sso.get_paginator.return_value.paginate.return_value = [{"AccountAssignments": []}]
    sso.create_account_assignment.return_value = {"AccountAssignmentCreationStatus": {"Status": "SUCCEEDED"}}

    svc.assign_group_to_accounts("g-1", "Admins", "arn:ps", ["111122223333"])

    assert _outcomes(caplog) == ["succeeded"]
    sso.create_account_assignment.assert_called_once()


def test_benign_errors_are_recognised():
    assert is_benign_error({"Code": "AccountAlreadyRegisteredException", "Message": "x"})
    assert is_benign_error({"Code": "ValidationError", "Message": "No updates are to be performed."})
    assert is_benign_error(
        {"Code": "ConflictException", "Message": "Member and Group relationship already exists"}
    )
    assert not is_benign_error({"Code": "AccessDenied", "Message": "not allowed"})
    assert not is_benign_error({})


def test_sso_token_refresh_is_not_a_dry_run_violation():
    assert "sso-oidc.CreateToken" in DRY_RUN_ALLOWED


def test_dry_run_move_is_simulated_and_changes_nothing(caplog):
    svc = AccountService(MagicMock())
    svc.org_client = MagicMock()
    svc.get_account_parent_id = MagicMock(return_value="ou-old")  # type: ignore[method-assign]

    assert svc.simulate_move("111122223333", "dev", "ou-new") is True
    assert svc.simulate_move("111122223333", "dev", "ou-old") is False

    (event,) = _events(caplog)
    assert event["outcome"] == "simulated"
    assert event["details"]["from_parent"] == "ou-old"
    assert event["details"]["to_parent"] == "ou-new"
    svc.org_client.move_account.assert_not_called()


def test_failed_change_set_reports_its_status_reason_and_owning_stack():
    cfn = MagicMock()
    cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "D"
    )
    cfn.get_waiter.return_value.wait.side_effect = WaiterError("ChangeSetCreateComplete", "FAILED", {})
    cfn.describe_change_set.return_value = {
        "Status": "FAILED",
        "StatusReason": "p-123 already exists in stack arn:aws:cloudformation:us-east-1:1:stack/myorg-scps/abc",
    }

    with pytest.raises(DeploymentError) as exc_info:
        CloudFormationService(MagicMock()).import_resources_and_deploy_stack(
            cfn_client=cfn, stack_name="new-scps", template_body="Resources: {}", resources_to_import=[]
        )

    details = str(exc_info.value.details)
    assert "p-123 already exists in stack" in details
    assert "organization.name" in details
