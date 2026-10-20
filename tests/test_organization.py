"""OrganizationService tests against botocore Stubber clients (requests validated against service models)."""

from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_schema import Contact, ContactsConfig, RootAccessConfig
from tarmac.core.exceptions import GovernanceError
from tarmac.services.organization import DEFAULT_TRUSTED_SERVICES, OrganizationService

ORG = {"Id": "o-abc123def4", "FeatureSet": "ALL", "MasterAccountId": "111111111111"}


def _client(service: str) -> Any:
    name: Any = service
    return boto3.client(
        name, region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing"
    )


@pytest.fixture
def stubs():
    clients = {name: _client(name) for name in ("organizations", "account", "iam")}
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.get_client.side_effect = lambda svc, **kw: clients[svc]
    stubbers = {name: Stubber(c) for name, c in clients.items()}
    for s in stubbers.values():
        s.activate()
    yield OrganizationService(mgr), stubbers
    for s in stubbers.values():
        s.assert_no_pending_responses()
        s.deactivate()


def _contact(label: str) -> Contact:
    return Contact(
        name=f"{label} Team", title=label, email=f"{label.lower()}@example.com", phone="+15555550100"
    )


def test_ensure_organization_existing(stubs):
    svc, s = stubs
    s["organizations"].add_response("describe_organization", {"Organization": ORG})
    assert svc.ensure_organization() == ORG["Id"]


def test_ensure_organization_creates_when_not_in_use(stubs):
    svc, s = stubs
    org = s["organizations"]
    org.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException")
    org.add_response("create_organization", {"Organization": ORG}, {"FeatureSet": "ALL"})
    assert svc.ensure_organization() == ORG["Id"]


def test_ensure_organization_recovers_from_concurrent_creation(stubs):
    svc, s = stubs
    org = s["organizations"]
    org.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException")
    org.add_client_error("create_organization", service_error_code="AlreadyInOrganizationException")
    org.add_response("describe_organization", {"Organization": ORG})
    assert svc.ensure_organization() == ORG["Id"]


def test_ensure_organization_create_failure(stubs):
    svc, s = stubs
    org = s["organizations"]
    org.add_client_error("describe_organization", service_error_code="AWSOrganizationsNotInUseException")
    org.add_client_error(
        "create_organization", service_error_code="AccessDeniedException", service_message="nope"
    )
    with pytest.raises(GovernanceError, match="create AWS Organization") as exc:
        svc.ensure_organization()
    assert "nope" in str(exc.value.details)


def test_ensure_organization_describe_failure(stubs):
    svc, s = stubs
    s["organizations"].add_client_error("describe_organization", service_error_code="AccessDeniedException")
    with pytest.raises(GovernanceError, match="describe AWS Organization"):
        svc.ensure_organization()


def test_set_account_contacts_all_types_in_order(stubs):
    svc, s = stubs
    contacts = ContactsConfig(
        billing=_contact("Billing"), operations=_contact("Ops"), security=_contact("Sec")
    )
    for kind, c in (
        ("BILLING", contacts.billing),
        ("OPERATIONS", contacts.operations),
        ("SECURITY", contacts.security),
    ):
        s["account"].add_response(
            "put_alternate_contact",
            {},
            {
                "AlternateContactType": kind,
                "Name": c.name,
                "Title": c.title,
                "EmailAddress": c.email,
                "PhoneNumber": c.phone,
            },
        )
    assert svc.set_account_contacts(contacts) == ["BILLING", "OPERATIONS", "SECURITY"]


def test_set_account_contacts_failure_stops(stubs):
    svc, s = stubs
    contacts = ContactsConfig(
        billing=_contact("Billing"), operations=_contact("Ops"), security=_contact("Sec")
    )
    s["account"].add_client_error("put_alternate_contact", service_error_code="AccessDeniedException")
    with pytest.raises(GovernanceError, match="BILLING"):
        svc.set_account_contacts(contacts)


def test_enable_trusted_services_skips_failures(stubs):
    svc, s = stubs
    org = s["organizations"]
    services = ["a.amazonaws.com", "b.amazonaws.com", "c.amazonaws.com"]
    org.add_response("enable_aws_service_access", {}, {"ServicePrincipal": "a.amazonaws.com"})
    org.add_client_error("enable_aws_service_access", service_error_code="ConstraintViolationException")
    org.add_response("enable_aws_service_access", {}, {"ServicePrincipal": "c.amazonaws.com"})
    assert svc.enable_trusted_services(services) == ["a.amazonaws.com", "c.amazonaws.com"]


def test_enable_trusted_services_defaults(stubs):
    svc, s = stubs
    for sp in DEFAULT_TRUSTED_SERVICES:
        s["organizations"].add_response("enable_aws_service_access", {}, {"ServicePrincipal": sp})
    assert svc.enable_trusted_services() == DEFAULT_TRUSTED_SERVICES


def test_configure_root_access_disabled_makes_no_calls(stubs):
    svc, _ = stubs
    result = svc.configure_root_access(RootAccessConfig(enabled=False))
    assert result == {
        "iam_trusted_access": False,
        "root_credentials_management": False,
        "root_sessions": False,
        "delegated_admin": False,
    }


def test_configure_root_access_full_with_name_normalized_admin(stubs):
    svc, s = stubs
    s["organizations"].add_response(
        "enable_aws_service_access", {}, {"ServicePrincipal": "iam.amazonaws.com"}
    )
    s["iam"].add_response("enable_organizations_root_credentials_management", {})
    s["iam"].add_response("enable_organizations_root_sessions", {})
    s["organizations"].add_response(
        "register_delegated_administrator",
        {},
        {"AccountId": "222222222222", "ServicePrincipal": "iam.amazonaws.com"},
    )
    result = svc.configure_root_access(
        RootAccessConfig(delegated_admin_account="Log Archive"), {"log_archive": "222222222222"}
    )
    assert result == {
        "iam_trusted_access": True,
        "root_credentials_management": True,
        "root_sessions": True,
        "delegated_admin": True,
    }


def test_configure_root_access_feature_flags_skip_calls(stubs):
    svc, s = stubs
    s["organizations"].add_response(
        "enable_aws_service_access", {}, {"ServicePrincipal": "iam.amazonaws.com"}
    )
    result = svc.configure_root_access(
        RootAccessConfig(enable_root_credentials_management=False, enable_root_sessions=False)
    )
    assert result["iam_trusted_access"] is True
    assert result["root_credentials_management"] is False
    assert result["root_sessions"] is False


def test_configure_root_access_records_failures(stubs):
    svc, s = stubs
    s["organizations"].add_client_error(
        "enable_aws_service_access", service_error_code="AccessDeniedException", service_message="iam denied"
    )
    s["iam"].add_client_error(
        "enable_organizations_root_credentials_management",
        service_error_code="AccessDeniedException",
        service_message="creds denied",
    )
    s["iam"].add_client_error(
        "enable_organizations_root_sessions",
        service_error_code="AccessDeniedException",
        service_message="sess denied",
    )
    result = svc.configure_root_access(RootAccessConfig())
    assert not any(result.values())
    assert svc.last_error == {
        "iam_trusted_access": "iam denied",
        "root_credentials_management": "creds denied",
        "root_sessions": "sess denied",
    }


def test_delegated_admin_already_registered_counts_as_success(stubs):
    svc, s = stubs
    s["organizations"].add_response(
        "enable_aws_service_access", {}, {"ServicePrincipal": "iam.amazonaws.com"}
    )
    s["organizations"].add_client_error(
        "register_delegated_administrator", service_error_code="AccountAlreadyRegisteredException"
    )
    result = svc.configure_root_access(
        RootAccessConfig(
            enable_root_credentials_management=False,
            enable_root_sessions=False,
            delegated_admin_account="audit",
        ),
        {"audit": "333333333333"},
    )
    assert result["delegated_admin"] is True


def test_delegated_admin_unknown_account(stubs):
    svc, s = stubs
    s["organizations"].add_response(
        "enable_aws_service_access", {}, {"ServicePrincipal": "iam.amazonaws.com"}
    )
    result = svc.configure_root_access(
        RootAccessConfig(
            enable_root_credentials_management=False,
            enable_root_sessions=False,
            delegated_admin_account="audit",
        ),
        {"other": "444444444444"},
    )
    assert result["delegated_admin"] is False
    assert "audit" in svc.last_error["delegated_admin"]


def test_delegated_admin_resolves_accounts_from_paginated_active_list(stubs):
    svc, s = stubs
    org = s["organizations"]
    org.add_response(
        "list_accounts",
        {"Accounts": [{"Id": "555555555555", "Name": "suspended", "Status": "SUSPENDED"}], "NextToken": "t"},
    )
    org.add_response(
        "list_accounts",
        {"Accounts": [{"Id": "666666666666", "Name": "audit", "Status": "ACTIVE"}]},
        {"NextToken": "t"},
    )
    org.add_response("enable_aws_service_access", {}, {"ServicePrincipal": "iam.amazonaws.com"})
    org.add_response(
        "register_delegated_administrator",
        {},
        {"AccountId": "666666666666", "ServicePrincipal": "iam.amazonaws.com"},
    )
    result = svc.configure_root_access(
        RootAccessConfig(
            enable_root_credentials_management=False,
            enable_root_sessions=False,
            delegated_admin_account="audit",
        )
    )
    assert result["delegated_admin"] is True


def test_delegated_admin_lookup_failure_degrades(stubs):
    svc, s = stubs
    org = s["organizations"]
    org.add_client_error("list_accounts", service_error_code="AccessDeniedException")
    org.add_response("enable_aws_service_access", {}, {"ServicePrincipal": "iam.amazonaws.com"})
    result = svc.configure_root_access(
        RootAccessConfig(
            enable_root_credentials_management=False,
            enable_root_sessions=False,
            delegated_admin_account="audit",
        )
    )
    assert result["delegated_admin"] is False


def test_register_service_delegated_administrators_attempts_all_then_raises(stubs):
    svc, s = stubs
    org = s["organizations"]
    sps = ["a.amazonaws.com", "b.amazonaws.com", "c.amazonaws.com"]
    org.add_client_error(
        "register_delegated_administrator", service_error_code="AccountAlreadyRegisteredException"
    )
    org.add_client_error(
        "register_delegated_administrator",
        service_error_code="AccessDeniedException",
        service_message="denied",
    )
    org.add_response(
        "register_delegated_administrator",
        {},
        {"AccountId": "777777777777", "ServicePrincipal": "c.amazonaws.com"},
    )
    with pytest.raises(GovernanceError, match="1 service") as exc:
        svc.register_service_delegated_administrators("777777777777", sps)
    assert "b.amazonaws.com" in str(exc.value.details)
    assert "AccessDeniedException" in str(exc.value.details)


def test_register_service_delegated_administrators_success(stubs):
    svc, s = stubs
    for sp in ("a.amazonaws.com", "b.amazonaws.com"):
        s["organizations"].add_response(
            "register_delegated_administrator", {}, {"AccountId": "888888888888", "ServicePrincipal": sp}
        )
    assert svc.register_service_delegated_administrators(
        "888888888888", ["a.amazonaws.com", "b.amazonaws.com"]
    ) == [
        "a.amazonaws.com",
        "b.amazonaws.com",
    ]


def test_default_trusted_services_cover_config_delegation() -> None:
    """Phase 5 delegates Config administration, which AWS refuses unless service access is already on."""
    assert "config-multiaccountsetup.amazonaws.com" in DEFAULT_TRUSTED_SERVICES
    assert "config.amazonaws.com" in DEFAULT_TRUSTED_SERVICES
