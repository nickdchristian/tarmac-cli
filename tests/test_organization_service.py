"""OrganizationService phase-tag, contact and root-access tests."""

from typing import Any
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from tarmac.core.config_schema import (
    Contact,
    ContactsConfig,
    RootAccessConfig,
)
from tarmac.services.organization import OrganizationService


def test_ensure_organization_existing():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-1234567890"}}

    service = OrganizationService(mock_session_mgr)
    org_id = service.ensure_organization()

    assert org_id == "o-1234567890"
    mock_org.describe_organization.assert_called_once()


def test_set_account_contacts():
    mock_session_mgr = MagicMock()
    mock_account = MagicMock()
    mock_session_mgr.get_client.return_value = mock_account

    service = OrganizationService(mock_session_mgr)
    contacts = ContactsConfig(
        billing=Contact(
            name="Billing Team", title="Billing", email="billing@example.com", phone="+10000000000"
        ),
        operations=Contact(name="Ops Team", title="Ops", email="ops@example.com", phone="+10000000000"),
        security=Contact(name="Sec Team", title="Security", email="sec@example.com", phone="+10000000000"),
    )

    updated = service.set_account_contacts(contacts)
    assert set(updated) == {"BILLING", "OPERATIONS", "SECURITY"}
    assert mock_account.put_alternate_contact.call_count == 3


def test_configure_root_access():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_iam = MagicMock()

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "organizations":
            return mock_org
        if service_name == "iam":
            return mock_iam
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect

    service = OrganizationService(mock_session_mgr)
    cfg = RootAccessConfig(enable_root_credentials_management=True, enable_root_sessions=True)

    results = service.configure_root_access(cfg, "Audit", account_id_map={"Audit": "999999999999"})
    assert results["iam_trusted_access"] is True
    assert results["root_credentials_management"] is True
    assert results["root_sessions"] is True
    assert results["delegated_admin"] is True

    # Test case and separator-insensitive matching
    results_norm = service.configure_root_access(
        RootAccessConfig(), "audit-account", account_id_map={"Audit Account": "888888888888"}
    )
    assert results_norm["delegated_admin"] is True


def test_get_completed_phases_parses_tags():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [
        {
            "Tags": [
                {"Key": "tarmac:completed-phases", "Value": "org+ou+accounts"},
                {"Key": "tarmac:managed-by", "Value": "tarmac"},
            ]
        }
    ]
    mock_org.get_paginator.return_value = tag_paginator

    service = OrganizationService(mock_session_mgr)
    phases = service.get_completed_phases("123456789012")
    assert phases == {"org", "ou", "accounts"}


def test_get_completed_phases_empty_when_no_tag_or_error():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": []}]
    mock_org.get_paginator.return_value = tag_paginator

    service = OrganizationService(mock_session_mgr)
    assert service.get_completed_phases("123456789012") == set()

    mock_org.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListTagsForResource"
    )
    assert service.get_completed_phases("123456789012") == set()


def test_record_phase_completed_updates_tags():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": [{"Key": "tarmac:completed-phases", "Value": "org"}]}]
    mock_org.get_paginator.return_value = tag_paginator

    service = OrganizationService(mock_session_mgr)
    service.record_phase_completed("123456789012", "ou")

    mock_org.tag_resource.assert_called_once()
    call_kwargs = mock_org.tag_resource.call_args[1]
    assert call_kwargs["ResourceId"] == "123456789012"
    tag_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert tag_dict["tarmac:completed-phases"] == "org+ou"
    assert tag_dict["tarmac:managed-by"] == "tarmac"
    assert tag_dict["tarmac:status"] == "in-progress"


def test_mark_deployment_ready():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    service = OrganizationService(mock_session_mgr)
    service.mark_deployment_ready("123456789012")

    mock_org.tag_resource.assert_called_once()
    call_kwargs = mock_org.tag_resource.call_args[1]
    assert call_kwargs["ResourceId"] == "123456789012"
    tag_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert tag_dict["tarmac:status"] == "ready"


def test_activate_cost_allocation_tags():
    mock_session_mgr = MagicMock()
    mock_ce = MagicMock()
    mock_session_mgr.get_client.return_value = mock_ce

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "CostAllocationTags": [
                {"TagKey": "Environment", "Status": "Inactive"},
                {"TagKey": "CostCenter", "Status": "Inactive"},
                {"TagKey": "UnrelatedTag", "Status": "Inactive"},
            ]
        }
    ]
    mock_ce.get_paginator.return_value = paginator

    service = OrganizationService(mock_session_mgr)
    activated = service.activate_cost_allocation_tags(["Environment", "CostCenter", "Owner"])

    assert set(activated) == {"Environment", "CostCenter"}
    mock_ce.update_cost_allocation_tags_status.assert_called_once_with(
        CostAllocationTagsStatus=[
            {"TagKey": "Environment", "Status": "Active"},
            {"TagKey": "CostCenter", "Status": "Active"},
        ]
    )


def test_activate_cost_allocation_tags_none_inactive():
    mock_session_mgr = MagicMock()
    mock_ce = MagicMock()
    mock_session_mgr.get_client.return_value = mock_ce

    paginator = MagicMock()
    paginator.paginate.return_value = [{"CostAllocationTags": []}]
    mock_ce.get_paginator.return_value = paginator

    service = OrganizationService(mock_session_mgr)
    activated = service.activate_cost_allocation_tags(["Environment"])

    assert activated == []
    mock_ce.update_cost_allocation_tags_status.assert_not_called()
