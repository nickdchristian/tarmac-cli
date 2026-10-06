"""Tests for OUEngine logic."""

from unittest.mock import MagicMock

from tarmac.core.config_schema import OUDef
from tarmac.services.ou import OUService


def test_ou_sync_creates_missing_and_reuses_existing():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.list_roots.return_value = {"Roots": [{"Id": "r-root123"}]}

    paginator = MagicMock()
    # Assume 'Security' already exists, but 'Infrastructure' does not
    paginator.paginate.return_value = [{"OrganizationalUnits": [{"Id": "ou-sec-111", "Name": "Security"}]}]
    mock_org_client.get_paginator.return_value = paginator

    mock_org_client.create_organizational_unit.return_value = {
        "OrganizationalUnit": {"Id": "ou-infra-222", "Name": "Infrastructure"}
    }

    engine = OUService(mock_session_mgr)
    desired = [
        OUDef(name="Security"),
        OUDef(name="Infrastructure"),
    ]

    report = engine.sync_ou_structure(desired)

    assert report.synced_ous["Security"] == "ou-sec-111"
    assert report.synced_ous["Infrastructure"] == "ou-infra-222"
    assert "Security" in report.existing_ous
    assert "Infrastructure" in report.created_ous
    mock_org_client.create_organizational_unit.assert_called_once_with(
        ParentId="r-root123", Name="Infrastructure"
    )


def test_list_all_ous_nested():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.list_roots.return_value = {"Roots": [{"Id": "r-root"}]}

    paginator = MagicMock()

    def paginate_side_effect(ParentId: str):
        if ParentId == "r-root":
            return [{"OrganizationalUnits": [{"Id": "ou-workloads", "Name": "Workloads"}]}]
        if ParentId == "ou-workloads":
            return [
                {
                    "OrganizationalUnits": [
                        {"Id": "ou-prod", "Name": "Production"},
                        {"Id": "ou-stage", "Name": "Staging"},
                    ]
                }
            ]
        return [{"OrganizationalUnits": []}]

    paginator.paginate.side_effect = paginate_side_effect
    mock_org_client.get_paginator.return_value = paginator

    engine = OUService(mock_session_mgr)
    all_ous = engine.list_all_ous()

    assert all_ous == {
        "Workloads": "ou-workloads",
        "Production": "ou-prod",
        "Staging": "ou-stage",
    }


def test_ou_create_recovers_from_duplicate_race_condition():
    """Verify that DuplicateOrganizationalUnitException recovers by re-discovering the created OU."""
    from botocore.exceptions import ClientError

    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    duplicate_err = ClientError(
        {"Error": {"Code": "DuplicateOrganizationalUnitException", "Message": "OU already exists"}},
        "CreateOrganizationalUnit",
    )
    mock_org_client.create_organizational_unit.side_effect = duplicate_err

    # On refresh, list_organizational_units_for_parent finds the newly existing OU
    paginator = MagicMock()
    paginator.paginate.return_value = [{"OrganizationalUnits": [{"Id": "ou-race-999", "Name": "Workloads"}]}]
    mock_org_client.get_paginator.return_value = paginator

    engine = OUService(mock_session_mgr)
    ou_id = engine._create_ou("r-root123", "Workloads")

    assert ou_id == "ou-race-999"
    mock_org_client.create_organizational_unit.assert_called_once_with(ParentId="r-root123", Name="Workloads")


def test_ou_create_duplicate_race_unresolved_raises_ou_management_error():
    """Verify that DuplicateOrganizationalUnitException raises OUManagementError if refresh still misses it."""
    import pytest
    from botocore.exceptions import ClientError

    from tarmac.core.exceptions import OUManagementError

    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    duplicate_err = ClientError(
        {"Error": {"Code": "DuplicateOrganizationalUnitException", "Message": "OU already exists"}},
        "CreateOrganizationalUnit",
    )
    mock_org_client.create_organizational_unit.side_effect = duplicate_err

    # Refresh returns empty (e.g. AWS replication lag or name conflict with differing casing)
    paginator = MagicMock()
    paginator.paginate.return_value = [{"OrganizationalUnits": []}]
    mock_org_client.get_paginator.return_value = paginator

    engine = OUService(mock_session_mgr)
    with pytest.raises(OUManagementError) as exc_info:
        engine._create_ou("r-root123", "Workloads")

    assert "Failed to create OU 'Workloads'" in str(exc_info.value)
    assert "OU already exists" in (exc_info.value.details or "")


def test_get_root_id_empty_roots_raises():
    """Verify get_root_id raises OUManagementError when Roots list is empty."""
    import pytest

    from tarmac.core.exceptions import OUManagementError

    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client
    mock_org_client.list_roots.return_value = {"Roots": []}

    engine = OUService(mock_session_mgr)
    with pytest.raises(OUManagementError, match="No AWS Organizations root found"):
        engine.get_root_id()


def test_get_root_id_client_error_raises():
    """Verify get_root_id raises OUManagementError when list_roots fails with ClientError."""
    import pytest
    from botocore.exceptions import ClientError

    from tarmac.core.exceptions import OUManagementError

    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client
    mock_org_client.list_roots.side_effect = ClientError(
        {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "Account not in an organization"}},
        "ListRoots",
    )

    engine = OUService(mock_session_mgr)
    with pytest.raises(OUManagementError, match="Failed to query organization roots"):
        engine.get_root_id()


def test_ou_sync_multi_level_tree():
    """Verify sync_ou_structure creates parent OU first and passes newly created parent ID to children."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.list_roots.return_value = {"Roots": [{"Id": "r-root-1"}]}

    # Initially no OUs under root or children
    paginator = MagicMock()
    paginator.paginate.return_value = [{"OrganizationalUnits": []}]
    mock_org_client.get_paginator.return_value = paginator

    def create_side_effect(ParentId: str, Name: str):
        if Name == "Workloads":
            return {"OrganizationalUnit": {"Id": "ou-workloads-new", "Name": "Workloads"}}
        if Name == "Production":
            return {"OrganizationalUnit": {"Id": "ou-prod-new", "Name": "Production"}}
        return {"OrganizationalUnit": {"Id": f"ou-{Name.lower()}", "Name": Name}}

    mock_org_client.create_organizational_unit.side_effect = create_side_effect

    engine = OUService(mock_session_mgr)
    tree = [
        OUDef(
            name="Workloads",
            children=[OUDef(name="Production")],
        )
    ]

    report = engine.sync_ou_structure(tree)

    assert report.synced_ous["Workloads"] == "ou-workloads-new"
    assert report.synced_ous["Production"] == "ou-prod-new"
    assert set(report.created_ous) == {"Workloads", "Production"}

    # Verify Production was created with ParentId pointing to Workloads
    assert mock_org_client.create_organizational_unit.call_count == 2
    calls = mock_org_client.create_organizational_unit.call_args_list
    assert calls[0].kwargs == {"ParentId": "r-root-1", "Name": "Workloads"}
    assert calls[1].kwargs == {"ParentId": "ou-workloads-new", "Name": "Production"}
