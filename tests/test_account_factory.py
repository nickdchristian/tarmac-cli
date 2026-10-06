"""Tests for AccountFactory planning, provisioning, and inventory export."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import AccountDef, AccountsCatalog
from tarmac.core.exceptions import AccountProvisioningError
from tarmac.services.accounts import AccountService


def test_account_factory_plan():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    # Mock list_accounts: Account "Deployment" exists, "Network-Central" does not
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE"},
                {"Id": "222222222222", "Name": "WrongOUPosition", "Status": "ACTIVE"},
            ]
        }
    ]
    mock_org_client.get_paginator.return_value = paginator

    def mock_list_parents(ChildId):
        if ChildId == "111111111111":
            return {"Parents": [{"Id": "ou-infra-123"}]}
        elif ChildId == "222222222222":
            return {"Parents": [{"Id": "ou-old-root"}]}
        return {"Parents": []}

    mock_org_client.list_parents.side_effect = mock_list_parents

    factory = AccountService(mock_session_mgr)

    catalog = AccountsCatalog(
        accounts=[
            AccountDef(name="Deployment", email="dep@example.com", ou="Infrastructure"),
            AccountDef(name="WrongOUPosition", email="wrong@example.com", ou="Security"),
            AccountDef(name="Network-Central", email="net@example.com", ou="Infrastructure"),
        ]
    )

    ou_map = {
        "Infrastructure": "ou-infra-123",
        "Security": "ou-sec-456",
    }

    plan = factory.plan(catalog, ou_map)

    plan_by_name = {item.name: item for item in plan}

    assert plan_by_name["Deployment"].action == "NOOP"
    assert plan_by_name["WrongOUPosition"].action == "MOVE"
    assert plan_by_name["Network-Central"].action == "CREATE"


def test_export_inventory(tmp_path: Path):
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE"},
            ]
        }
    ]
    mock_org_client.get_paginator.return_value = paginator

    factory = AccountService(mock_session_mgr)
    catalog = AccountsCatalog(
        accounts=[
            AccountDef(name="Deployment", email="dep@example.com", ou="Infrastructure"),
            AccountDef(name="Production", email="prod@example.com", ou="Production"),
        ]
    )
    ou_map = {"Infrastructure": "ou-infra-123", "Production": "ou-prod-456"}

    output_file = factory.export_inventory(catalog, ou_map, tmp_path)
    assert output_file.exists()

    with open(output_file) as f:
        data = json.load(f)

    assert len(data) == 2
    assert data[0]["name"] == "Deployment"
    assert data[0]["account_id"] == "111111111111"
    assert data[1]["name"] == "Production"
    assert data[1]["account_id"] is None

    env_file = tmp_path / "env.sh"
    assert env_file.exists()
    content = env_file.read_text()
    assert 'export DEPLOYMENT_ACCOUNT_ID="111111111111"' in content


def test_sync_account_tags_updates_drifted_or_missing_tags():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": [{"Key": "Environment", "Value": "stage"}]}]
    mock_org_client.get_paginator.return_value = tag_paginator

    service = AccountService(mock_session_mgr)
    declared_tags = {"Environment": "dev", "ManagedBy": "tarmac"}

    updated = service.sync_account_tags("111111111111", "dev-account", declared_tags)
    assert updated is True
    mock_org_client.tag_resource.assert_called_once_with(
        ResourceId="111111111111",
        Tags=[
            {"Key": "Environment", "Value": "dev"},
            {"Key": "ManagedBy", "Value": "tarmac"},
        ],
    )


def test_sync_account_tags_noop_when_in_sync():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [
        {
            "Tags": [
                {"Key": "Environment", "Value": "dev"},
                {"Key": "ManagedBy", "Value": "tarmac"},
            ]
        }
    ]
    mock_org_client.get_paginator.return_value = tag_paginator

    service = AccountService(mock_session_mgr)
    declared_tags = {"Environment": "dev", "ManagedBy": "tarmac"}

    updated = service.sync_account_tags("111111111111", "dev-account", declared_tags)
    assert updated is False
    mock_org_client.tag_resource.assert_not_called()


def test_sync_account_tags_dry_run():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": []}]
    mock_org_client.get_paginator.return_value = tag_paginator

    service = AccountService(mock_session_mgr)
    declared_tags = {"Environment": "dev"}

    updated = service.sync_account_tags("111111111111", "dev-account", declared_tags, dry_run=True)
    assert updated is True
    mock_org_client.tag_resource.assert_not_called()


def test_provision_account_reused_syncs_tags():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [
        {"Accounts": [{"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE"}]}
    ]

    tags_paginator = MagicMock()
    tags_paginator.paginate.return_value = [{"Tags": []}]

    def get_paginator_side_effect(operation_name: str) -> MagicMock:
        if operation_name == "list_accounts":
            return accts_paginator
        if operation_name == "list_tags_for_resource":
            return tags_paginator
        return MagicMock()

    mock_org_client.get_paginator.side_effect = get_paginator_side_effect
    mock_org_client.list_parents.return_value = {"Parents": [{"Id": "ou-infra-123"}]}

    service = AccountService(mock_session_mgr)
    acct_def = AccountDef(
        name="Deployment",
        email="dep@example.com",
        ou="Infrastructure",
        tags={"Environment": "Infrastructure", "ManagedBy": "tarmac"},
    )

    result = service.provision_account(acct_def, target_ou_id="ou-infra-123", dry_run=False)
    assert result.status == "SUCCEEDED"
    assert result.action_taken == "TAGGED"
    mock_org_client.tag_resource.assert_called_once_with(
        ResourceId="111111111111",
        Tags=[
            {"Key": "Environment", "Value": "Infrastructure"},
            {"Key": "ManagedBy", "Value": "tarmac"},
        ],
    )


def test_account_factory_plan_detects_removed_account_for_suspension():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client
    mock_session_mgr.get_caller_identity.return_value = {"Account": "999999999999"}

    # Existing accounts: "Deployment" (in catalog) and "OldWorkload" (omitted from catalog, managed by tarmac)
    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE", "Email": "dep@example.com"},
                {"Id": "333333333333", "Name": "OldWorkload", "Status": "ACTIVE", "Email": "old@example.com"},
            ]
        }
    ]

    tags_paginator = MagicMock()
    tags_paginator.paginate.return_value = [{"Tags": [{"Key": "tarmac:managed-by", "Value": "tarmac"}]}]

    def get_paginator_side_effect(operation_name: str) -> MagicMock:
        if operation_name == "list_accounts":
            return accts_paginator
        if operation_name == "list_tags_for_resource":
            return tags_paginator
        return MagicMock()

    mock_org_client.get_paginator.side_effect = get_paginator_side_effect
    mock_org_client.list_parents.side_effect = lambda ChildId: {
        "Parents": [{"Id": "ou-infra-123" if ChildId == "111111111111" else "ou-workloads-789"}]
    }

    factory = AccountService(mock_session_mgr)
    catalog = AccountsCatalog(
        accounts=[
            AccountDef(name="Deployment", email="dep@example.com", ou="Infrastructure"),
        ]
    )
    ou_map = {"Infrastructure": "ou-infra-123", "Suspended": "ou-suspended-999"}

    plan = factory.plan(catalog, ou_map)
    plan_by_name = {item.name: item for item in plan}

    assert "OldWorkload" in plan_by_name
    assert plan_by_name["OldWorkload"].action == "SUSPEND"
    assert plan_by_name["OldWorkload"].ou == "Suspended"
    assert plan_by_name["OldWorkload"].account_id == "333333333333"


def test_suspend_account_quarantine():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.list_parents.return_value = {"Parents": [{"Id": "ou-active-123"}]}
    tags_paginator = MagicMock()
    tags_paginator.paginate.return_value = [{"Tags": []}]
    mock_org_client.get_paginator.return_value = tags_paginator

    service = AccountService(mock_session_mgr)
    res = service.suspend_account(
        account_id="333333333333",
        account_name="OldWorkload",
        suspended_ou_id="ou-suspended-999",
        dry_run=False,
        close=False,
    )

    assert res.status == "SUCCEEDED"
    assert res.closed is False
    mock_org_client.move_account.assert_called_once_with(
        AccountId="333333333333",
        SourceParentId="ou-active-123",
        DestinationParentId="ou-suspended-999",
    )
    mock_org_client.tag_resource.assert_called_once()
    tag_keys = [t["Key"] for t in mock_org_client.tag_resource.call_args[1]["Tags"]]
    assert "tarmac:status" in tag_keys


def test_suspend_account_with_close():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.list_parents.return_value = {"Parents": [{"Id": "ou-suspended-999"}]}
    tags_paginator = MagicMock()
    tags_paginator.paginate.return_value = [{"Tags": []}]
    mock_org_client.get_paginator.return_value = tags_paginator

    service = AccountService(mock_session_mgr)
    res = service.suspend_account(
        account_id="333333333333",
        account_name="OldWorkload",
        suspended_ou_id="ou-suspended-999",
        dry_run=False,
        close=True,
    )

    assert res.status == "SUCCEEDED"
    assert res.closed is True
    mock_org_client.close_account.assert_called_once_with(AccountId="333333333333")


def test_plan_reports_suspended_and_quarantined_accounts():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client
    mock_session_mgr.get_caller_identity.return_value = {"Account": "999999999999"}

    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE", "Email": "dep@example.com"},
                {
                    "Id": "222222222222",
                    "Name": "ClosedInAws",
                    "Status": "SUSPENDED",
                    "Email": "closed@example.com",
                },
                {
                    "Id": "333333333333",
                    "Name": "QuarantinedAcct",
                    "Status": "ACTIVE",
                    "Email": "quar@example.com",
                },
                {
                    "Id": "444444444444",
                    "Name": "DeclaredClosed",
                    "Status": "SUSPENDED",
                    "Email": "decl@example.com",
                },
            ]
        }
    ]
    mock_org_client.get_paginator.return_value = accts_paginator

    def mock_parents(ChildId: str):
        if ChildId == "111111111111":
            return {"Parents": [{"Id": "ou-infra-123"}]}
        if ChildId == "333333333333":
            return {"Parents": [{"Id": "ou-suspended-999"}]}
        return {"Parents": [{"Id": "ou-old-123"}]}

    mock_org_client.list_parents.side_effect = mock_parents

    factory = AccountService(mock_session_mgr)
    catalog = AccountsCatalog(
        accounts=[
            AccountDef(name="Deployment", email="dep@example.com", ou="Infrastructure"),
            AccountDef(name="DeclaredClosed", email="decl@example.com", ou="Infrastructure"),
        ]
    )
    ou_map = {"Infrastructure": "ou-infra-123", "Suspended": "ou-suspended-999"}

    plan = factory.plan(catalog, ou_map)
    plan_by_name = {item.name: item for item in plan}

    assert plan_by_name["Deployment"].action == "NOOP"
    assert plan_by_name["DeclaredClosed"].action == "SUSPENDED"
    assert "SUSPENDED (closed)" in plan_by_name["DeclaredClosed"].reason

    assert plan_by_name["ClosedInAws"].action == "SUSPENDED"
    assert "SUSPENDED (closed) in AWS Organizations" in plan_by_name["ClosedInAws"].reason

    assert plan_by_name["QuarantinedAcct"].action == "SUSPENDED"
    assert "quarantined in Suspended OU" in plan_by_name["QuarantinedAcct"].reason


def test_provision_account_skips_suspended():
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [
        {"Accounts": [{"Id": "222222222222", "Name": "ClosedInAws", "Status": "SUSPENDED"}]}
    ]
    mock_org_client.get_paginator.return_value = accts_paginator

    service = AccountService(mock_session_mgr)
    acct_def = AccountDef(name="ClosedInAws", email="closed@example.com", ou="Infrastructure")

    result = service.provision_account(acct_def, target_ou_id="ou-infra-123", dry_run=False)
    assert result.status == "SKIPPED"
    assert result.action_taken == "SUSPENDED_SKIPPED"
    mock_org_client.move_account.assert_not_called()
    mock_org_client.tag_resource.assert_not_called()


def test_provision_account_new_account_full_lifecycle():
    """Verify asynchronous account creation: create request, polling SUCCEEDED, moving to OU, and tagging."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [{"Accounts": []}]

    tags_paginator = MagicMock()
    tags_paginator.paginate.return_value = [{"Tags": []}]

    def paginator_side_effect(op_name: str) -> MagicMock:
        return tags_paginator if op_name == "list_tags_for_resource" else accts_paginator

    mock_org_client.get_paginator.side_effect = paginator_side_effect

    mock_org_client.create_account.return_value = {
        "CreateAccountStatus": {"Id": "car-12345", "State": "IN_PROGRESS"}
    }

    mock_org_client.describe_create_account_status.side_effect = [
        {"CreateAccountStatus": {"State": "IN_PROGRESS"}},
        {"CreateAccountStatus": {"State": "SUCCEEDED", "AccountId": "555555555555"}},
    ]

    mock_org_client.list_parents.return_value = {"Parents": [{"Id": "r-root-001"}]}

    service = AccountService(mock_session_mgr)
    acct_def = AccountDef(
        name="SecurityHub-Master",
        email="sechub@example.com",
        ou="Security",
        tags={"Environment": "Security", "ManagedBy": "tarmac"},
    )

    with patch("time.sleep", return_value=None):
        res = service.provision_account(acct_def, target_ou_id="ou-sec-999", dry_run=False)

    assert res.status == "SUCCEEDED"
    assert res.action_taken == "CREATED"
    assert res.account_id == "555555555555"

    mock_org_client.create_account.assert_called_once_with(
        Email="sechub@example.com",
        AccountName="SecurityHub-Master",
        RoleName="OrganizationAccountAccessRole",
        Tags=[
            {"Key": "Environment", "Value": "Security"},
            {"Key": "ManagedBy", "Value": "tarmac"},
        ],
    )
    mock_org_client.move_account.assert_called_once_with(
        AccountId="555555555555",
        SourceParentId="r-root-001",
        DestinationParentId="ou-sec-999",
    )
    mock_org_client.tag_resource.assert_called_once()


def test_poll_create_account_status_failure_surfaces_aws_reason():
    """Verify that when AWS async account creation fails, AccountProvisioningError extracts AWS FailureReason."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.describe_create_account_status.return_value = {
        "CreateAccountStatus": {
            "State": "FAILED",
            "FailureReason": "EMAIL_ALREADY_EXISTS",
        }
    }

    service = AccountService(mock_session_mgr)
    with patch("time.sleep", return_value=None):
        with pytest.raises(AccountProvisioningError) as exc_info:
            service._poll_create_account_status("car-fail-99", "DupeAccount")

    assert "FAILED" in str(exc_info.value)
    assert "EMAIL_ALREADY_EXISTS" in (exc_info.value.details or "")


def test_poll_create_account_status_timeout():
    """Verify that when account creation status times out, AccountProvisioningError is raised."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.describe_create_account_status.return_value = {
        "CreateAccountStatus": {"State": "IN_PROGRESS"}
    }

    service = AccountService(mock_session_mgr)
    with patch("time.sleep", return_value=None):
        with pytest.raises(AccountProvisioningError) as exc_info:
            service._poll_create_account_status("car-slow-99", "SlowAccount", max_attempts=3, delay_sec=0)

    assert "timed out" in (exc_info.value.details or "").lower()


def test_move_account_client_error_wrapped():
    """Verify move_account ClientError is wrapped into AccountProvisioningError with AWS error details."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    mock_org_client.list_parents.return_value = {"Parents": [{"Id": "ou-old"}]}
    mock_org_client.move_account.side_effect = ClientError(
        {"Error": {"Code": "SourceParentNotFoundException", "Message": "Source parent not found"}},
        "MoveAccount",
    )

    service = AccountService(mock_session_mgr)
    with pytest.raises(AccountProvisioningError) as exc_info:
        service.move_account_if_needed("111122223333", "BrokenMove", "ou-new")

    assert "Failed to move account 'BrokenMove'" in str(exc_info.value)
    assert "Source parent not found" in (exc_info.value.details or "")


def test_sync_account_tags_pattern_error_provides_actionable_hint():
    """Verify sync_account_tags appends actionable character set guidance when regex pattern error occurs."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": []}]
    mock_org_client.get_paginator.return_value = tag_paginator

    mock_org_client.tag_resource.side_effect = ClientError(
        {
            "Error": {
                "Code": "InvalidInputException",
                "Message": "Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*",
            }
        },
        "TagResource",
    )

    service = AccountService(mock_session_mgr)
    with pytest.raises(AccountProvisioningError) as exc_info:
        service.sync_account_tags("111122223333", "TaggedAcct", {"Env": "bad,comma"})

    assert "commas and other punctuation are not allowed" in (exc_info.value.details or "")


def test_provision_accounts_batch_mixed_existing_and_new():
    """Verify provision_accounts handles mixed existing and new accounts in parallel."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    # list_accounts returns Existing-1
    acct_paginator = MagicMock()
    acct_paginator.paginate.return_value = [
        {"Accounts": [{"Id": "111111111111", "Name": "Existing-1", "Status": "ACTIVE"}]}
    ]
    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": []}]

    def paginator_side_effect(operation_name):
        if operation_name == "list_accounts":
            return acct_paginator
        if operation_name == "list_tags_for_resource":
            return tag_paginator
        return MagicMock()

    mock_org_client.get_paginator.side_effect = paginator_side_effect
    mock_org_client.list_parents.return_value = {"Parents": [{"Id": "ou-workloads"}]}
    mock_org_client.create_account.return_value = {"CreateAccountStatus": {"Id": "car-new-2"}}
    mock_org_client.describe_create_account_status.return_value = {
        "CreateAccountStatus": {"State": "SUCCEEDED", "AccountId": "222222222222"}
    }

    service = AccountService(mock_session_mgr)
    accts = [
        AccountDef(name="Existing-1", email="ex1@test.com", ou="Workloads", tags={"Env": "Prod"}),
        AccountDef(name="New-2", email="new2@test.com", ou="Workloads", tags={"Env": "Dev"}),
    ]
    ou_map = {"Workloads": "ou-workloads"}

    with patch("time.sleep", return_value=None):
        results = service.provision_accounts(accts, ou_map=ou_map, poll_delay_sec=0)

    assert len(results) == 2
    assert results[0].name == "Existing-1"
    assert results[0].account_id == "111111111111"
    assert results[0].action_taken in ["REUSED", "TAGGED"]
    assert results[0].status == "SUCCEEDED"

    assert results[1].name == "New-2"
    assert results[1].account_id == "222222222222"
    assert results[1].action_taken == "CREATED"
    assert results[1].status == "SUCCEEDED"


def test_provision_accounts_missing_target_ou():
    """Verify provision_accounts records FAILED for missing target OU without crashing other accounts."""
    mock_session_mgr = MagicMock()
    mock_org_client = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org_client

    acct_paginator = MagicMock()
    acct_paginator.paginate.return_value = [{"Accounts": []}]
    mock_org_client.get_paginator.return_value = acct_paginator

    service = AccountService(mock_session_mgr)
    accts = [
        AccountDef(name="BadOU-Acct", email="bad@test.com", ou="NonExistentOU"),
    ]
    ou_map = {"ValidOU": "ou-valid"}

    results = service.provision_accounts(accts, ou_map=ou_map)
    assert len(results) == 1
    assert results[0].name == "BadOU-Acct"
    assert results[0].status == "FAILED"
    assert results[0].action_taken == "FAILED"


def test_find_existing_account_normalized():
    mock_session_mgr = MagicMock()
    service = AccountService(mock_session_mgr)
    existing = {
        "Log-Archive": {"Id": "111111111111", "Name": "Log-Archive"},
        "Audit Account": {"Id": "222222222222", "Name": "Audit Account"},
    }

    assert service.find_existing_account("Log-Archive", existing) == existing["Log-Archive"]
    assert service.find_existing_account("log_archive", existing) == existing["Log-Archive"]
    assert service.find_existing_account("audit-account", existing) == existing["Audit Account"]
    assert service.find_existing_account("NonExistent", existing) is None
