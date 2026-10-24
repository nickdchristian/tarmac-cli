"""IdentityService and permission-set tests."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml
from botocore.exceptions import ClientError

from tarmac.core.config_schema import (
    AssignmentDef,
    GroupDef,
    IdentityCenterConfig,
    PermissionSetDef,
    UserDef,
)
from tarmac.core.exceptions import IdentityCenterError
from tarmac.services.identity import IdentityService


def test_identity_get_instance_details():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_session_mgr.get_client.return_value = mock_sso

    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    service = IdentityService(mock_session_mgr)
    arn, store_id = service.get_instance_details()

    assert arn == "arn:aws:sso:::instance/ssoins-123"
    assert store_id == "d-1234567890"


def test_identity_auto_discovers_region():
    mock_session_mgr = MagicMock()
    mock_session_mgr.default_region = "us-east-2"

    mock_sso_east2 = MagicMock()
    mock_sso_east2.list_instances.return_value = {"Instances": []}

    mock_sso_east1 = MagicMock()
    mock_sso_east1.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-auto", "IdentityStoreId": "d-auto"}]
    }

    def client_side_effect(service_name: str, region_name: str | None = None, **kwargs):
        if service_name == "sso-admin":
            if region_name == "us-east-1":
                return mock_sso_east1
            return mock_sso_east2
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect

    service = IdentityService(mock_session_mgr, preferred_region="us-east-2")
    arn, store_id = service.get_instance_details()

    assert arn == "arn:aws:sso:::instance/ssoins-auto"
    assert store_id == "d-auto"
    assert service.region == "us-east-1"


def test_identity_get_or_create_user():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "sso-admin":
            return mock_sso
        if service_name == "identitystore":
            return mock_idstore
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    # User does not exist, create user
    mock_idstore.list_users.return_value = {"Users": []}
    mock_idstore.create_user.return_value = {"UserId": "u-user123"}

    service = IdentityService(mock_session_mgr)
    user_id = service.get_or_create_user(
        UserDef(username="testuser", email="test@example.com", first_name="Test", last_name="User")
    )

    assert user_id == "u-user123"
    mock_idstore.create_user.assert_called_once()


def test_identity_get_user_id_by_username():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()

    mock_session_mgr.get_client.side_effect = lambda s, **kw: mock_sso if s == "sso-admin" else mock_idstore
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    mock_idstore.list_users.return_value = {"Users": [{"UserId": "u-admin456"}]}
    service = IdentityService(mock_session_mgr)
    uid = service.get_user_id_by_username("admin")
    assert uid == "u-admin456"

    # User not found
    mock_idstore.list_users.return_value = {"Users": []}
    assert service.get_user_id_by_username("nonexistent") is None


def test_identity_add_user_to_group():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()

    mock_session_mgr.get_client.side_effect = lambda s, **kw: mock_sso if s == "sso-admin" else mock_idstore
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    service = IdentityService(mock_session_mgr)

    # Success (newly added)
    assert service.add_user_to_group("g-123", "u-456", "app-admin", "admin") is True
    mock_idstore.create_group_membership.assert_called_once_with(
        IdentityStoreId="d-1234567890",
        GroupId="g-123",
        MemberId={"UserId": "u-456"},
    )

    # Already member (ConflictException)
    conflict_err = ClientError(
        {"Error": {"Code": "ConflictException", "Message": "Conflict"}}, "CreateGroupMembership"
    )
    mock_idstore.create_group_membership.side_effect = conflict_err
    assert service.add_user_to_group("g-123", "u-456", "app-admin", "admin") is False


def test_identity_assign_group_to_accounts_polling_and_success():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()

    mock_session_mgr.get_client.side_effect = lambda s, **kw: mock_sso if s == "sso-admin" else mock_idstore
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    # Simulate IN_PROGRESS then SUCCEEDED polling
    mock_sso.create_account_assignment.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "IN_PROGRESS", "RequestId": "req-1"}
    }
    mock_sso.describe_account_assignment_creation_status.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "SUCCEEDED"}
    }

    service = IdentityService(mock_session_mgr)
    count = service.assign_group_to_accounts(
        group_id="g-123",
        group_name="app-admin",
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-456",
        account_ids=["111122223333"],
    )
    assert count == 1
    mock_sso.create_account_assignment.assert_called_once()
    mock_sso.describe_account_assignment_creation_status.assert_called_once()


def test_identity_assign_group_to_accounts_conflict():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()

    mock_session_mgr.get_client.side_effect = lambda s, **kw: mock_sso if s == "sso-admin" else mock_idstore
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    conflict_err = ClientError(
        {"Error": {"Code": "ConflictException", "Message": "Conflict"}}, "CreateAccountAssignment"
    )
    mock_sso.create_account_assignment.side_effect = conflict_err

    service = IdentityService(mock_session_mgr)
    count = service.assign_group_to_accounts(
        group_id="g-123",
        group_name="app-admin",
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-456",
        account_ids=["111122223333"],
    )
    # Existing assignment is counted as configured
    assert count == 1


def test_identity_assign_group_to_accounts_failure():
    from tarmac.core.exceptions import IdentityCenterError

    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()

    mock_session_mgr.get_client.side_effect = lambda s, **kw: mock_sso if s == "sso-admin" else mock_idstore
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    mock_sso.create_account_assignment.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "FAILED", "FailureReason": "Access denied by SCP"}
    }

    service = IdentityService(mock_session_mgr)
    with pytest.raises(IdentityCenterError) as exc_info:
        service.assign_group_to_accounts(
            group_id="g-123",
            group_name="app-admin",
            permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-456",
            account_ids=["111122223333"],
        )
    assert "Access denied by SCP" in str(exc_info.value)


def test_identity_sync_identity():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()
    mock_org = MagicMock()

    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "organization-sso-permission-sets", "StackStatus": "CREATE_COMPLETE"}]
    }
    mock_cfn.get_paginator.return_value.paginate.return_value = [
        {"StackResourceSummaries": [{"LogicalResourceId": "PermissionSetAdministratorAccess"}]}
    ]

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "sso-admin":
            return mock_sso
        if service_name == "identitystore":
            return mock_idstore
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-123", "IdentityStoreId": "d-1234567890"}]
    }

    ps_paginator = MagicMock()
    ps_paginator.paginate.return_value = [
        {"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-123/ps-test"]}
    ]
    mock_sso.get_paginator.return_value = ps_paginator
    mock_sso.describe_permission_set.return_value = {
        "PermissionSet": {
            "Name": "AdministratorAccess",
            "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-123/ps-test",
        }
    }

    mock_idstore.list_users.return_value = {"Users": []}
    mock_idstore.create_user.return_value = {"UserId": "u-123"}

    mock_idstore.list_groups.return_value = {"Groups": []}
    mock_idstore.create_group.return_value = {"GroupId": "g-123"}

    mock_idstore.create_group_membership.return_value = {"MembershipId": "m-123"}

    mock_sso.create_account_assignment.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "SUCCEEDED"}
    }

    service = IdentityService(mock_session_mgr)
    id_cfg = IdentityCenterConfig(
        admin_user=UserDef(username="admin", email="admin@example.com", first_name="Admin", last_name="User"),
        breakglass_user=UserDef(
            username="breakglass", email="bg@example.com", first_name="Break", last_name="Glass"
        ),
        permission_sets=[PermissionSetDef(name="AdministratorAccess")],
        groups=[
            GroupDef(
                name="Admins",
                members=["admin"],
                assignments=[AssignmentDef(permission_set="AdministratorAccess", accounts=["TestAccount"])],
            )
        ],
    )

    report = service.sync_identity(id_cfg, active_accounts={"TestAccount": "111122223333"})

    assert "AdministratorAccess" in report.permission_sets_synced
    assert "admin" in report.users_synced
    assert "breakglass" in report.users_synced
    assert "Admins" in report.groups_synced
    assert report.assignments_created == 1
    assert report.memberships_added == 1


def test_identity_synthesize_permission_sets_template(tmp_path: Path):
    mock_session_mgr = MagicMock()
    service = IdentityService(mock_session_mgr)

    policy_file = tmp_path / "custom-inline.json"
    policy_file.write_text(
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )

    defs = [
        PermissionSetDef(
            name="CloudOps",
            description="Cloud Ops Role",
            session_duration="PT4H",
            managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"],
            inline_policy_file=str(policy_file),
        ),
        PermissionSetDef(
            name="ReadOnly",
            session_duration="PT8H",
            managed_policies=["arn:aws:iam::aws:policy/ReadOnlyAccess"],
        ),
    ]

    tmpl = service.synthesize_permission_sets_template(
        instance_arn="arn:aws:sso:::instance/ssoins-abc",
        permission_sets=defs,
        project_root=tmp_path,
    )

    assert tmpl["AWSTemplateFormatVersion"] == "2010-09-09"
    assert "PermissionSetCloudOps" in tmpl["Resources"]
    assert "PermissionSetReadOnly" in tmpl["Resources"]

    cloud_ops = tmpl["Resources"]["PermissionSetCloudOps"]
    assert cloud_ops["Type"] == "AWS::SSO::PermissionSet"
    assert cloud_ops["DeletionPolicy"] == "Retain"
    assert cloud_ops["Properties"]["InstanceArn"] == "arn:aws:sso:::instance/ssoins-abc"
    assert cloud_ops["Properties"]["SessionDuration"] == "PT4H"
    assert cloud_ops["Properties"]["ManagedPolicies"] == ["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert "InlinePolicy" in cloud_ops["Properties"]
    assert cloud_ops["Properties"]["InlinePolicy"]["Statement"][0]["Effect"] == "Allow"


def test_identity_sync_permission_sets_via_cfn_deploy(tmp_path: Path):
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_cfn = MagicMock()

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "sso-admin":
            return mock_sso
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-live", "IdentityStoreId": "d-live"}]
    }

    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )

    ps_paginator = MagicMock()
    ps_paginator.paginate.side_effect = [
        [],  # initial check: no pre-existing permission sets
        [{"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-live/ps-live"]}],  # final check
    ]
    mock_sso.get_paginator.return_value = ps_paginator
    mock_sso.describe_permission_set.return_value = {
        "PermissionSet": {
            "Name": "DeployRole",
            "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-live/ps-live",
        }
    }

    service = IdentityService(mock_session_mgr)
    defs = [
        PermissionSetDef(name="DeployRole", managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"])
    ]

    res = service.sync_permission_sets_via_cloudformation(
        permission_sets=defs,
        project_root=tmp_path,
        org_name="myorg",
        org_tags={"CostCenter": "CC-Global"},
    )

    assert res == {"DeployRole": "arn:aws:sso:::permissionSet/ssoins-live/ps-live"}
    assert (tmp_path / "outputs" / "sso-permission-sets.yaml").exists()
    mock_cfn.create_stack.assert_called_once()
    assert mock_cfn.create_stack.call_args[1]["StackName"] == "myorg-sso-permission-sets"
    assert mock_cfn.create_stack.call_args[1]["Tags"] == [
        {"Key": "ManagedBy", "Value": "tarmac"},
        {"Key": "CostCenter", "Value": "CC-Global"},
    ]


def test_identity_sync_permission_sets_via_cfn_imports_when_preexisting(tmp_path: Path):
    """Verify that pre-existing permission sets trigger CloudFormation resource import."""
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_cfn = MagicMock()

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "sso-admin":
            return mock_sso
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-live", "IdentityStoreId": "d-live"}]
    }

    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )

    ps_paginator = MagicMock()
    ps_paginator.paginate.return_value = [
        {"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-live/ps-live"]}
    ]
    mock_sso.get_paginator.return_value = ps_paginator
    mock_sso.describe_permission_set.return_value = {
        "PermissionSet": {
            "Name": "DeployRole",
            "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-live/ps-live",
        }
    }

    service = IdentityService(mock_session_mgr)
    defs = [
        PermissionSetDef(name="DeployRole", managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"])
    ]

    res = service.sync_permission_sets_via_cloudformation(
        permission_sets=defs,
        project_root=tmp_path,
        org_name="myorg",
    )

    assert res == {"DeployRole": "arn:aws:sso:::permissionSet/ssoins-live/ps-live"}
    mock_cfn.create_change_set.assert_called_once()
    call_kwargs = mock_cfn.create_change_set.call_args[1]
    assert call_kwargs["ChangeSetType"] == "IMPORT"
    assert call_kwargs["ResourcesToImport"] == [
        {
            "ResourceType": "AWS::SSO::PermissionSet",
            "LogicalResourceId": "PermissionSetDeployRole",
            "ResourceIdentifier": {
                "InstanceArn": "arn:aws:sso:::instance/ssoins-live",
                "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-live/ps-live",
            },
        }
    ]
    mock_cfn.execute_change_set.assert_called_once()


def test_identity_sync_permission_sets_import_failure_raises_without_deleting(tmp_path: Path):
    """If importing pre-existing permission sets fails, nothing is deleted and the error surfaces."""
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_cfn = MagicMock()

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "sso-admin":
            return mock_sso
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-live", "IdentityStoreId": "d-live"}]
    }

    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )
    mock_cfn.create_change_set.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Cannot modify tags during import"}},
        "CreateChangeSet",
    )

    ps_paginator = MagicMock()
    ps_paginator.paginate.side_effect = [
        [{"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-live/ps-live"]}],
        [],
        [{"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-live/ps-new"]}],
    ]
    mock_sso.get_paginator.return_value = ps_paginator
    mock_sso.describe_permission_set.return_value = {
        "PermissionSet": {
            "Name": "DeployRole",
            "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-live/ps-new",
        }
    }

    service = IdentityService(mock_session_mgr)
    defs = [
        PermissionSetDef(name="DeployRole", managed_policies=["arn:aws:iam::aws:policy/AdministratorAccess"])
    ]

    with pytest.raises(IdentityCenterError):
        service.sync_permission_sets_via_cloudformation(
            permission_sets=defs,
            project_root=tmp_path,
            org_name="myorg",
        )

    mock_sso.delete_permission_set.assert_not_called()
    mock_cfn.create_stack.assert_not_called()


def test_identity_poll_assignment_status_failed_raises_error():
    """Verify that _poll_assignment_status raises IdentityCenterError when status transitions to FAILED."""
    from tarmac.core.exceptions import IdentityCenterError

    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_session_mgr.get_client.return_value = mock_sso

    mock_sso.describe_account_assignment_creation_status.return_value = {
        "AccountAssignmentCreationStatus": {
            "Status": "FAILED",
            "FailureReason": "Target account is not accessible due to SCP",
        }
    }

    service = IdentityService(mock_session_mgr)
    with pytest.raises(IdentityCenterError) as exc_info:
        service._poll_assignment_status(
            instance_arn="arn:aws:sso:::instance/sso-1",
            request_id="req-123",
            group_name="Developers",
            acct_id="111122223333",
            timeout_seconds=5.0,
            poll_interval=0.01,
        )

    assert "Target account is not accessible due to SCP" in str(exc_info.value)


def test_identity_poll_assignment_status_timeout_logs_warning(caplog):
    """Verify that _poll_assignment_status times out cleanly without crashing when status stays IN_PROGRESS."""
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_session_mgr.get_client.return_value = mock_sso

    mock_sso.describe_account_assignment_creation_status.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "IN_PROGRESS"}
    }

    service = IdentityService(mock_session_mgr)
    # With a small timeout, verify it completes without unhandled exception
    service._poll_assignment_status(
        instance_arn="arn:aws:sso:::instance/sso-1",
        request_id="req-123",
        group_name="Developers",
        acct_id="111122223333",
        timeout_seconds=0.05,
        poll_interval=0.01,
    )
    assert mock_sso.describe_account_assignment_creation_status.call_count >= 1
    assert any(r.levelname == "WARNING" and "111122223333" in r.getMessage() for r in caplog.records), (
        "timeout must be surfaced as a warning that names the account"
    )


def _identity_service(mock_sso: MagicMock, mock_cfn: MagicMock) -> IdentityService:
    mgr = MagicMock()
    mgr.get_client.side_effect = lambda name, **_: mock_sso if name == "sso-admin" else mock_cfn
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1"}]
    }
    return IdentityService(mgr)


def test_import_failure_raises_and_never_deletes_permission_sets(tmp_path: Path):
    mock_sso, mock_cfn = MagicMock(), MagicMock()
    service = _identity_service(mock_sso, mock_cfn)
    paginator = MagicMock()
    paginator.paginate.return_value = [{"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-1/ps-1"]}]
    mock_sso.get_paginator.return_value = paginator
    mock_sso.describe_permission_set.return_value = {"PermissionSet": {"Name": "AdministratorAccess"}}
    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )
    mock_cfn.create_change_set.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "boom"}}, "CreateChangeSet"
    )

    with pytest.raises(IdentityCenterError) as exc:
        service.sync_permission_sets_via_cloudformation(
            [PermissionSetDef(name="AdministratorAccess", managed_policies=[])],
            project_root=tmp_path,
            org_name="myorg",
        )

    assert "AdministratorAccess" in str(exc.value)
    mock_sso.delete_permission_set.assert_not_called()
    mock_sso.delete_account_assignment.assert_not_called()
    mock_cfn.create_stack.assert_not_called()


def test_permission_set_template_carries_ownership_tag_unless_importing():
    service = _identity_service(MagicMock(), MagicMock())
    defs = [PermissionSetDef(name="Ops", managed_policies=[])]
    tagged = service.synthesize_permission_sets_template("arn:inst", defs)
    untagged = service.synthesize_permission_sets_template("arn:inst", defs, include_ownership_tag=False)
    assert tagged["Resources"]["PermissionSetOps"]["Properties"]["Tags"] == [
        {"Key": "tarmac:managed-by", "Value": "tarmac"}
    ]
    assert "Tags" not in untagged["Resources"]["PermissionSetOps"]["Properties"]


def test_is_tarmac_managed_permission_set_fails_closed():
    mock_sso = MagicMock()
    service = _identity_service(mock_sso, MagicMock())
    paginator = MagicMock()
    mock_sso.get_paginator.return_value = paginator

    paginator.paginate.return_value = [{"Tags": [{"Key": "tarmac:managed-by", "Value": "tarmac"}]}]
    assert service.is_tarmac_managed_permission_set("i", "p") is True

    paginator.paginate.return_value = [{"Tags": [{"Key": "Team", "Value": "x"}]}]
    assert service.is_tarmac_managed_permission_set("i", "p") is False

    paginator.paginate.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "x")
    assert service.is_tarmac_managed_permission_set("i", "p") is False


def test_identity_synthesize_permission_sets_disambiguates_colliding_logical_ids():
    service = _identity_service(MagicMock(), MagicMock())
    defs = [
        PermissionSetDef(name="dev-admin", managed_policies=[]),
        PermissionSetDef(name="dev_admin", managed_policies=[]),
        PermissionSetDef(name="---", managed_policies=[]),
    ]
    tmpl = service.synthesize_permission_sets_template("arn:inst", defs)
    resources = tmpl["Resources"]
    assert len(resources) == 3
    for logical_id in resources:
        assert logical_id.isalnum()
        assert logical_id != "PermissionSet"


def test_identity_sync_permission_sets_imports_only_preexisting_when_mixed_with_new(tmp_path: Path):
    """When only a subset of declared permission sets exist in AWS, IMPORT includes only pre-existing ones."""
    import yaml

    mock_sso, mock_cfn = MagicMock(), MagicMock()
    service = _identity_service(mock_sso, mock_cfn)
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"PermissionSets": ["arn:aws:sso:::permissionSet/ssoins-1/ps-existing"]}
    ]
    mock_sso.get_paginator.return_value = paginator
    mock_sso.describe_permission_set.return_value = {
        "PermissionSet": {
            "Name": "ExistingRole",
            "PermissionSetArn": "arn:aws:sso:::permissionSet/ssoins-1/ps-existing",
        }
    }
    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )

    defs = [
        PermissionSetDef(name="ExistingRole", managed_policies=[]),
        PermissionSetDef(name="BrandNewRole", managed_policies=[]),
    ]
    service.sync_permission_sets_via_cloudformation(defs, project_root=tmp_path, org_name="myorg")

    import_kwargs = mock_cfn.create_change_set.call_args.kwargs
    import_doc = yaml.safe_load(import_kwargs["TemplateBody"])
    assert list(import_doc["Resources"].keys()) == ["PermissionSetExistingRole"]
    assert [r["LogicalResourceId"] for r in import_kwargs["ResourcesToImport"]] == [
        "PermissionSetExistingRole"
    ]

    final_kwargs = (mock_cfn.create_stack.call_args or mock_cfn.update_stack.call_args).kwargs
    final_doc = yaml.safe_load(final_kwargs["TemplateBody"])
    assert set(final_doc["Resources"].keys()) == {"PermissionSetExistingRole", "PermissionSetBrandNewRole"}


def test_identity_delete_permission_set_returns_false_on_client_error():
    mock_sso = MagicMock()
    service = _identity_service(mock_sso, MagicMock())
    service.get_assignments_for_permission_set = MagicMock(return_value=[])  # type: ignore[method-assign]
    mock_sso.delete_permission_set.side_effect = ClientError(
        {"Error": {"Code": "ConflictException", "Message": "Still assigned"}}, "DeletePermissionSet"
    )
    assert service.delete_permission_set("arn:inst", "arn:ps") is False


def test_existing_sets_missing_from_an_existing_stack_are_imported_into_it(tmp_path: Path):
    """A stack that manages some sets imports the other pre-existing ones, keeping its live template."""
    session_mgr, sso, cfn = MagicMock(), MagicMock(), MagicMock()
    session_mgr.get_client.side_effect = lambda name, **kw: {"sso-admin": sso, "cloudformation": cfn}.get(
        name, MagicMock()
    )
    sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-live", "IdentityStoreId": "d-live"}]
    }
    arns = {
        "Admin": "arn:aws:sso:::permissionSet/ssoins-live/ps-1",
        "Deploy": "arn:aws:sso:::permissionSet/ssoins-live/ps-2",
    }
    sso.get_paginator.return_value.paginate.return_value = [{"PermissionSets": list(arns.values())}]
    sso.describe_permission_set.side_effect = lambda **kw: {
        "PermissionSet": {
            "Name": next(n for n, a in arns.items() if a == kw["PermissionSetArn"]),
            "PermissionSetArn": kw["PermissionSetArn"],
        }
    }
    cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "UPDATE_ROLLBACK_COMPLETE"}]}
    cfn.get_paginator.return_value.paginate.return_value = [
        {"StackResourceSummaries": [{"LogicalResourceId": "PermissionSetAdmin"}]}
    ]
    live = "Resources:\n  PermissionSetAdmin:\n    Type: AWS::SSO::PermissionSet\n    Properties: {Name: Admin}\n"
    cfn.get_template.return_value = {"TemplateBody": live}

    IdentityService(session_mgr).sync_permission_sets_via_cloudformation(
        permission_sets=[PermissionSetDef(name="Admin"), PermissionSetDef(name="Deploy")],
        project_root=tmp_path,
        org_name="myorg",
    )

    change_set = cfn.create_change_set.call_args.kwargs
    assert change_set["ChangeSetType"] == "IMPORT"
    assert [r["LogicalResourceId"] for r in change_set["ResourcesToImport"]] == ["PermissionSetDeploy"]
    resources = yaml.safe_load(change_set["TemplateBody"])["Resources"]
    assert resources["PermissionSetAdmin"] == {
        "Type": "AWS::SSO::PermissionSet",
        "Properties": {"Name": "Admin"},
    }
    assert resources["PermissionSetDeploy"]["Properties"]["Name"] == "Deploy"
    cfn.update_stack.assert_called()


def _access_service(assignments: list[tuple[str, str]], members: dict[str, str]) -> IdentityService:
    """An IdentityService whose group holds ``assignments`` and has ``members`` ({username: user id})."""
    session_mgr = MagicMock()
    sso, idstore = MagicMock(), MagicMock()
    session_mgr.get_client.side_effect = lambda name, **_: {"sso-admin": sso, "identitystore": idstore}.get(
        name, MagicMock()
    )
    sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:i", "IdentityStoreId": "d-1"}]}
    sso.get_paginator.return_value.paginate.return_value = [
        {"AccountAssignments": [{"AccountId": a, "PermissionSetArn": p} for a, p in assignments]}
    ]
    idstore.get_paginator.return_value.paginate.return_value = [
        {
            "GroupMemberships": [
                {"MembershipId": f"m-{u}", "MemberId": {"UserId": uid}} for u, uid in members.items()
            ]
        }
    ]
    by_id = {uid: u for u, uid in members.items()}
    idstore.describe_user.side_effect = lambda IdentityStoreId, UserId: {"UserName": by_id[UserId]}
    return IdentityService(session_mgr)


def test_undeclared_access_is_found_only_on_the_accounts_tarmac_manages():
    service = _access_service(
        assignments=[("111", "arn:admin"), ("111", "arn:read"), ("222", "arn:read"), ("999", "arn:admin")],
        members={"alice": "u-1", "bob": "u-2"},
    )
    group = GroupDef(
        name="Admins",
        members=["alice"],
        assignments=[AssignmentDef(permission_set="Admin", accounts=["dev"])],
    )
    assignments, members = service.undeclared_access(
        "arn:i",
        group,
        "g-1",
        {"Admin": "arn:admin", "Read": "arn:read"},
        {"dev": "111", "prod": "222", "management": "999"},
        managed_ids={"111", "222"},
    )
    # 999 (the management account) is not in accounts.yaml, so its assignment is left alone.
    assert assignments == [("111", "arn:read"), ("222", "arn:read")]
    assert members == {"bob": "m-bob"}


def test_sync_identity_removes_what_identity_yaml_no_longer_declares(monkeypatch):
    service = _access_service(assignments=[("111", "arn:read")], members={"bob": "u-2"})
    monkeypatch.setattr(
        service, "sync_permission_sets_via_cloudformation", lambda *a, **k: {"Read": "arn:read"}
    )
    monkeypatch.setattr(service, "get_or_create_user", lambda user: f"u-{user.username}")
    monkeypatch.setattr(service, "sync_groups_and_assignments", lambda *a: (0, {"Admins": "g-1"}, ["Admins"]))
    monkeypatch.setattr(service, "sync_group_memberships", lambda *a: 0)
    removed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service,
        "delete_account_assignment",
        lambda inst, acct, ps, kind, pid: removed.append((acct, ps)) or True,
    )
    cfg = IdentityCenterConfig(
        admin_user=UserDef(username="admin", email="a@example.com", first_name="A", last_name="U"),
        breakglass_user=UserDef(username="bg", email="b@example.com", first_name="B", last_name="G"),
        groups=[GroupDef(name="Admins", members=[], assignments=[])],
    )

    report = service.sync_identity(cfg, active_accounts={"dev": "111"}, managed_accounts=["dev"])

    assert removed == [("111", "arn:read")]
    assert (report.assignments_removed, report.memberships_removed) == (1, 1)
    service.identitystore_client.delete_group_membership.assert_called_once_with(
        IdentityStoreId="d-1", MembershipId="m-bob"
    )


def test_an_assignment_that_cannot_be_removed_fails_the_sync(monkeypatch):
    service = _access_service(assignments=[("111", "arn:read")], members={})
    monkeypatch.setattr(service, "sync_permission_sets_via_cloudformation", lambda *a, **k: {})
    monkeypatch.setattr(service, "get_or_create_user", lambda user: "u")
    monkeypatch.setattr(service, "sync_groups_and_assignments", lambda *a: (0, {"Admins": "g-1"}, ["Admins"]))
    monkeypatch.setattr(service, "sync_group_memberships", lambda *a: 0)
    monkeypatch.setattr(service, "delete_account_assignment", lambda *a: False)
    cfg = IdentityCenterConfig(
        admin_user=UserDef(username="admin", email="a@example.com", first_name="A", last_name="U"),
        breakglass_user=UserDef(username="bg", email="b@example.com", first_name="B", last_name="G"),
        groups=[GroupDef(name="Admins")],
    )
    with pytest.raises(IdentityCenterError, match="Could not remove 1 undeclared assignment"):
        service.sync_identity(cfg, active_accounts={"dev": "111"}, managed_accounts=["dev"])
