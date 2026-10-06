"""Tests for OrganizationService, CloudFormationService, and IdentityService."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import (
    AssignmentDef,
    Contact,
    ContactsConfig,
    GroupDef,
    IdentityCenterConfig,
    PermissionSetDef,
    RootAccessConfig,
    UserDef,
)
from tarmac.core.exceptions import DeploymentError
from tarmac.services.cloudformation import CloudFormationService
from tarmac.services.identity import IdentityService
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
    cfg = RootAccessConfig(
        enabled=True,
        enable_root_credentials_management=True,
        enable_root_sessions=True,
        delegated_admin_account="Audit",
    )

    results = service.configure_root_access(cfg, account_id_map={"Audit": "999999999999"})
    assert results["iam_trusted_access"] is True
    assert results["root_credentials_management"] is True
    assert results["root_sessions"] is True
    assert results["delegated_admin"] is True

    # Test case and separator-insensitive matching
    cfg_hyphen = RootAccessConfig(enabled=True, delegated_admin_account="audit-account")
    results_norm = service.configure_root_access(cfg_hyphen, account_id_map={"Audit Account": "888888888888"})
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


def test_cfn_deploy_stack_dry_run(tmp_path: Path):
    template = tmp_path / "test-template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()

    service = CloudFormationService(mock_session_mgr)
    report = service.deploy_stack(
        cfn_client=mock_cfn,
        stack_name="my-test-stack",
        template_file=template,
        parameters={"Param1": "Val1"},
        dry_run=True,
    )

    assert report.status == "SIMULATED"
    assert report.action == "SIMULATED"
    mock_cfn.create_stack.assert_not_called()


def test_cfn_deploy_stack_creates_new_stack(tmp_path: Path):
    template = tmp_path / "test-template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()

    # Stack does not exist
    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Message": "Stack does not exist", "Code": "ValidationError"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": [{"OutputKey": "TestOut", "OutputValue": "TestVal"}]}]},
    ]

    mock_waiter = MagicMock()
    mock_cfn.get_waiter.return_value = mock_waiter

    service = CloudFormationService(mock_session_mgr)
    report = service.deploy_stack(
        cfn_client=mock_cfn,
        stack_name="my-test-stack",
        template_file=template,
        parameters={"Key": "Value"},
        dry_run=False,
    )

    assert report.status == "SUCCEEDED"
    assert report.action == "CREATED"
    assert report.outputs.get("TestOut") == "TestVal"
    mock_cfn.create_stack.assert_called_once()
    mock_waiter.wait.assert_called_once()


def test_cfn_deploy_missing_template():
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    service = CloudFormationService(mock_session_mgr)

    with pytest.raises(DeploymentError, match="CloudFormation template not found"):
        service.deploy_stack(
            cfn_client=mock_cfn,
            stack_name="invalid-stack",
            template_file=Path("/nonexistent/template.yaml"),
            parameters={},
        )


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

    # Dry run
    assert service.add_user_to_group("g-123", "u-456", "flumen-admin", "admin", dry_run=True) is True
    mock_idstore.create_group_membership.assert_not_called()

    # Success (newly added)
    assert service.add_user_to_group("g-123", "u-456", "flumen-admin", "admin") is True
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
    assert service.add_user_to_group("g-123", "u-456", "flumen-admin", "admin") is False


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
        group_name="flumen-admin",
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
        group_name="flumen-admin",
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
            group_name="flumen-admin",
            permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-456",
            account_ids=["111122223333"],
        )
    assert "Access denied by SCP" in str(exc_info.value)


def test_get_member_client_caller_account():
    from unittest.mock import patch

    from tarmac.core.aws_client import AwsSessionManager

    with patch("boto3.Session"):
        mgr = AwsSessionManager(region_name="us-east-1")
        mgr.get_caller_identity = MagicMock(
            return_value={"Account": "316941624511", "Arn": "arn:aws:iam::316941624511:root"}
        )
        mock_client = MagicMock()
        mgr.get_client = MagicMock(return_value=mock_client)

        client = mgr.get_member_client("316941624511", "s3")
        assert client == mock_client
        mgr.get_client.assert_called_once_with("s3", region_name=None)


def test_identity_sync_identity():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_idstore = MagicMock()
    mock_org = MagicMock()

    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "organization-sso-permission-sets", "StackStatus": "CREATE_COMPLETE"}]
    }

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


def test_package_exports():
    import tarmac
    import tarmac.core
    import tarmac.services

    assert hasattr(tarmac, "__version__")
    assert isinstance(tarmac.__version__, str)
    assert len(tarmac.__version__.split(".")) >= 3

    assert hasattr(tarmac.services, "SCPService")
    assert hasattr(tarmac.services, "PreflightService")
    assert hasattr(tarmac.services, "AccountService")
    assert hasattr(tarmac.services, "BaselineService")
    assert hasattr(tarmac.services, "CloudFormationService")
    assert hasattr(tarmac.services, "IdentityService")
    assert hasattr(tarmac.services, "OrganizationService")
    assert hasattr(tarmac.services, "OUService")
    assert hasattr(tarmac.services, "StatusService")
    assert hasattr(tarmac.services, "DriftService")
    assert hasattr(tarmac.services, "SecurityServicesService")

    assert hasattr(tarmac.core, "PreflightReport")
    assert hasattr(tarmac.core, "PreflightCheckResult")
    assert hasattr(tarmac.core, "PreflightCheckStatus")
    assert hasattr(tarmac.core, "SecurityServiceReport")
    assert hasattr(tarmac.core, "normalize_account_name")
    assert hasattr(tarmac.core, "AwsSessionManager")
    assert hasattr(tarmac.core, "load_all_configs")


def test_cfn_deploy_stack_handles_rollback_complete(tmp_path: Path):
    template = tmp_path / "test-template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()

    # First describe_stacks returns ROLLBACK_COMPLETE, second returns created outputs
    mock_cfn.describe_stacks.side_effect = [
        {"Stacks": [{"StackName": "my-broken-stack", "StackStatus": "ROLLBACK_COMPLETE"}]},
        {"Stacks": [{"Outputs": [{"OutputKey": "TestOut", "OutputValue": "Recreated"}]}]},
    ]

    mock_delete_waiter = MagicMock()
    mock_create_waiter = MagicMock()
    mock_cfn.get_waiter.side_effect = lambda name: (
        mock_delete_waiter if name == "stack_delete_complete" else mock_create_waiter
    )

    service = CloudFormationService(mock_session_mgr)
    report = service.deploy_stack(
        cfn_client=mock_cfn,
        stack_name="my-broken-stack",
        template_file=template,
        parameters={"Env": "Test"},
        dry_run=False,
    )

    mock_cfn.delete_stack.assert_called_once_with(StackName="my-broken-stack")
    mock_delete_waiter.wait.assert_called_once()
    mock_cfn.create_stack.assert_called_once()
    assert report.status == "SUCCEEDED"
    assert report.action == "CREATED"


def test_cfn_deploy_stack_surfaces_event_failure_causes(tmp_path: Path):
    from botocore.exceptions import WaiterError

    template = tmp_path / "test-template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()

    # Stack does not exist
    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Message": "Stack does not exist", "Code": "ValidationError"}}, "DescribeStacks"
    )

    mock_waiter = MagicMock()
    mock_waiter.wait.side_effect = WaiterError("Wait failed", "CREATE_FAILED", {})
    mock_cfn.get_waiter.return_value = mock_waiter

    mock_cfn.describe_stack_events.return_value = {
        "StackEvents": [
            {
                "LogicalResourceId": "CloudTrailBucket",
                "ResourceStatus": "CREATE_FAILED",
                "ResourceStatusReason": "Bucket already exists globally in S3",
            }
        ]
    }

    service = CloudFormationService(mock_session_mgr)
    with pytest.raises(DeploymentError) as exc_info:
        service.deploy_stack(
            cfn_client=mock_cfn,
            stack_name="failing-stack",
            template_file=template,
            parameters={},
            dry_run=False,
        )

    assert "Bucket already exists globally in S3" in (exc_info.value.details or "")


def test_cfn_import_resources_and_deploy_stack_omits_tags_on_import():
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()

    mock_change_set_waiter = MagicMock()
    mock_import_waiter = MagicMock()
    mock_update_waiter = MagicMock()

    def waiter_side_effect(name: str):
        if name == "change_set_create_complete":
            return mock_change_set_waiter
        if name == "stack_import_complete":
            return mock_import_waiter
        if name == "stack_update_complete":
            return mock_update_waiter
        return MagicMock()

    mock_cfn.get_waiter.side_effect = waiter_side_effect
    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackName": "my-import-stack", "Outputs": []}]}

    service = CloudFormationService(mock_session_mgr)
    report = service.import_resources_and_deploy_stack(
        cfn_client=mock_cfn,
        stack_name="my-import-stack",
        template_body="Resources: {}",
        resources_to_import=[
            {
                "ResourceType": "AWS::Organizations::Policy",
                "LogicalResourceId": "ScpRoot",
                "ResourceIdentifier": {"Id": "p-123"},
            }
        ],
        tags={"Environment": "production"},
        dry_run=False,
    )

    mock_cfn.create_change_set.assert_called_once()
    call_kwargs = mock_cfn.create_change_set.call_args.kwargs
    assert call_kwargs["ChangeSetType"] == "IMPORT"
    # CRITICAL: create_change_set with IMPORT must NOT have Tags
    assert "Tags" not in call_kwargs

    mock_change_set_waiter.wait.assert_called_once()
    mock_cfn.execute_change_set.assert_called_once()
    mock_import_waiter.wait.assert_called_once()

    # Tags must be applied via update_stack after import
    mock_cfn.update_stack.assert_called_once()
    update_kwargs = mock_cfn.update_stack.call_args.kwargs
    assert update_kwargs["StackName"] == "my-import-stack"
    assert update_kwargs["UsePreviousTemplate"] is True
    assert any(t["Key"] == "Environment" and t["Value"] == "production" for t in update_kwargs["Tags"])
    mock_update_waiter.wait.assert_called_once()

    assert report.status == "SUCCEEDED"
    assert report.action == "IMPORTED"


def test_cfn_import_resources_failure_raises_deployment_error():
    from botocore.exceptions import ClientError

    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()

    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Message": "Stack does not exist", "Code": "ValidationError"}}, "DescribeStacks"
    )
    mock_cfn.create_change_set.side_effect = ClientError(
        {"Error": {"Message": "Template error", "Code": "ValidationError"}}, "CreateChangeSet"
    )

    service = CloudFormationService(mock_session_mgr)
    with pytest.raises(DeploymentError) as exc_info:
        service.import_resources_and_deploy_stack(
            cfn_client=mock_cfn,
            stack_name="failing-import-stack",
            template_body="Resources: {}",
            resources_to_import=[],
            dry_run=False,
        )

    assert "Failed to import resources into stack 'failing-import-stack'" in str(exc_info.value)


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


def test_identity_sync_permission_sets_via_cfn_dry_run():
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_session_mgr.get_client.return_value = mock_sso
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-dry", "IdentityStoreId": "d-dry"}]
    }

    service = IdentityService(mock_session_mgr)
    defs = [PermissionSetDef(name="DryRole")]
    res = service.sync_permission_sets_via_cloudformation(defs, dry_run=True)

    assert "DryRole" in res
    assert "simulated" in res["DryRole"]


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
        dry_run=False,
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
        dry_run=False,
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


def test_identity_sync_permission_sets_fallback_when_import_fails(tmp_path: Path):
    """Verify that if import fails, conflicting permission sets are cleaned up and stack is deployed fresh."""
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

    res = service.sync_permission_sets_via_cloudformation(
        permission_sets=defs,
        project_root=tmp_path,
        org_name="myorg",
        dry_run=False,
    )

    mock_sso.delete_permission_set.assert_called_once_with(
        InstanceArn="arn:aws:sso:::instance/ssoins-live",
        PermissionSetArn="arn:aws:sso:::permissionSet/ssoins-live/ps-live",
    )
    mock_cfn.create_stack.assert_called_once()
    assert res == {"DeployRole": "arn:aws:sso:::permissionSet/ssoins-live/ps-new"}


def test_identity_delete_permission_set_unassigns_accounts():
    """Verify delete_permission_set purges account assignments before deleting."""
    mock_session_mgr = MagicMock()
    mock_sso = MagicMock()
    mock_session_mgr.get_client.return_value = mock_sso

    acct_paginator = MagicMock()
    acct_paginator.paginate.return_value = [{"AccountIds": ["111122223333"]}]
    assign_paginator = MagicMock()
    assign_paginator.paginate.return_value = [
        {
            "AccountAssignments": [
                {
                    "AccountId": "111122223333",
                    "PrincipalType": "GROUP",
                    "PrincipalId": "g-12345",
                }
            ]
        }
    ]

    def paginator_side_effect(op: str) -> MagicMock:
        if op == "list_accounts_for_provisioned_permission_set":
            return acct_paginator
        if op == "list_account_assignments":
            return assign_paginator
        return MagicMock()

    mock_sso.get_paginator.side_effect = paginator_side_effect
    mock_sso.delete_account_assignment.return_value = {
        "AccountAssignmentDeletionStatus": {"Status": "SUCCEEDED"}
    }

    service = IdentityService(mock_session_mgr)
    service.delete_permission_set("arn:aws:sso:::instance/ssoins-1", "arn:aws:sso:::permissionSet/ps-1")

    mock_sso.delete_account_assignment.assert_called_once_with(
        InstanceArn="arn:aws:sso:::instance/ssoins-1",
        TargetId="111122223333",
        TargetType="AWS_ACCOUNT",
        PermissionSetArn="arn:aws:sso:::permissionSet/ps-1",
        PrincipalType="GROUP",
        PrincipalId="g-12345",
    )
    mock_sso.delete_permission_set.assert_called_once_with(
        InstanceArn="arn:aws:sso:::instance/ssoins-1",
        PermissionSetArn="arn:aws:sso:::permissionSet/ps-1",
    )


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


def test_identity_poll_assignment_status_timeout_logs_warning():
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


def test_status_service_inspect_end_to_end(sample_config_dir: Path):
    """Verify StatusService.inspect end-to-end against live AWS resource state."""
    from tarmac.core.config_loader import load_all_configs
    from tarmac.services.status import StatusService

    bundle, errors = load_all_configs(sample_config_dir)
    assert bundle is not None
    assert not errors

    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_cfn_mgmt = MagicMock()
    mock_cfn_dep = MagicMock()
    mock_sso = MagicMock()

    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-live123", "FeatureSet": "ALL"}}
    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-root-live"}]}

    # Paginator for list_accounts
    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE"},
                {"Id": "222222222222", "Name": "Production", "Status": "ACTIVE"},
                {"Id": "333333333333", "Name": "ClosedOld", "Status": "SUSPENDED"},
            ]
        }
    ]
    ous_paginator = MagicMock()
    ous_paginator.paginate.side_effect = lambda ParentId: (
        [{"OrganizationalUnits": [{"Id": "ou-infra", "Name": "Infrastructure"}]}]
        if ParentId == "r-root-live"
        else [{"OrganizationalUnits": []}]
    )

    def org_paginator_side_effect(op: str) -> MagicMock:
        return accts_paginator if op == "list_accounts" else ous_paginator

    mock_org.get_paginator.side_effect = org_paginator_side_effect

    # CFN Stacks: CloudTrail on mgmt, Backend on deployment
    mock_cfn_mgmt.describe_stacks.return_value = {
        "Stacks": [{"StackName": "flumen-organization-cloudtrail", "StackStatus": "CREATE_COMPLETE"}]
    }
    mock_cfn_dep.describe_stacks.return_value = {
        "Stacks": [{"StackName": "flumen-terraform-backend", "StackStatus": "CREATE_COMPLETE"}]
    }

    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/sso-test", "IdentityStoreId": "d-123"}]
    }

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn_mgmt
        if service_name == "sso-admin":
            return mock_sso
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_session_mgr.get_member_client.return_value = mock_cfn_dep

    status_service = StatusService(mock_session_mgr)
    status = status_service.inspect(bundle, target_region="eu-west-1")

    assert status.org_id == "o-live123"
    assert status.feature_set == "ALL"
    assert status.accounts_live == 2  # 2 active
    assert status.accounts_suspended == 1  # 1 suspended
    assert status.cloudtrail_status == "CREATE_COMPLETE"
    assert status.backend_status == "CREATE_COMPLETE"
    assert status.sso_configured is True


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


def test_drift_service_inspect_in_sync(sample_config_dir):
    from tarmac.core.config_loader import load_all_configs
    from tarmac.services.drift import DriftService

    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()

    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-root123"}]}

    def get_paginator(operation_name: str) -> MagicMock:
        p = MagicMock()
        if operation_name in ["list_organizational_units_for_parent", "list_children"]:
            p.paginate.return_value = [
                {
                    "OrganizationalUnits": [
                        {"Id": f"ou-{ou.name.lower()}", "Name": ou.name} for ou in bundle.org.ou_structure
                    ]
                }
            ]
        elif operation_name == "list_accounts":
            p.paginate.return_value = [
                {
                    "Accounts": [
                        {"Id": f"11111111111{i}", "Name": a.name, "Status": "ACTIVE"}
                        for i, a in enumerate(bundle.accounts.accounts)
                    ]
                }
            ]
        elif operation_name == "list_policies":
            p.paginate.return_value = [
                {
                    "Policies": [
                        {"Id": f"p-{p.name}", "Name": p.name}
                        for p in bundle.org.service_control_policies.policies
                    ]
                }
            ]
        elif operation_name == "list_targets_for_policy":
            p.paginate.return_value = [{"Targets": [{"TargetId": "r-root123"}]}]
        else:
            p.paginate.return_value = [{"Tags": []}]
        return p

    mock_org.get_paginator.side_effect = get_paginator
    mock_org.describe_policy.return_value = {
        "Policy": {"Content": '{"Version": "2012-10-17", "Statement": []}'}
    }

    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "test-stack", "StackStatus": "CREATE_COMPLETE"}]
    }

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_session_mgr.get_member_client.return_value = mock_cfn

    drift_service = DriftService(mock_session_mgr)
    report = drift_service.inspect_drift(bundle, target_region="eu-west-1", project_root=sample_config_dir)

    assert report.in_sync_count > 0
    assert isinstance(report.has_drift, bool)
