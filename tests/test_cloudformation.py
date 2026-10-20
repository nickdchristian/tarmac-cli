"""CloudFormationService deploy/import tests."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.exceptions import DeploymentError
from tarmac.services.cloudformation import CloudFormationService


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
