"""Tests that run destructive/ownership code against botocore Stubber clients.

Unlike MagicMock, Stubber validates every request against the real AWS service model, so a
misspelled operation or parameter (for example `Delete={"Object": ...}`) fails here instead of
mid-teardown against a live account.
"""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from tarmac.cli.bootstrap import _grant
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.exceptions import GovernanceError, IdentityCenterError
from tarmac.services.cloudformation import CloudFormationService
from tarmac.services.identity import IdentityService, deployment_policy
from tarmac.services.scp import SCPService
from tarmac.services.teardown import TeardownService
from tarmac.services.teardown_s3 import empty_s3_bucket

OWNED = [{"Key": "tarmac:managed-by", "Value": "tarmac"}]
INST = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
PS = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef"
ACCOUNT = "111122223333"
USER = "90676d1a42-11112222-3333-4444-5555-666677778888"
REQ = "11111111-2222-3333-4444-555555555555"


def _client(service: str) -> Any:
    name: Any = service
    return boto3.client(
        name,
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def _mgr(**clients: Any) -> MagicMock:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.default_region = "us-east-1"
    mgr.get_client.side_effect = lambda svc, **kw: clients[svc.replace("-", "_")]
    return mgr


def test_empty_s3_bucket_validates_requests_against_service_model():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions",
            {
                "Versions": [{"Key": "a", "VersionId": "v1"}],
                "DeleteMarkers": [{"Key": "b", "VersionId": "v2"}],
            },
            {"Bucket": "b"},
        )
        stub.add_response(
            "delete_objects",
            {},
            {
                "Bucket": "b",
                "Delete": {
                    "Objects": [{"Key": "a", "VersionId": "v1"}, {"Key": "b", "VersionId": "v2"}],
                    "Quiet": True,
                },
            },
        )
        stub.add_response("list_objects_v2", {"KeyCount": 0}, {"Bucket": "b"})

        assert empty_s3_bucket(s3, "b") == 2
        stub.assert_no_pending_responses()


_DENIED = {"Errors": [{"Key": "a", "VersionId": "v1", "Code": "AccessDenied", "Message": "locked"}]}
_DELETE = {"Bucket": "b", "Delete": {"Objects": [{"Key": "a", "VersionId": "v1"}], "Quiet": True}}
_BYPASS = {**_DELETE, "BypassGovernanceRetention": True}


def test_empty_s3_bucket_raises_when_s3_reports_per_object_errors():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions", {"Versions": [{"Key": "a", "VersionId": "v1"}]}, {"Bucket": "b"}
        )
        stub.add_response(
            "delete_objects",
            {"Errors": [{"Key": "a", "VersionId": "v1", "Code": "InternalError", "Message": "try again"}]},
            _DELETE,
        )
        with pytest.raises(GovernanceError, match="Failed to delete 1 object"):
            empty_s3_bucket(s3, "b")


def test_empty_s3_bucket_bypasses_governance_retention_when_allowed():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions", {"Versions": [{"Key": "a", "VersionId": "v1"}]}, {"Bucket": "b"}
        )
        stub.add_response("delete_objects", _DENIED, _DELETE)
        stub.add_response("delete_objects", {}, _BYPASS)
        stub.add_response("list_objects_v2", {"Contents": []}, {"Bucket": "b"})
        assert empty_s3_bucket(s3, "b") == 1


def test_empty_s3_bucket_explains_a_lock_it_cannot_bypass():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions", {"Versions": [{"Key": "a", "VersionId": "v1"}]}, {"Bucket": "b"}
        )
        stub.add_response("delete_objects", _DENIED, _DELETE)
        stub.add_response("delete_objects", _DENIED, _BYPASS)
        with pytest.raises(GovernanceError) as exc:
            empty_s3_bucket(s3, "b")
    assert "COMPLIANCE" in str(exc.value)


def test_delete_retained_bucket_issues_valid_delete_bucket_call():
    s3 = _client("s3")
    svc = TeardownService(_mgr(s3=s3))
    with Stubber(s3) as stub:
        stub.add_response("delete_bucket", {}, {"Bucket": "b"})
        assert svc._delete_retained_bucket(s3, "b", "log-archive", "111122223333") == []
        stub.add_client_error("delete_bucket", "BucketNotEmpty", "not empty", expected_params={"Bucket": "b"})
        items = svc._delete_retained_bucket(s3, "b", "log-archive", "111122223333")
    assert [i.action for i in items] == ["FAILED"]


@pytest.mark.parametrize(
    ("tags", "expected"), [(OWNED, True), ([{"Key": "x", "Value": "y"}], False), ([], False)]
)
def test_scp_ownership_tag_lookup(tags, expected):
    org = _client("organizations")
    svc = SCPService(_mgr(organizations=org))
    with Stubber(org) as stub:
        stub.add_response("list_tags_for_resource", {"Tags": tags}, {"ResourceId": "p-abc12345"})
        assert svc.is_tarmac_managed("p-abc12345") is expected


@pytest.mark.parametrize(("tags", "expected"), [(OWNED, True), ([], False)])
def test_permission_set_ownership_tag_lookup(tags, expected):
    sso = _client("sso-admin")
    svc = _identity(sso)
    with Stubber(sso) as stub:
        stub.add_response("list_tags_for_resource", {"Tags": tags}, {"InstanceArn": INST, "ResourceArn": PS})
        assert svc.is_tarmac_managed_permission_set(INST, PS) is expected


@pytest.mark.parametrize(("tags", "expected"), [(OWNED, "arn:t"), ([], "")])
def test_trail_ownership_lookup_uses_valid_cloudtrail_calls(tags, expected):
    trail = _client("cloudtrail")
    with Stubber(trail) as stub:
        stub.add_response("get_trail", {"Trail": {"TrailARN": "arn:t"}}, {"Name": "t"})
        stub.add_response(
            "list_tags",
            {"ResourceTagList": [{"ResourceId": "arn:t", "TagsList": tags}]},
            {"ResourceIdList": ["arn:t"]},
        )
        assert TeardownService._find_tarmac_trail_arn(trail, "t") == expected


def test_empty_s3_bucket_raises_when_bucket_exists_but_is_inaccessible():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error(
            "head_bucket", "403", "Forbidden", http_status_code=403, expected_params={"Bucket": "b"}
        )
        with pytest.raises(GovernanceError, match="cannot be accessed"):
            empty_s3_bucket(s3, "b")


def test_empty_s3_bucket_returns_zero_when_bucket_missing():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error(
            "head_bucket", "404", "Not Found", http_status_code=404, expected_params={"Bucket": "b"}
        )
        assert empty_s3_bucket(s3, "b") == 0


def _identity(sso: Any) -> IdentityService:
    return IdentityService(
        _mgr(sso_admin=sso, identitystore=_client("identitystore")), preferred_region="us-east-1"
    )


def _assign(stub: Stubber, status: dict[str, str]) -> None:
    stub.add_response(
        "list_account_assignments",
        {"AccountAssignments": []},
        {"InstanceArn": INST, "AccountId": ACCOUNT, "PermissionSetArn": PS},
    )
    stub.add_response(
        "create_account_assignment",
        {"AccountAssignmentCreationStatus": {"Status": "IN_PROGRESS", "RequestId": REQ}},
        {
            "InstanceArn": INST,
            "TargetId": ACCOUNT,
            "TargetType": "AWS_ACCOUNT",
            "PermissionSetArn": PS,
            "PrincipalType": "USER",
            "PrincipalId": USER,
        },
    )
    stub.add_response(
        "describe_account_assignment_creation_status",
        {"AccountAssignmentCreationStatus": status},
        {"InstanceArn": INST, "AccountAssignmentCreationRequestId": REQ},
    )


def _create_permission_set(stub: Stubber, name: str) -> None:
    stub.add_response("list_permission_sets", {"PermissionSets": []}, {"InstanceArn": INST})
    stub.add_response(
        "create_permission_set",
        {"PermissionSet": {"Name": name, "PermissionSetArn": PS}},
        {
            "InstanceArn": INST,
            "Name": name,
            "SessionDuration": "PT4H",
            "Tags": [{"Key": "tarmac:managed-by", "Value": "tarmac"}],
        },
    )


def test_bootstrap_grant_creates_the_deployment_permission_set_and_assigns_it():
    sso = _client("sso-admin")
    policy = deployment_policy()
    with Stubber(sso) as stub:
        _create_permission_set(stub, "TarmacDeployment")
        stub.add_response(
            "put_inline_policy_to_permission_set",
            {},
            {"InstanceArn": INST, "PermissionSetArn": PS, "InlinePolicy": policy},
        )
        _assign(stub, {"Status": "SUCCEEDED"})
        _grant(_identity(sso), INST, ACCOUNT, USER, "TarmacDeployment", policy)
        stub.assert_no_pending_responses()


def test_bootstrap_grant_reports_why_an_assignment_failed():
    sso = _client("sso-admin")
    with Stubber(sso) as stub:
        _create_permission_set(stub, "ManagementAdministrator")
        stub.add_response(
            "attach_managed_policy_to_permission_set",
            {},
            {
                "InstanceArn": INST,
                "PermissionSetArn": PS,
                "ManagedPolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        )
        _assign(stub, {"Status": "FAILED", "FailureReason": "Policy is invalid"})
        with pytest.raises(
            IdentityCenterError, match="Assigning ManagementAdministrator failed: Policy is invalid"
        ):
            _grant(_identity(sso), INST, ACCOUNT, USER, "ManagementAdministrator", None)


def test_bootstrap_grant_rerun_reprovisions_the_updated_policy():
    sso = _client("sso-admin")
    with Stubber(sso) as stub:
        stub.add_response("list_permission_sets", {"PermissionSets": [PS]}, {"InstanceArn": INST})
        stub.add_response(
            "describe_permission_set",
            {"PermissionSet": {"Name": "TarmacDeployment", "PermissionSetArn": PS}},
            {"InstanceArn": INST, "PermissionSetArn": PS},
        )
        stub.add_response(
            "put_inline_policy_to_permission_set",
            {},
            {"InstanceArn": INST, "PermissionSetArn": PS, "InlinePolicy": "{}"},
        )
        stub.add_response(
            "list_account_assignments",
            {
                "AccountAssignments": [
                    {
                        "AccountId": ACCOUNT,
                        "PermissionSetArn": PS,
                        "PrincipalType": "USER",
                        "PrincipalId": USER,
                    }
                ]
            },
            {"InstanceArn": INST, "AccountId": ACCOUNT, "PermissionSetArn": PS},
        )
        stub.add_response(
            "provision_permission_set",
            {"PermissionSetProvisioningStatus": {"Status": "IN_PROGRESS", "RequestId": REQ}},
            {"InstanceArn": INST, "PermissionSetArn": PS, "TargetType": "ALL_PROVISIONED_ACCOUNTS"},
        )
        stub.add_response(
            "describe_permission_set_provisioning_status",
            {"PermissionSetProvisioningStatus": {"Status": "SUCCEEDED"}},
            {"InstanceArn": INST, "ProvisionPermissionSetRequestId": REQ},
        )
        _grant(_identity(sso), INST, ACCOUNT, USER, "TarmacDeployment", "{}")
        stub.assert_no_pending_responses()


def test_delete_permission_set_removes_its_assignments_first():
    sso = _client("sso-admin")
    with Stubber(sso) as stub:
        stub.add_response(
            "list_accounts_for_provisioned_permission_set",
            {"AccountIds": [ACCOUNT]},
            {"InstanceArn": INST, "PermissionSetArn": PS},
        )
        stub.add_response(
            "list_account_assignments",
            {
                "AccountAssignments": [
                    {
                        "AccountId": ACCOUNT,
                        "PermissionSetArn": PS,
                        "PrincipalType": "GROUP",
                        "PrincipalId": USER,
                    }
                ]
            },
            {"InstanceArn": INST, "AccountId": ACCOUNT, "PermissionSetArn": PS},
        )
        stub.add_response(
            "delete_account_assignment",
            {"AccountAssignmentDeletionStatus": {"Status": "IN_PROGRESS", "RequestId": REQ}},
            {
                "InstanceArn": INST,
                "TargetId": ACCOUNT,
                "TargetType": "AWS_ACCOUNT",
                "PermissionSetArn": PS,
                "PrincipalType": "GROUP",
                "PrincipalId": USER,
            },
        )
        stub.add_response(
            "describe_account_assignment_deletion_status",
            {"AccountAssignmentDeletionStatus": {"Status": "SUCCEEDED"}},
            {"InstanceArn": INST, "AccountAssignmentDeletionRequestId": REQ},
        )
        stub.add_response("delete_permission_set", {}, {"InstanceArn": INST, "PermissionSetArn": PS})
        assert _identity(sso).delete_permission_set(INST, PS) is True
        stub.assert_no_pending_responses()


def _stack(status: str, **extra: Any) -> dict[str, Any]:
    return {"Stacks": [{"StackName": "s", "CreationTime": datetime.now(UTC), "StackStatus": status, **extra}]}


_STACK = {"StackName": "s"}
_CREATE = {
    "StackName": "s",
    "TemplateBody": "Resources: {}",
    "Parameters": [{"ParameterKey": "Env", "ParameterValue": "test"}],
    "Capabilities": ["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
    "Tags": [{"Key": "ManagedBy", "Value": "tarmac"}],
}


def test_deploy_creates_a_new_stack_and_returns_its_outputs():
    cfn = _client("cloudformation")
    with Stubber(cfn) as stub:
        stub.add_client_error(
            "describe_stacks", "ValidationError", "Stack with id s does not exist", expected_params=_STACK
        )
        stub.add_response("create_stack", {"StackId": "id"}, _CREATE)
        stub.add_response("describe_stacks", _stack("CREATE_COMPLETE"), _STACK)
        stub.add_response(
            "describe_stacks",
            _stack("CREATE_COMPLETE", Outputs=[{"OutputKey": "K", "OutputValue": "V"}]),
            _STACK,
        )
        report = CloudFormationService(MagicMock()).deploy_stack(
            cfn, "s", template_body="Resources: {}", parameters={"Env": "test"}
        )
        stub.assert_no_pending_responses()
    assert (report.action, report.outputs) == ("CREATED", {"K": "V"})


def test_deploy_force_deletes_a_rollback_failed_stack_then_recreates_it():
    cfn = _client("cloudformation")
    with Stubber(cfn) as stub:
        stub.add_response("describe_stacks", _stack("ROLLBACK_FAILED"), _STACK)
        stub.add_response("delete_stack", {}, _STACK)
        stub.add_response("describe_stacks", _stack("DELETE_FAILED"), _STACK)
        stub.add_response("delete_stack", {}, {**_STACK, "DeletionMode": "FORCE_DELETE_STACK"})
        stub.add_response("describe_stacks", _stack("DELETE_COMPLETE"), _STACK)
        stub.add_response("create_stack", {"StackId": "id"}, _CREATE)
        stub.add_response("describe_stacks", _stack("CREATE_COMPLETE"), _STACK)
        stub.add_response("describe_stacks", _stack("CREATE_COMPLETE"), _STACK)
        report = CloudFormationService(MagicMock()).deploy_stack(
            cfn, "s", template_body="Resources: {}", parameters={"Env": "test"}
        )
        stub.assert_no_pending_responses()
    assert report.action == "CREATED"


def test_teardown_turns_off_termination_protection_before_deleting():
    cfn = _client("cloudformation")
    progress: list[str] = []
    with Stubber(cfn) as stub:
        stub.add_response("describe_stacks", _stack("CREATE_COMPLETE"), _STACK)
        stub.add_response(
            "describe_stacks", _stack("CREATE_COMPLETE", EnableTerminationProtection=True), _STACK
        )
        stub.add_response(
            "update_termination_protection",
            {"StackId": "id"},
            {**_STACK, "EnableTerminationProtection": False},
        )
        stub.add_response("delete_stack", {}, _STACK)
        stub.add_response("describe_stacks", _stack("DELETE_COMPLETE"), _STACK)
        deleted = CloudFormationService(MagicMock()).delete_stack(
            cfn, "s", on_progress=progress.append, release_protection=True
        )
        stub.assert_no_pending_responses()
    assert deleted is True
    assert any("termination protection" in m for m in progress)


def test_log_archive_buckets_and_key_are_read_from_the_stack():
    cfn = _client("cloudformation")
    svc = TeardownService(_mgr(cloudformation=cfn))
    outputs = [
        {"OutputKey": "LogBucketName", "OutputValue": "acme-logs-abc"},
        {"OutputKey": "AccessLogBucketArn", "OutputValue": "arn:aws:s3:::acme-access-abc"},
        {"OutputKey": "KmsKeyArn", "OutputValue": "arn:aws:kms:us-east-1:111122223333:key/k"},
    ]
    with Stubber(cfn) as stub:
        stub.add_response("describe_stacks", _stack("CREATE_COMPLETE", Outputs=outputs), _STACK)
        stub.add_response(
            "describe_stack_resource",
            {
                "StackResourceDetail": {
                    "LogicalResourceId": "LogArchiveKmsKey",
                    "PhysicalResourceId": "key-1",
                    "ResourceType": "AWS::KMS::Key",
                    "LastUpdatedTimestamp": datetime.now(UTC),
                    "ResourceStatus": "CREATE_COMPLETE",
                }
            },
            {**_STACK, "LogicalResourceId": "LogArchiveKmsKey"},
        )
        assert svc._output_buckets(cfn, "s") == {"acme-logs-abc", "acme-access-abc"}
        assert svc._log_archive_key_id(cfn, "s") == "key-1"
