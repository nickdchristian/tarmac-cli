"""Unit tests for TeardownService and teardown CLI."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from tarmac.cli.deploy import app
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_loader import load_all_configs
from tarmac.core.exceptions import GovernanceError
from tarmac.services.teardown import (
    TeardownItemReport,
    TeardownReport,
    TeardownService,
    cleanup_orphaned_bucket,
    empty_s3_bucket,
    is_s3_bucket_empty,
    normalize_bucket_name,
    teardown_deployment,
)

runner = CliRunner()


@pytest.fixture
def teardown_config_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cfg = Path("test-config")
    if cfg.is_dir() and (cfg / "organization.yaml").exists():
        return cfg
    temp_dir = tmp_path_factory.mktemp("test_cfg")
    from tarmac.services.scaffold import scaffold_project

    scaffold_project(temp_dir)
    return temp_dir


@pytest.fixture
def test_bundle(teardown_config_dir: Path):
    bundle, errors = load_all_configs(teardown_config_dir)
    assert not errors
    assert bundle is not None
    return bundle


def test_empty_s3_bucket_purges_versions_and_delete_markers():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {}

    paginator_versions = MagicMock()
    paginator_versions.paginate.return_value = [
        {
            "Versions": [
                {"Key": "file1.txt", "VersionId": "v1"},
                {"Key": "file2.txt", "VersionId": "v2"},
            ],
            "DeleteMarkers": [
                {"Key": "file3.txt", "VersionId": "m1"},
            ],
        }
    ]

    paginator_objects = MagicMock()
    paginator_objects.paginate.return_value = []

    def get_paginator(name):
        if name == "list_object_versions":
            return paginator_versions
        return paginator_objects

    mock_s3.get_paginator.side_effect = get_paginator

    purged = empty_s3_bucket(mock_s3, "my-test-bucket")
    assert purged == 3
    mock_s3.delete_objects.assert_called_once_with(
        Bucket="my-test-bucket",
        Delete={
            "Objects": [
                {"Key": "file1.txt", "VersionId": "v1"},
                {"Key": "file2.txt", "VersionId": "v2"},
                {"Key": "file3.txt", "VersionId": "m1"},
            ],
            "Quiet": True,
        },
    )


def test_empty_s3_bucket_nonexistent_bucket_returns_zero():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.side_effect = ClientError(
        {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
    )

    purged = empty_s3_bucket(mock_s3, "missing-bucket")
    assert purged == 0
    mock_s3.delete_objects.assert_not_called()


def test_teardown_cloudtrail(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_cfn = MagicMock()
    mock_trail = MagicMock()

    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}
    mock_session_mgr.get_client.side_effect = lambda svc, **kwargs: (
        mock_cfn if svc == "cloudformation" else mock_trail
    )
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111122223333"}

    service = TeardownService(mock_session_mgr)
    reports = service.teardown_cloudtrail(test_bundle, "us-east-1", dry_run=False)

    deleted_reports = [r for r in reports if r.action == "DELETED"]
    assert len(deleted_reports) >= 1
    mock_cfn.delete_stack.assert_called_once_with(
        StackName=f"{test_bundle.org.organization.name}-organization-cloudtrail"
    )
    mock_trail.delete_trail.assert_called_once()


def test_teardown_log_archive(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_cfn = MagicMock()
    mock_s3 = MagicMock()

    mock_cfn.describe_stacks.return_value = {
        "Stacks": [
            {
                "StackStatus": "CREATE_COMPLETE",
                "Outputs": [{"OutputKey": "CloudTrailBucketName", "OutputValue": "myorg-test-bucket"}],
            }
        ]
    }
    mock_s3.head_bucket.return_value = {}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = []
    mock_s3.get_paginator.return_value = mock_paginator

    def member_client(acct_id, svc, **kwargs):
        if svc == "cloudformation":
            return mock_cfn
        if svc == "s3":
            return mock_s3
        return MagicMock()

    mock_session_mgr.get_member_client.side_effect = member_client

    acct_map = {"Log-Archive": "835780011065"}
    service = TeardownService(mock_session_mgr)
    reports = service.teardown_log_archive(test_bundle, "us-east-1", dry_run=False, account_id_map=acct_map)

    deleted = [r for r in reports if r.action == "DELETED"]
    assert len(deleted) == 1
    assert deleted[0].resource_name == f"{test_bundle.org.organization.name}-log-archive-hardening"
    mock_cfn.delete_stack.assert_called_once()
    assert mock_s3.delete_bucket.called


def test_teardown_budgets(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_cfn = MagicMock()
    mock_budgets = MagicMock()
    mock_ce = MagicMock()

    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}
    mock_budgets.describe_budget.return_value = {"Budget": {}}
    mock_ce.get_anomaly_monitors.return_value = {
        "AnomalyMonitors": [{"MonitorName": "Deployment-cost-anomaly-monitor", "MonitorArn": "arn:ce:mon"}]
    }

    def member_client(acct_id, svc, **kwargs):
        if svc == "cloudformation":
            return mock_cfn
        if svc == "budgets":
            return mock_budgets
        if svc == "ce":
            return mock_ce
        return MagicMock()

    mock_session_mgr.get_member_client.side_effect = member_client
    mock_session_mgr.default_region = "us-east-1"

    acct_map = {a.name: f"11111111111{i}" for i, a in enumerate(test_bundle.accounts.accounts)}
    service = TeardownService(mock_session_mgr)
    reports = service.teardown_budgets(test_bundle, dry_run=False, account_id_map=acct_map)

    deleted_cfn = [r for r in reports if r.resource_type == "CloudFormation Stack" and r.action == "DELETED"]
    deleted_budgets = [r for r in reports if r.resource_type == "AWS Budget" and r.action == "DELETED"]
    assert len(deleted_cfn) == len(test_bundle.accounts.accounts)
    assert len(deleted_budgets) == len(test_bundle.accounts.accounts)
    assert mock_cfn.delete_stack.call_count == len(test_bundle.accounts.accounts)
    assert mock_budgets.delete_budget.call_count == len(test_bundle.accounts.accounts)


def test_teardown_scps(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_cfn = MagicMock()
    mock_org = MagicMock()

    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}
    mock_session_mgr.default_region = "us-east-1"
    mock_session_mgr.get_client.side_effect = lambda svc, **kwargs: (
        mock_cfn if svc == "cloudformation" else mock_org
    )
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111122223333"}

    mock_paginator_policies = MagicMock()
    mock_paginator_policies.paginate.return_value = [
        {
            "Policies": [
                {"Id": "p-12345", "Name": "DenyMemberRootActivity"},
                {"Id": "p-67890", "Name": "DenyLeaveOrganization"},
            ]
        }
    ]
    mock_paginator_targets = MagicMock()
    mock_paginator_targets.paginate.return_value = [{"Targets": [{"TargetId": "r-root"}]}]

    def get_paginator(name):
        if name == "list_policies":
            return mock_paginator_policies
        return mock_paginator_targets

    mock_org.get_paginator.side_effect = get_paginator

    service = TeardownService(mock_session_mgr)
    reports = service.teardown_scps(test_bundle, dry_run=False)

    deleted = [r for r in reports if r.action == "DELETED"]
    assert len(deleted) >= 3  # Stack + 2 SCPs
    mock_cfn.delete_stack.assert_called_once_with(
        StackName=f"{test_bundle.org.organization.name}-organization-scps"
    )
    assert mock_org.detach_policy.call_count == 2
    assert mock_org.delete_policy.call_count == 2


def test_teardown_all_orchestration(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_session_mgr.default_region = "us-east-1"
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111122223333"}

    mock_org = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Name": a.name, "Id": f"12345678901{i}", "Status": "ACTIVE"}
                for i, a in enumerate(test_bundle.accounts.accounts)
            ]
        }
    ]
    mock_org.get_paginator.return_value = mock_paginator
    mock_session_mgr.get_client.return_value = mock_org

    service = TeardownService(mock_session_mgr)
    service.teardown_cloudtrail = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "ct", "Mgmt", "111", "DELETED")]
    )
    service.teardown_log_archive = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "la", "Log", "222", "DELETED")]
    )
    service.teardown_budgets = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "bgt", "Acct", "333", "DELETED")]
    )
    service.teardown_backend = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "tf", "Deploy", "444", "DELETED")]
    )
    service.teardown_audit = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "aud", "Audit", "555", "DELETED")]
    )
    service.teardown_identity = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "id", "Mgmt", "111", "DELETED")]
    )
    service.teardown_scps = MagicMock(
        return_value=[TeardownItemReport("CloudFormation Stack", "scp", "Mgmt", "111", "DELETED")]
    )
    service.reset_milestones = MagicMock(
        return_value=[TeardownItemReport("Organization Tag", "tag", "Mgmt", "111", "DELETED")]
    )

    report = service.teardown_all(test_bundle, "us-east-1", dry_run=False)

    assert isinstance(report, TeardownReport)
    assert report.status == "COMPLETED"
    assert report.deleted_count == 8
    assert report.failed_count == 0


def test_teardown_deployment_helper(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_session_mgr.default_region = "us-east-1"
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111122223333"}

    report = teardown_deployment(test_bundle, session_mgr=mock_session_mgr, dry_run=True)
    assert isinstance(report, TeardownReport)
    assert report.status == "SIMULATED"


def test_cli_teardown_dry_run(monkeypatch, teardown_config_dir: Path):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    res = runner.invoke(app, ["teardown", "--dry-run", "-c", str(teardown_config_dir), "-y"])
    assert res.exit_code == 0
    assert "Teardown Summary" in res.stdout
    assert "Teardown dry-run simulation complete" in res.stdout


def test_cli_destroy_alias(monkeypatch, teardown_config_dir: Path):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    res = runner.invoke(app, ["destroy", "--dry-run", "-c", str(teardown_config_dir), "-y"])
    assert res.exit_code == 0
    assert "Teardown Summary" in res.stdout


def test_cli_teardown_handles_bracketed_markup_messages(monkeypatch, teardown_config_dir: Path):
    from unittest.mock import patch

    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_td:
        mock_td.return_value = TeardownReport(
            items=[
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name="myorg-organization-scps",
                    account_name="Management",
                    account_id="123456789012",
                    action="FAILED",
                    message="Error: policy already exists for [DenyMemberRootActivity] [/:] invalid token",
                )
            ],
            status="FAILED",
        )
        res = runner.invoke(app, ["destroy", "-c", str(teardown_config_dir), "-y"])
        assert res.exit_code == 0
        assert "Teardown Summary" in res.stdout
        assert "[DenyMemberRo" in res.stdout
        assert "[/:]" in res.stdout


def test_teardown_identity_deletes_stacks_and_retained_permission_sets(tmp_path: Path):
    """Verify teardown_identity deletes permission sets stack and retained SSO permission sets."""
    from typing import Any
    from unittest.mock import MagicMock, patch

    from tarmac.core.config_schema import PermissionSetDef
    from tarmac.services.teardown import TeardownService

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111122223333"}
    mock_cfn = MagicMock()
    mock_sso = MagicMock()

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "cloudformation":
            return mock_cfn
        if service_name == "sso-admin":
            return mock_sso
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "myorg-sso-permission-sets", "StackStatus": "CREATE_COMPLETE"}]
    }

    mock_bundle = MagicMock()
    mock_bundle.org.organization.name = "myorg"
    mock_bundle.identity.identity_center.permission_sets = [PermissionSetDef(name="AdministratorAccess")]

    service = TeardownService(mock_session_mgr)
    with (
        patch.object(service.cfn_service, "delete_stack") as mock_del_stack,
        patch("tarmac.services.teardown.IdentityService") as mock_id_cls,
    ):
        mock_id_inst = MagicMock()
        mock_id_cls.return_value = mock_id_inst
        mock_id_inst.get_instance_details.return_value = ("arn:aws:sso:::instance/ssoins-1", "d-1")
        mock_id_inst.list_permission_sets.return_value = {
            "AdministratorAccess": "arn:aws:sso:::permissionSet/ps-admin"
        }

        reports = service.teardown_identity(mock_bundle, "us-east-1", dry_run=False)

        # First stack checked is myorg-sso-permission-sets
        assert mock_del_stack.call_count == 2
        mock_id_inst.delete_permission_set.assert_called_once_with(
            "arn:aws:sso:::instance/ssoins-1",
            "arn:aws:sso:::permissionSet/ps-admin",
        )
        assert len(reports) == 3  # 2 stacks deleted + 1 permission set deleted
        assert reports[0].resource_type == "CloudFormation Stack"
        assert reports[0].action == "DELETED"
        assert reports[2].resource_type == "Permission Set"
        assert reports[2].action == "DELETED"


def test_teardown_service_callbacks(test_bundle):
    """Verify that on_phase, on_progress, and on_item callbacks are called during teardown."""
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_session_mgr.default_region = "us-east-1"
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111122223333"}

    mock_org = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Name": a.name, "Id": f"12345678901{i}", "Status": "ACTIVE"}
                for i, a in enumerate(test_bundle.accounts.accounts)
            ]
        }
    ]
    mock_org.get_paginator.return_value = mock_paginator
    mock_session_mgr.get_client.return_value = mock_org

    phase_calls: list[str] = []
    progress_calls: list[str] = []
    item_calls: list[TeardownItemReport] = []

    service = TeardownService(
        mock_session_mgr,
        on_progress=lambda msg: progress_calls.append(msg),
        on_item=lambda item: item_calls.append(item),
        on_phase=lambda p: phase_calls.append(p),
    )

    item1 = TeardownItemReport("CloudFormation Stack", "ct", "Mgmt", "111", "DELETED")
    item2 = TeardownItemReport("S3 Bucket", "logs", "Log", "222", "EMPTY")

    # Use _new_results_list to verify item reporting
    def fake_teardown_cloudtrail(*args, **kwargs):
        res = service._new_results_list()
        service._notify_progress("Deleting cloudtrail stack...")
        res.append(item1)
        return res

    def fake_teardown_log_archive(*args, **kwargs):
        res = service._new_results_list()
        res.append(item2)
        return res

    service.teardown_cloudtrail = MagicMock(side_effect=fake_teardown_cloudtrail)
    service.teardown_log_archive = MagicMock(side_effect=fake_teardown_log_archive)
    service.teardown_budgets = MagicMock(return_value=[])
    service.teardown_backend = MagicMock(return_value=[])
    service.teardown_audit = MagicMock(return_value=[])
    service.teardown_identity = MagicMock(return_value=[])
    service.teardown_scps = MagicMock(return_value=[])
    service.reset_milestones = MagicMock(return_value=[])

    report = service.teardown_all(test_bundle, "us-east-1", dry_run=False)

    assert report.deleted_count == 2
    assert len(phase_calls) >= 5
    assert "Phase 3 | Organization CloudTrail" in phase_calls
    assert len(progress_calls) == 1
    assert "Deleting cloudtrail stack..." in progress_calls[0]
    assert len(item_calls) == 2
    assert item_calls[0].resource_name == "ct"
    assert item_calls[1].resource_name == "logs"


def test_empty_s3_bucket_progress_callback():
    """Verify empty_s3_bucket invokes on_progress callback."""
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {}

    paginator_versions = MagicMock()
    paginator_versions.paginate.return_value = [
        {
            "Versions": [{"Key": f"f_{i}.txt", "VersionId": f"v_{i}"} for i in range(1000)],
        }
    ]
    paginator_objects = MagicMock()
    paginator_objects.paginate.return_value = []

    def get_paginator(name):
        if name == "list_object_versions":
            return paginator_versions
        return paginator_objects

    mock_s3.get_paginator.side_effect = get_paginator

    progress_messages: list[str] = []
    purged = empty_s3_bucket(
        mock_s3,
        "my-test-bucket",
        on_progress=lambda msg: progress_messages.append(msg),
    )
    assert purged == 1000
    assert any("Purged 1000 items" in m for m in progress_messages)


def test_cli_teardown_live_progress_and_json_isolation(monkeypatch, teardown_config_dir: Path):
    """Verify live progress rendering in standard CLI teardown and pure JSON in --json mode."""
    import json

    monkeypatch.delenv("AWS_PROFILE", raising=False)

    # 1. Standard mode: live progress indicators in output
    res = runner.invoke(app, ["destroy", "--dry-run", "-c", str(teardown_config_dir), "-y"])
    assert res.exit_code == 0
    assert "Phase 3 | Organization CloudTrail" in res.stdout
    assert "Teardown Summary" in res.stdout

    # 2. JSON mode: output must be valid JSON only
    res_json = runner.invoke(app, ["destroy", "--dry-run", "-c", str(teardown_config_dir), "-y", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert "status" in data
    assert "items" in data
    assert data["status"] == "SIMULATED"


def test_normalize_bucket_name():
    assert normalize_bucket_name("my-bucket") == "my-bucket"
    assert (
        normalize_bucket_name("arn:aws:s3:::myorg-org-cloudtrail-logs-835780011065")
        == "myorg-org-cloudtrail-logs-835780011065"
    )
    assert normalize_bucket_name("arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap") == "my-ap"


def test_empty_s3_bucket_handles_bucket_arn():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Versions": [{"Key": "sample.log", "VersionId": "v1"}]}]
    mock_s3.get_paginator.return_value = mock_paginator

    purged = empty_s3_bucket(mock_s3, "arn:aws:s3:::myorg-org-cloudtrail-logs-835780011065")
    assert purged == 1
    mock_s3.head_bucket.assert_called_once_with(Bucket="myorg-org-cloudtrail-logs-835780011065")
    mock_s3.delete_objects.assert_called_once_with(
        Bucket="myorg-org-cloudtrail-logs-835780011065",
        Delete={"Objects": [{"Key": "sample.log", "VersionId": "v1"}], "Quiet": True},
    )


def test_teardown_log_archive_handles_bucket_arn_outputs(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_cfn = MagicMock()
    mock_s3 = MagicMock()

    mock_cfn.describe_stacks.return_value = {
        "Stacks": [
            {
                "StackStatus": "CREATE_COMPLETE",
                "Outputs": [
                    {"OutputKey": "CloudTrailBucketName", "OutputValue": "myorg-test-bucket"},
                    {
                        "OutputKey": "CloudTrailBucketArn",
                        "OutputValue": "arn:aws:s3:::myorg-test-bucket",
                    },
                ],
            }
        ]
    }
    mock_s3.head_bucket.return_value = {}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = []
    mock_s3.get_paginator.return_value = mock_paginator

    def member_client(acct_id, svc, **kwargs):
        if svc == "cloudformation":
            return mock_cfn
        if svc == "s3":
            return mock_s3
        return MagicMock()

    mock_session_mgr.get_member_client.side_effect = member_client

    acct_map = {"Log-Archive": "835780011065"}
    service = TeardownService(mock_session_mgr)
    reports = service.teardown_log_archive(test_bundle, "us-east-1", dry_run=False, account_id_map=acct_map)

    failed_reports = [r for r in reports if r.action == "FAILED"]
    assert len(failed_reports) == 0
    # Bucket should be emptied without parameter validation failure
    deleted_stacks = [
        r for r in reports if r.resource_type == "CloudFormation Stack" and r.action == "DELETED"
    ]
    assert len(deleted_stacks) == 1
    mock_cfn.delete_stack.assert_called_once()


def test_teardown_terraform_backend_handles_bucket_arn_outputs(test_bundle):
    mock_session_mgr = MagicMock(spec=AwsSessionManager)
    mock_cfn = MagicMock()
    mock_s3 = MagicMock()

    mock_cfn.describe_stacks.return_value = {
        "Stacks": [
            {
                "StackStatus": "CREATE_COMPLETE",
                "Outputs": [
                    {"OutputKey": "BucketName", "OutputValue": "myorg-state-bucket"},
                    {
                        "OutputKey": "BucketArn",
                        "OutputValue": "arn:aws:s3:::myorg-state-bucket",
                    },
                ],
            }
        ]
    }
    mock_s3.head_bucket.return_value = {}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = []
    mock_s3.get_paginator.return_value = mock_paginator

    def member_client(acct_id, svc, **kwargs):
        if svc == "cloudformation":
            return mock_cfn
        if svc == "s3":
            return mock_s3
        return MagicMock()

    mock_session_mgr.get_member_client.side_effect = member_client

    acct_map = {"deployment": "857953323343"}
    service = TeardownService(mock_session_mgr)
    reports = service.teardown_backend(test_bundle, "us-east-1", dry_run=False, account_id_map=acct_map)

    failed_reports = [r for r in reports if r.action == "FAILED"]
    assert len(failed_reports) == 0
    deleted_stacks = [
        r for r in reports if r.resource_type == "CloudFormation Stack" and r.action == "DELETED"
    ]
    assert len(deleted_stacks) == 1
    mock_cfn.delete_stack.assert_called_once()
    assert mock_s3.delete_bucket.called


def test_is_s3_bucket_empty():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {}

    paginator_versions = MagicMock()
    paginator_versions.paginate.return_value = [{"Versions": [], "DeleteMarkers": []}]
    mock_s3.get_paginator.return_value = paginator_versions
    mock_s3.list_objects_v2.return_value = {"KeyCount": 0, "Contents": []}

    # Empty bucket
    assert is_s3_bucket_empty(mock_s3, "empty-bucket") is True

    # Bucket with versioned objects
    paginator_versions.paginate.return_value = [{"Versions": [{"Key": "obj1"}]}]
    assert is_s3_bucket_empty(mock_s3, "has-versions") is False

    # Bucket with delete markers
    paginator_versions.paginate.return_value = [{"DeleteMarkers": [{"Key": "dm1"}]}]
    assert is_s3_bucket_empty(mock_s3, "has-markers") is False

    # Bucket with standard objects
    paginator_versions.paginate.return_value = []
    mock_s3.list_objects_v2.return_value = {"KeyCount": 1, "Contents": [{"Key": "file.txt"}]}
    assert is_s3_bucket_empty(mock_s3, "has-objects") is False

    # Bucket does not exist (404)
    mock_s3.head_bucket.side_effect = ClientError(
        {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
    )
    assert is_s3_bucket_empty(mock_s3, "non-existent") is True


def test_cleanup_orphaned_bucket_empty_bucket_deleted():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {}
    paginator = MagicMock()
    paginator.paginate.return_value = []
    mock_s3.get_paginator.return_value = paginator
    mock_s3.list_objects_v2.return_value = {"KeyCount": 0}

    result = cleanup_orphaned_bucket(mock_s3, "orphaned-empty-bucket", account_id="123456789012")
    assert result is True
    mock_s3.delete_bucket.assert_called_once_with(Bucket="orphaned-empty-bucket")


def test_cleanup_orphaned_bucket_non_existent():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.side_effect = ClientError(
        {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
    )

    result = cleanup_orphaned_bucket(mock_s3, "missing-bucket")
    assert result is False
    mock_s3.delete_bucket.assert_not_called()


def test_cleanup_orphaned_bucket_contains_data_raises_governance_error():
    mock_s3 = MagicMock()
    mock_s3.head_bucket.return_value = {}
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Versions": [{"Key": "important.log"}]}]
    mock_s3.get_paginator.return_value = paginator

    with pytest.raises(GovernanceError) as exc_info:
        cleanup_orphaned_bucket(mock_s3, "bucket-with-data", account_id="123456789012")

    assert "contains data" in str(exc_info.value)
    mock_s3.delete_bucket.assert_not_called()
