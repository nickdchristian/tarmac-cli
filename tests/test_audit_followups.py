"""Regression tests for the safety fixes made after the codebase audit."""

import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from tarmac.cli.deploy import _is_production_tagged, app
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_loader import load_all_configs
from tarmac.core.config_schema import PermissionSetDef
from tarmac.core.exceptions import GovernanceError, IdentityCenterError
from tarmac.core.models import PreflightCheckStatus
from tarmac.services.baseline import BaselineService
from tarmac.services.identity import IdentityService
from tarmac.services.preflight import PreflightService
from tarmac.services.scaffold import scaffold_project
from tarmac.services.teardown import (
    TeardownItemReport,
    TeardownReport,
    TeardownService,
    empty_s3_bucket,
)

runner = CliRunner()


def _make_config(tmp_path: Path, environment: str | None) -> Path:
    cfg = tmp_path / "cfg"
    scaffold_project(cfg)
    org_file = cfg / "organization.yaml"
    data = yaml.safe_load(org_file.read_text())
    tags = data.setdefault("organization", {}).setdefault("tags", {})
    tags.pop("Environment", None)
    if environment is not None:
        tags["Environment"] = environment
    org_file.write_text(yaml.safe_dump(data))
    return cfg


def _ok_report() -> TeardownReport:
    return TeardownReport(items=[], status="COMPLETED")


# --json must not stand in for consent
@pytest.mark.parametrize("command", ["destroy", "teardown"])
def test_teardown_json_without_yes_is_refused(tmp_path: Path, command: str):
    cfg = _make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_all,
    ):
        res = runner.invoke(app, [command, "--json", "-c", str(cfg)])
    assert res.exit_code == 2
    mock_all.assert_not_called()


def test_teardown_json_with_yes_or_dry_run_is_allowed(tmp_path: Path):
    cfg = _make_config(tmp_path, None)
    for extra in (["--yes"], ["--dry-run"]):
        with (
            patch("tarmac.cli.deploy.AwsSessionManager"),
            patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=_ok_report()),
        ):
            res = runner.invoke(app, ["destroy", "--json", "-c", str(cfg), *extra])
        assert res.exit_code == 0, res.output


def test_run_json_without_yes_is_refused_for_live_deploy(tmp_path: Path):
    cfg = _make_config(tmp_path, None)
    with patch("tarmac.cli.deploy.AwsSessionManager"), patch("tarmac.cli.deploy._run_phase_1_org") as phase:
        res = runner.invoke(app, ["run", "--json", "--phase", "1", "-c", str(cfg)])
    assert res.exit_code == 2
    phase.assert_not_called()


# production lock
@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        ({"Environment": "production"}, True),
        ({"Environment": "Production"}, True),
        ({"Environment": "prod"}, True),
        ({"Environment": "PRD"}, True),
        ({"env": " Prod "}, True),
        ({"Stage": "production"}, True),
        ({"Environment": "staging"}, False),
        ({"Environment": "Infrastructure"}, False),
        ({"Owner": "production"}, False),
        ({}, False),
    ],
)
def test_is_production_tagged(tags: dict[str, str], expected: bool):
    assert _is_production_tagged(tags) is expected


@pytest.mark.parametrize("env", ["production", "Production", "prod", "PRD"])
def test_destroy_blocked_for_production_tags_without_force(tmp_path: Path, env: str):
    cfg = _make_config(tmp_path, env)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=_ok_report()) as mock_all,
    ):
        res = runner.invoke(app, ["destroy", "--yes", "-c", str(cfg)])
        assert res.exit_code == 1
        assert "SAFETY LOCK" in res.output
        mock_all.assert_not_called()

        forced = runner.invoke(app, ["destroy", "--yes", "--force", "-c", str(cfg)])
        assert forced.exit_code == 0, forced.output
        mock_all.assert_called_once()


def test_destroy_dry_run_allowed_for_production(tmp_path: Path):
    cfg = _make_config(tmp_path, "prod")
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=_ok_report()),
    ):
        res = runner.invoke(app, ["destroy", "--dry-run", "-c", str(cfg)])
    assert res.exit_code == 0, res.output


# exit code reflects failure
@pytest.mark.parametrize("fmt", [[], ["--json"]])
def test_teardown_exits_nonzero_when_items_fail(tmp_path: Path, fmt: list[str]):
    cfg = _make_config(tmp_path, None)
    failed = TeardownReport(
        items=[TeardownItemReport("S3 Bucket", "b", "Acct", "1", "FAILED", "denied")], status="FAILED"
    )
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=failed),
    ):
        res = runner.invoke(app, ["destroy", "--yes", "-c", str(cfg), *fmt])
    assert res.exit_code == 1


# phase validation
@pytest.mark.parametrize("phase", ["0", "1", "7", "-3"])
def test_teardown_rejects_invalid_phase(tmp_path: Path, phase: str):
    cfg = _make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_all,
    ):
        res = runner.invoke(app, ["destroy", "--yes", "--phase", phase, "-c", str(cfg)])
    assert res.exit_code == 2
    mock_all.assert_not_called()


def test_run_rejects_invalid_phase(tmp_path: Path):
    cfg = _make_config(tmp_path, None)
    with patch("tarmac.cli.deploy.AwsSessionManager"):
        res = runner.invoke(app, ["run", "--yes", "--phase", "9", "-c", str(cfg)])
    assert res.exit_code == 2


# identity never deletes permission sets it does not own
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


def test_teardown_skips_permission_sets_not_owned_by_tarmac(tmp_path: Path):
    cfg = _make_config(tmp_path, None)
    bundle, errors = load_all_configs(cfg)
    assert bundle is not None, errors
    declared = bundle.identity.identity_center.permission_sets[0].name

    mgr = MagicMock()
    mgr.get_caller_identity.return_value = {"Account": "111122223333"}
    mock_sso = MagicMock()
    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )
    mgr.get_client.side_effect = lambda name, **_: mock_sso if name == "sso-admin" else mock_cfn
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1"}]
    }
    pager = MagicMock()
    pager.paginate.side_effect = lambda **kw: (
        [{"Tags": []}] if "ResourceArn" in kw else [{"PermissionSets": ["arn:ps-1"]}]
    )
    mock_sso.get_paginator.return_value = pager
    mock_sso.describe_permission_set.return_value = {"PermissionSet": {"Name": declared}}

    items = TeardownService(mgr).teardown_identity(bundle, "us-east-1", dry_run=False)

    skipped = [i for i in items if i.resource_type == "Permission Set"]
    assert [i.action for i in skipped] == ["SKIPPED"]
    mock_sso.delete_permission_set.assert_not_called()


# S3 purge and bucket deletion failures are reported
def test_empty_s3_bucket_raises_when_s3_reports_delete_errors():
    s3 = MagicMock()
    s3.head_bucket.return_value = {}
    versions = MagicMock()
    versions.paginate.return_value = [{"Versions": [{"Key": "locked", "VersionId": "1"}]}]
    s3.get_paginator.return_value = versions
    s3.delete_objects.return_value = {
        "Errors": [{"Key": "locked", "Code": "AccessDenied", "Message": "Object Lock"}]
    }

    with pytest.raises(GovernanceError) as exc:
        empty_s3_bucket(s3, "my-bucket")
    assert "AccessDenied" in str(exc.value)


def test_empty_s3_bucket_raises_on_listing_failure():
    s3 = MagicMock()
    s3.head_bucket.return_value = {}
    pager = MagicMock()
    pager.paginate.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "List")
    s3.get_paginator.return_value = pager
    with pytest.raises(GovernanceError):
        empty_s3_bucket(s3, "my-bucket")


def test_delete_retained_bucket_reports_failure_and_ignores_missing():
    svc = TeardownService(MagicMock())
    s3 = MagicMock()
    s3.delete_bucket.side_effect = ClientError({"Error": {"Code": "BucketNotEmpty", "Message": "full"}}, "x")
    items = svc._delete_retained_bucket(s3, "b", "Acct", "1")
    assert [i.action for i in items] == ["FAILED"]
    assert "full" in items[0].message

    s3.delete_bucket.side_effect = ClientError({"Error": {"Code": "NoSuchBucket", "Message": "gone"}}, "x")
    assert svc._delete_retained_bucket(s3, "b", "Acct", "1") == []

    s3.delete_bucket.side_effect = None
    assert svc._delete_retained_bucket(s3, "b", "Acct", "1") == []


# cost anomaly monitors are matched by exact tarmac-generated name
def test_teardown_budgets_only_deletes_exact_tarmac_monitors(tmp_path: Path):
    cfg = _make_config(tmp_path, None)
    bundle, errors = load_all_configs(cfg)
    assert bundle is not None, errors
    acct = bundle.accounts.accounts[0]

    mgr = MagicMock()
    mgr.get_caller_identity.return_value = {"Account": "111122223333"}
    mock_ce = MagicMock()
    mock_ce.get_anomaly_monitors.return_value = {
        "AnomalyMonitors": [
            {"MonitorName": f"{acct.name}-cost-anomaly-monitor", "MonitorArn": "arn:ours"},
            {"MonitorName": f"{acct.name}-team-spend-watch", "MonitorArn": "arn:theirs"},
            {"MonitorName": "my-tarmac-notes", "MonitorArn": "arn:theirs2"},
        ]
    }
    cfn = MagicMock()
    cfn.describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
    )
    mgr.get_member_client.side_effect = lambda _id, svc, **_: mock_ce if svc == "ce" else cfn

    TeardownService(mgr).teardown_budgets(bundle, dry_run=False, account_id_map={acct.name: "444455556666"})

    deleted = [c.kwargs["MonitorArn"] for c in mock_ce.delete_anomaly_monitor.call_args_list]
    assert deleted == ["arn:ours"]


# preflight must not report PASS when it could not verify
def test_account_quota_unverifiable_is_warning_not_pass(tmp_path: Path):
    cfg = _make_config(tmp_path, None)
    bundle, errors = load_all_configs(cfg)
    assert bundle is not None, errors

    mgr = MagicMock()
    org = MagicMock()
    pager = MagicMock()
    pager.paginate.return_value = [{"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}]
    org.get_paginator.return_value = pager
    sq = MagicMock()
    sq.get_service_quota.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "GetServiceQuota"
    )
    mgr.get_client.side_effect = lambda name, **_: sq if name == "service-quotas" else org

    res = PreflightService(mgr, bundle).check_account_quota()
    assert res.status == PreflightCheckStatus.WARN
    assert "could not be verified" in res.live_value
    assert res.action_required


# parallel default-VPC cleanup is exercised and thread-safe
def test_parallel_vpc_cleanup_runs_every_region_and_keeps_order():
    mgr = MagicMock()
    seen: set[str] = set()

    def member_client(_acct: str, _svc: str, region_name: str | None = None) -> MagicMock:
        ec2 = MagicMock()
        seen.add(str(region_name))
        ec2.describe_vpcs.return_value = {"Vpcs": []}
        return ec2

    mgr.get_member_client.side_effect = member_client
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]
    reports = BaselineService(mgr).cleanup_default_vpcs("123456789012", "Acct", regions=regions)

    assert [r.region for r in reports] == regions
    assert seen == set(regions)
    assert all(r.skipped and not r.error for r in reports)


def test_vpc_cleanup_unexpected_error_is_contained_and_flagged():
    mgr = MagicMock()
    mgr.get_member_client.side_effect = RuntimeError("credential provider race")
    reports = BaselineService(mgr).cleanup_default_vpcs("123456789012", "Acct", regions=["a", "b"])
    assert len(reports) == 2
    assert all(r.error for r in reports)


def test_session_manager_serializes_client_creation_across_threads():
    with patch("boto3.Session") as session_cls:
        mgr = AwsSessionManager(region_name="us-east-1")
        root = session_cls.return_value
        active = 0
        peak = 0
        guard = threading.Lock()

        def slow_client(*_a: Any, **_k: Any) -> MagicMock:
            nonlocal active, peak
            with guard:
                active += 1
                peak = max(peak, active)
            threading.Event().wait(0.01)
            with guard:
                active -= 1
            return MagicMock()

        root.client.side_effect = slow_client
        threads = [threading.Thread(target=lambda: mgr.get_client("ec2", "us-east-1")) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

    assert peak == 1


def test_baseline_account_not_marked_complete_when_a_region_errors():
    from tarmac.core.config_schema import AccountBaselineConfig, AccountDef

    mgr = MagicMock()
    mgr.default_region = "us-east-1"
    mgr.get_member_client.side_effect = RuntimeError("credential provider race")
    org = MagicMock()
    pager = MagicMock()
    pager.paginate.return_value = [{"Tags": []}]
    org.get_paginator.return_value = pager
    mgr.get_client.return_value = org

    acct = AccountDef(
        name="NewAccount",
        email="new@example.com",
        ou="Workloads",
        baseline=AccountBaselineConfig(delete_default_vpc=True),
    )
    report = BaselineService(mgr).baseline_account(acct, "123456789012", regions=["us-east-1"])

    assert report.vpc_reports[0].error is True
    org.tag_resource.assert_not_called()  # not marked tarmac:baseline=completed, so it is retried next run


# template hardening (packaged copy must match too)
@pytest.mark.parametrize("base", ["cloudformation", "src/tarmac/templates/cloudformation"])
def test_log_archive_template_hardening(base: str):
    root = Path(__file__).resolve().parents[1]

    class _Loader(yaml.SafeLoader):
        pass

    _Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    doc = yaml.load((root / base / "log-archive-hardening.yaml").read_text(), Loader=_Loader)
    res = doc["Resources"]

    key = res["LogArchiveKmsKey"]
    assert key["DeletionPolicy"] == "Retain"
    assert key["UpdateReplacePolicy"] == "Retain"
    assert "DeletionPolicy" not in res["LogArchiveKmsAlias"]

    enc = res["AccessLogsBucket"]["Properties"]["BucketEncryption"]["ServerSideEncryptionConfiguration"]
    assert enc[0]["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    sids = [s["Sid"] for s in key["Properties"]["KeyPolicy"]["Statement"]]
    assert "AllowS3LogDeliveryEncrypt" not in sids


# no silent fallback to example configuration


def test_default_config_dir_does_not_fall_back_to_repo_examples(tmp_path, monkeypatch):
    from tarmac.core.config_loader import get_default_config_dir

    monkeypatch.delenv("TARMAC_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    resolved = get_default_config_dir()

    assert "examples" not in resolved.parts
    assert resolved == tmp_path / "config"


def test_example_files_are_not_loaded_as_real_config(tmp_path):
    from tarmac.core.config_loader import resolve_file
    from tarmac.core.exceptions import ConfigurationError

    (tmp_path / "organization.yaml.example").write_text("organization: {}\n")

    with pytest.raises(ConfigurationError):
        resolve_file(tmp_path, "organization")


# email-first account matching and aggregated provisioning failures


def _acct_service(existing: dict[str, dict[str, Any]]):
    from tarmac.services.accounts import AccountService

    mgr = MagicMock(spec=AwsSessionManager)
    org = MagicMock()
    mgr.get_client.return_value = org
    svc = AccountService(mgr)
    svc.list_existing_accounts = MagicMock(return_value=existing)  # type: ignore[method-assign]
    return svc, org


def _acct_def(name: str, email: str, ou: str = "Workloads"):
    from tarmac.core.config_schema import AccountDef

    return AccountDef(name=name, email=email, ou=ou)


def test_find_existing_account_prefers_email_over_name():
    svc, _ = _acct_service({})
    existing = {
        "Prod App": {"Id": "111111111111", "Email": "other@example.com", "Status": "ACTIVE"},
        "renamed": {"Id": "222222222222", "Email": "prod@example.com", "Status": "ACTIVE"},
    }
    found = svc.find_existing_account("prod-app", existing, email="prod@example.com")
    assert found is not None
    assert found["Id"] == "222222222222"


def test_provision_refuses_to_adopt_name_match_with_different_email():
    svc, org = _acct_service(
        {"Prod App": {"Id": "111111111111", "Email": "other@example.com", "Status": "ACTIVE"}}
    )
    with pytest.raises(Exception, match="could not be provisioned") as exc:
        svc.provision_accounts([_acct_def("prod-app", "prod@example.com")], {"Workloads": "ou-1"})

    assert "email" in str(getattr(exc.value, "details", "")).lower()
    org.move_account.assert_not_called()
    org.create_account.assert_not_called()


def test_provision_continues_after_one_create_failure_then_aggregates():
    svc, org = _acct_service({})
    org.create_account.side_effect = [
        ClientError({"Error": {"Code": "ConstraintViolation", "Message": "quota"}}, "CreateAccount"),
        {"CreateAccountStatus": {"Id": "car-2"}},
    ]
    svc._describe_create_status = MagicMock(return_value=("SUCCEEDED", "333333333333", ""))  # type: ignore[method-assign]
    svc.move_account_if_needed = MagicMock(return_value=True)  # type: ignore[method-assign]
    svc.sync_account_tags = MagicMock(return_value=False)  # type: ignore[method-assign]

    accounts = [_acct_def("a", "a@example.com"), _acct_def("b", "b@example.com")]
    with pytest.raises(Exception, match="1 account") as exc:
        svc.provision_accounts(accounts, {"Workloads": "ou-1"}, poll_delay_sec=0, max_poll_attempts=2)

    assert "quota" in str(getattr(exc.value, "details", ""))
    # The second account was still polled, moved and tagged despite the first one failing.
    svc.move_account_if_needed.assert_called_once()
    svc.sync_account_tags.assert_called_once()
