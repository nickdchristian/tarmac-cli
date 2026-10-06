"""Tests for the tarmac Typer CLI commands."""

import json
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.models import IdentitySyncReport

runner = CliRunner()


def test_cli_help_and_subcommand_helps():
    """Verify root help and help for all major subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Tarmac: Enterprise AWS Governance & Multi-Account Landing Zone CLI" in result.stdout
    for subcmd in ["org", "ou", "account", "identity", "baseline", "deploy", "preflight", "doctor"]:
        sub_res = runner.invoke(app, [subcmd, "--help"])
        assert sub_res.exit_code == 0


def test_cli_validate(sample_config_dir):
    result = runner.invoke(app, ["validate", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "cross-references are valid!" in result.stdout


def test_cli_info(monkeypatch):
    from unittest.mock import MagicMock

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {
        "Account": "111111111111",
        "Arn": "arn:aws:iam::111111111111:root",
    }
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {
        "Organization": {
            "Id": "o-test12345",
            "MasterAccountId": "111111111111",
            "FeatureSet": "ALL",
        }
    }
    mock_sso = MagicMock()
    mock_sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:aws:sso:::instance/sso-123"}]}

    def client_mock(service_name: str, **kwargs):
        if service_name == "organizations":
            return mock_org
        if service_name == "sso-admin":
            return mock_sso
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_mock

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)

    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "111111111111" in result.stdout
    assert "o-test12345" in result.stdout
    assert "Authenticated as Management Account" in result.stdout


def test_cli_baseline_backend_s3_only(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    from tarmac.core.models import StackDeployReport

    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_org.list_accounts.return_value = {"Accounts": [{"Name": "Deployment", "Id": "222222222222"}]}
    mock_session_mgr.get_client.return_value = mock_org

    mock_service = MagicMock()
    mock_service.deploy_stack.return_value = StackDeployReport(
        stack_name="test-terraform-backend",
        action="CREATED",
        outputs={"BucketName": "test-bucket"},
    )

    monkeypatch.setattr("tarmac.cli.baseline.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.baseline.CloudFormationService", lambda sm: mock_service)

    result = runner.invoke(
        app,
        ["baseline", "backend", "--config-dir", str(sample_config_dir), "--s3-only"],
    )
    assert result.exit_code == 0
    assert mock_service.deploy_stack.call_count == 1
    call_args = mock_service.deploy_stack.call_args[0]
    params = call_args[3]
    assert params["EnableDynamoDB"] == "false"


def test_cli_baseline_cloudtrail_sse_s3(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    from tarmac.core.models import StackDeployReport

    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-test12345"}}
    mock_session_mgr.get_client.return_value = mock_org

    mock_service = MagicMock()
    mock_service.deploy_stack.return_value = StackDeployReport(
        stack_name="test-cloudtrail",
        action="CREATED",
        outputs={"BucketName": "test-cloudtrail-bucket"},
    )

    monkeypatch.setattr("tarmac.cli.baseline.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.baseline.CloudFormationService", lambda sm: mock_service)

    result = runner.invoke(
        app,
        ["baseline", "cloudtrail", "--config-dir", str(sample_config_dir), "--sse-s3"],
    )
    assert result.exit_code == 0
    assert mock_service.deploy_stack.call_count == 1
    call_args = mock_service.deploy_stack.call_args[0]
    params = call_args[3]
    assert params["EnableKmsEncryption"] == "false"


def test_cli_deploy_run_with_custom_tags(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    from tarmac.core.models import StackDeployReport

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111111111111"}
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-test12345"}}
    mock_org.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "888888888888", "Name": "Log-Archive", "Status": "ACTIVE"}]}
    ]
    mock_session_mgr.get_client.return_value = mock_org
    mock_session_mgr.get_member_client.return_value = MagicMock()

    mock_service = MagicMock()
    mock_service.deploy_stack.return_value = StackDeployReport(
        stack_name="test-cloudtrail",
        action="CREATED",
        outputs={"BucketName": "test-cloudtrail-bucket"},
    )

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy.CloudFormationService", lambda sm: mock_service)
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: MagicMock())

    result = runner.invoke(
        app,
        [
            "deploy",
            "run",
            "--config-dir",
            str(sample_config_dir),
            "--phase",
            "3",
            "--yes",
            "--tag",
            "CostCenter=Finance-99",
        ],
    )
    assert result.exit_code == 0
    assert mock_service.deploy_stack.call_count == 2
    for call in mock_service.deploy_stack.call_args_list:
        _, kwargs = call
        assert kwargs["tags"] == {"CostCenter": "Finance-99"}


def test_cli_deploy_phase_3_deploys_log_archive_hardening_before_trail(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    from tarmac.core.models import StackDeployReport

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111111111111"}
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-test12345"}}
    mock_org.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "888888888888", "Name": "Log-Archive", "Status": "ACTIVE"}]}
    ]
    mock_session_mgr.get_client.return_value = mock_org
    mock_session_mgr.get_member_client.return_value = MagicMock()

    deployed_stacks = []

    def mock_deploy_stack(cfn_client, stack_name, *args, **kwargs):
        deployed_stacks.append(stack_name)
        return StackDeployReport(stack_name=stack_name, action="CREATED", outputs={})

    mock_service = MagicMock()
    mock_service.deploy_stack.side_effect = mock_deploy_stack

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy.CloudFormationService", lambda sm: mock_service)
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: MagicMock())

    result = runner.invoke(
        app,
        [
            "deploy",
            "run",
            "--config-dir",
            str(sample_config_dir),
            "--phase",
            "3",
            "--yes",
        ],
    )
    assert result.exit_code == 0
    assert len(deployed_stacks) == 2
    assert "log-archive-hardening" in deployed_stacks[0]
    assert "organization-cloudtrail" in deployed_stacks[1]


def test_cli_init_project(tmp_path):
    target = tmp_path / "config"
    result = runner.invoke(app, ["init", "--config-dir", str(target)])
    assert result.exit_code == 0
    assert (target / "organization.yaml").exists()
    assert (target / "accounts.yaml").exists()
    assert (target / "identity.yaml").exists()
    assert "Created" in result.stdout

    # Positional directory argument test
    target_pos = tmp_path / "positional_config"
    result_pos = runner.invoke(app, ["init", str(target_pos)])
    assert result_pos.exit_code == 0
    assert (target_pos / "organization.yaml").exists()

    # With --force overwrites
    result_force = runner.invoke(app, ["init", "--config-dir", str(target), "--force"])
    assert result_force.exit_code == 0
    assert "Created" in result_force.stdout

    # Verify that scaffolded files pass full validation
    from tarmac.core.config_loader import load_all_configs

    bundle, errors = load_all_configs(target)
    assert errors == []
    assert bundle is not None
    assert bundle.org.organization.name == "myorg"
    assert len(bundle.accounts.accounts) == 4
    assert len(bundle.identity.identity_center.permission_sets) == 2

    # With --with-templates exports templates & policies
    target_tmpl = tmp_path / "templated_project" / "config"
    res_tmpl = runner.invoke(app, ["init", "--config-dir", str(target_tmpl), "--with-templates"])
    assert res_tmpl.exit_code == 0
    assert (target_tmpl / "organization.yaml").exists()
    assert (tmp_path / "templated_project" / "cloudformation" / "organization-cloudtrail.yaml").exists()
    assert (tmp_path / "templated_project" / "policies" / "scp" / "deny-leave-organization.json").exists()


def test_cli_validate_json(sample_config_dir):
    import json

    result = runner.invoke(app, ["validate", "--config-dir", str(sample_config_dir), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["valid"] is True
    assert data["summary"]["organization_name"] in {"flumen", "myorg"}
    assert data["errors"] == []


def test_cli_info_json(monkeypatch):
    import json
    from unittest.mock import MagicMock

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {
        "Account": "111111111111",
        "Arn": "arn:aws:iam::111111111111:root",
    }
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {
        "Organization": {
            "Id": "o-test12345",
            "MasterAccountId": "111111111111",
            "FeatureSet": "ALL",
        }
    }
    mock_sso = MagicMock()
    mock_sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:aws:sso:::instance/sso-123"}]}

    def client_mock(service_name: str, **kwargs):
        if service_name == "organizations":
            return mock_org
        if service_name == "sso-admin":
            return mock_sso
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_mock
    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)

    result = runner.invoke(app, ["info", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["account_id"] == "111111111111"
    assert data["organization_id"] == "o-test12345"
    assert data["is_management_account"] is True


def test_cli_plan_json(sample_config_dir, monkeypatch):
    import json
    from unittest.mock import MagicMock

    from tarmac.core.config_schema import AccountBaselineConfig
    from tarmac.core.models import AccountPlanItem

    mock_session_mgr = MagicMock()
    mock_ou_service = MagicMock()
    mock_ou_service.get_root_id.return_value = "r-1234"
    mock_ou_service.list_existing_ous_for_parent.return_value = {"Security": "ou-sec-123"}

    mock_acct_service = MagicMock()
    mock_acct_service.plan.return_value = [
        AccountPlanItem(
            name="Log-Archive",
            email="log@example.com",
            ou="Security",
            action="CREATE",
            account_id=None,
            reason="Account not found in organization",
            baseline=AccountBaselineConfig(),
        )
    ]

    monkeypatch.setattr("tarmac.cli.account.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.account.OUService", lambda sm: mock_ou_service)
    monkeypatch.setattr("tarmac.cli.account.AccountService", lambda sm: mock_acct_service)

    result = runner.invoke(app, ["account", "plan", "--config-dir", str(sample_config_dir), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["name"] == "Log-Archive"
    assert data[0]["action"] == "CREATE"


def test_cli_status(sample_config_dir, monkeypatch):
    import json
    from unittest.mock import MagicMock

    from tarmac.services.status import LandingZoneStatus

    mock_session_mgr = MagicMock()
    mock_status_service = MagicMock()
    mock_status = LandingZoneStatus(
        org_id="o-test123",
        feature_set="ALL",
        ous_declared=6,
        ous_live=6,
        accounts_declared=4,
        accounts_live=4,
        cloudtrail_status="CREATE_COMPLETE",
        backend_status="CREATE_COMPLETE",
        sso_configured=True,
    )
    mock_status_service.inspect.return_value = mock_status

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.main.StatusService", lambda sm: mock_status_service)

    result = runner.invoke(app, ["status", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "Landing Zone Reconciliation Status" in result.stdout
    assert "o-test123" in result.stdout

    result_json = runner.invoke(app, ["status", "--config-dir", str(sample_config_dir), "--json"])
    assert result_json.exit_code == 0
    data = json.loads(result_json.stdout)
    assert data["org_id"] == "o-test123"
    assert data["cloudtrail_status"] == "CREATE_COMPLETE"


def test_cli_status_with_drift(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    from tarmac.services.status import LandingZoneStatus

    mock_session_mgr = MagicMock()
    mock_status_service = MagicMock()
    mock_status = LandingZoneStatus(
        org_id="o-test123",
        feature_set="ALL",
        ous_declared=6,
        ous_live=2,
        accounts_declared=4,
        accounts_live=1,
        cloudtrail_status="NOT_FOUND",
        backend_status="NOT_FOUND",
        sso_configured=False,
    )
    mock_status_service.inspect.return_value = mock_status

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.main.StatusService", lambda sm: mock_status_service)

    result = runner.invoke(app, ["status", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "DRIFT" in result.stdout
    assert "PENDING" in result.stdout
    assert "Pending Actions & Remediation" in result.stdout
    assert "tarmac ou" in result.stdout
    assert "tarmac account apply" in result.stdout
    assert "tarmac baseline cloudtrail" in result.stdout
    assert "tarmac baseline backend" in result.stdout
    assert "tarmac identity sync" in result.stdout


def test_cli_deploy_run_prompts_and_yes(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    mock_session_mgr = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)

    # When user cancels prompt (input 'n')
    result_cancel = runner.invoke(
        app,
        ["deploy", "run", "--config-dir", str(sample_config_dir), "--phase", "1"],
        input="n\n",
    )
    assert result_cancel.exit_code == 0
    assert "Deployment cancelled by user" in result_cancel.stdout

    # With --yes flag and mocked phase 1
    mock_org_service = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: mock_org_service)

    result_yes = runner.invoke(
        app,
        ["deploy", "run", "--config-dir", str(sample_config_dir), "--phase", "1", "--yes"],
    )
    assert result_yes.exit_code == 0
    assert "Deployment pipeline completed successfully!" in result_yes.stdout


def test_cli_global_profile(monkeypatch):
    import os
    from unittest.mock import MagicMock

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {
        "Account": "123",
        "Arn": "arn:aws:iam::123:root",
    }
    mock_org = MagicMock()
    mock_org.describe_organization.side_effect = Exception("No org")
    mock_session_mgr.get_client.return_value = mock_org

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)

    result = runner.invoke(app, ["-p", "test-profile", "info"])
    assert result.exit_code == 0
    assert os.environ.get("AWS_PROFILE") == "test-profile"


def test_cli_identity_status(monkeypatch, sample_config_dir):
    mock_session_mgr = MagicMock()
    mock_service = MagicMock()
    mock_service.get_instance_details.return_value = (
        "arn:aws:sso:::instance/ssoins-test",
        "d-teststore",
    )
    mock_service.region = "us-east-1"

    monkeypatch.setattr("tarmac.cli.identity.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.identity.IdentityService", lambda *a, **kw: mock_service)

    result = runner.invoke(app, ["identity", "status", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "arn:aws:sso:::instance/ssoins-test" in result.stdout
    assert "d-teststore" in result.stdout


def test_cli_identity_sync(monkeypatch, sample_config_dir):
    mock_session_mgr = MagicMock()
    mock_service = MagicMock()

    mock_service.sync_identity.return_value = IdentitySyncReport(
        permission_sets_synced=["AdministratorAccess"],
        users_synced=["admin"],
        groups_synced=["flumen-admin"],
        assignments_created=2,
        memberships_added=1,
    )

    monkeypatch.setattr("tarmac.cli.identity.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.identity.IdentityService", lambda *a, **kw: mock_service)

    result = runner.invoke(app, ["identity", "sync", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "Synchronized" in result.stdout
    assert "Configured" in result.stdout
    assert "Synchronized group memberships" in result.stdout
    mock_service.sync_identity.assert_called_once()


def test_cli_anomaly_status(monkeypatch, sample_config_dir):
    mock_session_mgr = MagicMock()
    mock_baseliner = MagicMock()
    mock_baseliner.get_anomaly_overview.return_value = (
        [{"MonitorName": "flumen-prod-cost-anomaly-monitor", "MonitorType": "CUSTOM"}],
        [
            {
                "SubscriptionName": "flumen-prod-anomaly-alerts",
                "Threshold": 100.0,
                "Frequency": "DAILY",
                "Subscribers": [{"Address": "alerts@example.com"}],
            }
        ],
    )

    monkeypatch.setattr("tarmac.cli.baseline.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.baseline.BaselineService", lambda sm: mock_baseliner)

    result = runner.invoke(app, ["baseline", "anomaly-status", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "flumen-prod-cost-anomaly-monitor" in result.stdout
    assert "flumen-prod-anomaly-alerts" in result.stdout


def test_cli_account_sync_tags(monkeypatch, sample_config_dir):
    mock_session_mgr = MagicMock()
    mock_service = MagicMock()
    mock_service.list_existing_accounts.return_value = {
        "deployment": {"Id": "111111111111", "Name": "deployment"},
    }
    mock_service.find_existing_account.return_value = {"Id": "111111111111", "Name": "deployment"}
    mock_service.sync_account_tags.return_value = True

    monkeypatch.setattr("tarmac.cli.account.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.account.AccountService", lambda sm: mock_service)

    result = runner.invoke(app, ["account", "sync-tags", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "Account Tag Sync" in result.stdout
    assert "deployment" in result.stdout
    assert "111111111111" in result.stdout
    assert "UPDATED" in result.stdout
    mock_service.sync_account_tags.assert_called()


def test_cli_account_suspend(monkeypatch, sample_config_dir):
    from tarmac.core.models import AccountSuspensionResult

    mock_session_mgr = MagicMock()
    mock_service = MagicMock()
    mock_ou_service = MagicMock()

    mock_service.list_existing_accounts.return_value = {
        "OldDev": {"Id": "444444444444", "Name": "OldDev"},
    }
    mock_ou_service.get_root_id.return_value = "r-root"
    mock_ou_service.list_all_ous.return_value = {"Suspended": "ou-susp-999"}
    mock_service.suspend_account.return_value = AccountSuspensionResult(
        name="OldDev",
        account_id="444444444444",
        moved_to_ou="ou-susp-999",
        tags_updated=True,
        closed=False,
        status="SUCCEEDED",
        message="Account OldDev quarantined into Suspended OU.",
    )

    monkeypatch.setattr("tarmac.cli.account.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.account.AccountService", lambda sm: mock_service)
    monkeypatch.setattr("tarmac.cli.account.OUService", lambda sm: mock_ou_service)

    result = runner.invoke(
        app,
        ["account", "suspend", "OldDev", "--config-dir", str(sample_config_dir), "--yes"],
    )
    assert result.exit_code == 0
    assert "quarantined into Suspended OU" in result.stdout
    mock_service.suspend_account.assert_called_once_with(
        account_id="444444444444",
        account_name="OldDev",
        suspended_ou_id="ou-susp-999",
        dry_run=False,
        close=False,
    )


@pytest.mark.parametrize("dry_run", [False, True])
def test_cli_org_cleanup_vpc(monkeypatch, sample_config_dir, dry_run: bool):
    """Verify org cleanup-vpc live and dry-run execution."""
    from unittest.mock import MagicMock

    from tarmac.core.models import VpcCleanupReport

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {"Account": "000000000000"}
    mock_baseliner = MagicMock()
    mock_baseliner.cleanup_default_vpcs.return_value = [
        VpcCleanupReport(
            region="us-east-1",
            vpc_id="vpc-default123",
            deleted_vpc=not dry_run,
            skipped=dry_run,
            detached_igws=["igw-111"] if not dry_run else [],
            deleted_subnets=["subnet-222"] if not dry_run else [],
            message="Purged default VPC" if not dry_run else "Dry run simulation",
        )
    ]

    monkeypatch.setattr("tarmac.cli.org.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.org.BaselineService", lambda sm: mock_baseliner)

    cmd = ["org", "cleanup-vpc", "--config-dir", str(sample_config_dir)]
    if dry_run:
        cmd.append("--dry-run")
    result = runner.invoke(app, cmd)
    assert result.exit_code == 0
    assert "vpc-default123" in result.stdout
    if dry_run:
        assert "DRY-RUN" in result.stdout
    else:
        assert "Purged default VPC" in result.stdout


def test_cli_preflight_and_doctor_execution(monkeypatch, sample_config_dir):
    """Verify preflight and doctor commands execute with table and JSON formatting."""
    import json
    from unittest.mock import MagicMock

    from tarmac.core.models import PreflightCheckResult, PreflightCheckStatus, PreflightReport

    mock_report = PreflightReport(
        checks=[
            PreflightCheckResult(
                name="Root MFA",
                target="Account: 111111111111",
                status=PreflightCheckStatus.PASS,
                live_value="Enabled",
            )
        ],
        passed=1,
        warnings=0,
        failures=0,
        info=0,
        can_proceed=True,
    )
    mock_service = MagicMock()
    mock_service.run_all_checks.return_value = mock_report

    monkeypatch.setattr("tarmac.cli.preflight.AwsSessionManager", lambda **kw: MagicMock())
    monkeypatch.setattr("tarmac.cli.preflight.PreflightService", lambda sm, b: mock_service)

    res = runner.invoke(app, ["preflight", "--config-dir", str(sample_config_dir)])
    assert res.exit_code == 0
    assert "PASS" in res.stdout
    assert "1 passed" in res.stdout

    res_doc = runner.invoke(app, ["doctor", "--config-dir", str(sample_config_dir)])
    assert res_doc.exit_code == 0
    assert "PASS" in res_doc.stdout

    res_json = runner.invoke(app, ["preflight", "--config-dir", str(sample_config_dir), "--json"])
    assert res_json.exit_code == 0
    payload = json.loads(res_json.stdout)
    assert payload["can_proceed"] is True
    assert payload["summary"]["passed"] == 1


def test_cli_preflight_failures_and_strict_mode(monkeypatch, sample_config_dir):
    """Verify preflight failures and --strict warnings trigger exit code 1."""
    from unittest.mock import MagicMock

    from tarmac.core.models import PreflightCheckResult, PreflightCheckStatus, PreflightReport

    mock_service = MagicMock()
    monkeypatch.setattr("tarmac.cli.preflight.AwsSessionManager", lambda **kw: MagicMock())
    monkeypatch.setattr("tarmac.cli.preflight.PreflightService", lambda sm, b: mock_service)

    mock_service.run_all_checks.return_value = PreflightReport(
        checks=[
            PreflightCheckResult(
                name="Root MFA",
                target="Account: 111111111111",
                status=PreflightCheckStatus.FAIL,
                live_value="Disabled",
                action_required="Enable MFA on root account",
            )
        ],
        passed=0,
        warnings=0,
        failures=1,
        info=0,
        can_proceed=False,
    )
    res_fail = runner.invoke(app, ["preflight", "--config-dir", str(sample_config_dir)])
    assert res_fail.exit_code == 1
    assert "Action Required" in res_fail.stdout
    assert "Enable MFA on root account" in res_fail.stdout

    mock_service.run_all_checks.return_value = PreflightReport(
        checks=[
            PreflightCheckResult(
                name="SNS Subscriptions",
                target="Topic",
                status=PreflightCheckStatus.WARN,
                live_value="1 pending",
            )
        ],
        passed=0,
        warnings=1,
        failures=0,
        info=0,
        can_proceed=True,
    )
    res_warn = runner.invoke(app, ["preflight", "--config-dir", str(sample_config_dir)])
    assert res_warn.exit_code == 0

    res_strict = runner.invoke(app, ["preflight", "--config-dir", str(sample_config_dir), "--strict"])
    assert res_strict.exit_code == 1


def test_cli_org_scp_plan(sample_config_dir, monkeypatch):
    """Verify org scp plan dry-run output."""
    from unittest.mock import MagicMock

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client
    mock_client.list_roots.return_value = {"Roots": [{"Id": "r-root1"}]}

    paginator = MagicMock()
    paginator.paginate.return_value = [{"OrganizationalUnits": []}]
    mock_client.get_paginator.return_value = paginator

    monkeypatch.setattr("tarmac.cli.org.AwsSessionManager", lambda **kwargs: mock_session)

    result = runner.invoke(app, ["org", "scp", "plan", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "Service Control Policies Plan (Dry-Run)" in result.stdout
    assert "DenyMemberRootActivity" in result.stdout
    assert "DenyLeaveOrganization" in result.stdout


def test_cli_org_scp_apply(sample_config_dir, monkeypatch):
    """Verify org scp apply dry-run output."""
    from unittest.mock import MagicMock

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client
    mock_client.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }

    paginator = MagicMock()
    paginator.paginate.return_value = [{"Policies": []}, {"OrganizationalUnits": []}]
    mock_client.get_paginator.return_value = paginator
    mock_client.create_policy.return_value = {"Policy": {"PolicySummary": {"Id": "p-123", "Name": "Test"}}}
    mock_client.list_targets_for_policy.return_value = {"Targets": []}

    monkeypatch.setattr("tarmac.cli.org.AwsSessionManager", lambda **kwargs: mock_session)

    result = runner.invoke(app, ["org", "scp", "apply", "--dry-run", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "Service Control Policies (Dry-Run)" in result.stdout
    assert "DenyMemberRootActivity" in result.stdout


def test_cli_deploy_run_preflight_failure(monkeypatch, sample_config_dir):

    from unittest.mock import MagicMock

    from tarmac.core.models import PreflightCheckResult, PreflightCheckStatus, PreflightReport

    mock_report = PreflightReport(
        checks=[
            PreflightCheckResult(
                name="Root MFA",
                target="Account: 111111111111",
                status=PreflightCheckStatus.FAIL,
                live_value="Disabled",
                action_required="Enable MFA on root account",
            )
        ],
        passed=0,
        warnings=0,
        failures=1,
        info=0,
        can_proceed=False,
    )
    mock_service = MagicMock()
    mock_service.run_all_checks.return_value = mock_report

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: MagicMock())
    monkeypatch.setattr("tarmac.services.preflight.PreflightService.run_all_checks", lambda self: mock_report)

    result = runner.invoke(app, ["deploy", "run", "--config-dir", str(sample_config_dir), "--yes"])
    assert result.exit_code == 1
    assert "Pre-flight failed" in result.output
    assert "--skip-preflight" in result.output


def test_cli_version_flags():
    from tarmac import __version__

    res_long = runner.invoke(app, ["--version"])
    assert res_long.exit_code == 0
    assert f"tarmac-cli v{__version__}" in res_long.stdout

    res_short = runner.invoke(app, ["-V"])
    assert res_short.exit_code == 0
    assert f"tarmac-cli v{__version__}" in res_short.stdout


def test_cli_account_list(sample_config_dir, monkeypatch):
    mock_session_mgr = MagicMock()
    mock_ou_service = MagicMock()
    mock_ou_service.get_root_id.return_value = "r-root-123"
    mock_ou_service.list_all_ous.return_value = {
        "Infrastructure": "ou-infra-123",
        "Suspended": "ou-suspended-999",
    }

    mock_acct_service = MagicMock()
    mock_acct_service.list_all_accounts.return_value = [
        {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE", "Email": "dep@example.com"},
        {"Id": "222222222222", "Name": "OldWorkload", "Status": "SUSPENDED", "Email": "old@example.com"},
    ]
    mock_acct_service.get_account_parent_id.side_effect = lambda acct_id: (
        "ou-infra-123" if acct_id == "111111111111" else "ou-suspended-999"
    )

    monkeypatch.setattr("tarmac.cli.account.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.account.OUService", lambda sm: mock_ou_service)
    monkeypatch.setattr("tarmac.cli.account.AccountService", lambda sm: mock_acct_service)

    res = runner.invoke(app, ["account", "list", "--config-dir", str(sample_config_dir)])
    assert res.exit_code == 0
    assert "Deployment" in res.stdout
    assert "OldWorkload" in res.stdout
    assert "ACTIVE" in res.stdout
    assert "SUSPENDED" in res.stdout

    res_sus = runner.invoke(app, ["account", "list", "--config-dir", str(sample_config_dir), "--suspended"])
    assert res_sus.exit_code == 0
    assert "OldWorkload" in res_sus.stdout
    assert "Deployment" not in res_sus.stdout

    res_json = runner.invoke(app, ["account", "list", "--config-dir", str(sample_config_dir), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert len(data) == 2
    assert data[0]["name"] == "Deployment"
    assert data[1]["name"] == "OldWorkload"
    assert data[1]["status"] == "SUSPENDED"


def test_cli_drift_command(monkeypatch, sample_config_dir):
    from tarmac.services.drift import DriftItem, DriftReport

    mock_session_mgr = MagicMock()
    mock_drift_service = MagicMock()
    mock_drift_service.inspect_drift.return_value = DriftReport(
        items=[
            DriftItem(
                category="OU",
                name="Security",
                declared="Present",
                live="Present",
                status="IN_SYNC",
                remediation="",
            ),
            DriftItem(
                category="Account",
                name="dev-app",
                declared="OU: NonProduction",
                live="Missing",
                status="MISSING",
                remediation="tarmac account apply",
            ),
        ],
        has_drift=True,
        in_sync_count=1,
        drift_count=0,
        missing_count=1,
    )

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.main.DriftService", lambda sm: mock_drift_service)

    res = runner.invoke(app, ["drift", "--config-dir", str(sample_config_dir)])
    assert res.exit_code == 0
    assert "Landing Zone Drift Inspection" in res.stdout
    assert "Security" in res.stdout
    assert "dev-app" in res.stdout
    assert "MISSING" in res.stdout

    # Test JSON output
    res_json = runner.invoke(app, ["drift", "--config-dir", str(sample_config_dir), "--json"])
    assert res_json.exit_code == 0
    assert '"has_drift": true' in res_json.stdout

    # Test strict mode exits with code 1 when drift is detected
    res_strict = runner.invoke(app, ["drift", "--config-dir", str(sample_config_dir), "--strict"])
    assert res_strict.exit_code == 1


def test_cli_activate_cost_tags_command(monkeypatch, sample_config_dir):
    mock_session_mgr = MagicMock()
    mock_org_service = MagicMock()
    mock_org_service.activate_cost_allocation_tags.return_value = ["Environment", "CostCenter"]

    monkeypatch.setattr("tarmac.cli.org.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.org.OrganizationService", lambda sm: mock_org_service)

    res = runner.invoke(app, ["org", "activate-cost-tags", "--config-dir", str(sample_config_dir)])
    assert res.exit_code == 0
    assert "Activated 2 Cost Allocation Tag(s)" in res.stdout
    assert "Environment, CostCenter" in res.stdout


def test_cli_deploy_run_dry_run_full(sample_config_dir, monkeypatch):
    """Verify that deploy run --dry-run outputs clean structured plan tables and summary."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    result = runner.invoke(app, ["deploy", "run", "--dry-run", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "Dry-Run Execution Plan (Simulation Mode)" in result.stdout
    assert "Phase 0 Plan: Pre-Flight Operational Readiness Scope" in result.stdout
    assert "Phase 1 Plan: Organization Bootstrap & Management Baseline" in result.stdout
    assert "Phase 2 Plan: Organizational Units Hierarchy" in result.stdout
    assert "Phase 2 Plan: Service Control Policies (SCPs)" in result.stdout
    assert "Phase 3 Plan: Foundational Organization CloudTrail" in result.stdout
    assert "Phase 4 Plan: Account Factory Provisioning & Baselining" in result.stdout
    assert "Phase 5 Plan: Foundation Infrastructure & Security Delegation" in result.stdout
    assert "Phase 6 Plan: IAM Identity Center Permission Sets" in result.stdout
    assert "Phase 6 Plan: Identity Center Users & Groups" in result.stdout
    assert "Dry-Run Plan Summary" in result.stdout
    assert "Simulation Scope:" in result.stdout
    assert "tarmac deploy run" in result.stdout


def test_cli_deploy_run_dry_run_single_phase(sample_config_dir, monkeypatch):
    """Verify that deploy run --dry-run --phase 4 executes only Phase 4 and renders its plan table."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    result = runner.invoke(
        app, ["deploy", "run", "--dry-run", "--phase", "4", "--config-dir", str(sample_config_dir)]
    )
    assert result.exit_code == 0
    assert "Phase 4 Plan: Account Factory Provisioning & Baselining" in result.stdout
    assert "Simulation Scope: Phase 4" in result.stdout
    assert "Phase 1 Plan:" not in result.stdout


def test_cli_deploy_run_dry_run_json(sample_config_dir, monkeypatch):
    """Verify that deploy run --dry-run --json outputs structured, machine-readable JSON."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    result = runner.invoke(
        app, ["deploy", "run", "--dry-run", "--json", "--config-dir", str(sample_config_dir)]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["dry_run"] is True
    assert "target_region" in data
    assert "organization" in data
    assert "phases" in data
    assert "summary" in data
    assert data["summary"]["outcome"] == "SUCCESS"
    assert set(data["summary"]["phases_simulated"]) == {0, 1, 2, 3, 4, 5, 6}
    assert "0_preflight" in data["phases"]
    assert "1_org" in data["phases"]
    assert "2_ou" in data["phases"]
    assert "3_cloudtrail" in data["phases"]
    assert "4_accounts" in data["phases"]
    assert "5_foundation" in data["phases"]
    assert "6_identity" in data["phases"]


def test_cli_deploy_run_dry_run_json_single_phase(sample_config_dir, monkeypatch):
    """Verify that deploy run --dry-run --phase 4 --json outputs JSON scoped only to Phase 4."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    result = runner.invoke(
        app, ["deploy", "run", "--dry-run", "--phase", "4", "--json", "--config-dir", str(sample_config_dir)]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["dry_run"] is True
    assert data["summary"]["phases_simulated"] == [4]
    assert list(data["phases"].keys()) == ["4_accounts"]
    assert len(data["phases"]["4_accounts"]) > 0
