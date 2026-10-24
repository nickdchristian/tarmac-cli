"""Tests for the tarmac Typer CLI commands."""

import json
import re
from unittest.mock import MagicMock

from typer.testing import CliRunner

from tarmac.cli.main import app

runner = CliRunner()


def test_cli_help_and_subcommand_helps():
    """Verify root help and help for all major subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Tarmac: set up and maintain a multi-account AWS Organization from YAML" in result.stdout
    for subcmd in [
        "bootstrap",
        "account",
        "deploy",
        "destroy",
        "inventory",
        "preflight",
        "status",
        "info",
        "logs",
    ]:
        sub_res = runner.invoke(app, [subcmd, "--help"])
        assert sub_res.exit_code == 0


def test_cli_validate(sample_config_dir):
    result = runner.invoke(app, ["validate", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0
    assert "cross-references are valid." in result.stdout


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
        action="CREATED",
        outputs={"BucketName": "test-cloudtrail-bucket"},
    )

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy_phases.CloudFormationService", lambda sm: mock_service)
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: MagicMock())
    monkeypatch.setattr("tarmac.cli.deploy_phases.OrganizationService", lambda sm: MagicMock())

    result = runner.invoke(
        app,
        [
            "deploy",
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
        return StackDeployReport(action="CREATED", outputs={})

    mock_service = MagicMock()
    mock_service.deploy_stack.side_effect = mock_deploy_stack

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy_phases.CloudFormationService", lambda sm: mock_service)
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: MagicMock())
    monkeypatch.setattr("tarmac.cli.deploy_phases.OrganizationService", lambda sm: MagicMock())

    result = runner.invoke(
        app,
        [
            "deploy",
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
    assert data["summary"]["organization_name"] == "myorg"
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
    # Rich wraps long cells; compare against the text with table borders and line breaks removed.
    flat = " ".join(re.sub(r"[│┃╭╮╰╯─━]", " ", result.stdout).split())
    for phase in (2, 3, 4, 5, 6):
        assert f"tarmac deploy --phase {phase}" in flat


def test_cli_deploy_run_prompts_and_yes(sample_config_dir, monkeypatch):
    from unittest.mock import MagicMock

    mock_session_mgr = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)

    # When user cancels prompt (input 'n')
    result_cancel = runner.invoke(
        app,
        ["deploy", "--config-dir", str(sample_config_dir), "--phase", "1"],
        input="n\n",
    )
    assert result_cancel.exit_code == 0
    assert "Deployment cancelled by user" in result_cancel.stdout

    # With --yes flag and mocked phase 1
    mock_org_service = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: mock_org_service)
    monkeypatch.setattr("tarmac.cli.deploy_phases.OrganizationService", lambda sm: mock_org_service)

    result_yes = runner.invoke(
        app,
        ["deploy", "--config-dir", str(sample_config_dir), "--phase", "1", "--yes"],
    )
    assert result_yes.exit_code == 0
    assert "Deployment complete." in result_yes.stdout


def test_cli_global_profile(monkeypatch):
    import os
    from unittest.mock import MagicMock

    from botocore.exceptions import ClientError

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {
        "Account": "123",
        "Arn": "arn:aws:iam::123:root",
    }
    mock_org = MagicMock()
    mock_org.describe_organization.side_effect = ClientError(
        {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "No org"}}, "DescribeOrganization"
    )
    mock_session_mgr.get_client.return_value = mock_org

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)

    result = runner.invoke(app, ["-p", "test-profile", "info"])
    assert result.exit_code == 0
    assert os.environ.get("AWS_PROFILE") == "test-profile"


def test_cli_info_shows_identity_store_and_portal(monkeypatch):
    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {
        "Account": "111111111111",
        "Arn": "arn:aws:iam::1:role/x",
    }
    mock_session_mgr.default_region = "us-east-1"
    mock_session_mgr.is_root_identity.return_value = False
    mock_sso = MagicMock()
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-test", "IdentityStoreId": "d-teststore"}]
    }
    mock_session_mgr.get_client.side_effect = lambda name, **kw: (
        mock_sso if name == "sso-admin" else MagicMock()
    )
    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)

    result = runner.invoke(app, ["info", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["identity_center_arn"] == "arn:aws:sso:::instance/ssoins-test"
    assert data["identity_store_id"] == "d-teststore"
    assert data["access_portal_url"] == "https://d-teststore.awsapps.com/start"


def test_cli_removed_commands_are_gone():
    for argv in (
        ["identity", "status"],
        ["ou", "list"],
        ["account", "anomaly-status"],
        ["account", "sync-tags"],
        ["account", "baseline"],
        ["account", "export"],
        ["deploy", "run"],
    ):
        assert runner.invoke(app, argv).exit_code != 0, argv


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


def test_cli_account_suspend_close_failure_exits_nonzero(monkeypatch, sample_config_dir):
    """A failed CloseAccount must not be reported as success or exit 0."""
    from tarmac.core.models import AccountSuspensionResult

    mock_service = MagicMock()
    mock_ou_service = MagicMock()
    mock_service.list_existing_accounts.return_value = {"OldDev": {"Id": "444444444444", "Name": "OldDev"}}
    mock_ou_service.get_root_id.return_value = "r-root"
    mock_ou_service.list_all_ous.return_value = {"Suspended": "ou-susp-999"}
    mock_service.suspend_account.return_value = AccountSuspensionResult(
        name="OldDev",
        account_id="444444444444",
        tags_updated=True,
        closed=False,
        status="CLOSE_FAILED",
        message="Account OldDev quarantined. Account closure failed: quota exceeded",
    )
    monkeypatch.setattr("tarmac.cli.account.AwsSessionManager", lambda **kw: MagicMock())
    monkeypatch.setattr("tarmac.cli.account.AccountService", lambda sm: mock_service)
    monkeypatch.setattr("tarmac.cli.account.OUService", lambda sm: mock_ou_service)

    result = runner.invoke(
        app,
        ["account", "suspend", "OldDev", "--close", "--config-dir", str(sample_config_dir), "--yes"],
    )
    assert result.exit_code == 1
    assert "quota exceeded" in result.output


def test_cli_preflight_execution(monkeypatch, sample_config_dir):
    """Verify the preflight command executes with table and JSON formatting."""
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

    result = runner.invoke(app, ["deploy", "--config-dir", str(sample_config_dir), "--yes"])
    assert result.exit_code == 1
    assert "Pre-flight found 1 blocking problem;" in result.output
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


def test_cli_status_detail_shows_drift(monkeypatch, sample_config_dir):
    from tarmac.services.drift import DriftItem, DriftReport
    from tarmac.services.status import LandingZoneStatus

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
                declared="OU: Test",
                live="Missing",
                status="MISSING",
                remediation="tarmac deploy --phase 4",
            ),
        ],
        has_drift=True,
        in_sync_count=1,
        drift_count=0,
        missing_count=1,
    )

    monkeypatch.setattr("tarmac.cli.main.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.main.DriftService", lambda sm: mock_drift_service)
    mock_ou_service = MagicMock()
    mock_ou_service.list_all_ous.return_value = {"Security": "ou-sec-1"}
    monkeypatch.setattr("tarmac.cli.main.OUService", lambda sm: mock_ou_service)
    mock_baseliner = MagicMock()
    mock_baseliner.get_anomaly_overview.return_value = (
        [{"MonitorName": "workload-prod-cost-anomaly-monitor", "MonitorType": "CUSTOM"}],
        [
            {
                "SubscriptionName": "workload-prod-anomaly-alerts",
                "Threshold": 100.0,
                "Frequency": "DAILY",
                "Subscribers": [{"Address": "alerts@example.com"}],
            }
        ],
    )
    monkeypatch.setattr("tarmac.cli.main.BaselineService", lambda sm: mock_baseliner)
    mock_status_service = MagicMock()
    mock_status_service.inspect.return_value = LandingZoneStatus(
        org_id="o-test12345",
        feature_set="ALL",
        ous_declared=1,
        ous_live=1,
        accounts_declared=1,
        accounts_live=0,
        cloudtrail_status="CREATE_COMPLETE",
        backend_status="CREATE_COMPLETE",
        sso_configured=True,
    )
    monkeypatch.setattr("tarmac.cli.main.StatusService", lambda sm: mock_status_service)

    plain = runner.invoke(app, ["status", "--config-dir", str(sample_config_dir)])
    assert plain.exit_code == 0
    assert "Landing Zone Drift Inspection" not in plain.stdout
    mock_drift_service.inspect_drift.assert_not_called()

    res = runner.invoke(app, ["status", "--detail", "--config-dir", str(sample_config_dir)])
    assert res.exit_code == 0
    assert "Landing Zone Drift Inspection" in res.stdout
    assert "Security" in res.stdout
    assert "dev-app" in res.stdout
    assert "MISSING" in res.stdout
    assert "ou-sec-1" in res.stdout
    assert "workload-prod-cost-anomaly-monitor" in res.stdout
    assert "workload-prod-anomaly-alerts" in res.stdout

    res_json = runner.invoke(app, ["status", "--detail", "--config-dir", str(sample_config_dir), "--json"])
    assert res_json.exit_code == 0
    payload = json.loads(res_json.stdout)
    assert payload["org_id"] == "o-test12345"
    assert payload["drift"]["has_drift"] is True
    assert payload["organizational_units"] == {"Security": "ou-sec-1"}
    assert payload["cost_anomaly"]["subscriptions"][0]["Threshold"] == 100.0

    res_strict = runner.invoke(app, ["status", "--config-dir", str(sample_config_dir), "--strict"])
    assert res_strict.exit_code == 1


def _fake_plan(phases):
    from tarmac.services.plan import DeploymentPlan, PhasePlan, PlanItem

    plan = DeploymentPlan(region="eu-west-1")
    for number in phases:
        plan.phases.append(
            PhasePlan(
                number,
                f"Title {number}",
                [PlanItem("stack", f"stack-{number}", "NO CHANGE")],
                [f"note {number}"],
            )
        )
    plan.phases[0].items.append(PlanItem("OU", "Workloads", "CREATE", "under Root"))
    return plan


def _patch_planner(monkeypatch):
    built: dict[str, object] = {}

    class FakePlanner:
        def __init__(self, *args, **kwargs):
            built["kwargs"] = kwargs

        def build(self, phases):
            built["phases"] = phases
            return _fake_plan(phases)

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: MagicMock())
    monkeypatch.setattr("tarmac.cli.deploy.Planner", FakePlanner)
    return built


def test_cli_deploy_dry_run_renders_every_phase(sample_config_dir, monkeypatch):
    built = _patch_planner(monkeypatch)
    result = runner.invoke(app, ["deploy", "--dry-run", "--config-dir", str(sample_config_dir)])
    assert result.exit_code == 0, result.output
    assert built["phases"] == [1, 2, 3, 4, 5, 6]
    for number in range(1, 7):
        assert f"Phase {number}: Title {number}" in result.stdout
    assert "Workloads" in result.stdout
    assert "Plan: 1 to create, 6 unchanged." in result.stdout


def test_cli_deploy_dry_run_single_phase_json(sample_config_dir, monkeypatch):
    built = _patch_planner(monkeypatch)
    result = runner.invoke(
        app, ["deploy", "--dry-run", "--phase", "4", "--json", "--config-dir", str(sample_config_dir)]
    )
    assert result.exit_code == 0, result.output
    assert built["phases"] == [4]
    data = json.loads(result.stdout)
    assert data["dry_run"] is True
    assert [p["phase"] for p in data["phases"]] == [4]
    assert data["summary"] == {"NO CHANGE": 1, "CREATE": 1}


def test_cli_deploy_account_filter_needs_phase_4(sample_config_dir):
    result = runner.invoke(
        app, ["deploy", "--dry-run", "--account", "deployment", "--config-dir", str(sample_config_dir)]
    )
    assert result.exit_code == 2
    assert "--phase 4" in result.output


def test_cli_deploy_account_filter_rejects_undeclared_accounts(sample_config_dir):
    result = runner.invoke(
        app,
        ["deploy", "--dry-run", "--phase", "4", "-a", "nope", "--config-dir", str(sample_config_dir)],
    )
    assert result.exit_code == 2
    assert "Not declared in accounts.yaml: nope" in result.output


def test_cli_deploy_skip_preflight_only_for_a_full_run(sample_config_dir):
    result = runner.invoke(
        app,
        ["deploy", "--yes", "--phase", "2", "--skip-preflight", "--config-dir", str(sample_config_dir)],
    )
    assert result.exit_code == 2


def test_cli_deploy_phase_4_aborts_on_failed_account_provisioning(sample_config_dir, monkeypatch):
    """Verify Phase 4 exits non-zero and does not record phase completion when an account fails to provision."""
    from unittest.mock import MagicMock

    from tarmac.core.models import AccountProvisionResult

    mock_session_mgr = MagicMock()
    mock_session_mgr.get_caller_identity.return_value = {"Account": "111111111111"}
    mock_ou_service = MagicMock()
    mock_ou_service.list_all_ous.return_value = {
        "Security": "ou-sec",
        "Infrastructure": "ou-inf",
        "Deployments": "ou-dep",
        "Prod": "ou-prd",
        "Test": "ou-tst",
        "Suspended": "ou-sus",
    }
    mock_acct_service = MagicMock()
    mock_acct_service.provision_accounts.return_value = [
        AccountProvisionResult(
            name="log-archive",
            email="logs@example.com",
            account_id="",
            ou_name="Security",
            ou_id="ou-sec",
            action_taken="FAILED",
            status="FAILED",
        )
    ]
    mock_org_service = MagicMock()

    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mock_session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy_phases.OUService", lambda sm: mock_ou_service)
    monkeypatch.setattr("tarmac.cli.deploy_phases.AccountService", lambda sm: mock_acct_service)
    monkeypatch.setattr("tarmac.cli.deploy_phases.BaselineService", lambda sm: MagicMock())
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: mock_org_service)
    monkeypatch.setattr("tarmac.cli.deploy_phases.OrganizationService", lambda sm: mock_org_service)

    result = runner.invoke(
        app,
        ["deploy", "--config-dir", str(sample_config_dir), "--phase", "4", "--yes"],
    )
    assert result.exit_code != 0
    mock_org_service.record_phase_completed.assert_not_called()
    mock_acct_service.provision_accounts.assert_called_once()


def test_deploy_hardening_stacks_skips_log_archive_when_requested(sample_config_dir):
    """Verify _deploy_hardening_stacks skips log-archive-hardening when skip_log_archive_hardening=True."""
    from unittest.mock import MagicMock

    from tarmac.cli.deploy_phases import _deploy_hardening_stacks
    from tarmac.core.config_loader import load_all_configs
    from tarmac.core.models import StackDeployReport

    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None

    mock_session_mgr = MagicMock()
    mock_cfn_service = MagicMock()
    deployed: list[str] = []

    def record_deploy(cfn_client, stack_name, *args, **kwargs):
        deployed.append(stack_name)
        return StackDeployReport(action="CREATED", outputs={})

    mock_cfn_service.deploy_stack.side_effect = record_deploy
    accts = {"Log-Archive": "888888888888", "Audit": "777777777777"}

    _deploy_hardening_stacks(
        mock_cfn_service,
        mock_session_mgr,
        bundle,
        "eu-west-1",
        sample_config_dir.parent,
        "o-test123",
        accts,
        skip_log_archive_hardening=True,
    )

    assert len(deployed) == 1
    assert "audit-account-hardening" in deployed[0]
    assert all("log-archive-hardening" not in s for s in deployed)


def test_deploy_hardening_stacks_delegates_cloudtrail_to_audit(sample_config_dir):
    from unittest.mock import MagicMock, patch

    from tarmac.cli.deploy_phases import _deploy_hardening_stacks
    from tarmac.core.config_loader import load_all_configs

    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None

    with patch("tarmac.cli.deploy_phases.OrganizationService") as org:
        _deploy_hardening_stacks(
            MagicMock(),
            MagicMock(),
            bundle,
            "eu-west-1",
            sample_config_dir.parent,
            "o-test123",
            {"Audit": "777777777777"},
            skip_log_archive_hardening=True,
        )

    register = org.return_value.register_service_delegated_administrators
    assert register.call_args.args == (
        "777777777777",
        ["config-multiaccountsetup.amazonaws.com", "config.amazonaws.com", "cloudtrail.amazonaws.com"],
    )
