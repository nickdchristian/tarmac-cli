"""Lifecycle regressions: fresh account -> deploy -> teardown -> redeploy ("start over")."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tarmac.cli import deploy_phases
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_loader import load_all_configs
from tarmac.core.exceptions import AccountProvisioningError, GovernanceError
from tarmac.core.models import (
    AccountProvisionResult,
    AnomalyReport,
    BaselineReport,
    BudgetReport,
    SecurityServiceReport,
    VpcCleanupReport,
)
from tarmac.services.cloudformation import CloudFormationService


def _ce(code: str, op: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


@pytest.fixture
def bundle(sample_config_dir: Path):
    b, errors = load_all_configs(sample_config_dir)
    assert b is not None, errors
    return b


# brand-new accounts: OrganizationAccountAccessRole propagates asynchronously


def _manager_with_sts(sts: MagicMock) -> AwsSessionManager:
    with patch("tarmac.core.aws_client.boto3.Session") as session_cls:
        session_cls.return_value.client.return_value = sts
        mgr = AwsSessionManager(region_name="us-east-1")
    mgr._sts_client = sts
    return mgr


_CREDS = {
    "Credentials": {
        "AccessKeyId": "a",
        "SecretAccessKey": "b",
        "SessionToken": "c",
        "Expiration": __import__("datetime").datetime(2099, 1, 1, tzinfo=__import__("datetime").UTC),
    }
}


def test_assume_role_retries_access_denied_while_new_account_role_propagates():
    sts = MagicMock()
    sts.assume_role.side_effect = [_ce("AccessDenied"), _ce("AccessDenied"), _CREDS]
    mgr = _manager_with_sts(sts)

    with patch("tarmac.core.aws_client.time.sleep") as sleep:
        mgr.get_assumed_session("222222222222")

    assert sts.assume_role.call_count == 3
    assert sleep.call_count == 2


def test_assume_role_does_not_retry_other_errors():
    sts = MagicMock()
    sts.assume_role.side_effect = _ce("MalformedPolicyDocument")
    mgr = _manager_with_sts(sts)

    with patch("tarmac.core.aws_client.time.sleep") as sleep, pytest.raises(Exception, match="assume role"):
        mgr.get_assumed_session("222222222222")

    assert sts.assume_role.call_count == 1
    sleep.assert_not_called()


def test_assume_role_gives_up_when_access_stays_denied():
    sts = MagicMock()
    sts.assume_role.side_effect = _ce("AccessDenied")
    mgr = _manager_with_sts(sts)
    mgr.ASSUME_ROLE_RETRY_SECONDS = 0.0

    with patch("tarmac.core.aws_client.time.sleep"), pytest.raises(Exception, match="assume role"):
        mgr.get_assumed_session("222222222222")

    assert sts.assume_role.call_count == 1


# redeploy after a failed teardown: DELETE_FAILED / CREATE_FAILED stacks


@pytest.mark.parametrize("status", ["DELETE_FAILED", "CREATE_FAILED", "ROLLBACK_COMPLETE"])
def test_deploy_stack_recreates_stacks_stuck_in_unusable_states(status):
    svc = CloudFormationService(MagicMock())
    cfn = MagicMock()
    svc._get_stack_status = MagicMock(return_value=status)  # type: ignore[method-assign]
    svc._delete_broken_stack = MagicMock()  # type: ignore[method-assign]
    svc._execute_deployment = MagicMock(return_value="CREATED")  # type: ignore[method-assign]
    svc._fetch_stack_outputs = MagicMock(return_value={})  # type: ignore[method-assign]

    report = svc.deploy_stack(cfn, "s", template_body="{}")

    svc._delete_broken_stack.assert_called_once_with(cfn, "s")
    assert svc._execute_deployment.call_args.args[-1] is False  # stack_exists=False -> create
    assert report.action == "CREATED"


def test_deploy_stack_updates_healthy_stacks_in_place():
    svc = CloudFormationService(MagicMock())
    svc._get_stack_status = MagicMock(return_value="CREATE_COMPLETE")  # type: ignore[method-assign]
    svc._delete_broken_stack = MagicMock()  # type: ignore[method-assign]
    svc._execute_deployment = MagicMock(return_value="UPDATED")  # type: ignore[method-assign]
    svc._fetch_stack_outputs = MagicMock(return_value={})  # type: ignore[method-assign]

    svc.deploy_stack(MagicMock(), "s", template_body="{}")

    svc._delete_broken_stack.assert_not_called()


# closed accounts cannot be re-created: fail clearly instead of assuming into them


def _result(name: str, status: str, account_id: str = "999999999999") -> AccountProvisionResult:
    return AccountProvisionResult(
        name=name,
        email=f"{name}@example.com",
        account_id=account_id,
        ou_name="Security",
        ou_id="ou-1",
        action_taken="SUSPENDED_SKIPPED" if status == "SKIPPED" else "CREATED",
        status=status,
    )


def test_phase_3_fails_clearly_when_log_archive_account_is_closed(bundle, tmp_path):
    mgr = MagicMock()
    mgr.get_client.return_value.describe_organization.return_value = {"Organization": {"Id": "o-abc1234567"}}
    accounts = MagicMock()
    accounts.provision_accounts.return_value = [_result("log-archive", "SKIPPED")]

    with (
        patch("tarmac.cli.deploy_phases.get_active_account_id_map", return_value={}),
        patch("tarmac.cli.deploy_phases.AccountService", return_value=accounts),
        patch("tarmac.cli.deploy_phases.OUService", return_value=_ous(bundle)),
        patch("tarmac.cli.deploy_phases.CloudFormationService") as cfn,
        pytest.raises(GovernanceError, match="closed/suspended"),
    ):
        deploy_phases._run_phase_3_cloudtrail(mgr, bundle, "us-east-1", tmp_path, dry_run=False)

    # It must not go on to assume a role into the closed account or deploy any stack.
    mgr.get_member_client.assert_not_called()
    cfn.return_value.deploy_stack.assert_not_called()


def _ous(bundle) -> MagicMock:
    """An OUService whose live OU tree already holds every OU the declared accounts need."""
    ou_service = MagicMock()
    ou_service.list_all_ous.return_value = {a.ou: f"ou-{a.ou.lower()}" for a in bundle.accounts.accounts}
    return ou_service


def _phase_4_mocks(results: list[AccountProvisionResult], baseline_reports: dict[str, BaselineReport]):
    accounts = MagicMock()
    accounts.provision_accounts.return_value = results
    accounts.plan.return_value = []
    baseliner = MagicMock()
    baseliner.baseline_account.side_effect = lambda acct_def, *a, **k: baseline_reports[acct_def.name]
    org = MagicMock()
    return accounts, baseliner, org


def test_phase_4_skips_baselining_closed_accounts_and_warns(bundle, tmp_path):
    names = [a.name for a in bundle.accounts.accounts]
    results = [_result(n, "SUCCEEDED", f"{i:012d}") for i, n in enumerate(names[:-1], start=1)]
    results.append(_result(names[-1], "SKIPPED"))
    reports = {n: BaselineReport(account_name=n, account_id="x") for n in names}
    accounts, baseliner, org = _phase_4_mocks(results, reports)
    mgr = MagicMock()
    mgr.get_caller_identity.return_value = {"Account": "111111111111"}

    with (
        patch("tarmac.cli.deploy_phases.OUService", return_value=_ous(bundle)),
        patch("tarmac.cli.deploy_phases.AccountService", return_value=accounts),
        patch("tarmac.cli.deploy_phases.BaselineService", return_value=baseliner),
        patch("tarmac.cli.deploy_phases.OrganizationService", return_value=org),
        patch("tarmac.cli.deploy_phases.print_warning") as warn,
    ):
        deploy_phases._run_phase_4_accounts(mgr, bundle, tmp_path, dry_run=False)

    baselined = {c.args[0].name for c in baseliner.baseline_account.call_args_list}
    assert names[-1] not in baselined
    assert baselined == set(names[:-1])
    assert any("closed/suspended" in str(c.args[0]) for c in warn.call_args_list)


@pytest.mark.parametrize(
    "bad_report",
    [
        BaselineReport(
            account_name="a",
            account_id="1",
            budget_report=BudgetReport("a", "1", "b", 10.0, 80.0, "FAILED", "SNS denied"),
        ),
        BaselineReport(
            account_name="a",
            account_id="1",
            anomaly_report=AnomalyReport("a", "1", "m", 5.0, "FAILED", "CE denied"),
        ),
        BaselineReport(
            account_name="a",
            account_id="1",
            vpc_reports=[VpcCleanupReport(region="us-east-1", error=True, message="boom")],
        ),
    ],
)
def test_phase_4_does_not_report_success_when_a_baseline_step_failed(bundle, tmp_path, bad_report):
    names = [a.name for a in bundle.accounts.accounts]
    results = [_result(n, "SUCCEEDED", f"{i:012d}") for i, n in enumerate(names, start=1)]
    reports = {n: BaselineReport(account_name=n, account_id="x") for n in names}
    reports[names[0]] = bad_report
    accounts, baseliner, org = _phase_4_mocks(results, reports)
    mgr = MagicMock()
    mgr.get_caller_identity.return_value = {"Account": "111111111111"}

    with (
        patch("tarmac.cli.deploy_phases.OUService", return_value=_ous(bundle)),
        patch("tarmac.cli.deploy_phases.AccountService", return_value=accounts),
        patch("tarmac.cli.deploy_phases.BaselineService", return_value=baseliner),
        patch("tarmac.cli.deploy_phases.OrganizationService", return_value=org),
        pytest.raises(AccountProvisioningError, match="failed baseline step"),
    ):
        deploy_phases._run_phase_4_accounts(mgr, bundle, tmp_path, dry_run=False)

    org.record_phase_completed.assert_not_called()


# phase 5: security-service failures and missing accounts are not silent


def test_security_delegation_failure_fails_the_phase(bundle):
    bundle.org.security_services.guardduty.enabled = True
    sec = MagicMock()
    sec.configure_security_services.return_value = [
        SecurityServiceReport("GuardDuty", "audit", "ENABLED", message="ok"),
        SecurityServiceReport("SecurityHub", "audit", "FAILED", message="not subscribed"),
    ]
    with (
        patch("tarmac.cli.deploy_phases.SecurityServicesService", return_value=sec),
        pytest.raises(GovernanceError, match="security service delegation") as exc,
    ):
        deploy_phases._delegate_security_services(MagicMock(), bundle, "us-east-1", {}, dry_run=False)

    assert "not subscribed" in str(exc.value.details if hasattr(exc.value, "details") else exc.value)


def test_phase_5_warns_when_backend_and_audit_accounts_are_missing(bundle, tmp_path):
    mgr = MagicMock()
    mgr.get_client.return_value.describe_organization.return_value = {"Organization": {"Id": "o-abc1234567"}}
    mgr.get_caller_identity.return_value = {"Account": "111111111111"}

    with (
        patch("tarmac.cli.deploy_phases.get_active_account_id_map", return_value={}),
        patch("tarmac.cli.deploy_phases.CloudFormationService"),
        patch("tarmac.cli.deploy_phases.OrganizationService"),
        patch("tarmac.cli.deploy_phases.SecurityServicesService") as sec,
        patch("tarmac.cli.deploy_phases.print_warning") as warn,
    ):
        sec.return_value.configure_security_services.return_value = []
        deploy_phases._run_phase_5_hardening(mgr, bundle, "us-east-1", tmp_path, dry_run=False)

    messages = " ".join(str(c.args[0]) for c in warn.call_args_list)
    assert "Backend account" in messages
    assert "Audit account" in messages


# teardown output sets expectations for "start over"


def test_full_teardown_lists_what_it_does_not_remove(tmp_path):
    from typer.testing import CliRunner

    from tarmac.cli.deploy import app
    from tarmac.services.scaffold import scaffold_project
    from tarmac.services.teardown import TeardownItemReport, TeardownReport

    scaffold_project(tmp_path)
    report = TeardownReport(
        items=[TeardownItemReport("CloudFormation Stack", "s", "Management", "1", "DELETED")],
        status="COMPLETED",
    )
    with patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=report):
        full = CliRunner().invoke(app, ["destroy", "-c", str(tmp_path), "-y"])
        one_phase = CliRunner().invoke(app, ["destroy", "-c", str(tmp_path), "-y", "--phase", "4"])

    assert full.exit_code == 0
    assert "Not removed by teardown" in full.stdout
    assert "GuardDuty" in full.stdout
    assert "Not removed by teardown" not in one_phase.stdout


def test_phase_5_stops_before_audit_stack_when_delegated_admin_registration_fails(bundle, tmp_path):
    org_service = MagicMock()
    org_service.register_service_delegated_administrators.side_effect = GovernanceError(
        "Could not register account", details="config.amazonaws.com: denied"
    )
    cfn = MagicMock()
    mgr = MagicMock()
    accounts = {bundle.get_audit_account_name() or "audit": "444455556666"}

    with (
        patch("tarmac.cli.deploy_phases.OrganizationService", return_value=org_service),
        patch("tarmac.cli.deploy_phases._deploy_log_archive_hardening_stack"),
        pytest.raises(GovernanceError, match="Could not register"),
    ):
        deploy_phases._deploy_hardening_stacks(
            cfn,
            mgr,
            bundle,
            "us-east-1",
            tmp_path,
            "o-abc1234567",
            accounts,
            dry_run=False,
            skip_log_archive_hardening=True,
        )

    cfn.deploy_stack.assert_not_called()


def test_assumed_session_credentials_refresh_before_expiry():
    import datetime as dt

    def creds(key: str, expires: dt.datetime) -> dict:
        return {
            "Credentials": {
                "AccessKeyId": key,
                "SecretAccessKey": "s",
                "SessionToken": "t",
                "Expiration": expires,
            }
        }

    soon = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=30)
    later = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
    sts = MagicMock()
    sts.assume_role.side_effect = [creds("FIRST", soon), creds("SECOND", later)]
    mgr = _manager_with_sts(sts)

    session = mgr.get_assumed_session("222222222222")
    credentials = session.get_credentials()
    assert credentials is not None
    frozen = credentials.get_frozen_credentials()

    assert frozen.access_key == "SECOND"
    assert sts.assume_role.call_count == 2
    assert mgr.get_assumed_session("222222222222") is session


def test_phase_4_stops_when_an_ou_does_not_exist_yet(bundle, tmp_path):
    """Phase 4 must not create OUs: only phase 2 does, because it also attaches their SCPs."""
    ou_service = MagicMock()
    ou_service.list_all_ous.return_value = {}
    accounts = MagicMock()

    with (
        patch("tarmac.cli.deploy_phases.OUService", return_value=ou_service),
        patch("tarmac.cli.deploy_phases.AccountService", return_value=accounts),
        patch("tarmac.cli.deploy_phases.BaselineService"),
        pytest.raises(GovernanceError, match="do not exist yet"),
    ):
        deploy_phases._run_phase_4_accounts(MagicMock(), bundle, tmp_path, dry_run=False)

    ou_service.sync_ou_structure.assert_not_called()
    accounts.provision_accounts.assert_not_called()


def test_phase_4_applies_organization_tags_to_accounts(bundle, tmp_path):
    names = [a.name for a in bundle.accounts.accounts]
    results = [_result(n, "SUCCEEDED", f"{i:012d}") for i, n in enumerate(names, start=1)]
    reports = {n: BaselineReport(account_name=n, account_id="x") for n in names}
    accounts, baseliner, org = _phase_4_mocks(results, reports)
    mgr = MagicMock()
    mgr.get_caller_identity.return_value = {"Account": "111111111111"}

    with (
        patch("tarmac.cli.deploy_phases.OUService", return_value=_ous(bundle)),
        patch("tarmac.cli.deploy_phases.AccountService", return_value=accounts),
        patch("tarmac.cli.deploy_phases.BaselineService", return_value=baseliner),
        patch("tarmac.cli.deploy_phases.OrganizationService", return_value=org),
    ):
        deploy_phases._run_phase_4_accounts(mgr, bundle, tmp_path, dry_run=False)

    assert accounts.provision_accounts.call_args.kwargs["org_tags"] == bundle.get_organization_tags()
