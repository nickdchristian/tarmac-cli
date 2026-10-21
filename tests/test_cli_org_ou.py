"""CLI-level tests for `tarmac org` and `tarmac ou` commands (services patched, exit codes and output asserted)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli import org as org_cli
from tarmac.cli import ou as ou_cli
from tarmac.core.exceptions import GovernanceError
from tarmac.core.models import OUSyncReport, VpcCleanupReport

runner = CliRunner()


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    return make_config(tmp_path, None)


@pytest.fixture
def org_mocks():
    with (
        patch("tarmac.cli.org.AwsSessionManager") as mgr_cls,
        patch("tarmac.cli.org.OrganizationService") as svc_cls,
        patch("tarmac.cli.org.BaselineService") as baseliner_cls,
    ):
        mgr_cls.return_value.get_caller_identity.return_value = {"Account": "111111111111"}
        yield mgr_cls.return_value, svc_cls.return_value, baseliner_cls.return_value


def test_bootstrap_runs_every_step_and_reports(cfg: Path, org_mocks):
    _, svc, baseliner = org_mocks
    svc.ensure_organization.return_value = "o-abc123"
    svc.enable_trusted_services.return_value = ["a", "b"]
    svc.activate_cost_allocation_tags.return_value = ["Project"]
    baseliner.cleanup_default_vpcs.return_value = [
        VpcCleanupReport(region="eu-west-1", vpc_id="vpc-1", deleted_vpc=True)
    ]

    res = runner.invoke(org_cli.app, ["bootstrap", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert "o-abc123" in res.output
    assert "Enabled 2 trusted services" in res.output
    svc.set_account_contacts.assert_called_once()
    baseliner.cleanup_default_vpcs.assert_called_once_with("111111111111", "management", regions=None)


def test_bootstrap_governance_error_exits_1(cfg: Path, org_mocks):
    _, svc, _ = org_mocks
    svc.ensure_organization.side_effect = GovernanceError("boom", details="denied")

    res = runner.invoke(org_cli.app, ["bootstrap", "-c", str(cfg)])

    assert res.exit_code == 1
    assert "Bootstrap Failed" in res.output
    svc.set_account_contacts.assert_not_called()


def test_cleanup_vpc_dry_run_reports_candidates(cfg: Path, org_mocks):
    _, _, baseliner = org_mocks
    baseliner.cleanup_default_vpcs.return_value = [
        VpcCleanupReport(region="eu-west-1", vpc_id="vpc-9", skipped=True, message="dry run"),
        VpcCleanupReport(region="us-east-1", skipped=True, message="No default VPC"),
    ]

    res = runner.invoke(org_cli.app, ["cleanup-vpc", "--dry-run", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert "Would delete default VPC" in res.output
    assert "vpc-9" in res.output
    assert baseliner.cleanup_default_vpcs.call_args.kwargs["dry_run"] is True


def test_cleanup_vpc_clean_account(cfg: Path, org_mocks):
    _, _, baseliner = org_mocks
    baseliner.cleanup_default_vpcs.return_value = [
        VpcCleanupReport(region="eu-west-1", skipped=True, message="No default VPC")
    ]
    res = runner.invoke(org_cli.app, ["cleanup-vpc", "-c", str(cfg)])
    assert res.exit_code == 0
    assert "Management Account is clean" in res.output


def test_cleanup_vpc_without_account_id_exits_1(cfg: Path, org_mocks):
    mgr, _, baseliner = org_mocks
    mgr.get_caller_identity.return_value = {}

    res = runner.invoke(org_cli.app, ["cleanup-vpc", "-c", str(cfg)])

    assert res.exit_code == 1
    baseliner.cleanup_default_vpcs.assert_not_called()


def test_contacts_success_and_failure(cfg: Path, org_mocks):
    _, svc, _ = org_mocks
    svc.set_account_contacts.return_value = ["BILLING", "OPERATIONS", "SECURITY"]
    ok = runner.invoke(org_cli.app, ["contacts", "-c", str(cfg)])
    assert ok.exit_code == 0
    assert "BILLING, OPERATIONS, SECURITY" in ok.output

    svc.set_account_contacts.side_effect = GovernanceError("Failed to set BILLING contact")
    bad = runner.invoke(org_cli.app, ["contacts", "-c", str(cfg)])
    assert bad.exit_code == 1
    assert "Contacts Failed" in bad.output


def test_root_access_prints_enabled_and_skipped_features(cfg: Path, org_mocks):
    _, svc, _ = org_mocks
    svc.configure_root_access.return_value = {
        "iam_trusted_access": True,
        "root_sessions": False,
        "delegated_admin": False,
    }
    svc.last_error = {"root_sessions": "AccessDenied"}

    with patch("tarmac.cli.org.get_active_account_id_map", return_value={"audit": "222222222222"}):
        res = runner.invoke(org_cli.app, ["root-access", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert "Enabled Iam Trusted Access" in res.output
    assert "Root Sessions: AccessDenied" in res.output
    assert "Delegated Admin: Skipped or disabled" in res.output
    assert svc.configure_root_access.call_args.kwargs["management_account_id"] == "111111111111"


def test_scp_apply_uses_cloudformation_when_scp_stack_is_active(cfg: Path):
    with (
        patch("tarmac.cli.org.AwsSessionManager") as mgr_cls,
        patch("tarmac.cli.org.OUService") as ou_cls,
        patch("tarmac.cli.org.SCPService") as scp_cls,
    ):
        cfn = MagicMock()
        cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "UPDATE_COMPLETE"}]}
        mgr_cls.return_value.get_client.return_value = cfn
        ou_cls.return_value.get_root_id.return_value = "r-root"
        ou_cls.return_value.list_all_ous.return_value = {}
        scp_cls.return_value.reconcile_via_cloudformation.return_value = []

        res = runner.invoke(org_cli.app, ["scp", "apply", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    scp_cls.return_value.reconcile_via_cloudformation.assert_called_once()
    scp_cls.return_value.reconcile_all.assert_not_called()


def test_root_access_governance_error_exits_1(cfg: Path, org_mocks):
    _, svc, _ = org_mocks
    svc.configure_root_access.side_effect = GovernanceError("nope")
    with patch("tarmac.cli.org.get_active_account_id_map", return_value={}):
        res = runner.invoke(org_cli.app, ["root-access", "-c", str(cfg)])
    assert res.exit_code == 1
    assert "Root Access Failed" in res.output


def test_activate_cost_tags_paths(cfg: Path, org_mocks):
    _, svc, _ = org_mocks
    with patch("tarmac.core.config_loader.ConfigBundle.get_cost_allocation_tags", return_value=[]):
        none_cfg = runner.invoke(org_cli.app, ["activate-cost-tags", "-c", str(cfg)])
    assert none_cfg.exit_code == 0
    assert "No cost allocation tags configured" in none_cfg.output
    svc.activate_cost_allocation_tags.assert_not_called()

    with patch("tarmac.core.config_loader.ConfigBundle.get_cost_allocation_tags", return_value=["Project"]):
        svc.activate_cost_allocation_tags.return_value = ["Project"]
        done = runner.invoke(org_cli.app, ["activate-cost-tags", "-c", str(cfg)])
        assert "Activated 1 Cost Allocation Tag" in done.output

        svc.activate_cost_allocation_tags.return_value = []
        nothing = runner.invoke(org_cli.app, ["activate-cost-tags", "-c", str(cfg)])
        assert "No inactive cost allocation tags" in nothing.output

        svc.activate_cost_allocation_tags.side_effect = GovernanceError("ce down")
        failed = runner.invoke(org_cli.app, ["activate-cost-tags", "-c", str(cfg)])
        assert failed.exit_code == 1


@pytest.fixture
def ou_service():
    with patch("tarmac.cli.ou.AwsSessionManager"), patch("tarmac.cli.ou.OUService") as svc_cls:
        yield svc_cls.return_value


def test_ou_sync_marks_created_and_existing(cfg: Path, ou_service: MagicMock):
    ou_service.sync_ou_structure.return_value = OUSyncReport(
        synced_ous={"Security": "ou-1", "Workloads": "ou-2"},
        created_ous=["Security"],
        existing_ous=["Workloads"],
    )

    res = runner.invoke(ou_cli.app, ["sync", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert "CREATED" in res.output
    assert "EXISTING" in res.output
    assert "ou-2" in res.output


def test_ou_sync_governance_error_exits_1(cfg: Path, ou_service: MagicMock):
    ou_service.sync_ou_structure.side_effect = GovernanceError("cannot create")
    res = runner.invoke(ou_cli.app, ["sync", "-c", str(cfg)])
    assert res.exit_code == 1
    assert "OU Sync Failed" in res.output


def test_ou_list_and_failure(ou_service: MagicMock):
    ou_service.get_root_id.return_value = "r-root"
    ou_service.list_all_ous.return_value = {"Security": "ou-1"}
    ok = runner.invoke(ou_cli.app, ["list"])
    assert ok.exit_code == 0
    assert "r-root" in ok.output
    assert "ou-1" in ok.output

    ou_service.get_root_id.side_effect = GovernanceError("no root")
    bad = runner.invoke(ou_cli.app, ["list"])
    assert bad.exit_code == 1
    assert "List OUs Failed" in bad.output
