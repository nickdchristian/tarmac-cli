"""Phase 1 must not report success when the management account's default VPC cleanup failed."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from tarmac.cli import deploy_phases
from tarmac.cli.main import app
from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.exceptions import GovernanceError
from tarmac.core.models import VpcCleanupReport
from tarmac.services.scaffold import scaffold_project


@pytest.fixture
def bundle(tmp_path: Path) -> ConfigBundle:
    scaffold_project(tmp_path)
    loaded, errors = load_all_configs(tmp_path)
    assert loaded is not None
    assert not errors
    assert loaded.org.organization.delete_default_vpc
    return loaded


def _failed() -> VpcCleanupReport:
    return VpcCleanupReport(
        region="us-east-1", skipped=True, error=True, message="Error cleaning VPC: AccessDenied"
    )


def _session() -> MagicMock:
    session = MagicMock()
    session.get_caller_identity.return_value = {"Account": "111111111111"}
    return session


def _patch_services(monkeypatch: pytest.MonkeyPatch, baseliner: MagicMock, org_service: MagicMock) -> None:
    monkeypatch.setattr(deploy_phases, "BaselineService", lambda *a, **k: baseliner)
    monkeypatch.setattr(deploy_phases, "OrganizationService", lambda *a, **k: org_service)


def test_failed_cleanup_stops_phase_1_and_records_no_milestone(bundle: ConfigBundle, monkeypatch):
    baseliner, org_service = MagicMock(), MagicMock()
    baseliner.cleanup_default_vpcs.return_value = [_failed()]
    _patch_services(monkeypatch, baseliner, org_service)

    with pytest.raises(GovernanceError, match="default VPC cleanup failed"):
        deploy_phases._run_phase_1_org(_session(), bundle, dry_run=False)

    baseliner.mark_account_baselined.assert_not_called()
    org_service.record_phase_completed.assert_not_called()


def test_clean_run_still_completes_phase_1(bundle: ConfigBundle, monkeypatch):
    baseliner, org_service = MagicMock(), MagicMock()
    baseliner.cleanup_default_vpcs.return_value = [VpcCleanupReport(region="us-east-1", skipped=True)]
    _patch_services(monkeypatch, baseliner, org_service)

    deploy_phases._run_phase_1_org(_session(), bundle, dry_run=False)

    baseliner.mark_account_baselined.assert_called_once_with("111111111111")
    org_service.record_phase_completed.assert_called_once_with("111111111111", "org")


def test_deploy_phase_1_exits_nonzero_when_cleanup_fails(tmp_path: Path, monkeypatch):
    scaffold_project(tmp_path)
    session = _session()
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: session)
    org_service = MagicMock()
    org_service.ensure_organization.return_value = "o-abc"
    org_service.get_completed_phases.return_value = set()
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda s: org_service)
    baseliner = MagicMock()
    baseliner.cleanup_default_vpcs.return_value = [_failed()]
    _patch_services(monkeypatch, baseliner, org_service)

    result = CliRunner().invoke(app, ["deploy", "run", "--phase", "1", "--yes", "-c", str(tmp_path)])

    assert result.exit_code == 1
    assert "AccessDenied" in result.output
    org_service.record_phase_completed.assert_not_called()
