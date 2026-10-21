"""CLI-level tests for `tarmac ou` (services patched, exit codes and output asserted)."""

from pathlib import Path
from unittest.mock import patch

from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.config_loader import load_all_configs
from tarmac.core.exceptions import GovernanceError

runner = CliRunner()


def test_ou_list_uses_the_configured_region_and_reports_failures(tmp_path: Path):
    cfg = make_config(tmp_path, None)
    bundle, _ = load_all_configs(cfg)
    assert bundle is not None
    with patch("tarmac.cli.ou.AwsSessionManager") as mgr_cls, patch("tarmac.cli.ou.OUService") as svc_cls:
        service = svc_cls.return_value
        service.get_root_id.return_value = "r-root"
        service.list_all_ous.return_value = {"Security": "ou-1"}
        ok = runner.invoke(app, ["ou", "list", "-c", str(cfg)])

        assert ok.exit_code == 0, ok.output
        assert "r-root" in ok.output
        assert "ou-1" in ok.output
        assert mgr_cls.call_args.kwargs["region_name"] == bundle.org.organization.primary_region

        service.get_root_id.side_effect = GovernanceError("no root")
        bad = runner.invoke(app, ["ou", "list", "-c", str(cfg)])
        assert bad.exit_code == 1
        assert "List OUs Failed" in bad.output
