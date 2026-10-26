"""`tarmac plan` is `tarmac deploy --dry-run`."""

from pathlib import Path
from unittest.mock import MagicMock

from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli.main import app

runner = CliRunner()


def test_plan_is_deploy_dry_run(tmp_path: Path, monkeypatch):
    """`tarmac plan` and `tarmac deploy --dry-run` are one code path, so their plans can't drift apart."""
    deploy = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy.deploy_command", deploy)
    cfg = make_config(tmp_path, None)

    res = runner.invoke(app, ["plan", "--phase", "3", "--json", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    kwargs = deploy.call_args.kwargs
    assert kwargs["dry_run"] is True
    assert (kwargs["phase"], kwargs["json_output"], kwargs["yes"]) == (3, True, False)
