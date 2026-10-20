"""Guardrails on destructive CLI commands: consent, production lock, exit codes and phase validation."""

from pathlib import Path
from unittest.mock import patch

import pytest
from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli.deploy import _is_production_tagged, app
from tarmac.services.teardown import (
    TeardownItemReport,
    TeardownReport,
)

runner = CliRunner()


def _ok_report() -> TeardownReport:
    return TeardownReport(items=[], status="COMPLETED")


@pytest.mark.parametrize("command", ["destroy", "teardown"])
def test_teardown_json_without_yes_is_refused(tmp_path: Path, command: str):
    cfg = make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_all,
    ):
        res = runner.invoke(app, [command, "--json", "-c", str(cfg)])
    assert res.exit_code == 2
    mock_all.assert_not_called()


def test_teardown_json_with_yes_or_dry_run_is_allowed(tmp_path: Path):
    cfg = make_config(tmp_path, None)
    for extra in (["--yes"], ["--dry-run"]):
        with (
            patch("tarmac.cli.deploy.AwsSessionManager"),
            patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=_ok_report()),
        ):
            res = runner.invoke(app, ["destroy", "--json", "-c", str(cfg), *extra])
        assert res.exit_code == 0, res.output


def test_run_json_without_yes_is_refused_for_live_deploy(tmp_path: Path):
    cfg = make_config(tmp_path, None)
    with patch("tarmac.cli.deploy.AwsSessionManager"), patch("tarmac.cli.deploy._run_phase_1_org") as phase:
        res = runner.invoke(app, ["run", "--json", "--phase", "1", "-c", str(cfg)])
    assert res.exit_code == 2
    phase.assert_not_called()


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
    cfg = make_config(tmp_path, env)
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
    cfg = make_config(tmp_path, "prod")
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=_ok_report()),
    ):
        res = runner.invoke(app, ["destroy", "--dry-run", "-c", str(cfg)])
    assert res.exit_code == 0, res.output


@pytest.mark.parametrize("fmt", [[], ["--json"]])
def test_teardown_exits_nonzero_when_items_fail(tmp_path: Path, fmt: list[str]):
    cfg = make_config(tmp_path, None)
    failed = TeardownReport(
        items=[TeardownItemReport("S3 Bucket", "b", "Acct", "1", "FAILED", "denied")], status="FAILED"
    )
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=failed),
    ):
        res = runner.invoke(app, ["destroy", "--yes", "-c", str(cfg), *fmt])
    assert res.exit_code == 1


@pytest.mark.parametrize("phase", ["0", "1", "7", "-3"])
def test_teardown_rejects_invalid_phase(tmp_path: Path, phase: str):
    cfg = make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_all,
    ):
        res = runner.invoke(app, ["destroy", "--yes", "--phase", phase, "-c", str(cfg)])
    assert res.exit_code == 2
    mock_all.assert_not_called()


def test_run_rejects_invalid_phase(tmp_path: Path):
    cfg = make_config(tmp_path, None)
    with patch("tarmac.cli.deploy.AwsSessionManager"):
        res = runner.invoke(app, ["run", "--yes", "--phase", "9", "-c", str(cfg)])
    assert res.exit_code == 2


def test_scp_plan_exits_1_when_a_target_cannot_be_resolved(tmp_path: Path):
    from tarmac.cli import org as org_cli
    from tarmac.core.models import SCPReconciliationResult

    cfg = make_config(tmp_path, None)
    failed = SCPReconciliationResult(
        name="Guard", policy_id="p-1", action_taken="NOOP", status="FAILED", unresolved_targets=["Typo"]
    )
    with (
        patch("tarmac.cli.org.AwsSessionManager"),
        patch("tarmac.cli.org.OUService"),
        patch("tarmac.cli.org.SCPService") as scp_cls,
    ):
        scp_cls.return_value.reconcile_all.return_value = [failed]
        res = runner.invoke(org_cli.app, ["scp", "plan", "-c", str(cfg)])

    assert res.exit_code == 1
    assert "Typo" in res.output


def test_scp_apply_resolves_policy_files_relative_to_the_config_dir(tmp_path: Path, monkeypatch):
    """Policy files resolve against the project that owns the config, not the current directory."""
    from tarmac.cli import org as org_cli

    cfg = make_config(tmp_path, None)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    with (
        patch("tarmac.cli.org.AwsSessionManager"),
        patch("tarmac.cli.org.OUService"),
        patch("tarmac.cli.org.SCPService") as scp_cls,
    ):
        scp_cls.return_value.reconcile_all.return_value = []
        res = runner.invoke(org_cli.app, ["scp", "plan", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert scp_cls.return_value.reconcile_all.call_args.kwargs["project_root"] == cfg.parent
