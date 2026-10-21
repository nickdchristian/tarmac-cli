"""Guardrails on destructive CLI commands: consent, production lock, exit codes and phase validation."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli.deploy import _is_production_tagged
from tarmac.cli.main import app
from tarmac.services.teardown import (
    TeardownItemReport,
    TeardownReport,
)

runner = CliRunner()


def _ok_report() -> TeardownReport:
    return TeardownReport(items=[], status="COMPLETED")


def test_teardown_json_without_yes_is_refused(tmp_path: Path):
    cfg = make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_all,
    ):
        res = runner.invoke(app, ["destroy", "--json", "-c", str(cfg)])
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
        res = runner.invoke(app, ["deploy", "--json", "--phase", "1", "-c", str(cfg)])
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


@pytest.mark.parametrize("phase", ["0", "7", "9"])
def test_run_rejects_invalid_phase(tmp_path: Path, phase: str):
    cfg = make_config(tmp_path, None)
    with patch("tarmac.cli.deploy.AwsSessionManager"):
        res = runner.invoke(app, ["deploy", "--yes", "--phase", phase, "-c", str(cfg)])
    assert res.exit_code == 2


def test_phase_2_fails_when_an_scp_target_cannot_be_resolved(tmp_path: Path):
    from tarmac.cli import deploy_phases
    from tarmac.core.config_loader import load_all_configs
    from tarmac.core.exceptions import GovernanceError
    from tarmac.core.models import SCPReconciliationResult

    bundle, _ = load_all_configs(make_config(tmp_path, None))
    assert bundle is not None
    failed = SCPReconciliationResult(
        name="Guard", action_taken="NOOP", status="FAILED", unresolved_targets=["Typo"]
    )
    with (
        patch("tarmac.cli.deploy_phases.OUService"),
        patch("tarmac.cli.deploy_phases.OrganizationService") as org_cls,
        patch("tarmac.cli.deploy_phases.SCPService") as scp_cls,
    ):
        scp_cls.return_value.reconcile_via_cloudformation.return_value = [failed]
        with pytest.raises(GovernanceError, match="SCP targets") as raised:
            deploy_phases._run_phase_2_ou(MagicMock(), bundle, tmp_path)

    assert "Typo" in str(raised.value)
    org_cls.return_value.record_phase_completed.assert_not_called()


def test_phase_2_resolves_policy_files_relative_to_the_config_dir(tmp_path: Path, monkeypatch):
    """Policy files resolve against the project that owns the config, not the current directory."""
    cfg = make_config(tmp_path, None)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.cli.deploy.OrganizationService"),
        patch("tarmac.cli.deploy_phases.OrganizationService"),
        patch("tarmac.cli.deploy_phases.OUService"),
        patch("tarmac.cli.deploy_phases.SCPService") as scp_cls,
    ):
        scp_cls.return_value.reconcile_via_cloudformation.return_value = []
        res = runner.invoke(app, ["deploy", "--yes", "--phase", "2", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert scp_cls.return_value.reconcile_via_cloudformation.call_args.kwargs["project_root"] == cfg.parent


def test_teardown_without_yes_prompts_for_confirmation_and_cancels_on_no(tmp_path: Path):
    """Standard teardown without --yes or --dry-run must prompt for confirmation and abort on 'n'."""
    cfg = make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.services.teardown.TeardownService.teardown_all") as mock_all,
    ):
        res = runner.invoke(app, ["destroy", "-c", str(cfg)], input="n\n")
    assert res.exit_code == 0
    assert "Teardown cancelled by user" in res.output
    mock_all.assert_not_called()


def test_broken_stack_deletion_releases_termination_protection_when_needed():
    """_delete_broken_stack disables termination protection and retries when delete_stack fails due to protection."""
    from unittest.mock import MagicMock

    from botocore.exceptions import ClientError

    from tarmac.services.cloudformation import CloudFormationService

    cfn = MagicMock()
    cfn.delete_stack.side_effect = [
        ClientError(
            {
                "Error": {
                    "Code": "ValidationError",
                    "Message": "Stack [s1] cannot be deleted while TerminationProtection is enabled",
                }
            },
            "DeleteStack",
        ),
        {},
    ]
    svc = CloudFormationService(MagicMock())
    svc._delete_broken_stack(cfn, "s1")
    cfn.update_termination_protection.assert_called_once_with(
        StackName="s1", EnableTerminationProtection=False
    )
    assert cfn.delete_stack.call_count == 2


def test_production_lock_is_not_hidden_by_a_higher_precedence_tag():
    """accounts.yaml tags override organization.yaml tags, but a 'prod' anywhere must still block destroy."""
    from types import SimpleNamespace
    from typing import Any

    import typer

    from tarmac.cli.deploy import _enforce_production_lock

    bundle: Any = SimpleNamespace(
        org=SimpleNamespace(tags={"Environment": "prod"}, organization=SimpleNamespace(tags={})),
        accounts=SimpleNamespace(tags={"Environment": "dev"}),
        get_organization_tags=lambda: {"Environment": "dev"},
    )
    with pytest.raises(typer.Exit):
        _enforce_production_lock(bundle, dry_run=False, force=False)
    _enforce_production_lock(bundle, dry_run=False, force=True)
