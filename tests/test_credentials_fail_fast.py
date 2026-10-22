"""Unusable AWS credentials stop a command before it does any work."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from tarmac.cli.common import require_credentials_or_exit
from tarmac.cli.main import app
from tarmac.core.exceptions import AWSAuthenticationError
from tarmac.services.scaffold import scaffold_project

runner = CliRunner()


@pytest.fixture(autouse=True)
def real_credential_check(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in ("deploy", "importer", "preflight"):
        monkeypatch.setattr(f"tarmac.cli.{module}.require_credentials_or_exit", require_credentials_or_exit)


def _expired() -> MagicMock:
    mgr = MagicMock()
    mgr.default_region = "us-east-1"
    mgr.get_caller_identity.side_effect = AWSAuthenticationError(
        "Failed to authenticate with AWS credentials.",
        details="The security token included in the request is expired",
    )
    return mgr


@pytest.fixture
def project(tmp_path: Path) -> Path:
    scaffold_project(tmp_path / "config")
    return tmp_path / "config"


def _assert_stopped(result, mgr: MagicMock) -> None:
    assert result.exit_code == 1
    assert "credentials are not usable" in result.output
    assert "expired" in result.output
    assert "aws sso login" in result.output
    assert mgr.get_client.call_count == 0
    assert mgr.get_member_client.call_count == 0


@pytest.mark.parametrize("flags", [["--yes"], ["--dry-run"]])
def test_deploy_and_its_plan_stop_on_bad_credentials(monkeypatch, project: Path, flags: list[str]):
    mgr = _expired()
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mgr)
    _assert_stopped(runner.invoke(app, ["deploy", "-c", str(project), *flags]), mgr)


@pytest.mark.parametrize("flags", [[], ["--dry-run"]])
def test_destroy_stops_on_bad_credentials(monkeypatch, project: Path, flags: list[str]):
    mgr = _expired()
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: mgr)
    _assert_stopped(runner.invoke(app, ["destroy", "-c", str(project), "--yes", *flags]), mgr)


def test_import_stops_on_bad_credentials(monkeypatch, tmp_path: Path):
    mgr = _expired()
    monkeypatch.setattr("tarmac.cli.importer.AwsSessionManager", lambda region_name=None: mgr)
    _assert_stopped(runner.invoke(app, ["import", "-c", str(tmp_path / "cfg")]), mgr)
    assert not (tmp_path / "cfg").exists()


def test_preflight_stops_on_bad_credentials(monkeypatch, project: Path):
    mgr = _expired()
    monkeypatch.setattr("tarmac.cli.preflight.AwsSessionManager", lambda **kw: mgr)
    _assert_stopped(runner.invoke(app, ["preflight", "-c", str(project)]), mgr)
