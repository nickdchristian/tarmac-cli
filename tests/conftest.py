"""Pytest test fixtures."""

import shutil
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_aws_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent unit tests from reading host AWS configs or hitting live EC2 IMDS."""
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    for var in (
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def neutral_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make help and table output the same on a laptop and in CI.

    GitHub Actions sets GITHUB_ACTIONS (and runners may set FORCE_COLOR), which makes Typer and Rich colour their output
    and split words such as option names with escape codes. Tests should not depend on which side they run on.
    """
    for var in ("GITHUB_ACTIONS", "FORCE_COLOR", "CLICOLOR_FORCE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.fixture(autouse=True)
def isolate_inventory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the created-by-tarmac inventory out of the repository's example config."""
    from tarmac.core import inventory

    monkeypatch.setenv("TARMAC_INVENTORY_FILE", str(tmp_path / "inventory.json"))
    inventory.deactivate()


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_config_dir(project_root: Path) -> Path:
    examples_dir = project_root / "examples" / "config"
    if examples_dir.is_dir():
        return examples_dir
    return project_root / "config"


@pytest.fixture
def writable_config_dir(sample_config_dir: Path, tmp_path: Path) -> Path:
    """A throwaway copy of the example config, for tests that edit it. Never write to sample_config_dir."""
    target = tmp_path / "config"
    shutil.copytree(sample_config_dir, target)
    return target


@pytest.fixture(autouse=True)
def no_credential_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI tests run without AWS credentials; the up-front check has its own tests (test_credentials_fail_fast)."""
    for module in ("deploy", "importer"):
        monkeypatch.setattr(f"tarmac.cli.{module}.require_credentials_or_exit", lambda _mgr: None)


@pytest.fixture(autouse=True)
def reset_adopt_existing() -> None:
    """--adopt-existing lives in a context variable; never let one test's setting leak into the next."""
    from tarmac.core.adoption import set_adopt_existing

    set_adopt_existing(False)
