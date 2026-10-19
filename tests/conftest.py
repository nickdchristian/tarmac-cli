"""Pytest test fixtures."""

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


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_config_dir(project_root: Path) -> Path:
    examples_dir = project_root / "examples" / "config"
    if examples_dir.is_dir():
        return examples_dir
    return project_root / "config"
