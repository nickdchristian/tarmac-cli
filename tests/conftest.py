"""Pytest test fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_config_dir(project_root) -> Path:
    examples_dir = project_root / "examples" / "config"
    if examples_dir.is_dir():
        return examples_dir
    return project_root / "config"
