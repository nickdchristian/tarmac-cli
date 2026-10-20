"""Configuration directory resolution and example-file handling."""

import pytest


def test_default_config_dir_does_not_fall_back_to_repo_examples(tmp_path, monkeypatch):
    from tarmac.core.config_loader import get_default_config_dir

    monkeypatch.delenv("TARMAC_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    resolved = get_default_config_dir()

    assert "examples" not in resolved.parts
    assert resolved == tmp_path / "config"


def test_example_files_are_not_loaded_as_real_config(tmp_path):
    from tarmac.core.config_loader import resolve_file
    from tarmac.core.exceptions import ConfigurationError

    (tmp_path / "organization.yaml.example").write_text("organization: {}\n")

    with pytest.raises(ConfigurationError):
        resolve_file(tmp_path, "organization")
