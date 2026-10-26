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


def test_scp_targets_must_be_root_or_declared_ou(sample_config_dir):
    from tarmac.core.config_loader import load_all_configs

    bundle, errors = load_all_configs(sample_config_dir)
    assert bundle is not None, errors
    assert bundle.org.service_control_policies is not None
    bundle.org.service_control_policies.policies[0].targets = ["root", "security", "Securty"]

    problems = bundle._check_scp_targets()

    assert len(problems) == 1
    assert "Securty" in problems[0]


def test_config_is_only_read_from_config_dir(tmp_path, monkeypatch):
    """Local override folders and files used to win silently; now only config/<name>.yaml is read."""
    from tarmac.core.config_loader import get_default_config_dir, resolve_file

    monkeypatch.delenv("TARMAC_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "config"
    (config / "local").mkdir(parents=True)
    for path in (
        config / "local" / "organization.yaml",
        config / "organization.local.yaml",
        tmp_path / "organization.yaml",
    ):
        path.write_text("organization: {}\n")
    (config / "organization.yaml").write_text("organization: {name: real}\n")

    assert get_default_config_dir() == config
    assert resolve_file(config, "organization") == config / "organization.yaml"

    monkeypatch.setenv("TARMAC_CONFIG_DIR", str(tmp_path / "elsewhere"))
    assert get_default_config_dir() == tmp_path / "elsewhere"
