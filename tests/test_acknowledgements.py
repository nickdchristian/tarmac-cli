"""'Decided against it' for the two irreversible-or-costly options, checked through the real YAML loader.

Both warnings stay quiet only when the key is written down (`object_lock: null`, `config_recorder: null` or
`enabled: false`). That is decided by whether the key appears in the file, so these tests go file -> loader -> warning
rather than building the models in code, and pin that nothing tarmac generates acknowledges on the user's behalf.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

from tarmac.cli.common import warn_if_object_lock_unset
from tarmac.cli.deploy_config_recorder import warn_if_config_recorder_missing
from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.services.scaffold import scaffold_project


def _load(config_dir: Path, *, cloudtrail: dict[str, Any], security: dict[str, Any]) -> ConfigBundle:
    path = config_dir / "organization.yaml"
    data = yaml.safe_load(path.read_text())
    data["cloudtrail"] = {**data.get("cloudtrail", {}), **cloudtrail}
    data["security_services"] = {**data.get("security_services", {}), **security}
    # Merging with the example must not leak its keys into a case that is meant to leave them out.
    if "object_lock" not in cloudtrail:
        data["cloudtrail"].pop("object_lock", None)
    if "config_recorder" not in security:
        data["security_services"].pop("config_recorder", None)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    bundle, errors = load_all_configs(config_dir)
    assert bundle is not None, errors
    return bundle


def _warnings(monkeypatch: pytest.MonkeyPatch, bundle: ConfigBundle) -> tuple[list[str], list[str]]:
    lock: list[str] = []
    recorder: list[str] = []
    monkeypatch.setattr("tarmac.cli.common.print_warning", lock.append)
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.print_warning", recorder.append)
    warn_if_object_lock_unset(bundle)
    warn_if_config_recorder_missing(bundle)
    return lock, recorder


SECURITY_HUB_ON = {"securityhub": {"enabled": True}}


def test_both_warnings_fire_while_neither_key_is_in_the_file(writable_config_dir, monkeypatch):
    bundle = _load(writable_config_dir, cloudtrail={}, security=SECURITY_HUB_ON)
    lock, recorder = _warnings(monkeypatch, bundle)
    assert lock
    assert recorder


@pytest.mark.parametrize("recorder_value", [None, {"enabled": False}, {"enabled": True}])
def test_writing_either_key_down_acknowledges_it_after_a_round_trip_through_yaml(
    writable_config_dir, monkeypatch, recorder_value
):
    bundle = _load(
        writable_config_dir,
        cloudtrail={"object_lock": None},
        security={**SECURITY_HUB_ON, "config_recorder": recorder_value},
    )
    lock, recorder = _warnings(monkeypatch, bundle)
    assert lock == []
    assert recorder == []


def test_acknowledging_one_option_does_not_acknowledge_the_other(writable_config_dir, monkeypatch):
    bundle = _load(writable_config_dir, cloudtrail={"object_lock": None}, security=SECURITY_HUB_ON)
    lock, recorder = _warnings(monkeypatch, bundle)
    assert lock == []
    assert recorder


def test_a_scaffolded_project_acknowledges_nothing_for_you(tmp_path):
    scaffold_project(tmp_path)
    files = [f for f in tmp_path.rglob("organization.yaml*") if f.is_file()]
    assert files, "scaffold wrote no organization config, so this test would check nothing"
    for file in files:
        data = yaml.safe_load(file.read_text())
        assert "object_lock" not in data.get("cloudtrail", {}), file.name
        assert "config_recorder" not in data.get("security_services", {}), file.name


def test_import_does_not_acknowledge_either_option(tmp_path):
    from test_import import FakeSession

    from tarmac.services.importer import ImportService

    service = ImportService(FakeSession(with_sso=False), "us-east-1")  # type: ignore[arg-type]
    service.discover_and_write(tmp_path / "cfg", include_identity=False)
    org = yaml.safe_load((tmp_path / "cfg" / "organization.yaml").read_text())
    assert "object_lock" not in org.get("cloudtrail", {})
    assert "config_recorder" not in org.get("security_services", {})
