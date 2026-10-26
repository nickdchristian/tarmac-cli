"""`tarmac plan` recommends Object Lock and a Config recorder while they are off, with no way to hide it by writing
`null`: a setting means the same whether it is left out or written down."""

from pathlib import Path
from typing import Any

import yaml

from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.services.stack_parameters import config_recorder_advice, object_lock_advice

SECURITY_HUB_ON = {"securityhub": {"enabled": True}}


def _load(config_dir: Path, *, cloudtrail: dict[str, Any], security: dict[str, Any]) -> tuple[Any, list[str]]:
    path = config_dir / "organization.yaml"
    data = yaml.safe_load(path.read_text())
    data["cloudtrail"] = {**data.get("cloudtrail", {}), **cloudtrail}
    data["security_services"] = {**data.get("security_services", {}), **security}
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return load_all_configs(config_dir)


def _advice(bundle: ConfigBundle) -> tuple[str | None, str | None]:
    return object_lock_advice(bundle), config_recorder_advice(bundle)


def test_both_are_recommended_while_off(writable_config_dir):
    bundle, errors = _load(writable_config_dir, cloudtrail={}, security=SECURITY_HUB_ON)
    assert bundle is not None, errors
    lock, recorder = _advice(bundle)
    assert "GOVERNANCE" in (lock or "")
    assert "config_recorder.enabled: true" in (recorder or "")


def test_writing_null_or_false_does_not_hide_the_advice(writable_config_dir):
    bundle, errors = _load(
        writable_config_dir,
        cloudtrail={"object_lock": None},
        security={**SECURITY_HUB_ON, "config_recorder": {"enabled": False}},
    )
    assert bundle is not None, errors
    lock, recorder = _advice(bundle)
    assert lock
    assert recorder


def test_turning_them_on_ends_the_advice(writable_config_dir):
    bundle, errors = _load(
        writable_config_dir,
        cloudtrail={"object_lock": {"mode": "GOVERNANCE", "retention_days": 30}},
        security={**SECURITY_HUB_ON, "config_recorder": {"enabled": True}},
    )
    assert bundle is not None, errors
    assert _advice(bundle) == (None, None)


def test_config_recorder_null_is_an_error(writable_config_dir):
    bundle, errors = _load(writable_config_dir, cloudtrail={}, security={"config_recorder": None})
    assert bundle is None
    assert "security_services.config_recorder" in errors[0]
