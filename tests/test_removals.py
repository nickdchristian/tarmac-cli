"""The config is the source of truth: what it turns off, a deploy removes, and the dry run says so first."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tarmac.cli.deploy_config_recorder import deploy_config_recorder
from tarmac.cli.removals import apply_removals
from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.exceptions import GovernanceError
from tarmac.core.models import TeardownItemReport
from tarmac.services.plan import PhasePlan, Planner


def _item(action: str, name: str = "acme-config-recorder") -> TeardownItemReport:
    return TeardownItemReport("Config recorder StackSet", name, "Organization", "111", action, f"{action} it")


@pytest.fixture
def bundle(sample_config_dir: Path) -> ConfigBundle:
    loaded, errors = load_all_configs(sample_config_dir)
    assert loaded is not None, errors
    return loaded


def test_removals_report_what_was_deleted_and_fail_on_what_was_not(capsys):
    apply_removals("AWS Config recorders", [_item("DELETED"), _item("NOT_FOUND", "other")])
    assert "Removed Config recorder StackSet acme-config-recorder" in capsys.readouterr().out

    with pytest.raises(GovernanceError, match="Could not remove the AWS Config recorders"):
        apply_removals("AWS Config recorders", [_item("FAILED")])


def test_a_disabled_config_recorder_is_removed_on_deploy(bundle, monkeypatch):
    assert not bundle.org.security_services.config_recorder.enabled
    teardown = MagicMock()
    teardown.return_value.teardown_config_recorder.return_value = [_item("DELETED")]
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.TeardownService", teardown)

    deploy_config_recorder(MagicMock(), MagicMock(), bundle, "eu-west-1", Path("."), {})

    teardown.return_value.teardown_config_recorder.assert_called_once_with(bundle, "eu-west-1")


def test_the_dry_run_lists_what_a_deploy_would_remove(bundle, monkeypatch):
    planner = Planner(MagicMock(), bundle, "eu-west-1", bundle.config_dir.parent)
    teardown: Any = MagicMock()
    monkeypatch.setattr("tarmac.services.plan.TeardownService", lambda _s: teardown)
    phase = PhasePlan(5, "t")

    planner._removals(phase, "config_recorder is off", lambda t: [_item("SIMULATED"), _item("FAILED", "x")])

    assert [(i.name, i.action, i.detail) for i in phase.items] == [
        ("acme-config-recorder", "DELETE", "config_recorder is off"),
        ("x", "UNKNOWN", "FAILED it"),
    ]
