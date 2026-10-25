"""Settings recorded in the inventory that the config turns off are reverted; nothing else is touched."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tarmac.core import inventory as inv_mod
from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.inventory import Inventory
from tarmac.services.settings_off import settings_off
from tarmac.services.teardown import TeardownService


@pytest.fixture
def bundle(sample_config_dir: Path) -> ConfigBundle:
    loaded, errors = load_all_configs(sample_config_dir)
    assert loaded is not None, errors
    return loaded


def _service(clients: dict[str, Any]) -> TeardownService:
    session = MagicMock()
    session.get_client.side_effect = lambda name, region_name=None: clients.get(name, MagicMock())
    session.get_caller_identity.return_value = {"Account": "111", "Arn": "arn:aws:sts::111:assumed-role/A/x"}
    return TeardownService(session)


def test_root_access_settings_follow_root_access_management(bundle):
    assert not settings_off(bundle)("root-sessions", "")
    root = bundle.org.root_access_management
    root.enable_root_sessions = False
    off = settings_off(bundle)
    assert off("root-sessions", "")
    assert not off("root-credentials-management", "")
    root.enable_root_credentials_management = False
    root.delegate_to_audit = False
    off = settings_off(bundle)
    assert off("root-credentials-management", "")
    assert off("delegated-admin", "iam.amazonaws.com:222")
    assert not off("delegated-admin", "guardduty.amazonaws.com:222")
    assert not off("trusted-access", "iam.amazonaws.com")


def test_groups_and_cost_tags_follow_the_config_but_users_are_kept(bundle):
    off = settings_off(bundle)
    declared = bundle.identity.identity_center.groups[0].name
    assert not off("identity-group", declared)
    assert off("identity-group", "RemovedGroup")
    assert not off("identity-user", "someone-left-out")
    assert off("cost-allocation-tag", "NotAConfiguredTag")


def test_only_the_cost_tags_the_config_dropped_are_deactivated():
    inv = Inventory()
    inv.record("cost-allocation-tags:management", {"tag_keys": ["CostCenter", "Team"]})
    ce = MagicMock()

    items = _service({"ce": ce}).teardown_org_settings(inv, only=lambda kind, key: key == "Team")

    ce.update_cost_allocation_tags_status.assert_called_once_with(
        CostAllocationTagsStatus=[{"TagKey": "Team", "Status": "Inactive"}]
    )
    assert [i.action for i in items] == ["DELETED"]
    assert inv.get("cost-allocation-tags") == {"management": {"tag_keys": ["CostCenter"]}}


def test_a_filter_leaves_every_other_setting_alone():
    inv = Inventory()
    inv.record("trusted-access:cloudtrail.amazonaws.com")
    inv.record("root-sessions")
    org, iam = MagicMock(), MagicMock()

    items = _service({"organizations": org, "iam": iam}).teardown_org_settings(
        inv, only=lambda kind, _key: kind == "root-sessions"
    )

    iam.disable_organizations_root_sessions.assert_called_once()
    org.disable_aws_service_access.assert_not_called()
    assert [i.action for i in items] == ["DELETED"]


def test_the_dry_run_reads_the_inventory_without_writing_it():
    s3, cfn = MagicMock(), MagicMock()
    cfn.describe_stacks.return_value = {
        "Stacks": [{"Outputs": [{"OutputKey": "BucketName", "OutputValue": "b"}]}]
    }
    s3.get_object.return_value = {
        "Body": MagicMock(read=lambda: b'{"entries": {"ou": {"A": {}}}}'),
        "ETag": "e",
    }
    session = MagicMock()
    session.get_client.side_effect = lambda name, region_name=None: {"s3": s3, "cloudformation": cfn}[name]

    recorded = inv_mod.read(session, "acme", "us-east-1")
    recorded.forget("ou", "A")

    assert recorded.get("ou") == {}
    s3.put_object.assert_not_called()


def test_turning_off_root_sessions_is_flagged_only_when_tarmac_turned_them_on(bundle):
    from tarmac.services.settings_off import turns_off_root_sessions

    recorded = Inventory()
    bundle.org.root_access_management.enable_root_sessions = False
    assert not turns_off_root_sessions(bundle, recorded)
    recorded.record("root-sessions:o-abc1234567")
    assert turns_off_root_sessions(bundle, recorded)
    bundle.org.root_access_management.enable_root_sessions = True
    assert not turns_off_root_sessions(bundle, recorded)
