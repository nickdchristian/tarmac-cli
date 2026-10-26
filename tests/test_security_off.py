"""GuardDuty and Security Hub turned off in the config: GuardDuty is suspended and resumed, Security Hub disabled."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from tarmac.cli import deploy_phases
from tarmac.core import inventory
from tarmac.core.inventory import Inventory
from tarmac.core.models import TeardownItemReport
from tarmac.services.security import SecurityServicesService
from tarmac.services.security_off import SECURITY_HUB_WARNING, SecurityServicesOff, regions_off

AUDIT = "222222222222"


def _guardduty(delegated: bool = True, members: list[str] | None = None) -> tuple[Any, Any]:
    """A session whose management GuardDuty client lists the delegated admin, and the audit account's client."""
    mgr, management, audit_gd = MagicMock(), MagicMock(), MagicMock()
    management.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminAccountId": AUDIT}] if delegated else []
    }
    mgr.get_client.return_value = management
    mgr.get_member_client.return_value = audit_gd
    audit_gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    audit_gd.get_paginator.return_value.paginate.return_value = [
        {"Members": [{"AccountId": a, "RelationshipStatus": "Enabled"} for a in members or []]}
    ]
    return mgr, audit_gd


def test_guardduty_is_suspended_in_the_members_and_stays_on_in_the_audit_account():
    mgr, gd = _guardduty(members=["111", "333"])

    items = SecurityServicesOff(mgr).suspend_guardduty(AUDIT, ["us-east-1"], dry_run=False)

    gd.update_organization_configuration.assert_called_once_with(
        DetectorId="det-1", AutoEnableOrganizationMembers="NONE"
    )
    gd.stop_monitoring_members.assert_called_once_with(DetectorId="det-1", AccountIds=["111", "333"])
    # AWS only suspends an administrator's detector once its members are disassociated.
    gd.update_detector.assert_not_called()
    gd.delete_detector.assert_not_called()
    (item,) = items
    assert item.action == "DELETED"
    assert item.message.startswith("Suspended it in 2 member accounts; findings are kept.")
    assert "stays on in the audit account" in item.message


def test_guardduty_already_suspended_or_not_run_by_tarmac_is_left_alone():
    # Once suspended, the members no longer show as Enabled, so a second deploy changes nothing.
    for mgr, gd in (_guardduty(members=[]), _guardduty(delegated=False, members=["111"])):
        assert SecurityServicesOff(mgr).suspend_guardduty(AUDIT, ["us-east-1"], dry_run=False) == []
        gd.stop_monitoring_members.assert_not_called()


def test_turning_guardduty_back_on_resumes_suspended_members():
    gd = MagicMock()
    gd.get_paginator.return_value.paginate.return_value = [
        {
            "Members": [
                {"AccountId": "111", "RelationshipStatus": "Disabled"},
                {"AccountId": "222", "RelationshipStatus": "Enabled"},
            ]
        }
    ]

    SecurityServicesService(MagicMock())._resume_suspended_members(gd, "det-1", AUDIT, "us-east-1")

    # AWS rejects StartMonitoringMembers while auto-enable covers all accounts, so it is turned off first.
    assert [c[0] for c in gd.method_calls if c[0] != "get_paginator"] == [
        "update_organization_configuration",
        "start_monitoring_members",
    ]
    gd.update_organization_configuration.assert_called_once_with(
        DetectorId="det-1", AutoEnableOrganizationMembers="NONE"
    )
    gd.start_monitoring_members.assert_called_once_with(DetectorId="det-1", AccountIds=["111"])


def test_nothing_is_resumed_when_no_member_is_suspended():
    gd = MagicMock()
    gd.get_paginator.return_value.paginate.return_value = [
        {"Members": [{"AccountId": "222", "RelationshipStatus": "Enabled"}]}
    ]
    SecurityServicesService(MagicMock())._resume_suspended_members(gd, "det-1", AUDIT, "us-east-1")
    gd.update_organization_configuration.assert_not_called()
    gd.start_monitoring_members.assert_not_called()


def test_security_hub_is_disabled_after_a_warning(monkeypatch, capsys):
    bundle = MagicMock()
    bundle.org.security_services.guardduty.enabled = True
    bundle.org.security_services.securityhub.enabled = False
    bundle.org.organization.additional_regions = []
    bundle.resolve_account_id.return_value = AUDIT
    off = MagicMock()
    item = TeardownItemReport(
        "Security Hub (us-east-1)", "hub", AUDIT, AUDIT, "DELETED", "Disable Security Hub"
    )
    off.disable_securityhub.return_value = [item]
    monkeypatch.setattr(deploy_phases, "SecurityServicesOff", lambda _s: off)
    _recorded({"guardduty": ["us-east-1"], "securityhub": ["us-east-1"]})

    deploy_phases._turn_off_security_services(MagicMock(), bundle, "us-east-1", {"audit": AUDIT})

    out = capsys.readouterr().out
    assert out.index(SECURITY_HUB_WARNING[:40]) < out.index("Disable Security Hub")
    assert [c.kwargs["dry_run"] for c in off.disable_securityhub.call_args_list] == [True, False]
    off.suspend_guardduty.assert_not_called()


def _recorded(regions: dict[str, list[str]]) -> Inventory:
    """The active inventory, connected to a bucket, recording ``{service: [Region, ...]}``."""
    inv = inventory.activate()
    inv.bucket = "inventory-bucket"
    inv.entries = {kind: {r: {"admin": AUDIT} for r in rs} for kind, rs in regions.items()}
    return inv


def _bundle(guardduty: bool, securityhub: bool, additional: list[str] | None = None) -> MagicMock:
    bundle = MagicMock()
    bundle.org.security_services.guardduty.enabled = guardduty
    bundle.org.security_services.securityhub.enabled = securityhub
    bundle.org.organization.additional_regions = additional or []
    bundle.resolve_account_id.return_value = AUDIT
    return bundle


@pytest.mark.parametrize(
    ("enabled", "additional", "expected"),
    [
        (True, ["us-west-2"], []),
        (True, [], ["us-west-2"]),  # the Region was dropped
        (False, ["us-west-2"], ["us-east-1", "us-west-2"]),  # the service was turned off
    ],
)
def test_only_recorded_regions_the_config_no_longer_wants_are_turned_off(enabled, additional, expected):
    recorded = _recorded({"guardduty": ["us-east-1", "us-west-2"]})
    bundle = _bundle(guardduty=enabled, securityhub=True, additional=additional)
    assert regions_off(bundle, recorded, "guardduty", "us-east-1") == expected
    assert regions_off(bundle, recorded, "securityhub", "us-east-1") == []
    assert regions_off(bundle, None, "guardduty", "us-east-1") == []


def test_a_service_tarmac_never_recorded_is_left_alone_even_when_the_config_turns_it_off(monkeypatch):
    # An adopted organization can have GuardDuty and Security Hub delegated to an account named audit by
    # someone else; imported with both off, the next deploy must not disable them.
    off = MagicMock()
    monkeypatch.setattr(deploy_phases, "SecurityServicesOff", lambda _s: off)
    _recorded({})

    deploy_phases._turn_off_security_services(
        MagicMock(), _bundle(guardduty=False, securityhub=False), "us-east-1", {"audit": AUDIT}
    )

    off.suspend_guardduty.assert_not_called()
    off.disable_securityhub.assert_not_called()


def test_a_dropped_region_suspends_guardduty_there_only(monkeypatch):
    off = MagicMock()
    off.suspend_guardduty.return_value = []
    monkeypatch.setattr(deploy_phases, "SecurityServicesOff", lambda _s: off)
    _recorded({"guardduty": ["us-east-1", "us-west-2"]})

    deploy_phases._turn_off_security_services(
        MagicMock(), _bundle(guardduty=True, securityhub=True), "us-east-1", {"audit": AUDIT}
    )

    off.suspend_guardduty.assert_called_once_with(AUDIT, ["us-west-2"], dry_run=False)
    off.disable_securityhub.assert_not_called()


def test_destroy_says_which_security_services_it_keeps():
    from tarmac.services.teardown import TeardownService

    bundle = _bundle(guardduty=True, securityhub=False)
    bundle.org.security_services.audit_account = "audit"

    (item,) = TeardownService(MagicMock()).report_security_services_kept(bundle)

    assert (item.resource_name, item.action) == ("GuardDuty", "SKIPPED")
    assert "--disable-security-services" in item.message


def test_security_hub_in_a_dropped_region_is_left_on_with_a_warning(monkeypatch, capsys):
    # Under central configuration AWS refused, live: "This account is currently associated with a central
    # configuration policy, so only the administrator can access this operation."
    off = MagicMock()
    monkeypatch.setattr(deploy_phases, "SecurityServicesOff", lambda _s: off)
    _recorded({"securityhub": ["us-east-1", "us-west-2"]})

    deploy_phases._turn_off_security_services(
        MagicMock(), _bundle(guardduty=True, securityhub=True), "us-east-1", {"audit": AUDIT}
    )

    off.disable_securityhub.assert_not_called()
    assert "Security Hub stays on in us-west-2" in capsys.readouterr().out
