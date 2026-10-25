"""GuardDuty and Security Hub turned off in the config: GuardDuty is suspended and resumed, Security Hub disabled."""

from typing import Any
from unittest.mock import MagicMock

from tarmac.cli import deploy_phases
from tarmac.core.models import TeardownItemReport
from tarmac.services.security import SecurityServicesService
from tarmac.services.security_off import SECURITY_HUB_WARNING, SecurityServicesOff

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

    deploy_phases._turn_off_security_services(MagicMock(), bundle, "us-east-1", {"audit": AUDIT})

    out = capsys.readouterr().out
    assert out.index(SECURITY_HUB_WARNING[:40]) < out.index("Disable Security Hub")
    assert [c.kwargs["dry_run"] for c in off.disable_securityhub.call_args_list] == [True, False]
    off.suspend_guardduty.assert_not_called()
