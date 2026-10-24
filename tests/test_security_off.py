"""GuardDuty and Security Hub turned off in the config: GuardDuty is suspended and resumed, Security Hub disabled."""

from typing import Any
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from tarmac.cli import deploy_phases
from tarmac.core.models import TeardownItemReport
from tarmac.services.security import SecurityServicesService
from tarmac.services.security_off import SECURITY_HUB_WARNING, SecurityServicesOff

AUDIT = "222222222222"


def _guardduty(
    delegated: bool = True, status: str = "ENABLED", members: list[str] | None = None
) -> tuple[Any, Any]:
    """A session whose management GuardDuty client lists the delegated admin, and the audit account's client."""
    mgr, management, audit_gd = MagicMock(), MagicMock(), MagicMock()
    management.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminAccountId": AUDIT}] if delegated else []
    }
    mgr.get_client.return_value = management
    mgr.get_member_client.return_value = audit_gd
    audit_gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    audit_gd.get_detector.return_value = {"Status": status}
    audit_gd.get_paginator.return_value.paginate.return_value = [
        {"Members": [{"AccountId": a, "RelationshipStatus": "Enabled"} for a in members or []]}
    ]
    return mgr, audit_gd


def test_guardduty_is_suspended_in_the_members_and_the_audit_account():
    mgr, gd = _guardduty(members=["111", "333"])

    items = SecurityServicesOff(mgr).suspend_guardduty(AUDIT, ["us-east-1"], dry_run=False)

    gd.update_organization_configuration.assert_called_once_with(
        DetectorId="det-1", AutoEnableOrganizationMembers="NONE"
    )
    gd.stop_monitoring_members.assert_called_once_with(DetectorId="det-1", AccountIds=["111", "333"])
    gd.update_detector.assert_called_once_with(DetectorId="det-1", Enable=False)
    gd.delete_detector.assert_not_called()
    assert [(i.action, i.message) for i in items] == [
        ("DELETED", "Suspended it in 2 member accounts and the audit account; findings are kept")
    ]


def test_an_audit_detector_aws_will_not_suspend_is_reported_without_failing():
    mgr, gd = _guardduty(members=["111"])
    gd.update_detector.side_effect = ClientError(
        {"Error": {"Code": "BadRequestException", "Message": "no"}}, "x"
    )

    (item,) = SecurityServicesOff(mgr).suspend_guardduty(AUDIT, ["us-east-1"], dry_run=False)

    assert item.action == "DELETED"
    assert "stays on in the audit account" in item.message


def test_guardduty_already_suspended_or_not_run_by_tarmac_is_left_alone():
    for mgr, gd in (_guardduty(status="DISABLED"), _guardduty(delegated=False, members=["111"])):
        assert SecurityServicesOff(mgr).suspend_guardduty(AUDIT, ["us-east-1"], dry_run=False) == []
        gd.stop_monitoring_members.assert_not_called()


def test_turning_guardduty_back_on_resumes_suspended_members():
    gd = MagicMock()
    gd.get_paginator.return_value.paginate.return_value = [
        {"Members": [{"AccountId": "111", "RelationshipStatus": "Disabled"}]}
    ]
    mgr = MagicMock()
    mgr.get_client.return_value.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "111", "Email": "a@example.com", "Status": "ACTIVE", "State": "ACTIVE"}]}
    ]

    SecurityServicesService(mgr)._add_existing_guardduty_members(gd, "det-1", AUDIT, "us-east-1")

    gd.start_monitoring_members.assert_called_once_with(DetectorId="det-1", AccountIds=["111"])
    gd.create_members.assert_not_called()


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
    off.disable_securityhub.side_effect = lambda *a, dry_run: [item] if not dry_run else [item]
    monkeypatch.setattr(deploy_phases, "SecurityServicesOff", lambda _s: off)

    deploy_phases._turn_off_security_services(MagicMock(), bundle, "us-east-1", {"audit": AUDIT})

    out = capsys.readouterr().out
    assert out.index(SECURITY_HUB_WARNING[:40]) < out.index("Disable Security Hub")
    assert [c.kwargs["dry_run"] for c in off.disable_securityhub.call_args_list] == [True, False]
    off.suspend_guardduty.assert_not_called()
