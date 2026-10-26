"""GuardDuty or Security Hub turned off in the config, or in a Region the config no longer lists.

Only Regions the inventory records tarmac setting the service up in are touched, and only while the audit account
is still its delegated administrator there: a service someone else runs is left alone.

GuardDuty is suspended in the member accounts: monitoring and charges stop, findings are kept, and turning it back on
resumes it. It stays on in the audit account, because AWS only suspends a detector once its members are disassociated.
Security Hub has no suspend, so it is disabled, and AWS then deletes its findings (archived after 30 days, active
after 90). In a Region dropped while Security Hub stays on, only the accounts' hubs there are disabled; the delegation
and organization settings are left, since central configuration manages them from the home Region.
"""

import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.inventory import Inventory, regions_to_remove
from ..core.models import TeardownItemReport
from ..core.text import plural
from .teardown_security import SecurityServicesTeardown

logger = logging.getLogger(__name__)

SECURITY_HUB_WARNING = (
    "Disabling Security Hub. AWS deletes its archived findings after 30 days and its active findings, insights and "
    "settings after 90 days; turning it back on before then restores them. Export any findings you need to keep first."
)


def regions_off(
    bundle: ConfigBundle, recorded: Inventory | None, service: str, primary_region: str
) -> list[str]:
    """Where tarmac set up ``service`` ("guardduty" or "securityhub") and the config no longer wants it."""
    enabled = getattr(bundle.org.security_services, service).enabled
    keep = [primary_region, *bundle.org.organization.additional_regions] if enabled else []
    return regions_to_remove(recorded, service, keep)


class SecurityServicesOff:
    def __init__(self, session_mgr: AwsSessionManager) -> None:
        self.session_mgr = session_mgr

    def _delegated(self, service: str, region: str, audit_id: str) -> bool:
        """Whether the audit account is still the service's delegated administrator, so tarmac has it running."""
        admins = self.session_mgr.get_client(service, region_name=region).list_organization_admin_accounts()
        key = "AdminAccountId" if service == "guardduty" else "AccountId"
        return any(a.get(key) == audit_id for a in admins.get("AdminAccounts", []))

    def suspend_guardduty(self, audit_id: str, regions: list[str], dry_run: bool) -> list[TeardownItemReport]:
        """Stop monitoring the member accounts, keeping the delegation, the members and their findings.

        The audit account's own detector stays on: "All member accounts must be disassociated or deleted before you
        can suspend or disable GuardDuty", and disassociating them would undo the setup turning it back on resumes.
        """
        results: list[TeardownItemReport] = []
        for region in regions:
            if not self._delegated("guardduty", region, audit_id):
                continue
            gd: Any = self.session_mgr.get_member_client(audit_id, "guardduty", region_name=region)
            for detector in gd.list_detectors().get("DetectorIds", []):
                members = [
                    str(m["AccountId"])
                    for page in gd.get_paginator("list_members").paginate(
                        DetectorId=detector, OnlyAssociated="true"
                    )
                    for m in page.get("Members", [])
                    if m.get("RelationshipStatus") == "Enabled"
                ]
                if not members:
                    continue
                name = region
                if dry_run:
                    message = f"Would suspend it in {plural(len(members), 'member account')}"
                    results.append(
                        TeardownItemReport("GuardDuty", name, "audit", audit_id, "SIMULATED", message)
                    )
                    continue
                try:
                    # Members can only be stopped once auto-enable no longer forces them on.
                    gd.update_organization_configuration(
                        DetectorId=detector, AutoEnableOrganizationMembers="NONE"
                    )
                    for start in range(0, len(members), 50):
                        gd.stop_monitoring_members(
                            DetectorId=detector, AccountIds=members[start : start + 50]
                        )
                except ClientError as e:
                    results.append(TeardownItemReport("GuardDuty", name, "audit", audit_id, "FAILED", str(e)))
                    continue
                message = (
                    f"Suspended it in {plural(len(members), 'member account')}; findings are kept. It stays on in "
                    "the audit account, since AWS needs the members disassociated to suspend it there"
                )
                results.append(TeardownItemReport("GuardDuty", name, "audit", audit_id, "DELETED", message))
        return results

    def disable_securityhub(
        self,
        bundle: ConfigBundle,
        audit_id: str,
        regions: list[str],
        accounts: dict[str, str],
        mgmt_id: str,
        primary_region: str,
        dry_run: bool,
    ) -> list[TeardownItemReport]:
        """Disable Security Hub in ``regions``, where the audit account is still its delegated administrator.

        With Security Hub off in the config, this is what `destroy --disable-security-services` does. With it still
        on, these are Regions the config dropped: only the hubs there are disabled.
        """
        results: list[TeardownItemReport] = []
        teardown = SecurityServicesTeardown(self.session_mgr, list, lambda _m: None)
        members = teardown.member_ids(bundle, accounts, audit_id, mgmt_id)
        still_on = bundle.org.security_services.securityhub.enabled
        for region in regions:
            if not self._delegated("securityhub", region, audit_id):
                continue
            if still_on:
                teardown.disable_hubs(results, region, audit_id, members, dry_run)
            else:
                teardown.disable_securityhub(
                    results, region, region == primary_region, audit_id, members, dry_run
                )
        return [r for r in results if r.action != "NOT_FOUND"]
