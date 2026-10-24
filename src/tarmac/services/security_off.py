"""GuardDuty or Security Hub turned off in the config.

GuardDuty is suspended: monitoring and charges stop, findings are kept, and turning it back on resumes it. Security Hub
has no suspend, so it is disabled, and AWS then deletes its findings (archived after 30 days, active after 90).
"""

import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.models import TeardownItemReport
from .teardown_security import SecurityServicesTeardown

logger = logging.getLogger(__name__)

SECURITY_HUB_WARNING = (
    "Disabling Security Hub. AWS deletes its archived findings after 30 days and its active findings, insights and "
    "settings after 90 days; turning it back on before then restores them. Export any findings you need to keep first."
)


class SecurityServicesOff:
    def __init__(self, session_mgr: AwsSessionManager) -> None:
        self.session_mgr = session_mgr

    def _delegated(self, service: str, region: str, audit_id: str) -> bool:
        """Whether the audit account is still the service's delegated administrator, so tarmac has it running."""
        admins = self.session_mgr.get_client(service, region_name=region).list_organization_admin_accounts()
        key = "AdminAccountId" if service == "guardduty" else "AccountId"
        return any(a.get(key) == audit_id for a in admins.get("AdminAccounts", []))

    def suspend_guardduty(self, audit_id: str, regions: list[str], dry_run: bool) -> list[TeardownItemReport]:
        """Stop monitoring the members and the audit account's own detector, keeping the delegation and findings."""
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
                if gd.get_detector(DetectorId=detector).get("Status") == "DISABLED" and not members:
                    continue
                name = region
                if dry_run:
                    message = f"Would suspend it in the audit account and {len(members)} member accounts"
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
                    f"Suspended it in {len(members)} member accounts and the audit account; findings are kept"
                )
                try:
                    gd.update_detector(DetectorId=detector, Enable=False)
                except ClientError as e:
                    # The members carry the cost; the audit account's own detector is reported, not retried as a failure.
                    message = f"Suspended it in {len(members)} member accounts; it stays on in the audit account: {e}"
                results.append(TeardownItemReport("GuardDuty", name, "audit", audit_id, "DELETED", message))
        return results

    def disable_securityhub(
        self,
        bundle: ConfigBundle,
        audit_id: str,
        regions: list[str],
        accounts: dict[str, str],
        mgmt_id: str,
        dry_run: bool,
    ) -> list[TeardownItemReport]:
        """Disable Security Hub the way `destroy --disable-security-services` does, in Regions where tarmac runs it."""
        results: list[TeardownItemReport] = []
        teardown = SecurityServicesTeardown(self.session_mgr, list, lambda _m: None)
        members = teardown.member_ids(bundle, accounts, audit_id, mgmt_id)
        for region in regions:
            if self._delegated("securityhub", region, audit_id):
                teardown.disable_securityhub(
                    results, region, region == regions[0], audit_id, members, dry_run
                )
        return [r for r in results if r.action != "NOT_FOUND"]
