"""Delegated Administration Service for AWS GuardDuty and AWS Security Hub."""

import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import GuardDutyConfig, SecurityHubConfig, SecurityServicesConfig
from ..core.exceptions import GovernanceError
from ..core.logging import bind
from ..core.models import SecurityServiceReport

logger = logging.getLogger(__name__)


_GUARDDUTY_FEATURE_FLAGS = {
    "S3_DATA_EVENTS": "s3_data_events",
    "EKS_AUDIT_LOGS": "eks_audit_logs",
    "EBS_MALWARE_PROTECTION": "malware_protection",
    "RDS_LOGIN_EVENTS": "rds_login_events",
    "LAMBDA_NETWORK_LOGS": "lambda_network_logs",
}
_GUARDDUTY_FEATURE_NAMES = frozenset(_GUARDDUTY_FEATURE_FLAGS)


def _guardduty_features(config: GuardDutyConfig) -> list[dict[str, str]]:
    """Every optional feature tarmac manages, explicitly ENABLED or DISABLED.

    The CreateDetector documentation: "When you don't specify any `features`, with an exception to
    `RUNTIME_MONITORING`, all the optional features are enabled by default." Leaving the list out would switch on
    every paid protection plan.
    """
    return [
        {"Name": name, "Status": "ENABLED" if getattr(config.features, flag) else "DISABLED"}
        for name, flag in _GUARDDUTY_FEATURE_FLAGS.items()
    ]


class SecurityServicesService:
    """Manages delegated administration, detector creation, and finding aggregation for security services."""

    def __init__(self, session_mgr: AwsSessionManager) -> None:
        self.session_mgr = session_mgr

    def configure_security_services(
        self,
        config: SecurityServicesConfig,
        primary_region: str,
        all_regions: list[str],
        account_id_map: dict[str, str],
        dry_run: bool = False,
    ) -> list[SecurityServiceReport]:
        """Configure all enabled security services (GuardDuty, Security Hub)."""
        reports: list[SecurityServiceReport] = []
        audit_id = self._resolve_account_id(config.delegated_account, account_id_map)
        if not audit_id:
            msg = f"Delegated admin account '{config.delegated_account}' could not be resolved."
            logger.warning(msg)
            for sname, enabled in (
                ("GuardDuty", config.guardduty.enabled),
                ("SecurityHub", config.securityhub.enabled),
            ):
                if enabled:
                    reports.append(
                        SecurityServiceReport(
                            service_name=sname,
                            delegated_account=config.delegated_account,
                            status="FAILED",
                            message=msg,
                        )
                    )
            return reports

        if config.guardduty.enabled:
            reports.append(
                self.configure_guardduty(
                    audit_id, primary_region, all_regions, config.guardduty, dry_run=dry_run
                )
            )

        if config.securityhub.enabled:
            reports.append(
                self.configure_securityhub(
                    audit_id, primary_region, all_regions, config.securityhub, dry_run=dry_run
                )
            )

        return reports

    def _resolve_account_id(self, target_name: str, account_id_map: dict[str, str]) -> str | None:
        if target_name in account_id_map:
            return account_id_map[target_name]
        norm = normalize_account_name(target_name)
        for name, acct_id in account_id_map.items():
            if normalize_account_name(name) == norm:
                return acct_id
        return None

    def configure_guardduty(
        self,
        audit_id: str,
        primary_region: str,
        all_regions: list[str],
        config: GuardDutyConfig,
        dry_run: bool = False,
    ) -> SecurityServiceReport:
        """Delegate and configure GuardDuty across all designated regions."""
        if dry_run:
            audit(
                "delegate",
                f"guardduty:{audit_id}",
                Outcome.SUCCEEDED,
                f"Would delegate GuardDuty administration to account {audit_id} across {len(all_regions)} region(s)",
                dry_run=True,
                regions=all_regions,
            )
            return SecurityServiceReport(
                service_name="GuardDuty",
                delegated_account=audit_id,
                status="SIMULATED",
                regions=all_regions,
                message=f"[DRY-RUN] Would delegate GuardDuty to {audit_id} across {len(all_regions)} region(s)",
            )

        try:
            self._ensure_guardduty_admin(audit_id, primary_region)
        except ClientError as e:
            audit(
                "delegate",
                f"guardduty:{audit_id}",
                Outcome.FAILED,
                f"Could not register account {audit_id} as GuardDuty delegated administrator: {e}",
            )
            return SecurityServiceReport(
                service_name="GuardDuty",
                delegated_account=audit_id,
                status="FAILED",
                message=f"Failed to register delegated admin: {e}",
            )

        configured_regions: list[str] = []
        failed_regions: dict[str, str] = {}
        for reg in all_regions:
            try:
                with bind(region=reg):
                    # The delegated administrator is Regional: the primary Region was done above, every other
                    # Region needs its own registration before the audit account may configure members there.
                    if reg != primary_region:
                        self._ensure_guardduty_admin(audit_id, reg)
                    self._configure_guardduty_region(audit_id, reg, config)
                configured_regions.append(reg)
            except ClientError as e:
                audit(
                    "configure",
                    f"guardduty:{audit_id}:{reg}",
                    Outcome.FAILED,
                    f"Could not configure GuardDuty in {reg}: {e}",
                    region=reg,
                )
                failed_regions[reg] = str(e)

        return SecurityServiceReport(
            service_name="GuardDuty",
            delegated_account=audit_id,
            status="FAILED" if failed_regions else "ENABLED",
            regions=configured_regions,
            message=self._region_message(
                f"Delegated to {audit_id} with auto-enable", configured_regions, failed_regions
            ),
        )

    @staticmethod
    def _region_message(prefix: str, configured: list[str], failed: dict[str, str]) -> str:
        """Summarize per-region results; any failed region must be visible, never averaged away."""
        if not failed:
            return f"{prefix} in {len(configured)} region(s)"
        details = "; ".join(f"{region}: {reason}" for region, reason in failed.items())
        return f"{prefix} configured in {len(configured)} region(s) but FAILED in {len(failed)}: {details}"

    def _ensure_guardduty_admin(self, audit_id: str, region: str) -> None:
        """Register the delegated GuardDuty administrator in one Region, if not already registered.

        GuardDuty is Regional: "The delegated GuardDuty administrator accounts and their member accounts must be added
        through AWS Organizations in each desired Region", and it must be the same account in every Region.
        """
        gd_mgmt = self.session_mgr.get_client("guardduty", region_name=region)
        admins = gd_mgmt.list_organization_admin_accounts().get("AdminAccounts", [])
        already_registered = any(
            a.get("AdminAccountId") == audit_id and a.get("AdminStatus") == "ENABLED" for a in admins
        )
        if not already_registered:
            gd_mgmt.enable_organization_admin_account(AdminAccountId=audit_id)
            audit(
                "delegate",
                f"guardduty:{audit_id}",
                Outcome.SUCCEEDED,
                f"Registered account {audit_id} as GuardDuty delegated administrator in {region}",
                region=region,
            )

    def _configure_guardduty_region(self, audit_id: str, region: str, config: GuardDutyConfig) -> None:
        """Create detector and configure auto-enrollment in the Audit account for a single region."""
        gd_audit = self.session_mgr.get_member_client(audit_id, "guardduty", region_name=region)
        detectors = gd_audit.list_detectors().get("DetectorIds", [])
        wanted = _guardduty_features(config)
        if not detectors:
            create_resp = gd_audit.create_detector(
                Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES", Features=wanted
            )
            detector_id = str(create_resp.get("DetectorId", ""))
            audit(
                "create",
                f"guardduty-detector:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Created GuardDuty detector {detector_id} in {region}",
                detector_id=detector_id,
                region=region,
            )
        else:
            detector_id = str(detectors[0])
            self._reconcile_existing_detector(gd_audit, audit_id, region, detector_id, wanted)

        if config.auto_enable_members and detector_id:
            org_features = [
                {"Name": f["Name"], "AutoEnable": "ALL" if f["Status"] == "ENABLED" else "NONE"}
                for f in wanted
            ]
            try:
                gd_audit.update_organization_configuration(
                    DetectorId=detector_id, AutoEnableOrganizationMembers="ALL", Features=org_features
                )
            except ClientError:
                gd_audit.update_organization_configuration(
                    DetectorId=detector_id, AutoEnable=True, Features=org_features
                )
            audit(
                "configure",
                f"guardduty:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Turned on GuardDuty auto-enable for organization members in {region}",
                region=region,
            )

    @staticmethod
    def _reconcile_existing_detector(
        gd_audit: Any, audit_id: str, region: str, detector_id: str, wanted: list[dict[str, str]]
    ) -> None:
        """Turn on requested features of a detector tarmac did not create; never turn existing ones off.

        Switching a protection plan off on a detector someone else set up removes coverage they chose, so tarmac only
        reports the optional features that are on but not requested.
        """
        response = gd_audit.get_detector(DetectorId=detector_id)
        raw = response.get("Features", []) if isinstance(response, dict) else []
        current = (
            {f.get("Name"): f.get("Status") for f in raw if isinstance(f, dict)}
            if isinstance(raw, list)
            else {}
        )
        to_enable = [f for f in wanted if f["Status"] == "ENABLED" and current.get(f["Name"]) != "ENABLED"]
        if to_enable:
            gd_audit.update_detector(DetectorId=detector_id, Features=to_enable)
            audit(
                "configure",
                f"guardduty-detector:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Enabled GuardDuty features {[f['Name'] for f in to_enable]} in {region}",
                region=region,
            )
        requested = {f["Name"] for f in wanted if f["Status"] == "ENABLED"}
        extra = sorted(
            n for n, s in current.items() if s == "ENABLED" and n in _GUARDDUTY_FEATURE_NAMES - requested
        )
        if extra:
            audit(
                "configure",
                f"guardduty-detector:{audit_id}:{region}",
                Outcome.SKIPPED,
                f"GuardDuty features {extra} are on in {region} but not requested; left as they are because they "
                "are billed per use. Set them with the guardduty.features flags or turn them off in GuardDuty.",
                region=region,
            )

    def configure_securityhub(
        self,
        audit_id: str,
        primary_region: str,
        all_regions: list[str],
        config: SecurityHubConfig,
        dry_run: bool = False,
    ) -> SecurityServiceReport:
        """Delegate and configure Security Hub, standards, and finding aggregator."""
        if dry_run:
            audit(
                "delegate",
                f"securityhub:{audit_id}",
                Outcome.SUCCEEDED,
                f"Would delegate Security Hub administration to account {audit_id} across {len(all_regions)} region(s)",
                dry_run=True,
                regions=all_regions,
            )
            return SecurityServiceReport(
                service_name="SecurityHub",
                delegated_account=audit_id,
                status="SIMULATED",
                regions=all_regions,
                message=f"[DRY-RUN] Would delegate Security Hub to {audit_id} across {len(all_regions)} region(s)",
            )

        try:
            self._ensure_securityhub_admin(audit_id, primary_region)
        except ClientError as e:
            audit(
                "delegate",
                f"securityhub:{audit_id}",
                Outcome.FAILED,
                f"Could not register account {audit_id} as Security Hub delegated administrator: {e}",
            )
            return SecurityServiceReport(
                service_name="SecurityHub",
                delegated_account=audit_id,
                status="FAILED",
                message=f"Failed to register delegated admin: {e}",
            )

        configured_regions: list[str] = []
        failed_regions: dict[str, str] = {}
        for reg in all_regions:
            try:
                with bind(region=reg):
                    # Local configuration: the delegated administrator is set per Region (central configuration sets
                    # it in every linked Region itself).
                    if reg != primary_region:
                        self._ensure_securityhub_admin(audit_id, reg)
                    self._configure_securityhub_region(audit_id, reg, config)
                configured_regions.append(reg)
            except (ClientError, GovernanceError) as e:
                audit(
                    "configure",
                    f"securityhub:{audit_id}:{reg}",
                    Outcome.FAILED,
                    f"Could not configure Security Hub in {reg}: {e}",
                    region=reg,
                )
                failed_regions[reg] = str(e)

        try:
            sh_primary = self.session_mgr.get_member_client(
                audit_id, "securityhub", region_name=primary_region
            )
            self._ensure_finding_aggregator(sh_primary)
        except ClientError as e:
            audit(
                "create",
                "securityhub-finding-aggregator",
                Outcome.FAILED,
                f"Could not set up the Security Hub finding aggregator in {primary_region}: {e}",
            )
            failed_regions[f"{primary_region} (finding aggregator)"] = str(e)

        return SecurityServiceReport(
            service_name="SecurityHub",
            delegated_account=audit_id,
            status="FAILED" if failed_regions else "ENABLED",
            regions=configured_regions,
            message=self._region_message(
                f"Delegated to {audit_id} with standards {config.standards}",
                configured_regions,
                failed_regions,
            ),
        )

    def _ensure_securityhub_admin(self, audit_id: str, region: str) -> None:
        """Register the delegated Security Hub administrator in one Region, if not already registered.

        Security Hub CSPM "sets the delegated administrator in the current AWS Region only, and you must repeat the
        action in other Regions"; with central configuration it designates the same account in every linked Region.
        """
        sh_mgmt = self.session_mgr.get_client("securityhub", region_name=region)
        admins = sh_mgmt.list_organization_admin_accounts().get("AdminAccounts", [])
        already_registered = any(
            a.get("AccountId") == audit_id and a.get("Status") == "ENABLED" for a in admins
        )
        if not already_registered:
            sh_mgmt.enable_organization_admin_account(AdminAccountId=audit_id)
            audit(
                "delegate",
                f"securityhub:{audit_id}",
                Outcome.SUCCEEDED,
                f"Registered account {audit_id} as Security Hub delegated administrator in {region}",
                region=region,
            )

    def _configure_securityhub_region(self, audit_id: str, region: str, config: SecurityHubConfig) -> None:
        """Enable Security Hub, subscribe to standards, and configure auto-enrollment in a single region."""
        sh_audit = self.session_mgr.get_member_client(audit_id, "securityhub", region_name=region)
        try:
            sh_audit.describe_hub()
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            if err_code in ("ResourceNotFoundException", "InvalidAccessException"):
                sh_audit.enable_security_hub(EnableDefaultStandards=False)
                audit(
                    "enable",
                    f"securityhub:{audit_id}:{region}",
                    Outcome.SUCCEEDED,
                    f"Enabled Security Hub in {region}",
                    region=region,
                )
            else:
                raise

        self._ensure_standards(sh_audit, config.standards)

        if config.auto_enable_members:
            sh_audit.update_organization_configuration(AutoEnable=True, AutoEnableStandards="NONE")
            audit(
                "configure",
                f"securityhub:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Turned on Security Hub auto-enable for organization members in {region}",
                region=region,
            )

    def _ensure_standards(self, sh_client: Any, desired_standards: list[str]) -> None:
        """Ensure declared compliance standards (e.g. FSBP) are subscribed.

        Raises ClientError if AWS rejects a call and GovernanceError if a declared standard does not
        exist, so the region is reported as failed instead of silently lacking its standards.
        """
        available = sh_client.describe_standards().get("Standards", [])
        enabled_resp = sh_client.get_enabled_standards().get("StandardsSubscriptions", [])
        enabled_arns = {s.get("StandardsArn") for s in enabled_resp}

        for desired in desired_standards:
            norm_desired = desired.lower().replace("_", "-")
            matching_arn: str | None = None
            for std in available:
                std_arn = str(std.get("StandardsArn", ""))
                std_name = str(std.get("Name", "")).lower()
                if norm_desired in std_arn.lower() or norm_desired in std_name:
                    matching_arn = std_arn
                    break
            if matching_arn is None:
                raise GovernanceError(
                    f"Unknown Security Hub standard '{desired}'.",
                    details="Check security_services.securityhub.standards in organization.yaml.",
                )
            if matching_arn not in enabled_arns:
                sh_client.batch_enable_standards(
                    StandardsSubscriptionRequests=[{"StandardsArn": matching_arn}]
                )
                audit(
                    "enable",
                    f"securityhub-standard:{matching_arn}",
                    Outcome.SUCCEEDED,
                    f"Subscribed to Security Hub standard {matching_arn}",
                    standard=matching_arn,
                )

    def _ensure_finding_aggregator(self, sh_client: Any) -> None:
        """Ensure a Finding Aggregator exists in the primary region linking all member regions.

        ClientError propagates so the caller can report the Security Hub setup as incomplete.
        """
        aggregators = sh_client.list_finding_aggregators().get("FindingAggregators", [])
        if not aggregators:
            sh_client.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS")
            audit(
                "create",
                "securityhub-finding-aggregator",
                Outcome.SUCCEEDED,
                "Created Security Hub finding aggregator linking all regions",
            )
