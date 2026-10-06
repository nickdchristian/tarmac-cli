"""Delegated Administration Service for AWS GuardDuty and AWS Security Hub."""

import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import GuardDutyConfig, SecurityHubConfig, SecurityServicesConfig
from ..core.models import SecurityServiceReport

logger = logging.getLogger(__name__)


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
        """Resolve account name to account ID case-insensitively."""
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
            logger.warning("Could not register GuardDuty delegated admin: %s", e)
            return SecurityServiceReport(
                service_name="GuardDuty",
                delegated_account=audit_id,
                status="FAILED",
                message=f"Failed to register delegated admin: {e}",
            )

        configured_regions: list[str] = []
        for reg in all_regions:
            try:
                self._configure_guardduty_region(audit_id, reg, config)
                configured_regions.append(reg)
            except ClientError as e:
                logger.warning("Could not configure GuardDuty in region %s: %s", reg, e)

        return SecurityServiceReport(
            service_name="GuardDuty",
            delegated_account=audit_id,
            status="ENABLED",
            regions=configured_regions,
            message=f"Delegated to {audit_id} with auto-enable in {len(configured_regions)} region(s)",
        )

    def _ensure_guardduty_admin(self, audit_id: str, primary_region: str) -> None:
        """Enable GuardDuty organization admin in the Management Account if not already registered."""
        gd_mgmt = self.session_mgr.get_client("guardduty", region_name=primary_region)
        admins = gd_mgmt.list_organization_admin_accounts().get("AdminAccounts", [])
        already_registered = any(
            a.get("AdminAccountId") == audit_id and a.get("AdminStatus") == "ENABLED" for a in admins
        )
        if not already_registered:
            gd_mgmt.enable_organization_admin_account(AdminAccountId=audit_id)
            logger.info("Registered account %s as GuardDuty delegated administrator.", audit_id)

    def _configure_guardduty_region(self, audit_id: str, region: str, config: GuardDutyConfig) -> None:
        """Create detector and configure auto-enrollment in the Audit account for a single region."""
        gd_audit = self.session_mgr.get_member_client(audit_id, "guardduty", region_name=region)
        detectors = gd_audit.list_detectors().get("DetectorIds", [])
        if not detectors:
            create_resp = gd_audit.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")
            detector_id = str(create_resp.get("DetectorId", ""))
            logger.info("Created GuardDuty detector in %s (%s)", region, detector_id)
        else:
            detector_id = str(detectors[0])

        if config.auto_enable_members and detector_id:
            try:
                gd_audit.update_organization_configuration(
                    DetectorId=detector_id, AutoEnableOrganizationMembers="ALL"
                )
            except ClientError:
                gd_audit.update_organization_configuration(DetectorId=detector_id, AutoEnable=True)
            logger.info("Configured GuardDuty auto-enable members in region %s", region)

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
            logger.warning("Could not register Security Hub delegated admin: %s", e)
            return SecurityServiceReport(
                service_name="SecurityHub",
                delegated_account=audit_id,
                status="FAILED",
                message=f"Failed to register delegated admin: {e}",
            )

        configured_regions: list[str] = []
        for reg in all_regions:
            try:
                self._configure_securityhub_region(audit_id, reg, config)
                configured_regions.append(reg)
            except ClientError as e:
                logger.warning("Could not configure Security Hub in region %s: %s", reg, e)

        try:
            sh_primary = self.session_mgr.get_member_client(
                audit_id, "securityhub", region_name=primary_region
            )
            self._ensure_finding_aggregator(sh_primary)
        except ClientError as e:
            logger.warning("Could not setup Security Hub finding aggregator in %s: %s", primary_region, e)

        return SecurityServiceReport(
            service_name="SecurityHub",
            delegated_account=audit_id,
            status="ENABLED",
            regions=configured_regions,
            message=f"Delegated to {audit_id} with standards {config.standards} in {len(configured_regions)} region(s)",
        )

    def _ensure_securityhub_admin(self, audit_id: str, primary_region: str) -> None:
        """Enable Security Hub organization admin in the Management Account if not already registered."""
        sh_mgmt = self.session_mgr.get_client("securityhub", region_name=primary_region)
        admins = sh_mgmt.list_organization_admin_accounts().get("AdminAccounts", [])
        already_registered = any(
            a.get("AccountId") == audit_id and a.get("Status") == "ENABLED" for a in admins
        )
        if not already_registered:
            sh_mgmt.enable_organization_admin_account(AdminAccountId=audit_id)
            logger.info("Registered account %s as Security Hub delegated administrator.", audit_id)

    def _configure_securityhub_region(self, audit_id: str, region: str, config: SecurityHubConfig) -> None:
        """Enable Security Hub, subscribe to standards, and configure auto-enrollment in a single region."""
        sh_audit = self.session_mgr.get_member_client(audit_id, "securityhub", region_name=region)
        try:
            sh_audit.describe_hub()
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            if err_code in ("ResourceNotFoundException", "InvalidAccessException"):
                sh_audit.enable_security_hub(EnableDefaultStandards=False)
                logger.info("Enabled Security Hub in region %s", region)
            else:
                raise

        self._ensure_standards(sh_audit, config.standards)

        if config.auto_enable_members:
            try:
                sh_audit.update_organization_configuration(AutoEnable=True, AutoEnableStandards="NONE")
            except ClientError as e:
                logger.warning("Could not set Security Hub auto-enable in %s: %s", region, e)

    def _ensure_standards(self, sh_client: Any, desired_standards: list[str]) -> None:
        """Ensure declared compliance standards (e.g. FSBP) are subscribed."""
        try:
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
                if matching_arn and matching_arn not in enabled_arns:
                    sh_client.batch_enable_standards(
                        StandardsSubscriptionRequests=[{"StandardsArn": matching_arn}]
                    )
                    logger.info("Enabled Security Hub standard: %s", matching_arn)
        except ClientError as e:
            logger.warning("Could not reconcile Security Hub standards: %s", e)

    def _ensure_finding_aggregator(self, sh_client: Any) -> None:
        """Ensure a Finding Aggregator is created in the primary region linking all member regions."""
        try:
            aggregators = sh_client.list_finding_aggregators().get("FindingAggregators", [])
            if not aggregators:
                sh_client.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS")
                logger.info("Created Security Hub Finding Aggregator linking ALL_REGIONS.")
        except ClientError as e:
            logger.warning("Could not create Security Hub finding aggregator: %s", e)
