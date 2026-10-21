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
from .security_central import POLICY_NAME, SecurityHubCentralConfiguration, resolve_standard_arn

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

    def _ensure_guardduty_admin(self, audit_id: str, primary_region: str) -> None:
        """Enable GuardDuty organization admin in the Management Account if not already registered."""
        gd_mgmt = self.session_mgr.get_client("guardduty", region_name=primary_region)
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
                f"Registered account {audit_id} as GuardDuty delegated administrator",
            )

    def _configure_guardduty_region(self, audit_id: str, region: str, config: GuardDutyConfig) -> None:
        """Create detector and configure auto-enrollment in the Audit account for a single region."""
        gd_audit = self.session_mgr.get_member_client(audit_id, "guardduty", region_name=region)
        detectors = gd_audit.list_detectors().get("DetectorIds", [])
        if not detectors:
            create_resp = gd_audit.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES")
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

        if config.auto_enable_members and detector_id:
            try:
                gd_audit.update_organization_configuration(
                    DetectorId=detector_id, AutoEnableOrganizationMembers="ALL"
                )
            except ClientError:
                gd_audit.update_organization_configuration(DetectorId=detector_id, AutoEnable=True)
            audit(
                "configure",
                f"guardduty:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Turned on GuardDuty auto-enable for organization members in {region}",
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

        if config.central_configuration and config.auto_enable_members:
            return self._configure_securityhub_central(audit_id, primary_region, all_regions, config)

        configured_regions: list[str] = []
        failed_regions: dict[str, str] = {}
        for reg in all_regions:
            try:
                with bind(region=reg):
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

    def _configure_securityhub_central(
        self, audit_id: str, home_region: str, all_regions: list[str], config: SecurityHubConfig
    ) -> SecurityServiceReport:
        """Central configuration: enable the hub and aggregator in the home Region, then apply one policy to the root."""
        try:
            with bind(region=home_region):
                self._require_home_region_not_opt_in(home_region)
                sh = self.session_mgr.get_member_client(audit_id, "securityhub", region_name=home_region)
                self._ensure_hub_enabled(sh, audit_id, home_region)
                # Central policies take effect in every linked Region, so link only the declared ones.
                self._ensure_finding_aggregator(sh, [r for r in all_regions if r != home_region])
                SecurityHubCentralConfiguration(
                    sh,
                    policy_name=POLICY_NAME,
                    standards=config.standards,
                    root_id=self._root_id(),
                ).apply()
        except (ClientError, GovernanceError) as e:
            audit(
                "configure",
                f"securityhub:{audit_id}:{home_region}",
                Outcome.FAILED,
                f"Could not set up Security Hub central configuration from {home_region}: {e}",
                region=home_region,
            )
            return SecurityServiceReport(
                service_name="SecurityHub",
                delegated_account=audit_id,
                status="FAILED",
                regions=[],
                message=f"Central configuration failed in {home_region}: {e}",
            )
        return SecurityServiceReport(
            service_name="SecurityHub",
            delegated_account=audit_id,
            status="ENABLED",
            regions=all_regions,
            message=(
                f"Delegated to {audit_id}; central configuration from {home_region} applies standards "
                f"{config.standards} to the organization in {', '.join(all_regions)}"
            ),
        )

    def _require_home_region_not_opt_in(self, region: str) -> None:
        """Central configuration cannot use an opt-in Region as its home Region.

        The Security Hub documentation: "The home Region cannot be a Region that AWS has designated as an opt-in
        Region." EC2 reports such Regions as `opted-in` or `not-opted-in`; default Regions are `opt-in-not-required`.
        """
        try:
            regions = (
                self.session_mgr.get_client("ec2", region_name=region)
                .describe_regions(AllRegions=True, RegionNames=[region])
                .get("Regions", [])
            )
        except ClientError:
            return  # Cannot tell; Security Hub will refuse an opt-in Region itself.
        status = regions[0].get("OptInStatus") if isinstance(regions, list) and regions else None
        if status in ("opted-in", "not-opted-in"):
            raise GovernanceError(
                f"{region} is an opt-in Region, and Security Hub central configuration cannot use one as its home "
                "Region. Choose a default Region as organization.primary_region, or set "
                "security_services.securityhub.central_configuration: false."
            )

    def _root_id(self) -> str:
        roots = self.session_mgr.get_client("organizations").list_roots().get("Roots", [])
        if not roots:
            raise GovernanceError("Could not find the organization root.")
        return str(roots[0]["Id"])

    def _ensure_hub_enabled(self, sh_audit: Any, audit_id: str, region: str) -> None:
        try:
            sh_audit.describe_hub()
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            if err_code not in ("ResourceNotFoundException", "InvalidAccessException"):
                raise
            sh_audit.enable_security_hub(EnableDefaultStandards=False)
            audit(
                "enable",
                f"securityhub:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Enabled Security Hub in {region}",
                region=region,
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
            audit(
                "delegate",
                f"securityhub:{audit_id}",
                Outcome.SUCCEEDED,
                f"Registered account {audit_id} as Security Hub delegated administrator",
            )

    def _configure_securityhub_region(self, audit_id: str, region: str, config: SecurityHubConfig) -> None:
        """Enable Security Hub, subscribe to standards, and configure auto-enrollment in a single region."""
        sh_audit = self.session_mgr.get_member_client(audit_id, "securityhub", region_name=region)
        self._ensure_hub_enabled(sh_audit, audit_id, region)

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
            matching_arn = resolve_standard_arn(available, desired)
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

    def _ensure_finding_aggregator(self, sh_client: Any, linked_regions: list[str] | None = None) -> None:
        """Ensure a Finding Aggregator exists in the primary region.

        With ``linked_regions`` None it links every Region (local configuration only aggregates findings). With a
        list it links exactly those Regions (none, if empty): under central configuration the linked Regions are
        where the policy turns Security Hub on in every account, so they must be the Regions you declared.

        ClientError propagates so the caller can report the Security Hub setup as incomplete.
        """
        mode, regions = "ALL_REGIONS", []
        if linked_regions is not None:
            mode, regions = (
                ("SPECIFIED_REGIONS", sorted(linked_regions)) if linked_regions else ("NO_REGIONS", [])
            )
        settings: dict[str, Any] = {"RegionLinkingMode": mode, **({"Regions": regions} if regions else {})}

        aggregators = sh_client.list_finding_aggregators().get("FindingAggregators", [])
        if aggregators and linked_regions is not None:
            arn = aggregators[0]["FindingAggregatorArn"]
            current = sh_client.get_finding_aggregator(FindingAggregatorArn=arn)
            if (current.get("RegionLinkingMode"), sorted(current.get("Regions", []))) != (mode, regions):
                sh_client.update_finding_aggregator(FindingAggregatorArn=arn, **settings)
                audit(
                    "update",
                    "securityhub-finding-aggregator",
                    Outcome.SUCCEEDED,
                    f"Security Hub finding aggregator now links {', '.join(regions) or 'no Regions'} ({mode})",
                    regions=regions,
                )
            return
        if not aggregators:
            sh_client.create_finding_aggregator(**settings)
            audit(
                "create",
                "securityhub-finding-aggregator",
                Outcome.SUCCEEDED,
                "Created Security Hub finding aggregator linking "
                + (", ".join(regions) if linked_regions is not None else "all regions")
                + (" (none)" if mode == "NO_REGIONS" else ""),
            )
