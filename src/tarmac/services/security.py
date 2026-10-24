"""Delegated Administration Service for AWS GuardDuty and AWS Security Hub."""

import logging
import time
from typing import Any

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import GuardDutyConfig, SecurityHubConfig, SecurityServicesConfig
from ..core.exceptions import GovernanceError
from ..core.logging import bind
from ..core.models import SecurityServiceReport
from ..core.org_accounts import is_active, iter_accounts
from ..core.text import plural
from .guardduty_export import FindingsExport, reconcile_findings_export
from .security_central import (
    POLICY_NAME,
    SecurityHubCentralConfiguration,
    all_standards,
    resolve_standard_arn,
)

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
        findings_export: FindingsExport | None = None,
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
                    audit_id, primary_region, all_regions, config.guardduty, findings_export
                )
            )

        if config.securityhub.enabled:
            reports.append(
                self.configure_securityhub(audit_id, primary_region, all_regions, config.securityhub)
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
        findings_export: FindingsExport | None = None,
    ) -> SecurityServiceReport:
        """Delegate and configure GuardDuty across all designated regions.

        ``findings_export`` is reconciled on each Region's audit detector; None leaves exports untouched.
        """
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
                    self._configure_guardduty_region(audit_id, reg, config, findings_export)
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
            return f"{prefix} in {plural(len(configured), 'region')}"
        details = "; ".join(f"{region}: {reason}" for region, reason in failed.items())
        return f"{prefix} configured in {plural(len(configured), 'region')} but FAILED in {len(failed)}: {details}"

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

    def _configure_guardduty_region(
        self,
        audit_id: str,
        region: str,
        config: GuardDutyConfig,
        findings_export: FindingsExport | None = None,
    ) -> None:
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

        if findings_export is not None and detector_id:
            reconcile_findings_export(gd_audit, detector_id, findings_export, region)

        if config.auto_enable_members and detector_id:
            self._resume_suspended_members(gd_audit, detector_id, audit_id, region)
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
            self._ensure_management_detector(region, wanted)
            self._add_existing_guardduty_members(gd_audit, detector_id, audit_id, region)

    @staticmethod
    def _create_guardduty_members(
        gd_audit: Any, detector_id: str, accounts: list[dict[str, str]]
    ) -> list[str]:
        """Add members; returns the refusals. GuardDuty takes a few minutes to see a new management detector."""
        waited = 0.0
        while True:
            response = gd_audit.create_members(DetectorId=detector_id, AccountDetails=accounts)
            unprocessed = response.get("UnprocessedAccounts", [])
            waiting = {u["AccountId"] for u in unprocessed if "must first enable GuardDuty" in u["Result"]}
            if not waiting or waited >= 300:
                return [f"{u['AccountId']}: {u['Result']}" for u in unprocessed]
            accounts = [a for a in accounts if a["AccountId"] in waiting]
            time.sleep(15)
            waited += 15

    def _ensure_management_detector(self, region: str, wanted: list[dict[str, str]]) -> None:
        """GuardDuty only adds the management account as a member once it has a detector of its own."""
        gd_mgmt = self.session_mgr.get_client("guardduty", region_name=region)
        if gd_mgmt.list_detectors().get("DetectorIds"):
            return
        gd_mgmt.create_detector(Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES", Features=wanted)
        audit(
            "create",
            f"guardduty-detector:management:{region}",
            Outcome.SUCCEEDED,
            f"Turned on GuardDuty in the management account in {region}",
            region=region,
        )

    @staticmethod
    def _member_status(gd_audit: Any, detector_id: str) -> dict[str, str]:
        return {
            str(m["AccountId"]): str(m.get("RelationshipStatus"))
            for page in gd_audit.get_paginator("list_members").paginate(
                DetectorId=detector_id, OnlyAssociated="false"
            )
            for m in page.get("Members", [])
        }

    def _resume_suspended_members(self, gd_audit: Any, detector_id: str, audit_id: str, region: str) -> None:
        """Restart members suspended by turning GuardDuty off in the config, keeping their findings.

        AWS rejects StartMonitoringMembers while auto-enable is set to all accounts, so it is turned off first; the
        caller turns it back on straight after.
        """
        paused = [a for a, s in self._member_status(gd_audit, detector_id).items() if s == "Disabled"]
        if not paused:
            return
        try:
            gd_audit.update_organization_configuration(
                DetectorId=detector_id, AutoEnableOrganizationMembers="NONE"
            )
        except ClientError:
            gd_audit.update_organization_configuration(DetectorId=detector_id, AutoEnable=False)
        for start in range(0, len(paused), 50):
            gd_audit.start_monitoring_members(DetectorId=detector_id, AccountIds=paused[start : start + 50])
        audit(
            "configure",
            f"guardduty-members:{audit_id}:{region}",
            Outcome.SUCCEEDED,
            f"Resumed GuardDuty in {plural(len(paused), 'member account')} in {region}",
            region=region,
        )

    def _add_existing_guardduty_members(
        self, gd_audit: Any, detector_id: str, audit_id: str, region: str
    ) -> None:
        """Add the organization's existing accounts as members: auto-enable only covers accounts that join later.

        An account whose membership is not Enabled (for example Removed by an earlier teardown) is added again.
        """
        status = self._member_status(gd_audit, detector_id)
        missing = [
            {"AccountId": a["Id"], "Email": a["Email"]}
            for a in iter_accounts(self.session_mgr.get_client("organizations"))
            if is_active(a) and a["Id"] != audit_id and status.get(a["Id"]) not in ("Enabled", "Disabled")
        ]
        refused: list[str] = []
        for start in range(0, len(missing), 50):
            refused += self._create_guardduty_members(gd_audit, detector_id, missing[start : start + 50])
        if len(missing) > len(refused):
            audit(
                "configure",
                f"guardduty-members:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Added {plural(len(missing) - len(refused), 'existing account')} to GuardDuty in {region}",
                region=region,
            )
        if refused:
            audit(
                "configure",
                f"guardduty-members:{audit_id}:{region}",
                Outcome.FAILED,
                f"GuardDuty did not add {plural(len(refused), 'account')} in {region}: {'; '.join(refused)}",
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
        if isinstance(response, dict) and response.get("Status") == "DISABLED":
            # Suspended by turning GuardDuty off in the config.
            gd_audit.update_detector(DetectorId=detector_id, Enable=True)
            audit(
                "configure",
                f"guardduty-detector:{audit_id}:{region}",
                Outcome.SUCCEEDED,
                f"Resumed GuardDuty in the audit account in {region}",
                region=region,
            )
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
    ) -> SecurityServiceReport:
        """Delegate and configure Security Hub, standards, and finding aggregator."""
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

    def _configure_securityhub_central(
        self, audit_id: str, home_region: str, all_regions: list[str], config: SecurityHubConfig
    ) -> SecurityServiceReport:
        """Central configuration: enable the hub and aggregator in the home Region, then apply one policy to the root."""
        try:
            with bind(region=home_region):
                self._require_home_region_not_opt_in(home_region)
                sh = self.session_mgr.get_member_client(audit_id, "securityhub", region_name=home_region)
                self._ensure_hub_enabled(sh, audit_id, home_region)
                # A policy cannot be applied to the management account until it has Security Hub itself.
                mgmt_id = str(self.session_mgr.get_caller_identity()["Account"])
                for region in all_regions:
                    mgmt_sh = self.session_mgr.get_client("securityhub", region_name=region)
                    self._ensure_hub_enabled(mgmt_sh, mgmt_id, region)
                # Central policies take effect in every linked Region, so link only the declared ones.
                self._ensure_finding_aggregator(sh, [r for r in all_regions if r != home_region])
                enabled = SecurityHubCentralConfiguration(
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
                f"Delegated to {audit_id}; central configuration from {home_region} applies "
                f"{', '.join(enabled) or 'no standards'} to the organization in {', '.join(all_regions)}"
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
        status = regions[0].get("OptInStatus") if regions else None
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
        available = all_standards(sh_client)
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
