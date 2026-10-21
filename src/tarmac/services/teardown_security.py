"""Opt-in teardown of the security services tarmac delegates (GuardDuty, Security Hub, Config, IAM).

Disabling these deletes finding history and stops detection, so it only runs when the operator passes
``--disable-security-services``. Only services enabled in the configuration, delegated to the configured
audit account, are touched, and only in the declared regions and declared accounts.
"""

import logging
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.models import TeardownItemReport
from .security_central import POLICY_NAME

logger = logging.getLogger(__name__)

CONFIG_PRINCIPALS = ("config-multiaccountsetup.amazonaws.com", "config.amazonaws.com")
IAM_PRINCIPAL = "iam.amazonaws.com"
_NOT_ENABLED = {"InvalidAccessException", "ResourceNotFoundException", "BadRequestException"}


def _code(e: ClientError) -> str:
    return str(e.response.get("Error", {}).get("Code", ""))


class SecurityServicesTeardown:
    """Reverses what SecurityServicesService and the delegated-admin registrations set up."""

    def __init__(
        self,
        session_mgr: AwsSessionManager,
        new_results: Callable[[], list[TeardownItemReport]],
        notify: Callable[[str], None],
    ) -> None:
        self.session_mgr = session_mgr
        self._new_results = new_results
        self._notify = notify

    def run(
        self,
        bundle: ConfigBundle,
        primary_region: str,
        accounts: dict[str, str],
        mgmt_id: str,
        dry_run: bool = False,
    ) -> list[TeardownItemReport]:
        results = self._new_results()
        sec = bundle.org.security_services
        audit_id = bundle.resolve_account_id(sec.delegated_account, accounts)
        regions = [primary_region, *bundle.org.organization.additional_regions]
        member_ids = {
            acct_id
            for a in bundle.accounts.accounts
            if (acct_id := bundle.resolve_account_id(a.name, accounts)) and acct_id != audit_id
        }
        if mgmt_id:
            member_ids.add(mgmt_id)

        if not audit_id:
            results.append(
                self._item(
                    "Security Services",
                    sec.delegated_account,
                    sec.delegated_account,
                    "",
                    "SKIPPED",
                    "Delegated admin account not resolved in active accounts",
                )
            )
            return results

        for region in regions:
            if sec.securityhub.enabled:
                self._securityhub(results, region, region == primary_region, audit_id, member_ids, dry_run)
            if sec.guardduty.enabled:
                self._guardduty(results, region, audit_id, member_ids, dry_run)

        principals: list[str] = list(CONFIG_PRINCIPALS)
        rm = bundle.org.root_access_management
        if rm.enabled and rm.delegated_admin_account:
            iam_admin = bundle.resolve_account_id(rm.delegated_admin_account, accounts)
            if iam_admin:
                self._deregister(results, iam_admin, rm.delegated_admin_account, [IAM_PRINCIPAL], dry_run)
        self._deregister(results, audit_id, sec.delegated_account, principals, dry_run)
        return results

    @staticmethod
    def _item(
        rtype: str, name: str, acct_name: str, acct_id: str, action: str, message: str
    ) -> TeardownItemReport:
        return TeardownItemReport(rtype, name, acct_name, acct_id, action, message)

    def _record(
        self,
        results: list[TeardownItemReport],
        rtype: str,
        name: str,
        acct_id: str,
        step: Callable[[], bool],
        dry_run: bool,
        verb: str,
    ) -> None:
        """Run one idempotent step. `step` returns False when there was nothing to do."""
        if dry_run:
            results.append(self._item(rtype, name, acct_id, acct_id, "SIMULATED", f"Would {verb}"))
            return
        try:
            changed = step()
        except ClientError as e:
            logger.warning("%s %s (%s): %s", verb, name, acct_id, e)
            results.append(self._item(rtype, name, acct_id, acct_id, "FAILED", f"Could not {verb}: {e}"))
            return
        results.append(
            self._item(
                rtype,
                name,
                acct_id,
                acct_id,
                "DELETED" if changed else "NOT_FOUND",
                verb.capitalize() if changed else "Not enabled",
            )
        )

    def _securityhub(
        self,
        results: list[TeardownItemReport],
        region: str,
        is_primary: bool,
        audit_id: str,
        member_ids: set[str],
        dry_run: bool,
    ) -> None:
        self._notify(f"Disabling Security Hub organization settings in {region}...")
        mgr = self.session_mgr

        def stop_auto_enable() -> bool:
            sh = mgr.get_member_client(audit_id, "securityhub", region_name=region)
            try:
                sh.update_organization_configuration(AutoEnable=False, AutoEnableStandards="NONE")
            except ClientError as e:
                if _code(e) in _NOT_ENABLED:
                    return False
                raise
            return True

        def drop_aggregator() -> bool:
            sh = mgr.get_member_client(audit_id, "securityhub", region_name=region)
            removed = False
            try:
                for agg in sh.list_finding_aggregators().get("FindingAggregators", []):
                    sh.delete_finding_aggregator(FindingAggregatorArn=agg["FindingAggregatorArn"])
                    removed = True
            except ClientError as e:
                if _code(e) not in _NOT_ENABLED:
                    raise
            return removed

        def deregister_admin() -> bool:
            sh = mgr.get_client("securityhub", region_name=region)
            admins = sh.list_organization_admin_accounts().get("AdminAccounts", [])
            if not any(a.get("AccountId") == audit_id for a in admins):
                return False
            sh.disable_organization_admin_account(AdminAccountId=audit_id)
            return True

        if is_primary:
            self._record(
                results,
                "Security Hub central configuration",
                POLICY_NAME,
                audit_id,
                lambda: self._leave_central_configuration(audit_id, region),
                dry_run,
                "remove the central configuration policy and return to local configuration",
            )
        self._record(
            results,
            f"Security Hub auto-enable ({region})",
            "organization configuration",
            audit_id,
            stop_auto_enable,
            dry_run,
            "turn off Security Hub auto-enable",
        )
        if is_primary:
            self._record(
                results,
                "Security Hub finding aggregator",
                region,
                audit_id,
                drop_aggregator,
                dry_run,
                "delete the finding aggregator",
            )
        self._record(
            results,
            f"Security Hub delegated admin ({region})",
            audit_id,
            audit_id,
            deregister_admin,
            dry_run,
            "deregister Security Hub delegated administrator",
        )
        for acct in sorted({audit_id, *member_ids}):
            self._record(
                results,
                f"Security Hub ({region})",
                "hub",
                acct,
                lambda acct=acct: self._disable_hub(acct, region),
                dry_run,
                "disable Security Hub",
            )

    def _leave_central_configuration(self, audit_id: str, region: str) -> bool:
        """Remove tarmac's policy and switch back to local configuration (central mode locks the settings)."""
        mgr = self.session_mgr
        sh = mgr.get_member_client(audit_id, "securityhub", region_name=region)
        try:
            config = sh.describe_organization_configuration().get("OrganizationConfiguration", {})
        except ClientError as e:
            if _code(e) in _NOT_ENABLED:
                return False
            raise
        if config.get("ConfigurationType") != "CENTRAL":
            return False
        policy_ids = [
            summary["Id"]
            for page in sh.get_paginator("list_configuration_policies").paginate()
            for summary in page.get("ConfigurationPolicySummaries", [])
            if summary.get("Name") == POLICY_NAME
        ]
        roots = mgr.get_client("organizations").list_roots().get("Roots", []) if policy_ids else []
        for policy_id in policy_ids:
            if roots:
                sh.start_configuration_policy_disassociation(
                    ConfigurationPolicyIdentifier=policy_id, Target={"RootId": roots[0]["Id"]}
                )
            sh.delete_configuration_policy(Identifier=policy_id)
        sh.update_organization_configuration(
            AutoEnable=False, OrganizationConfiguration={"ConfigurationType": "LOCAL"}
        )
        return True

    def _disable_hub(self, account_id: str, region: str) -> bool:
        sh = self.session_mgr.get_member_client(account_id, "securityhub", region_name=region)
        try:
            sh.disable_security_hub()
        except ClientError as e:
            if _code(e) in _NOT_ENABLED:
                return False
            raise
        return True

    def _guardduty(
        self,
        results: list[TeardownItemReport],
        region: str,
        audit_id: str,
        member_ids: set[str],
        dry_run: bool,
    ) -> None:
        self._notify(f"Disabling GuardDuty organization settings in {region}...")
        mgr = self.session_mgr

        def stop_auto_enable() -> bool:
            gd = mgr.get_member_client(audit_id, "guardduty", region_name=region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            for det in detectors:
                try:
                    gd.update_organization_configuration(DetectorId=det, AutoEnableOrganizationMembers="NONE")
                except ClientError as e:
                    if _code(e) != "BadRequestException":
                        raise
                    gd.update_organization_configuration(DetectorId=det, AutoEnable=False)
            return bool(detectors)

        def deregister_admin() -> bool:
            gd = mgr.get_client("guardduty", region_name=region)
            admins = gd.list_organization_admin_accounts().get("AdminAccounts", [])
            if not any(a.get("AdminAccountId") == audit_id for a in admins):
                return False
            gd.disable_organization_admin_account(AdminAccountId=audit_id)
            return True

        self._record(
            results,
            f"GuardDuty auto-enable ({region})",
            "organization configuration",
            audit_id,
            stop_auto_enable,
            dry_run,
            "turn off GuardDuty auto-enable",
        )
        self._record(
            results,
            f"GuardDuty delegated admin ({region})",
            audit_id,
            audit_id,
            deregister_admin,
            dry_run,
            "deregister GuardDuty delegated administrator",
        )
        for acct in sorted({audit_id, *member_ids}):
            self._record(
                results,
                f"GuardDuty detector ({region})",
                "detector",
                acct,
                lambda acct=acct: self._delete_detectors(acct, region),
                dry_run,
                "delete GuardDuty detector",
            )

    def _delete_detectors(self, account_id: str, region: str) -> bool:
        gd: Any = self.session_mgr.get_member_client(account_id, "guardduty", region_name=region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        for det in detectors:
            gd.delete_detector(DetectorId=det)
        return bool(detectors)

    def _deregister(
        self,
        results: list[TeardownItemReport],
        account_id: str,
        account_name: str,
        principals: list[str],
        dry_run: bool,
    ) -> None:
        org = self.session_mgr.get_client("organizations")
        for principal in principals:

            def step(principal: str = principal) -> bool:
                try:
                    registered = org.list_delegated_administrators(ServicePrincipal=principal).get(
                        "DelegatedAdministrators", []
                    )
                except ClientError as e:
                    if _code(e) in {"ServiceException", "UnsupportedAPIEndpointException"}:
                        return False
                    raise
                if not any(a.get("Id") == account_id for a in registered):
                    return False
                org.deregister_delegated_administrator(AccountId=account_id, ServicePrincipal=principal)
                return True

            self._record(
                results,
                "Delegated Administrator",
                principal,
                account_id,
                step,
                dry_run,
                f"deregister {account_name} as delegated administrator for {principal}",
            )
