"""Preflight checks of the organization and the management account."""

import logging

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import PreflightCheckResult, PreflightCheckStatus
from ..core.org_accounts import is_active, iter_accounts
from ..core.text import plural

logger = logging.getLogger(__name__)


class OrganizationChecks:
    """Organization, root user, contacts and quota checks."""

    session_mgr: AwsSessionManager
    bundle: ConfigBundle

    def check_organization_status(self) -> PreflightCheckResult:
        """Verify that caller is authenticated as the Management Account with All Features enabled."""
        try:
            caller = self.session_mgr.get_caller_identity()
            caller_acct = caller.get("Account", "")
            org_client = self.session_mgr.get_client("organizations")
            org_desc = org_client.describe_organization()["Organization"]
            master_id = org_desc.get("MasterAccountId", "")
            feature_set = org_desc.get("FeatureSet", "")

            if caller_acct != master_id:
                return PreflightCheckResult(
                    name="AWS Organization Role",
                    target="Management Account",
                    status=PreflightCheckStatus.FAIL,
                    live_value=f"Member Account ({caller_acct})",
                    action_required=f"Authenticate using credentials for Management Account ({master_id})",
                )

            if feature_set != "ALL":
                return PreflightCheckResult(
                    name="AWS Organization Role",
                    target="Management Account",
                    status=PreflightCheckStatus.WARN,
                    live_value=f"Consolidated Billing ({feature_set})",
                    action_required="Enable 'All Features' in AWS Organizations before multi-account governance",
                )

            return PreflightCheckResult(
                name="AWS Organization Role",
                target="Management Account",
                status=PreflightCheckStatus.PASS,
                live_value=f"Management ({master_id}) - All Features",
            )
        except AWS_ERRORS as e:
            logger.debug("Organization status check: %s", e)
            return PreflightCheckResult(
                name="AWS Organization Role",
                target="Management Account",
                status=PreflightCheckStatus.INFO,
                live_value="Not Initialized / Inaccessible",
                action_required="Run 'tarmac deploy --phase 1' or check AWS Organizations permissions",
            )

    def check_root_mfa(self) -> PreflightCheckResult:
        """Verify that multi-factor authentication (MFA) is active on the root user."""
        try:
            iam = self.session_mgr.get_client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})
            mfa_count = summary.get("AccountMFAEnabled", 0)
            if mfa_count == 1:
                return PreflightCheckResult(
                    name="Root User MFA",
                    target="Management Account",
                    status=PreflightCheckStatus.PASS,
                    live_value="Enabled (1 device)",
                )
            return PreflightCheckResult(
                name="Root User MFA",
                target="Management Account",
                status=PreflightCheckStatus.FAIL,
                live_value="Disabled (0 devices)",
                action_required="Enable Hardware or Virtual MFA on Root user in IAM console",
            )
        except ClientError as e:
            logger.debug("Root MFA check failed: %s", e)
            return PreflightCheckResult(
                name="Root User MFA",
                target="Management Account",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=f"Check IAM permissions: {e}",
            )

    def check_iam_user_hygiene(self) -> PreflightCheckResult:
        """Verify absence of legacy local IAM users in Management Account (SSO adoption)."""
        try:
            iam = self.session_mgr.get_client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})
            user_count = summary.get("Users", 0)

            if user_count == 0:
                return PreflightCheckResult(
                    name="Local IAM User Hygiene",
                    target="Management Account",
                    status=PreflightCheckStatus.PASS,
                    live_value="0 Local IAM Users (SSO only)",
                )

            return PreflightCheckResult(
                name="Local IAM User Hygiene",
                target="Management Account",
                status=PreflightCheckStatus.WARN,
                live_value=f"{plural(user_count, 'Local IAM User')} Found",
                action_required="Migrate local users to IAM Identity Center and deprecate IAM users",
            )
        except AWS_ERRORS as e:
            logger.debug("IAM user hygiene check: %s", e)
            return PreflightCheckResult(
                name="Local IAM User Hygiene",
                target="Management Account",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=f"Verify IAM permissions: {e}",
            )

    def check_alternate_contacts(self) -> list[PreflightCheckResult]:
        """Verify that alternate contacts (Billing, Operations, Security) are set."""
        results: list[PreflightCheckResult] = []
        try:
            account = self.session_mgr.get_client("account")
            for c_type in ["BILLING", "OPERATIONS", "SECURITY"]:
                try:
                    resp = account.get_alternate_contact(AlternateContactType=c_type)
                    email = resp.get("AlternateContact", {}).get("EmailAddress", "")
                    results.append(
                        PreflightCheckResult(
                            name=f"Alternate Contact ({c_type.title()})",
                            target="Management Account",
                            status=PreflightCheckStatus.PASS,
                            live_value=email,
                        )
                    )
                except ClientError:
                    results.append(
                        PreflightCheckResult(
                            name=f"Alternate Contact ({c_type.title()})",
                            target="Management Account",
                            status=PreflightCheckStatus.WARN,
                            live_value="Not Configured",
                            action_required="Run 'tarmac deploy --phase 1' to configure",
                        )
                    )
        except AWS_ERRORS as e:
            logger.debug("Alternate contacts check failed: %s", e)
            results.append(
                PreflightCheckResult(
                    name="Alternate Contacts",
                    target="Management Account",
                    status=PreflightCheckStatus.INFO,
                    live_value="Unavailable",
                    action_required=str(e),
                )
            )
        return results

    def check_account_quota(self) -> PreflightCheckResult:
        """Verify whether AWS Organizations account creation quota is sufficient for declared accounts."""
        try:
            org = self.session_mgr.get_client("organizations")
            active_accounts = sum(1 for a in iter_accounts(org) if is_active(a))
            declared_count = len(self.bundle.accounts.accounts)

            sq = self.session_mgr.get_client("service-quotas", region_name="us-east-1")
            try:
                resp = sq.get_service_quota(ServiceCode="organizations", QuotaCode="L-25807E2B")
                quota_val = int(resp.get("Quota", {}).get("Value", 0))
                if quota_val > 0:
                    remaining = quota_val - active_accounts
                    if active_accounts + declared_count > quota_val:
                        return PreflightCheckResult(
                            name="AWS Organizations Account Quota",
                            target="Organizations",
                            status=PreflightCheckStatus.FAIL,
                            live_value=f"{active_accounts} active / {quota_val} max quota (need space for {declared_count})",
                            action_required="Request an account quota increase in AWS Service Quotas console (code: L-25807E2B)",
                        )
                    return PreflightCheckResult(
                        name="AWS Organizations Account Quota",
                        target="Organizations",
                        status=PreflightCheckStatus.PASS,
                        live_value=f"{active_accounts} active, {remaining} remaining of {quota_val} quota",
                    )
            except AWS_ERRORS as e:
                logger.debug("Could not query service-quotas for account limit: %s", e)

            return PreflightCheckResult(
                name="AWS Organizations Account Quota",
                target="Organizations",
                status=PreflightCheckStatus.WARN,
                live_value=f"{active_accounts} active accounts; quota could not be verified",
                action_required=(
                    f"Confirm the account quota allows {plural(declared_count, 'more account')} in AWS Service Quotas "
                    "(code: L-25807E2B); grant servicequotas:GetServiceQuota to automate this check"
                ),
            )
        except AWS_ERRORS as e:
            logger.debug("Account quota check failed: %s", e)
            return PreflightCheckResult(
                name="AWS Organizations Account Quota",
                target="Organizations",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=None,
            )

    def check_scp_quota(self) -> PreflightCheckResult:
        """Verify that Organization Root has capacity for declared SCPs (AWS limit: 5 per target)."""
        try:
            org = self.session_mgr.get_client("organizations")
            roots = org.list_roots().get("Roots", [])
            if not roots:
                return PreflightCheckResult(
                    name="SCP Attachment Quota",
                    target="Organization Root",
                    status=PreflightCheckStatus.INFO,
                    live_value="No Roots Found",
                )
            root_id = str(roots[0].get("Id", "root"))
            paginator = org.get_paginator("list_policies_for_target")
            attached_count = 0
            for page in paginator.paginate(TargetId=root_id, Filter="SERVICE_CONTROL_POLICY"):
                attached_count += len(page.get("Policies", []))
            if attached_count >= 5:
                return PreflightCheckResult(
                    name="SCP Attachment Quota",
                    target=f"Root ({root_id})",
                    status=PreflightCheckStatus.WARN,
                    live_value=f"{attached_count} of 5 SCPs attached",
                    action_required=(
                        "Organization Root has reached the maximum AWS limit of 5 attached SCPs. "
                        "Detach unused policies before applying new guardrails."
                    ),
                )
            return PreflightCheckResult(
                name="SCP Attachment Quota",
                target=f"Root ({root_id})",
                status=PreflightCheckStatus.PASS,
                live_value=f"{attached_count} of 5 SCPs attached",
            )
        except AWS_ERRORS as e:
            logger.debug("SCP quota check failed: %s", e)
            return PreflightCheckResult(
                name="SCP Attachment Quota",
                target="Organization Root",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=None,
            )
