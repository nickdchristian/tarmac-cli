"""Pre-Flight and Posture Verification Service for AWS Environment Readiness."""

import json
import logging
from collections import Counter
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS, aws_error_message
from ..core.models import PreflightCheckResult, PreflightCheckStatus, PreflightReport
from ..core.org_accounts import active_account_ids, is_active, iter_accounts
from ..core.placeholders import find_placeholder_values
from ..core.stack_names import ACCESS_STACK, TARMAC_STACK_SUFFIXES
from ..core.templates import resolve_resource_path

logger = logging.getLogger(__name__)

ACCESS_TEMPLATE = "cloudformation/tarmac-access.yaml"
ACCESS_DEFAULT_REGION = "us-east-1"
_LIVE_STACK_STATUSES = [
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "REVIEW_IN_PROGRESS",
]


def _normalise(template: object) -> str:
    """Reduce a template to comparable text: CloudFormation may hand back parsed JSON or the original YAML."""
    if isinstance(template, str):
        text = template
    elif isinstance(template, dict | list):
        text = json.dumps(template, sort_keys=True)
    else:
        text = str(template)
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").strip().split("\n"))


def _count_statuses(checks: list[PreflightCheckResult]) -> tuple[int, int, int, int]:
    """Count occurrences of each PreflightCheckStatus."""
    counts = Counter(c.status for c in checks)
    return (
        counts[PreflightCheckStatus.PASS],
        counts[PreflightCheckStatus.WARN],
        counts[PreflightCheckStatus.FAIL],
        counts[PreflightCheckStatus.INFO],
    )


class PreflightService:
    """Evaluates management account prerequisites, manual steps, and governance readiness."""

    def __init__(self, session_mgr: AwsSessionManager, bundle: ConfigBundle):
        self.session_mgr = session_mgr
        self.bundle = bundle

    def check_not_root_identity(self) -> PreflightCheckResult:
        """Fail when running as the root user: it cannot assume roles in member accounts."""
        try:
            is_root = self.session_mgr.is_root_identity()
        except AWS_ERRORS as e:
            logger.debug("Root identity check: %s", e)
            return PreflightCheckResult(
                name="Caller Identity",
                target="Non-root IAM principal",
                status=PreflightCheckStatus.INFO,
                live_value="Could not determine caller identity",
            )
        if is_root is True:
            return PreflightCheckResult(
                name="Caller Identity",
                target="Non-root IAM principal",
                status=PreflightCheckStatus.FAIL,
                live_value="Root user credentials",
                action_required=(
                    "Root cannot call sts:AssumeRole, so tarmac cannot reach member accounts. "
                    "Run 'tarmac access template' to create the tarmac role, then use it (see README: Bootstrap access)"
                ),
            )
        return PreflightCheckResult(
            name="Caller Identity",
            target="Non-root IAM principal",
            status=PreflightCheckStatus.PASS,
            live_value="IAM role or user",
        )

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
                action_required="Run 'tarmac deploy run --phase 1' or check AWS Organizations permissions",
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
                live_value=f"{user_count} Local IAM User(s) Found",
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
                            action_required="Run 'tarmac deploy run --phase 1' to configure",
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

    def check_identity_center(self, home_region: str) -> PreflightCheckResult:
        """Verify that IAM Identity Center is initialized in the target home region."""
        try:
            sso = self.session_mgr.get_client("sso-admin", region_name=home_region)
            instances = sso.list_instances().get("Instances", [])
            if instances:
                arn = instances[0].get("InstanceArn", "")
                short_id = arn.split("/")[-1] if "/" in arn else arn
                return PreflightCheckResult(
                    name="IAM Identity Center (SSO)",
                    target=f"Region {home_region}",
                    status=PreflightCheckStatus.PASS,
                    live_value=f"Active ({short_id})",
                )
            return PreflightCheckResult(
                name="IAM Identity Center (SSO)",
                target=f"Region {home_region}",
                status=PreflightCheckStatus.WARN,
                live_value="Not Initialized",
                action_required=f"Enable IAM Identity Center in '{home_region}' via AWS Console",
            )
        except ClientError as e:
            msg = aws_error_message(e)
            return PreflightCheckResult(
                name="IAM Identity Center (SSO)",
                target=f"Region {home_region}",
                status=PreflightCheckStatus.WARN,
                live_value="Not Accessible",
                action_required=f"Enable Identity Center in AWS Console: {msg}",
            )

    def check_identity_center_mfa_policy(self) -> PreflightCheckResult:
        """Advisory check for IAM Identity Center sign-in MFA enforcement."""
        return PreflightCheckResult(
            name="Identity Center MFA Policy",
            target="IAM Identity Center",
            status=PreflightCheckStatus.INFO,
            live_value="Manual Verification",
            action_required="Ensure 'Always require MFA' is enabled under Identity Center Settings -> Authentication",
        )

    def check_cost_explorer(self) -> PreflightCheckResult:
        """Verify that AWS Cost Explorer data ingestion has been activated."""
        try:
            ce = self.session_mgr.get_client("ce", region_name="us-east-1")
            today = datetime.now(UTC).date()
            yesterday = today - timedelta(days=1)
            ce.get_dimension_values(
                TimePeriod={"Start": str(yesterday), "End": str(today)},
                Dimension="SERVICE",
                MaxResults=1,
            )
            return PreflightCheckResult(
                name="AWS Cost Explorer",
                target="Management Account",
                status=PreflightCheckStatus.PASS,
                live_value="Active",
            )
        except ClientError as e:
            msg = aws_error_message(e)
            if "not enabled" in msg.lower() or "DataUnavailableException" in str(e):
                return PreflightCheckResult(
                    name="AWS Cost Explorer",
                    target="Management Account",
                    status=PreflightCheckStatus.WARN,
                    live_value="Not Activated",
                    action_required="Open Cost Explorer once in AWS Cost Management Console to initialize data",
                )
            return PreflightCheckResult(
                name="AWS Cost Explorer",
                target="Management Account",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=f"Verify Cost Explorer permissions: {msg}",
            )

    def check_cost_allocation_tags(self) -> PreflightCheckResult:
        """Verify that configured cost allocation tags are active in Cost Explorer."""
        if not self.bundle.org.cost_allocation_tags.enabled:
            return PreflightCheckResult(
                name="Cost Allocation Tags",
                target="Management Account",
                status=PreflightCheckStatus.PASS,
                live_value="Disabled in config",
                action_required=None,
            )

        target_tags = self.bundle.get_cost_allocation_tags()
        if not target_tags:
            return PreflightCheckResult(
                name="Cost Allocation Tags",
                target="Management Account",
                status=PreflightCheckStatus.WARN,
                live_value="None defined in configuration",
                action_required="Define cost_allocation_tags in organization.yaml for cost attribution tracking",
            )

        try:
            ce = self.session_mgr.get_client("ce", region_name="us-east-1")
            paginator = ce.get_paginator("list_cost_allocation_tags")
            active_keys: set[str] = {
                tag["TagKey"]
                for page in paginator.paginate(Status="Active")
                for tag in page.get("CostAllocationTags", [])
            }
            missing = [k for k in target_tags if k not in active_keys]
            if not missing:
                return PreflightCheckResult(
                    name="Cost Allocation Tags",
                    target="Management Account",
                    status=PreflightCheckStatus.PASS,
                    live_value=f"Active ({len(active_keys)} active in AWS, all {len(target_tags)} defined tags active)",
                )

            missing_str = ", ".join(missing)
            return PreflightCheckResult(
                name="Cost Allocation Tags",
                target="Management Account",
                status=PreflightCheckStatus.WARN,
                live_value=f"{len(active_keys)} active (missing: {missing_str})",
                action_required=(
                    f"Activate missing tag(s) ({missing_str}) in Billing & Cost Management console "
                    "or run: tarmac deploy run --phase 1"
                ),
            )
        except ClientError as e:
            logger.debug("Cost allocation tags check: %s", e)
            return PreflightCheckResult(
                name="Cost Allocation Tags",
                target="Management Account",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=None,
            )

    def check_sample_values(self) -> PreflightCheckResult:
        """Warn when sample values from `tarmac init` are still in the configuration."""
        problems = find_placeholder_values(self.bundle)
        if not problems:
            return PreflightCheckResult(
                name="Sample Configuration Values",
                target="YAML configuration",
                status=PreflightCheckStatus.PASS,
                live_value="None found",
            )
        return PreflightCheckResult(
            name="Sample Configuration Values",
            target="YAML configuration",
            status=PreflightCheckStatus.WARN,
            live_value=f"{len(problems)} sample value(s)",
            action_required="; ".join(problems[:3]) + (" ..." if len(problems) > 3 else ""),
        )

    def check_existing_organization_trail(self, target_region: str) -> PreflightCheckResult:
        """Warn about organization trails Tarmac did not create: a second one means a second paid copy of events."""
        declared = self.bundle.org.cloudtrail.trail_name
        try:
            cloudtrail = self.session_mgr.get_client("cloudtrail", region_name=target_region)
            trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
        except (ClientError, BotoCoreError) as e:
            logger.debug("Existing organization trail check: %s", e)
            return PreflightCheckResult(
                name="Existing Organization Trail",
                target="CloudTrail",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
            )
        others = sorted(
            str(t.get("Name", ""))
            for t in trails
            if t.get("IsOrganizationTrail") and t.get("Name") != declared
        )
        if not others:
            return PreflightCheckResult(
                name="Existing Organization Trail",
                target="CloudTrail",
                status=PreflightCheckStatus.PASS,
                live_value="None besides the declared trail",
            )
        return PreflightCheckResult(
            name="Existing Organization Trail",
            target="CloudTrail",
            status=PreflightCheckStatus.WARN,
            live_value=", ".join(others),
            action_required=(
                f"An organization trail already exists. Deploying '{declared}' adds a second copy of management "
                "events, which is billed ($2.00 per 100,000 events beyond the first copy). Delete one of them "
                "once the new trail is delivering logs."
            ),
        )

    def check_stack_name_prefix(self, target_region: str) -> PreflightCheckResult:
        """Warn when Tarmac stacks exist under a different organization name than the one now configured."""
        org_name = self.bundle.org.organization.name
        try:
            cfn = self.session_mgr.get_client("cloudformation", region_name=target_region)
            names = [
                str(summary.get("StackName", ""))
                for page in cfn.get_paginator("list_stacks").paginate(StackStatusFilter=_LIVE_STACK_STATUSES)
                for summary in page.get("StackSummaries", [])
            ]
        except (ClientError, BotoCoreError) as e:
            logger.debug("Stack name prefix check: %s", e)
            return PreflightCheckResult(
                name="Existing Tarmac Stacks",
                target=f"Region {target_region}",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
            )
        prefixes: set[str] = set()
        for name in names:
            for suffix in TARMAC_STACK_SUFFIXES:
                if name.endswith(f"-{suffix}") and not name.startswith(f"{org_name}-"):
                    prefixes.add(name[: -len(suffix) - 1])
        if not prefixes:
            return PreflightCheckResult(
                name="Existing Tarmac Stacks",
                target=f"Region {target_region}",
                status=PreflightCheckStatus.PASS,
                live_value="Consistent with organization.name",
            )
        found = ", ".join(sorted(prefixes))
        return PreflightCheckResult(
            name="Existing Tarmac Stacks",
            target=f"Region {target_region}",
            status=PreflightCheckStatus.WARN,
            live_value=f"Stacks named for: {found}",
            action_required=(
                f"organization.name is '{org_name}', but Tarmac stacks already exist under '{found}'. Stacks are "
                f"named after organization.name, so deploying now would try to recreate resources those stacks "
                f"already own and fail. Set organization.name back to '{found}'."
            ),
        )

    def check_sns_subscriptions(self, target_region: str) -> PreflightCheckResult:
        """Verify whether any alert SNS subscriptions are pending email confirmation."""
        try:
            sns = self.session_mgr.get_client("sns", region_name=target_region)
            pending = 0
            confirmed = 0
            for topic_page in sns.get_paginator("list_topics").paginate():
                for topic in topic_page.get("Topics", []):
                    sub_pages = sns.get_paginator("list_subscriptions_by_topic").paginate(
                        TopicArn=topic["TopicArn"]
                    )
                    for sub_page in sub_pages:
                        for sub in sub_page.get("Subscriptions", []):
                            if sub.get("SubscriptionArn") == "PendingConfirmation":
                                pending += 1
                            else:
                                confirmed += 1
            if pending > 0:
                return PreflightCheckResult(
                    name="SNS Alert Subscriptions",
                    target=f"Region {target_region}",
                    status=PreflightCheckStatus.WARN,
                    live_value=f"{pending} Pending Confirmation",
                    action_required="Confirm subscription email(s) sent to alert recipient inbox",
                )
            return PreflightCheckResult(
                name="SNS Alert Subscriptions",
                target=f"Region {target_region}",
                status=PreflightCheckStatus.PASS,
                live_value=f"{confirmed} Confirmed (0 pending)" if confirmed else "None configured",
            )
        except ClientError as e:
            logger.debug("SNS subscription check failed: %s", e)
            return PreflightCheckResult(
                name="SNS Alert Subscriptions",
                target=f"Region {target_region}",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=None,
            )

    def check_support_tier(self) -> PreflightCheckResult:
        """Inspect whether the account has Basic vs Business/Enterprise support."""
        try:
            support = self.session_mgr.get_client("support", region_name="us-east-1")
            support.describe_severity_levels()
            return PreflightCheckResult(
                name="AWS Support Plan",
                target="Account Tier",
                status=PreflightCheckStatus.PASS,
                live_value="Business / Enterprise",
            )
        except ClientError as e:
            if "SubscriptionRequiredException" in str(e):
                return PreflightCheckResult(
                    name="AWS Support Plan",
                    target="Account Tier",
                    status=PreflightCheckStatus.INFO,
                    live_value="Basic (Free)",
                    action_required="Upgrade support tier if 24x7 response SLA is required",
                )
            return PreflightCheckResult(
                name="AWS Support Plan",
                target="Account Tier",
                status=PreflightCheckStatus.INFO,
                live_value="Unavailable",
                action_required=None,
            )

    def check_payment_and_tax(self) -> PreflightCheckResult:
        """Advisory check for billing payment method on file and tax exemption status."""
        return PreflightCheckResult(
            name="Payment Method & Tax Status",
            target="Billing Console",
            status=PreflightCheckStatus.INFO,
            live_value="Manual Verification",
            action_required="Confirm valid payment card on file and tax settings in AWS Billing Console",
        )

    def check_account_quota(self) -> PreflightCheckResult:
        """Verify whether AWS Organizations account creation quota is sufficient for declared accounts."""
        try:
            org = self.session_mgr.get_client("organizations")
            active_accounts = sum(1 for a in iter_accounts(org) if is_active(a))
            declared_count = len(self.bundle.accounts.accounts)

            sq = self.session_mgr.get_client("service-quotas", region_name="us-east-1")
            try:
                resp = sq.get_service_quota(ServiceCode="organizations", QuotaCode="L-25807E2B")
                quota_val = 0
                if isinstance(resp, dict):
                    raw_val = resp.get("Quota", {}).get("Value")
                    if isinstance(raw_val, (int, float)) and not isinstance(raw_val, bool):
                        quota_val = int(raw_val)
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
                    f"Confirm the account quota allows {declared_count} more account(s) in AWS Service Quotas "
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
            roots_resp = org.list_roots()
            roots = roots_resp.get("Roots", []) if isinstance(roots_resp, dict) else []
            if not roots or not isinstance(roots, list) or not isinstance(roots[0], dict):
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
                if isinstance(page, dict):
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

    def check_s3_bucket_collision(self) -> list[PreflightCheckResult]:
        """Verify that planned foundational S3 bucket names are not globally owned by another AWS account."""
        results: list[PreflightCheckResult] = []
        try:
            s3 = self.session_mgr.get_client("s3")
            caller = self.session_mgr.get_caller_identity()
            mgmt_id = caller.get("Account", "")

            active_accts: dict[str, str] = {}
            try:
                active_accts = active_account_ids(self.session_mgr.get_client("organizations"))
            except AWS_ERRORS as e:
                logger.debug("Could not list accounts for S3 bucket collision check: %s", e)

            log_archive_name = self.bundle.get_log_archive_account_name() or "log-archive"
            log_archive_id = self.bundle.resolve_account_id(log_archive_name, active_accts) or mgmt_id

            backend_name = self.bundle.get_backend_account_name() or "deployment"
            deployment_id = self.bundle.resolve_account_id(backend_name, active_accts) or mgmt_id

            org_name = self.bundle.org.organization.name
            # Same rule as terraform-backend.yaml: tarmac always passes OrgName, which wins over BucketPrefix.
            tf_bucket = (
                f"{org_name}-terraform-state-{deployment_id}"
                if org_name
                else f"{self.bundle.org.terraform_backend.bucket_prefix}-{deployment_id}"
            )
            prefixes_to_check = [
                (
                    "CloudTrail Logs",
                    f"{org_name}-org-cloudtrail-logs-{log_archive_id}",
                    log_archive_id,
                ),
                (
                    "Terraform State",
                    tf_bucket,
                    deployment_id,
                ),
            ]
            for label, b_name, target_acct_id in prefixes_to_check:
                target_s3 = s3
                if target_acct_id and target_acct_id != mgmt_id:
                    try:
                        target_s3 = self.session_mgr.get_member_client(target_acct_id, "s3")
                    except AWS_ERRORS as e:
                        # Do NOT fall back to the management account's client: it would report the
                        # bucket as "Available" or "Taken" based on the wrong account's view.
                        logger.warning(
                            "Cannot assume role into account %s for S3 check: %s", target_acct_id, e
                        )
                        results.append(
                            PreflightCheckResult(
                                name=f"S3 Bucket Availability ({label})",
                                target=b_name,
                                status=PreflightCheckStatus.INFO,
                                live_value=f"Check skipped (cannot access account {target_acct_id})",
                            )
                        )
                        continue
                try:
                    target_s3.head_bucket(Bucket=b_name)
                    results.append(
                        PreflightCheckResult(
                            name=f"S3 Bucket Availability ({label})",
                            target=b_name,
                            status=PreflightCheckStatus.PASS,
                            live_value="Accessible / Owned",
                        )
                    )
                except ClientError as e:
                    code = str(e.response.get("Error", {}).get("Code", ""))
                    if code in ("404", "NoSuchBucket"):
                        results.append(
                            PreflightCheckResult(
                                name=f"S3 Bucket Availability ({label})",
                                target=b_name,
                                status=PreflightCheckStatus.PASS,
                                live_value="Available",
                            )
                        )
                    elif code in ("403", "AccessDenied"):
                        results.append(
                            PreflightCheckResult(
                                name=f"S3 Bucket Availability ({label})",
                                target=b_name,
                                status=PreflightCheckStatus.FAIL,
                                live_value="Forbidden (Taken Globally)",
                                action_required=(
                                    f"Bucket name '{b_name}' is globally claimed by another AWS account. "
                                    "Change bucket_prefix in organization.yaml."
                                ),
                            )
                        )
                    else:
                        results.append(
                            PreflightCheckResult(
                                name=f"S3 Bucket Availability ({label})",
                                target=b_name,
                                status=PreflightCheckStatus.INFO,
                                live_value=f"Check skipped ({code})",
                            )
                        )
        except AWS_ERRORS as e:
            logger.warning("S3 collision check failed: %s", e)
            results.append(
                PreflightCheckResult(
                    name="S3 Bucket Availability",
                    target="(all)",
                    status=PreflightCheckStatus.INFO,
                    live_value=f"Check skipped ({type(e).__name__})",
                )
            )
        return results

    def check_access_policy_current(self, home_region: str) -> PreflightCheckResult:
        """Warn when the deployed access role is older than this release's template.

        New features add API calls to the template's policy; a role bootstrapped by an older release then fails
        halfway through a deploy with AccessDenied. Comparing the two up front turns that into a one-line warning.
        """
        name, target = "Access Role Policy", f"Stack '{ACCESS_STACK}'"
        try:
            packaged = resolve_resource_path(ACCESS_TEMPLATE).read_text(encoding="utf-8")
        except (OSError, ValueError) as e:  # not expected: the template ships with the package
            logger.debug("Access policy check: %s", e)
            return PreflightCheckResult(
                name=name, target=target, status=PreflightCheckStatus.INFO, live_value="Unavailable"
            )

        for region in dict.fromkeys([ACCESS_DEFAULT_REGION, home_region]):
            try:
                cfn = self.session_mgr.get_client("cloudformation", region_name=region)
                body = cfn.get_template(StackName=ACCESS_STACK, TemplateStage="Original").get("TemplateBody")
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code == "ValidationError":  # no such stack in this region
                    continue
                logger.debug("Access policy check in %s: %s", region, e)
                return PreflightCheckResult(
                    name=name, target=target, status=PreflightCheckStatus.INFO, live_value="Unavailable"
                )
            except BotoCoreError as e:
                logger.debug("Access policy check in %s: %s", region, e)
                return PreflightCheckResult(
                    name=name, target=target, status=PreflightCheckStatus.INFO, live_value="Unavailable"
                )
            if _normalise(body) == _normalise(packaged):
                return PreflightCheckResult(
                    name=name,
                    target=target,
                    status=PreflightCheckStatus.PASS,
                    live_value=f"Matches this release ({region})",
                )
            return PreflightCheckResult(
                name=name,
                target=target,
                status=PreflightCheckStatus.WARN,
                live_value=f"Differs from this release ({region})",
                action_required=(
                    "The deployed access role was created by a different tarmac release and may lack permissions "
                    f"this release needs. Re-run 'tarmac access bootstrap --region {region}' (CloudShell, root) to "
                    "update it; the role keeps its name and your profiles keep working."
                ),
            )
        return PreflightCheckResult(
            name=name,
            target=target,
            status=PreflightCheckStatus.INFO,
            live_value="Not found (access set up another way)",
        )

    def run_all_checks(self, region_override: str | None = None) -> PreflightReport:
        """Orchestrate all prerequisite and readiness checks and compile report."""
        home_region = region_override or self.bundle.org.organization.primary_region

        checks: list[PreflightCheckResult] = [
            self.check_not_root_identity(),
            self.check_access_policy_current(home_region),
            self.check_organization_status(),
            self.check_root_mfa(),
            self.check_iam_user_hygiene(),
            *self.check_alternate_contacts(),
            self.check_account_quota(),
            self.check_scp_quota(),
            self.check_identity_center(home_region),
            self.check_identity_center_mfa_policy(),
            self.check_cost_explorer(),
            self.check_cost_allocation_tags(),
            *self.check_s3_bucket_collision(),
            self.check_sample_values(),
            self.check_existing_organization_trail(home_region),
            self.check_stack_name_prefix(home_region),
            self.check_sns_subscriptions(home_region),
            self.check_support_tier(),
            self.check_payment_and_tax(),
        ]

        passed, warnings, failures, info = _count_statuses(checks)

        return PreflightReport(
            checks=checks,
            passed=passed,
            warnings=warnings,
            failures=failures,
            info=info,
            can_proceed=(failures == 0),
        )
