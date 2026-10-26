"""Pre-Flight and Posture Verification Service for AWS Environment Readiness."""

import json
import logging
from collections import Counter

from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS, aws_error_message
from ..core.models import PreflightCheckResult, PreflightCheckStatus, PreflightReport
from ..core.placeholders import find_placeholder_values
from ..core.stack_names import Stack
from ..core.text import plural
from .cloudformation import resource_owner
from .identity import DEPLOYMENT_PERMISSION_SET, IdentityService, deployment_policy
from .preflight_billing import BillingChecks
from .preflight_org import OrganizationChecks

logger = logging.getLogger(__name__)


def _count_statuses(checks: list[PreflightCheckResult]) -> tuple[int, int, int, int]:
    """Count occurrences of each PreflightCheckStatus."""
    counts = Counter(c.status for c in checks)
    return (
        counts[PreflightCheckStatus.PASS],
        counts[PreflightCheckStatus.WARN],
        counts[PreflightCheckStatus.FAIL],
        counts[PreflightCheckStatus.INFO],
    )


class PreflightService(OrganizationChecks, BillingChecks):
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
                    "Run 'tarmac bootstrap' to create an IAM Identity Center login (see README: Starting from a "
                    "brand-new AWS account)"
                ),
            )
        return PreflightCheckResult(
            name="Caller Identity",
            target="Non-root IAM principal",
            status=PreflightCheckStatus.PASS,
            live_value="IAM role or user",
        )

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
            live_value=f"{plural(len(problems), 'sample value')}",
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
        if any(t.get("Name") == declared for t in trails):
            owner = resource_owner(
                self.session_mgr.get_client("cloudformation", region_name=target_region), declared
            )
            ours = Stack.CLOUDTRAIL.for_org(self.bundle.org.organization.name)
            if owner != ours:
                where = f"stack '{owner}'" if owner else "no CloudFormation stack"
                return PreflightCheckResult(
                    name="Existing Organization Trail",
                    target="CloudTrail",
                    status=PreflightCheckStatus.FAIL,
                    live_value=f"'{declared}' belongs to {where}",
                    action_required=(
                        f"A trail named '{declared}' already exists outside '{ours}', so creating tarmac's trail would "
                        "fail. If it is another tarmac deployment's, set organization.name to match it; otherwise "
                        "set cloudtrail.trail_name to a different name."
                    ),
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
                    action_required="Confirm the subscription emails sent to alert recipients",
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

    def check_deployment_policy_current(self) -> PreflightCheckResult:
        """Warn when the TarmacDeployment permission set's policy differs from this release's.

        New features add API calls to the policy; a permission set bootstrapped by an older release then fails
        halfway through a deploy with AccessDenied. Comparing the two up front turns that into a one-line warning.
        """
        name, target = "Deployment Policy", f"Permission set '{DEPLOYMENT_PERMISSION_SET}'"
        try:
            identity = IdentityService(
                self.session_mgr, preferred_region=self.bundle.identity.identity_center.region
            )
            instance_arn, _ = identity.get_instance_details()
            ps_arn = identity.list_permission_sets(instance_arn).get(DEPLOYMENT_PERMISSION_SET)
            live = ps_arn and identity.sso_client.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            ).get("InlinePolicy")
        except AWS_ERRORS as e:
            logger.debug("Deployment policy check: %s", e)
            return PreflightCheckResult(
                name=name, target=target, status=PreflightCheckStatus.INFO, live_value="Unavailable"
            )
        if not ps_arn:
            return PreflightCheckResult(
                name=name,
                target=target,
                status=PreflightCheckStatus.INFO,
                live_value="Not found (access set up another way)",
            )
        if live and json.loads(live) == json.loads(deployment_policy()):
            return PreflightCheckResult(
                name=name, target=target, status=PreflightCheckStatus.PASS, live_value="Matches this release"
            )
        return PreflightCheckResult(
            name=name,
            target=target,
            status=PreflightCheckStatus.WARN,
            live_value="Differs from this release",
            action_required="Re-run 'tarmac bootstrap' (CloudShell, root) to update it.",
        )

    def run_all_checks(self, region_override: str | None = None) -> PreflightReport:
        """Orchestrate all prerequisite and readiness checks and compile report."""
        home_region = region_override or self.bundle.org.organization.primary_region

        checks: list[PreflightCheckResult] = [
            self.check_not_root_identity(),
            self.check_deployment_policy_current(),
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
            self.check_sample_values(),
            self.check_existing_organization_trail(home_region),
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
