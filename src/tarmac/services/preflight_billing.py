"""Preflight checks of billing: Cost Explorer, cost allocation tags, support and payment."""

import logging
from datetime import UTC, datetime, timedelta

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import aws_error_message
from ..core.models import PreflightCheckResult, PreflightCheckStatus

logger = logging.getLogger(__name__)


class BillingChecks:
    """Billing and support checks."""

    session_mgr: AwsSessionManager
    bundle: ConfigBundle

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
                    "or run: tarmac deploy --phase 1"
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
