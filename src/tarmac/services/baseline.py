"""Account Baselining Service (Default VPC Cleanup, Budgets & Anomaly Detection)."""

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from ..core.adoption import ADOPT_HINT, adopt_existing
from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_schema import AccountDef, AnomalyDetectionConfig, BudgetConfig
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code, aws_error_message
from ..core.logging import bind, with_current_context
from ..core.models import (
    BASELINE_COMPLETED,
    TAG_BASELINE,
    TAG_MANAGED_BY,
    AnomalyReport,
    BaselineReport,
    BudgetReport,
    VpcCleanupReport,
)
from ..core.templates import resolve_resource_path
from ..core.text import plural
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)


BUDGET_TEMPLATE = "cloudformation/account-budget.yaml"


def budget_stack_name(account_name: str) -> str:
    return f"{account_name}-monthly-budget"


def budget_parameters(account_name: str, budget_cfg: BudgetConfig) -> dict[str, str]:
    """CloudFormation parameters for an account's budget stack (account-budget.yaml)."""
    emails = list(budget_cfg.notification_emails)
    parameters = {
        "AccountName": account_name,
        "MonthlyLimitUSD": str(budget_cfg.monthly_limit_usd),
        "AlertThresholdPercent": str(budget_cfg.alert_threshold_percent),
        "NotificationEmail": str(emails[0]) if emails else "",
    }
    if budget_cfg.forecast_alert_threshold_percent is not None:
        parameters["ForecastThresholdPercent"] = str(budget_cfg.forecast_alert_threshold_percent)
    if budget_cfg.incident_response_webhook_url:
        parameters["IncidentResponseWebhookUrl"] = str(budget_cfg.incident_response_webhook_url)
    return parameters


class BaselineService:
    """Applies security and operational baselines to AWS member accounts."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr: AwsSessionManager = session_mgr
        self.org_client: Any = session_mgr.get_client("organizations")

    def get_enabled_regions(self, account_id: str) -> list[str]:
        """Discover all active/enabled AWS regions for a member account."""
        try:
            ec2 = self.session_mgr.get_member_client(
                account_id, "ec2", region_name=self.session_mgr.default_region
            )
            resp = ec2.describe_regions(AllRegions=False)
            discovered = [r["RegionName"] for r in resp.get("Regions", []) if "RegionName" in r]
            if discovered:
                return sorted(discovered)
        except ClientError as e:
            logger.warning(
                "Could not dynamically query active regions for account %s (%s). Falling back to default region.",
                account_id,
                e,
            )
        return [self.session_mgr.default_region]

    def cleanup_default_vpcs(
        self,
        account_id: str,
        account_name: str,
        regions: list[str] | None = None,
    ) -> list[VpcCleanupReport]:
        """Purge default VPCs, subnets, and internet gateways across active AWS regions.

        If regions is None, dynamically queries all active/enabled AWS regions in the account.
        """
        target_regions = regions if regions is not None else self.get_enabled_regions(account_id)
        reports: list[VpcCleanupReport] = []

        logger.debug(
            "Scanning for default VPCs in account '%s' (%s) across %s...",
            account_name,
            account_id,
            plural(len(target_regions), "region"),
        )

        if len(target_regions) <= 1:
            for region in target_regions:
                reports.append(self._cleanup_region_default_vpc(account_id, account_name, region))
        else:
            with ThreadPoolExecutor(max_workers=min(8, len(target_regions))) as pool:
                reports = list(
                    pool.map(
                        with_current_context(
                            lambda reg: self._cleanup_region_default_vpc(account_id, account_name, reg)
                        ),
                        target_regions,
                    )
                )

        return reports

    def _cleanup_region_default_vpc(
        self, account_id: str, account_name: str, region: str
    ) -> VpcCleanupReport:
        """Scan and clean the default VPC in a single region, tagging log records with the account and region."""
        with bind(account_id=account_id, account_name=account_name, region=region):
            return self._clean_default_vpc(account_id, region)

    def _clean_default_vpc(self, account_id: str, region: str) -> VpcCleanupReport:
        try:
            ec2 = self.session_mgr.get_member_client(account_id, "ec2", region_name=region)
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])

            if not vpcs:
                return VpcCleanupReport(region=region, skipped=True, message="No default VPC found.")

            vpc_id = str(vpcs[0]["VpcId"])
            in_use = ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}], MaxResults=5
            ).get("NetworkInterfaces", [])
            if in_use:
                audit(
                    "delete",
                    f"default-vpc:{account_id}:{region}",
                    Outcome.SKIPPED,
                    f"Left default VPC {vpc_id} in {region} intact because network interfaces are attached",
                    vpc_id=vpc_id,
                )
                return VpcCleanupReport(
                    region=region,
                    skipped=True,
                    message=f"Default VPC {vpc_id} is in use (network interfaces attached); not deleted.",
                )
            detached_igws = self._detach_and_delete_igws(ec2, vpc_id)
            deleted_subnets = self._delete_subnets(ec2, vpc_id)
            ec2.delete_vpc(VpcId=vpc_id)
            audit(
                "delete",
                f"default-vpc:{account_id}:{region}",
                Outcome.SUCCEEDED,
                f"Deleted default VPC {vpc_id} in {region} "
                f"({plural(len(detached_igws), 'internet gateway')}, {plural(len(deleted_subnets), 'subnet')})",
                vpc_id=vpc_id,
                internet_gateways=detached_igws,
                subnets=deleted_subnets,
            )

            return VpcCleanupReport(
                region=region,
                vpc_id=vpc_id,
                detached_igws=detached_igws,
                deleted_subnets=deleted_subnets,
                deleted_vpc=True,
                message="Successfully deleted default VPC",
            )

        except ClientError as e:
            err_code = aws_error_code(e)
            err_msg = aws_error_message(e)
            if err_code == "DependencyViolation":
                err_msg = f"DependencyViolation: VPC has active network interfaces or dependent resources ({err_msg})"
            audit(
                "delete",
                f"default-vpc:{account_id}:{region}",
                Outcome.FAILED,
                f"Could not delete default VPC in {region}: {err_msg}",
            )
            return VpcCleanupReport(
                region=region,
                skipped=True,
                message=f"Error cleaning VPC: {err_msg}",
                error=True,
            )
        except Exception as e:  # worker-thread boundary: one region's failure must not abort the others
            audit(
                "delete",
                f"default-vpc:{account_id}:{region}",
                Outcome.FAILED,
                f"Unexpected error deleting default VPC in {region}: {e}",
            )
            return VpcCleanupReport(
                region=region,
                skipped=True,
                message=f"Error cleaning VPC: {e}",
                error=True,
            )

    def _detach_and_delete_igws(self, ec2: Any, vpc_id: str) -> list[str]:
        """Helper to detach and delete internet gateways for a VPC."""
        detached: list[str] = []
        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        ).get("InternetGateways", [])

        for igw in igws:
            igw_id = str(igw["InternetGatewayId"])
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
            detached.append(igw_id)
            logger.debug("Detached and deleted IGW %s", igw_id)

        return detached

    def _delete_subnets(self, ec2: Any, vpc_id: str) -> list[str]:
        """Helper to delete all subnets within a VPC."""
        deleted: list[str] = []
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("Subnets", [])

        for sn in subnets:
            sn_id = str(sn["SubnetId"])
            ec2.delete_subnet(SubnetId=sn_id)
            deleted.append(sn_id)
            logger.debug("Deleted subnet %s", sn_id)

        return deleted

    def setup_account_budget(
        self,
        account_id: str,
        account_name: str,
        budget_cfg: BudgetConfig,
        account_tags: dict[str, str] | None = None,
        org_tags: dict[str, str] | None = None,
        custom_tags: dict[str, str] | None = None,
    ) -> BudgetReport:
        """Create or update a monthly cost budget in the member account via CloudFormation."""
        budget_name = budget_stack_name(account_name)

        def budget_report(status: str, message: str) -> BudgetReport:
            return BudgetReport(
                account_name=account_name,
                account_id=account_id,
                alert_threshold_percent=budget_cfg.alert_threshold_percent,
                status=status,
                message=message,
            )

        if not budget_cfg.notification_emails and not budget_cfg.incident_response_webhook_url:
            return budget_report("SKIPPED", "No notification emails or incident response webhook specified.")

        emails = list(budget_cfg.notification_emails)
        if len(emails) > 1:
            logger.info(
                "Account '%s' lists %d alert emails; the SNS topic subscribes only '%s'. "
                "A shared team mailbox, or more subscriptions on the topic, reaches everyone.",
                account_name,
                len(emails),
                emails[0],
            )

        parameters = budget_parameters(account_name, budget_cfg)

        try:
            cfn_client = self.session_mgr.get_member_client(
                account_id, "cloudformation", region_name=self.session_mgr.default_region
            )
            template_path = resolve_resource_path(BUDGET_TEMPLATE)
            cfn_service = CloudFormationService(self.session_mgr)

            cfn_report = cfn_service.deploy_stack(
                cfn_client=cfn_client,
                stack_name=budget_name,
                template_file=template_path,
                parameters=parameters,
                tags=custom_tags,
                account_tags=account_tags,
                org_tags=org_tags,
                on_before_create=lambda: self._remove_unmanaged_budget(account_id, account_name, budget_name),
            )
            if len(emails) > 1:
                self._reconcile_additional_budget_emails(
                    account_id=account_id,
                    account_name=account_name,
                    topic_arn=cfn_report.outputs.get("BudgetTopicArn"),
                    additional_emails=[str(e) for e in emails[1:]],
                )
            status = "CREATED" if cfn_report.action == "CREATED" else "UPDATED"
            return budget_report(status, f"Budget stack {status.lower()} via CloudFormation")
        except AWS_ERRORS as e:
            audit(
                "deploy",
                f"budget:{budget_name}",
                Outcome.FAILED,
                f"Could not deploy budget '{budget_name}' in account '{account_name}': {e}",
                account_id=account_id,
            )
            return budget_report("FAILED", str(e))

    def _remove_unmanaged_budget(self, account_id: str, account_name: str, budget_name: str) -> None:
        """Delete a same-named budget tarmac did not create (only with --adopt-existing) so the stack can own it."""
        conflict: GovernanceError | None = None
        try:
            budgets_client = self.session_mgr.get_member_client(
                account_id, "budgets", region_name="us-east-1"
            )
            resp = budgets_client.describe_budget(AccountId=account_id, BudgetName=budget_name)
            if "Budget" in resp:
                logger.debug(
                    "Found pre-existing unmanaged budget '%s' in account '%s' (%s). "
                    "Removing orphan budget to allow CloudFormation to manage it...",
                    budget_name,
                    account_name,
                    account_id,
                )
                previous = resp["Budget"]
                limit = previous.get("BudgetLimit") or {}
                if not adopt_existing():
                    conflict = GovernanceError(
                        f"A budget named '{budget_name}' already exists in account '{account_name}' "
                        f"({account_id}) and tarmac did not create it.",
                        details=(
                            f"Its limit is {limit.get('Amount', '?')} {limit.get('Unit', '')}"
                            f" ({previous.get('TimeUnit', '?')}). Tarmac would delete it and create "
                            f"its own. {ADOPT_HINT} Or rename/delete it yourself first."
                        ),
                    )
                    raise conflict
                budgets_client.delete_budget(AccountId=account_id, BudgetName=budget_name)
                audit(
                    "delete",
                    f"budget:{budget_name}",
                    Outcome.SUCCEEDED,
                    f"Deleted unmanaged budget '{budget_name}' in account '{account_name}' "
                    "so CloudFormation can manage it",
                    account_id=account_id,
                    # Kept so the replaced budget can be recreated by hand if it mattered.
                    previous_limit=f"{limit.get('Amount', '?')} {limit.get('Unit', '')}".strip(),
                    previous_time_unit=previous.get("TimeUnit"),
                    previous_budget_type=previous.get("BudgetType"),
                )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in ("NotFoundException", "ResourceNotFoundException"):
                logger.debug("Error checking existing budget in %s: %s", account_name, e)
        except AWS_ERRORS as e:
            if e is conflict:
                raise
            logger.debug("Could not inspect existing budget in %s: %s", account_name, e)

    def _reconcile_additional_budget_emails(
        self,
        account_id: str,
        account_name: str,
        topic_arn: str | None,
        additional_emails: list[str],
    ) -> None:
        """Idempotently subscribe additional notification emails to the budget SNS topic."""
        if not additional_emails:
            return
        resolved_topic_arn = (
            topic_arn
            or f"arn:aws:sns:{self.session_mgr.default_region}:{account_id}:{account_name}-budget-alerts"
        )
        try:
            sns_client = self.session_mgr.get_member_client(
                account_id, "sns", region_name=self.session_mgr.default_region
            )
            subs_resp = sns_client.list_subscriptions_by_topic(TopicArn=resolved_topic_arn)
            existing_endpoints = {
                str(s.get("Endpoint", "")).lower() for s in subs_resp.get("Subscriptions", [])
            }
            for email in additional_emails:
                if email.lower() not in existing_endpoints:
                    sns_client.subscribe(
                        TopicArn=resolved_topic_arn,
                        Protocol="email",
                        Endpoint=email,
                    )
                    audit(
                        "subscribe",
                        f"sns:{resolved_topic_arn}",
                        Outcome.SUCCEEDED,
                        f"Subscribed {email} to budget alert topic {resolved_topic_arn}; "
                        "the recipient must confirm the subscription",
                        email=email,
                    )
        except AWS_ERRORS as e:
            logger.warning(
                "Could not subscribe additional emails to budget SNS topic in %s: %s",
                account_name,
                e,
            )

    def setup_cost_anomaly_monitor(
        self,
        account_id: str,
        account_name: str,
        anomaly_cfg: AnomalyDetectionConfig,
    ) -> AnomalyReport:
        """Create Cost Anomaly Detection monitor and subscription in the management account."""
        monitor_name = f"{account_name}-cost-anomaly-monitor"
        sub_name = f"{account_name}-anomaly-alerts"

        if not anomaly_cfg.enabled or not anomaly_cfg.notification_emails:
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                threshold_usd=anomaly_cfg.threshold_usd,
                status="SKIPPED",
                message="Anomaly detection disabled or missing notification emails.",
            )

        self._setup_member_anomaly_monitor(account_id, account_name, anomaly_cfg)
        ce_client = self.session_mgr.get_client("ce", region_name="us-east-1")

        try:
            monitor_arn, status = self._get_or_create_anomaly_monitor(ce_client, monitor_name, account_id)
            audit(
                "create",
                f"anomaly-monitor:{monitor_name}",
                Outcome.SUCCEEDED if status == "CREATED" else Outcome.UNCHANGED,
                f"Cost anomaly monitor '{monitor_name}' "
                + ("created" if status == "CREATED" else "already exists")
                + f" for account '{account_name}'",
                account_id=account_id,
            )
            self._ensure_anomaly_subscription(
                ce_client, sub_name, monitor_arn, anomaly_cfg.threshold_usd, anomaly_cfg.notification_emails
            )
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                threshold_usd=anomaly_cfg.threshold_usd,
                status=status,
                message="Anomaly monitor and subscription active",
            )
        except ClientError as e:
            err_msg = aws_error_message(e)
            audit(
                "create",
                f"anomaly-monitor:{monitor_name}",
                Outcome.FAILED,
                f"Could not set up cost anomaly monitor for account '{account_name}': {err_msg}",
                account_id=account_id,
            )
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                threshold_usd=anomaly_cfg.threshold_usd,
                status="FAILED",
                message=str(err_msg),
            )

    def get_anomaly_overview(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Fetch all Cost Anomaly monitors and subscriptions in the Management Account."""
        ce_client = self.session_mgr.get_client("ce", region_name="us-east-1")
        try:
            monitors = ce_client.get_anomaly_monitors().get("AnomalyMonitors", [])
            subs = ce_client.get_anomaly_subscriptions().get("AnomalySubscriptions", [])
            return monitors, subs
        except ClientError as e:
            logger.warning("Error fetching anomaly monitors: %s", e)
            return [], []

    def _setup_member_anomaly_monitor(
        self,
        account_id: str,
        account_name: str,
        anomaly_cfg: AnomalyDetectionConfig,
    ) -> None:
        """Create in-account DIMENSIONAL Cost Anomaly Monitor inside the member account."""
        try:
            member_ce = self.session_mgr.get_member_client(account_id, "ce", region_name="us-east-1")
            existing = member_ce.get_anomaly_monitors().get("AnomalyMonitors", [])
            monitor_name = f"{account_name}-services-monitor"
            monitor_arn = next(
                (
                    m["MonitorArn"]
                    for m in existing
                    if m.get("MonitorName") == monitor_name or m.get("MonitorType") == "DIMENSIONAL"
                ),
                None,
            )
            if not monitor_arn:
                resp = member_ce.create_anomaly_monitor(
                    AnomalyMonitor={
                        "MonitorName": monitor_name,
                        "MonitorType": "DIMENSIONAL",
                        "MonitorDimension": "SERVICE",
                    }
                )
                monitor_arn = resp["MonitorArn"]
                audit(
                    "create",
                    f"anomaly-monitor:{monitor_name}",
                    Outcome.SUCCEEDED,
                    f"Created in-account cost anomaly monitor '{monitor_name}' in '{account_name}'",
                    account_id=account_id,
                )

            self._ensure_anomaly_subscription(
                member_ce,
                f"{account_name}-local-alerts",
                monitor_arn,
                anomaly_cfg.threshold_usd,
                anomaly_cfg.notification_emails,
            )
        except ClientError as e:
            logger.warning("Could not set up local anomaly monitor in %s: %s", account_name, e)

    def _get_or_create_anomaly_monitor(
        self, ce_client: Any, monitor_name: str, account_id: str
    ) -> tuple[str, str]:
        """Fetch existing or create new custom Cost Anomaly Monitor."""
        existing_monitors = ce_client.get_anomaly_monitors().get("AnomalyMonitors", [])
        monitor_arn = next(
            (m["MonitorArn"] for m in existing_monitors if m.get("MonitorName") == monitor_name),
            None,
        )
        if monitor_arn:
            return monitor_arn, "EXISTING"

        resp = ce_client.create_anomaly_monitor(
            AnomalyMonitor={
                "MonitorName": monitor_name,
                "MonitorType": "CUSTOM",
                "MonitorSpecification": {
                    "Dimensions": {
                        "Key": "LINKED_ACCOUNT",
                        "Values": [account_id],
                    }
                },
            }
        )
        return resp["MonitorArn"], "CREATED"

    def _ensure_anomaly_subscription(
        self,
        ce_client: Any,
        sub_name: str,
        monitor_arn: str,
        threshold_usd: float,
        notification_emails: list[str],
    ) -> None:
        """Ensure an anomaly alert subscription exists for the monitor."""
        subs = ce_client.get_anomaly_subscriptions().get("AnomalySubscriptions", [])
        if any(s.get("SubscriptionName") == sub_name for s in subs):
            return

        subscribers = [{"Type": "EMAIL", "Address": email} for email in notification_emails]
        ce_client.create_anomaly_subscription(
            AnomalySubscription={
                "SubscriptionName": sub_name,
                "Threshold": threshold_usd,
                "Frequency": "DAILY",
                "MonitorArnList": [monitor_arn],
                "Subscribers": subscribers,
            }
        )

    def is_account_baselined(self, account_id: str) -> bool:
        """Check if an account has already been marked as baselined in AWS Organizations."""
        try:
            paginator = self.org_client.get_paginator("list_tags_for_resource")
            for page in paginator.paginate(ResourceId=account_id):
                for tag in page.get("Tags", []):
                    if tag.get("Key") == TAG_BASELINE and tag.get("Value") == BASELINE_COMPLETED:
                        return True
        except ClientError as e:
            logger.debug("Could not inspect tags on account %s: %s", account_id, e)
        return False

    def mark_account_baselined(self, account_id: str) -> None:
        """Tag account in AWS Organizations as baselined and managed by Tarmac."""
        try:
            self.org_client.tag_resource(
                ResourceId=account_id,
                Tags=[
                    {"Key": TAG_BASELINE, "Value": BASELINE_COMPLETED},
                    {"Key": TAG_MANAGED_BY, "Value": "tarmac"},
                ],
            )
            audit(
                "tag",
                f"account:{account_id}",
                Outcome.SUCCEEDED,
                f"Marked account {account_id} as baselined ({TAG_BASELINE}={BASELINE_COMPLETED})",
                account_id=account_id,
            )
        except ClientError as e:
            logger.warning("Could not tag account %s as baselined: %s", account_id, e)

    def baseline_account(
        self,
        acct_def: AccountDef,
        account_id: str,
        regions: list[str] | None = None,
        org_tags: dict[str, str] | None = None,
        custom_tags: dict[str, str] | None = None,
    ) -> BaselineReport:
        """Run all declared baselines for a single account and return a consolidated BaselineReport."""
        baseline = acct_def.baseline
        report = BaselineReport(account_name=acct_def.name, account_id=account_id)

        already_baselined = self.is_account_baselined(account_id)
        if already_baselined:
            logger.info(
                "Account '%s' (%s) is already baselined (%s=%s). Fast-forwarding...",
                acct_def.name,
                account_id,
                TAG_BASELINE,
                BASELINE_COMPLETED,
            )
            report.vpc_reports = [
                VpcCleanupReport(
                    region="all",
                    skipped=True,
                    message=f"Already baselined ({TAG_BASELINE}={BASELINE_COMPLETED})",
                )
            ]
        elif baseline.delete_default_vpc:
            report.vpc_reports = self.cleanup_default_vpcs(account_id, acct_def.name, regions=regions)

        if baseline.budget:
            report.budget_report = self.setup_account_budget(
                account_id,
                acct_def.name,
                baseline.budget,
                account_tags=acct_def.tags,
                org_tags=org_tags,
                custom_tags=custom_tags,
            )

        if baseline.anomaly_detection:
            report.anomaly_report = self.setup_cost_anomaly_monitor(
                account_id, acct_def.name, baseline.anomaly_detection
            )

        has_vpc_errors = any(r.error for r in report.vpc_reports)
        has_budget_failure = report.budget_report is not None and report.budget_report.status == "FAILED"
        has_anomaly_failure = report.anomaly_report is not None and report.anomaly_report.status == "FAILED"

        if not already_baselined and not (has_vpc_errors or has_budget_failure or has_anomaly_failure):
            self.mark_account_baselined(account_id)

        return report
