import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_schema import AccountDef, AnomalyDetectionConfig, BudgetConfig
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
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)


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
        dry_run: bool = False,
    ) -> list[VpcCleanupReport]:
        """Purge default VPCs, subnets, and internet gateways across active AWS regions.

        If regions is None, dynamically queries all active/enabled AWS regions in the account.
        """
        target_regions = regions if regions is not None else self.get_enabled_regions(account_id)
        reports: list[VpcCleanupReport] = []

        logger.info(
            "Scanning for default VPCs in account '%s' (%s) across %d region(s)...",
            account_name,
            account_id,
            len(target_regions),
        )

        for region in target_regions:
            report = self._cleanup_region_default_vpc(account_id, account_name, region, dry_run=dry_run)
            reports.append(report)

        return reports

    def _cleanup_region_default_vpc(
        self, account_id: str, account_name: str, region: str, dry_run: bool
    ) -> VpcCleanupReport:
        """Helper to scan and clean default VPC in a single region."""
        try:
            ec2 = self.session_mgr.get_member_client(account_id, "ec2", region_name=region)
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])

            if not vpcs:
                return VpcCleanupReport(region=region, skipped=True, message="No default VPC found.")

            vpc_id = str(vpcs[0]["VpcId"])
            if dry_run:
                logger.info("[DRY-RUN] [%s] Would delete default VPC: %s", region, vpc_id)
                return VpcCleanupReport(
                    region=region, vpc_id=vpc_id, skipped=True, message="Simulated VPC deletion"
                )

            detached_igws = self._detach_and_delete_igws(ec2, vpc_id)
            deleted_subnets = self._delete_subnets(ec2, vpc_id)
            ec2.delete_vpc(VpcId=vpc_id)
            logger.info("[%s] Successfully deleted default VPC %s", region, vpc_id)

            return VpcCleanupReport(
                region=region,
                vpc_id=vpc_id,
                detached_igws=detached_igws,
                deleted_subnets=deleted_subnets,
                deleted_vpc=True,
                message="Successfully deleted default VPC",
            )

        except ClientError as e:
            err_code = e.response["Error"].get("Code", "")
            err_msg = e.response["Error"].get("Message", str(e))
            if err_code == "DependencyViolation":
                err_msg = f"DependencyViolation: VPC has active network interfaces or dependent resources ({err_msg})"
            logger.warning("[%s] Error cleaning default VPC in %s: %s", region, account_name, err_msg)
            return VpcCleanupReport(
                region=region,
                skipped=True,
                message=f"Error cleaning VPC: {err_msg}",
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
        dry_run: bool = False,
    ) -> BudgetReport:
        """Create or update a monthly cost budget in the member account via CloudFormation."""
        budget_name = f"{account_name}-monthly-budget"

        if not budget_cfg.notification_emails and not budget_cfg.incident_response_webhook_url:
            return BudgetReport(
                account_name=account_name,
                account_id=account_id,
                budget_name=budget_name,
                limit_usd=budget_cfg.monthly_limit_usd,
                alert_threshold_percent=budget_cfg.alert_threshold_percent,
                status="SKIPPED",
                message="No notification emails or incident response webhook specified.",
            )

        subscribers_count = len(budget_cfg.notification_emails) + (
            1 if budget_cfg.incident_response_webhook_url else 0
        )
        if dry_run:
            logger.info(
                "[DRY-RUN] Would deploy budget stack '%s' ($%.2f/mo, %d subscribers)",
                budget_name,
                budget_cfg.monthly_limit_usd,
                subscribers_count,
            )
            return BudgetReport(
                account_name=account_name,
                account_id=account_id,
                budget_name=budget_name,
                limit_usd=budget_cfg.monthly_limit_usd,
                alert_threshold_percent=budget_cfg.alert_threshold_percent,
                status="SIMULATED",
                message="Simulated budget creation via CloudFormation",
            )

        emails = list(budget_cfg.notification_emails)
        if len(emails) > 1:
            logger.info(
                "FinOps Best Practice: Account '%s' specifies %d alert emails. "
                "The SNS topic is configured with primary subscription '%s'. "
                "Consider consolidating alerts to a shared team distribution list (e.g. finops-alerts@company.com) "
                "or subscribing additional endpoints to the SNS topic.",
                account_name,
                len(emails),
                emails[0],
            )

        parameters: dict[str, str] = {
            "AccountName": account_name,
            "MonthlyLimitUSD": str(budget_cfg.monthly_limit_usd),
            "AlertThresholdPercent": str(budget_cfg.alert_threshold_percent),
            "NotificationEmail": str(emails[0]) if emails else "",
        }
        if budget_cfg.incident_response_webhook_url:
            parameters["IncidentResponseWebhookUrl"] = str(budget_cfg.incident_response_webhook_url)

        try:
            cfn_client = self.session_mgr.get_member_client(
                account_id, "cloudformation", region_name=self.session_mgr.default_region
            )
            template_path = resolve_resource_path("cloudformation/account-budget.yaml")
            cfn_service = CloudFormationService(self.session_mgr)

            def _cleanup_orphan_budget() -> None:
                try:
                    budgets_client = self.session_mgr.get_member_client(
                        account_id, "budgets", region_name="us-east-1"
                    )
                    resp = budgets_client.describe_budget(AccountId=account_id, BudgetName=budget_name)
                    if isinstance(resp, dict) and "Budget" in resp:
                        logger.info(
                            "Found pre-existing unmanaged budget '%s' in account '%s' (%s). "
                            "Removing orphan budget to allow CloudFormation to manage it...",
                            budget_name,
                            account_name,
                            account_id,
                        )
                        budgets_client.delete_budget(AccountId=account_id, BudgetName=budget_name)
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code not in ("NotFoundException", "ResourceNotFoundException"):
                        logger.debug("Error checking existing budget in %s: %s", account_name, e)
                except Exception as e:
                    logger.debug("Could not inspect existing budget in %s: %s", account_name, e)

            cfn_report = cfn_service.deploy_stack(
                cfn_client=cfn_client,
                stack_name=budget_name,
                template_file=template_path,
                parameters=parameters,
                tags=custom_tags,
                account_tags=account_tags,
                org_tags=org_tags,
                dry_run=dry_run,
                on_before_create=_cleanup_orphan_budget,
            )
            status = "CREATED" if cfn_report.action == "CREATED" else "UPDATED"
            return BudgetReport(
                account_name=account_name,
                account_id=account_id,
                budget_name=budget_name,
                limit_usd=budget_cfg.monthly_limit_usd,
                alert_threshold_percent=budget_cfg.alert_threshold_percent,
                status=status,
                message=f"Budget stack {status.lower()} via CloudFormation",
            )
        except Exception as e:
            logger.warning("Failed to deploy budget stack in %s: %s", account_name, e)
            return BudgetReport(
                account_name=account_name,
                account_id=account_id,
                budget_name=budget_name,
                limit_usd=budget_cfg.monthly_limit_usd,
                alert_threshold_percent=budget_cfg.alert_threshold_percent,
                status="FAILED",
                message=str(e),
            )

    def setup_cost_anomaly_monitor(
        self,
        account_id: str,
        account_name: str,
        anomaly_cfg: AnomalyDetectionConfig,
        dry_run: bool = False,
    ) -> AnomalyReport:
        """Create Cost Anomaly Detection monitor and subscription in the management account."""
        monitor_name = f"{account_name}-cost-anomaly-monitor"
        sub_name = f"{account_name}-anomaly-alerts"

        if not anomaly_cfg.enabled or not anomaly_cfg.notification_emails:
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                monitor_name=monitor_name,
                threshold_usd=anomaly_cfg.threshold_usd,
                status="SKIPPED",
                message="Anomaly detection disabled or missing notification emails.",
            )

        if dry_run:
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                monitor_name=monitor_name,
                threshold_usd=anomaly_cfg.threshold_usd,
                status="SIMULATED",
                message="Simulated anomaly monitor creation",
            )

        self._setup_member_anomaly_monitor(account_id, account_name, anomaly_cfg)
        ce_client = self.session_mgr.get_client("ce", region_name="us-east-1")

        try:
            monitor_arn, status = self._get_or_create_anomaly_monitor(ce_client, monitor_name, account_id)
            self._ensure_anomaly_subscription(
                ce_client, sub_name, monitor_arn, anomaly_cfg.threshold_usd, anomaly_cfg.notification_emails
            )
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                monitor_name=monitor_name,
                threshold_usd=anomaly_cfg.threshold_usd,
                status=status,
                message="Anomaly monitor and subscription active",
            )
        except ClientError as e:
            err_msg = e.response["Error"].get("Message", str(e))
            logger.warning("Cost Anomaly setup error for %s: %s", account_name, err_msg)
            return AnomalyReport(
                account_name=account_name,
                account_id=account_id,
                monitor_name=monitor_name,
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
                logger.info("[%s] Created in-account Cost Anomaly Monitor %s", account_name, monitor_name)

            self._ensure_anomaly_subscription(
                member_ce,
                f"{account_name}-local-alerts",
                monitor_arn,
                anomaly_cfg.threshold_usd,
                anomaly_cfg.notification_emails,
            )
        except ClientError as e:
            logger.info("Could not set up local anomaly monitor in %s: %s", account_name, e)

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
            logger.info("Tagged account %s as %s=%s", account_id, TAG_BASELINE, BASELINE_COMPLETED)
        except ClientError as e:
            logger.warning("Could not tag account %s as baselined: %s", account_id, e)

    def baseline_account(
        self,
        acct_def: AccountDef,
        account_id: str,
        regions: list[str] | None = None,
        dry_run: bool = False,
        force: bool = False,
        org_tags: dict[str, str] | None = None,
        custom_tags: dict[str, str] | None = None,
    ) -> BaselineReport:
        """Run all declared baselines for a single account and return a consolidated BaselineReport."""
        baseline = acct_def.baseline
        report = BaselineReport(account_name=acct_def.name, account_id=account_id)

        already_baselined = False if force else self.is_account_baselined(account_id)
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
            report.vpc_reports = self.cleanup_default_vpcs(
                account_id, acct_def.name, regions=regions, dry_run=dry_run
            )

        if baseline.budget:
            report.budget_report = self.setup_account_budget(
                account_id,
                acct_def.name,
                baseline.budget,
                account_tags=acct_def.tags,
                org_tags=org_tags,
                custom_tags=custom_tags,
                dry_run=dry_run,
            )

        if baseline.anomaly_detection:
            report.anomaly_report = self.setup_cost_anomaly_monitor(
                account_id, acct_def.name, baseline.anomaly_detection, dry_run=dry_run
            )

        if not dry_run and not already_baselined:
            self.mark_account_baselined(account_id)

        return report
