"""Teardown and Deletion Service for Tarmac Governance Deployments.

Provides comprehensive, safe, and idempotent teardown of all resources provisioned
across deployment phases:
- S3 log archives and backend state buckets (purges all versions and delete markers before stack deletion)
- CloudFormation stacks across Management and Member accounts
- Service Control Policies (detaches and deletes policies)
- Standalone AWS Budgets and Cost Anomaly Monitors
- Standalone CloudTrail trails
- Milestone and status tags on the AWS Organization Root
"""

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import GovernanceError
from .cloudformation import CloudFormationService
from .identity import IdentityService
from .scp import SCPService

logger = logging.getLogger(__name__)


@dataclass
class TeardownItemReport:
    """Status of a single torn-down resource."""

    resource_type: str
    resource_name: str
    account_name: str
    account_id: str
    action: str  # DELETED, EMPTY, NOT_FOUND, SKIPPED, FAILED, SIMULATED
    message: str = ""


class _ReportingList(list[TeardownItemReport]):
    """Internal list that immediately notifies a callback when items are appended."""

    def __init__(self, callback: Callable[[TeardownItemReport], None] | None = None) -> None:
        super().__init__()
        self._callback = callback

    def append(self, item: TeardownItemReport) -> None:
        super().append(item)
        if self._callback is not None:
            self._callback(item)


@dataclass
class TeardownReport:
    """Overall summary report of teardown operations."""

    items: list[TeardownItemReport] = field(default_factory=list)
    status: str = "COMPLETED"

    @property
    def deleted_count(self) -> int:
        return sum(1 for i in self.items if i.action in ("DELETED", "EMPTY"))

    @property
    def failed_count(self) -> int:
        return sum(1 for i in self.items if i.action == "FAILED")


def normalize_bucket_name(name_or_arn: str) -> str:
    """Extract clean bucket name from S3 bucket name or ARN."""
    clean = name_or_arn.strip()
    if clean.startswith("arn:aws"):
        clean = clean.split(":")[-1].split("/")[-1]
    return clean


def empty_s3_bucket(
    s3_client: Any,
    bucket_name: str,
    on_progress: Callable[[str], None] | None = None,
) -> int:
    """Purge all object versions, delete markers, and unversioned objects from an S3 bucket.

    Returns the total number of deleted objects and delete markers.
    """
    bucket_name = normalize_bucket_name(bucket_name)
    if not bucket_name:
        return 0
    total_deleted = 0
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            logger.debug("Bucket '%s' does not exist.", bucket_name)
            return 0
        logger.debug("Bucket '%s' inaccessible: %s", bucket_name, e)
        return 0
    except Exception as e:
        logger.debug("Bucket '%s' check failed: %s", bucket_name, e)
        return 0

    msg = f"Purging all contents, versions, and delete markers from bucket '{bucket_name}'..."
    logger.info(msg)
    if on_progress is not None:
        on_progress(msg)

    # 1. Purge versions and delete markers (handles versioned and version-suspended buckets)
    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            to_delete: list[dict[str, str]] = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})

            if to_delete:
                for i in range(0, len(to_delete), 1000):
                    batch = to_delete[i : i + 1000]
                    s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={"Objects": batch, "Quiet": True},
                    )
                    total_deleted += len(batch)
                    if on_progress is not None and total_deleted > 0 and total_deleted % 1000 == 0:
                        on_progress(f"Purged {total_deleted} items from bucket '{bucket_name}' so far...")
    except ClientError as e:
        logger.debug("Error purging object versions in '%s': %s", bucket_name, e)

    # 2. Purge unversioned objects (fallback for standard non-versioned objects)
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            contents = page.get("Contents", [])
            if contents:
                to_delete_objs = [{"Key": obj["Key"]} for obj in contents]
                for i in range(0, len(to_delete_objs), 1000):
                    batch_objs = to_delete_objs[i : i + 1000]
                    s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={"Objects": batch_objs, "Quiet": True},
                    )
                    total_deleted += len(batch_objs)
                    if on_progress is not None and total_deleted > 0 and total_deleted % 1000 == 0:
                        on_progress(f"Purged {total_deleted} items from bucket '{bucket_name}' so far...")
    except ClientError as e:
        logger.debug("Error purging standard objects in '%s': %s", bucket_name, e)

    if total_deleted > 0:
        logger.info("Successfully purged %d items from bucket '%s'.", total_deleted, bucket_name)
    return total_deleted


def is_s3_bucket_empty(s3_client: Any, bucket_name: str) -> bool:
    """Check if an S3 bucket is completely empty (no versions, delete markers, or objects)."""
    clean_name = normalize_bucket_name(bucket_name)
    if not clean_name:
        return True
    try:
        s3_client.head_bucket(Bucket=clean_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            return True
        logger.debug("Bucket '%s' inaccessible during empty check: %s", clean_name, e)
        return False
    except Exception as e:
        logger.debug("Bucket '%s' check failed: %s", clean_name, e)
        return False

    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=clean_name, PaginationConfig={"MaxItems": 1}):
            if page.get("Versions") or page.get("DeleteMarkers"):
                return False
    except ClientError as e:
        logger.debug("Error checking object versions for '%s': %s", clean_name, e)

    try:
        resp = s3_client.list_objects_v2(Bucket=clean_name, MaxKeys=1)
        if resp.get("KeyCount", 0) > 0 or resp.get("Contents"):
            return False
    except ClientError as e:
        logger.debug("Error checking objects for '%s': %s", clean_name, e)

    return True


def cleanup_orphaned_bucket(s3_client: Any, bucket_name: str, account_id: str = "") -> bool:
    """If an orphaned bucket exists from a previous run: delete it if empty, or raise error if it has data.

    Returns True if bucket was found and deleted, False if bucket did not exist.
    """
    clean_name = normalize_bucket_name(bucket_name)
    if not clean_name:
        return False

    try:
        s3_client.head_bucket(Bucket=clean_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            return False
        logger.debug("Bucket '%s' check error: %s", clean_name, e)
        return False
    except Exception:
        return False

    if is_s3_bucket_empty(s3_client, clean_name):
        logger.info(
            "Deleting orphaned empty S3 bucket '%s' before stack creation to satisfy CloudFormation pre-deployment validation...",
            clean_name,
        )
        try:
            s3_client.delete_bucket(Bucket=clean_name)
            logger.info("Successfully deleted orphaned empty S3 bucket '%s'.", clean_name)
            return True
        except ClientError as e:
            logger.warning("Failed to delete orphaned empty S3 bucket '%s': %s", clean_name, e)
            return False
    else:
        acct_msg = f" in account {account_id}" if account_id else ""
        raise GovernanceError(
            f"Pre-deployment validation error: S3 bucket '{clean_name}' already exists{acct_msg} and contains data. "
            "CloudFormation cannot create this stack while an existing bucket with the same name exists. "
            "To proceed, please empty or delete this bucket before retrying deployment."
        )


class TeardownService:
    """Orchestrates comprehensive teardown of Tarmac governance resources."""

    def __init__(
        self,
        session_mgr: AwsSessionManager,
        on_progress: Callable[[str], None] | None = None,
        on_item: Callable[[TeardownItemReport], None] | None = None,
        on_phase: Callable[[str], None] | None = None,
    ) -> None:
        self.session_mgr = session_mgr
        self.cfn_service = CloudFormationService(session_mgr)
        self.on_progress = on_progress
        self.on_item = on_item
        self.on_phase = on_phase

    def _new_results_list(self) -> _ReportingList:
        return _ReportingList(self.on_item)

    def _notify_progress(self, message: str) -> None:
        logger.info(message)
        if self.on_progress is not None:
            self.on_progress(message)

    def _notify_phase(self, phase_name: str) -> None:
        logger.info("=== %s ===", phase_name)
        if self.on_phase is not None:
            self.on_phase(phase_name)

    def _get_active_accounts(self) -> dict[str, str]:
        """Fetch all ACTIVE accounts in the organization as {AccountName: AccountId}."""
        org_client = self.session_mgr.get_client("organizations")
        accts: dict[str, str] = {}
        try:
            paginator = org_client.get_paginator("list_accounts")
            for page in paginator.paginate():
                for a in page.get("Accounts", []):
                    if isinstance(a, dict) and a.get("Status") in ("ACTIVE", None):
                        accts[a["Name"]] = str(a["Id"])
        except Exception as e:
            logger.debug("Could not query active accounts: %s", e)
        return accts

    def _get_management_account_id(self) -> str:
        """Resolve current management account ID."""
        try:
            return str(self.session_mgr.get_caller_identity().get("Account", ""))
        except Exception:
            return ""

    def teardown_cloudtrail(
        self, bundle: ConfigBundle, target_region: str, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Tear down Organization CloudTrail stack and direct trail."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_name = f"{bundle.org.organization.name}-organization-cloudtrail"
        trail_name = bundle.org.cloudtrail.trail_name

        try:
            cfn_client = self.session_mgr.get_client("cloudformation", region_name=target_region)
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)
            if status and status != "DELETE_COMPLETE":
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name="Management",
                            account_id=mgmt_id,
                            action="SIMULATED",
                            message=f"Would delete CloudTrail stack (status: {status})",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Deleting CloudFormation stack '{stack_name}' in Management (waiting for AWS)..."
                    )
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name="Management",
                            account_id=mgmt_id,
                            action="DELETED",
                            message="Deleted CloudTrail CloudFormation stack",
                        )
                    )
            else:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=stack_name,
                        account_name="Management",
                        account_id=mgmt_id,
                        action="NOT_FOUND",
                        message="Stack does not exist",
                    )
                )
        except Exception as e:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name="Management",
                    account_id=mgmt_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        # Cleanup direct trail if left over
        try:
            trail_client = self.session_mgr.get_client("cloudtrail", region_name=target_region)
            if not dry_run:
                try:
                    trail_client.stop_logging(Name=trail_name)
                except ClientError:
                    pass
                self._notify_progress(f"Deleting standalone CloudTrail trail '{trail_name}' in Management...")
                trail_client.delete_trail(Name=trail_name)
                results.append(
                    TeardownItemReport(
                        resource_type="CloudTrail Trail",
                        resource_name=trail_name,
                        account_name="Management",
                        account_id=mgmt_id,
                        action="DELETED",
                        message="Deleted standalone CloudTrail trail",
                    )
                )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code not in ("TrailNotFoundException", "ResourceNotFoundException"):
                logger.debug("Trail deletion check: %s", e)

        return results

    def teardown_log_archive(
        self,
        bundle: ConfigBundle,
        target_region: str,
        dry_run: bool = False,
        account_id_map: dict[str, str] | None = None,
    ) -> list[TeardownItemReport]:
        """Empty S3 log buckets and delete Log-Archive hardening stack."""
        results: list[TeardownItemReport] = self._new_results_list()
        accts = account_id_map or self._get_active_accounts()
        log_acct_name = bundle.get_log_archive_account_name() or "log-archive"
        log_acct_id = bundle.resolve_account_id(log_acct_name, accts) or ""
        stack_name = f"{bundle.org.organization.name}-log-archive-hardening"

        if not log_acct_id:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name=log_acct_name,
                    account_id="",
                    action="SKIPPED",
                    message="Log Archive account not resolved in active accounts",
                )
            )
            return results

        try:
            cfn_client = self.session_mgr.get_member_client(
                log_acct_id, "cloudformation", region_name=target_region
            )
            s3_client = self.session_mgr.get_member_client(log_acct_id, "s3", region_name=target_region)
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)

            # Discover bucket names
            buckets_to_empty: set[str] = {
                f"{bundle.org.cloudtrail.bucket_prefix}-{log_acct_id}",
                f"{bundle.org.organization.name}-org-cloudtrail-logs-{log_acct_id}",
                f"{bundle.org.organization.name}-log-archive-access-logs-{log_acct_id}",
            }
            if status:
                outputs = self.cfn_service._fetch_stack_outputs(cfn_client, stack_name)
                for k, v in outputs.items():
                    if "Bucket" in k and v:
                        clean_b = normalize_bucket_name(v)
                        if clean_b:
                            buckets_to_empty.add(clean_b)

            for b in sorted(buckets_to_empty):
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="S3 Bucket",
                            resource_name=b,
                            account_name=log_acct_name,
                            account_id=log_acct_id,
                            action="SIMULATED",
                            message="Would purge all object versions and delete markers",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Purging object versions from S3 bucket '{b}' in {log_acct_name}..."
                    )
                    try:
                        purged_count = empty_s3_bucket(s3_client, b, on_progress=self.on_progress)
                        results.append(
                            TeardownItemReport(
                                resource_type="S3 Bucket",
                                resource_name=b,
                                account_name=log_acct_name,
                                account_id=log_acct_id,
                                action="EMPTY",
                                message=f"Purged {purged_count} objects/versions/markers",
                            )
                        )
                    except Exception as e:
                        logger.warning("Failed to purge bucket '%s': %s", b, e)
                        results.append(
                            TeardownItemReport(
                                resource_type="S3 Bucket",
                                resource_name=b,
                                account_name=log_acct_name,
                                account_id=log_acct_id,
                                action="FAILED",
                                message=f"Failed to purge bucket: {e}",
                            )
                        )

            if status and status != "DELETE_COMPLETE":
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name=log_acct_name,
                            account_id=log_acct_id,
                            action="SIMULATED",
                            message=f"Would delete Log-Archive hardening stack (status: {status})",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Deleting CloudFormation stack '{stack_name}' in {log_acct_name} (waiting for AWS)..."
                    )
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name=log_acct_name,
                            account_id=log_acct_id,
                            action="DELETED",
                            message="Deleted Log-Archive hardening stack",
                        )
                    )
            else:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=stack_name,
                        account_name=log_acct_name,
                        account_id=log_acct_id,
                        action="NOT_FOUND",
                        message="Stack does not exist",
                    )
                )

            # Delete the emptied S3 buckets that CloudFormation retained
            if not dry_run:
                for b in sorted(buckets_to_empty):
                    try:
                        s3_client.delete_bucket(Bucket=b)
                        logger.info("Deleted retained S3 bucket '%s' in %s.", b, log_acct_name)
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "")
                        if code not in ("NoSuchBucket", "NotFound"):
                            logger.debug("Bucket '%s' deletion after stack teardown: %s", b, e)
                    except Exception as e:
                        logger.debug("Bucket '%s' deletion error: %s", b, e)

        except Exception as e:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name=log_acct_name,
                    account_id=log_acct_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        return results

    def teardown_budgets(
        self,
        bundle: ConfigBundle,
        dry_run: bool = False,
        account_id_map: dict[str, str] | None = None,
    ) -> list[TeardownItemReport]:
        """Tear down budget stacks, standalone AWS Budgets, and Cost Anomaly Monitors in member accounts."""
        results: list[TeardownItemReport] = self._new_results_list()
        accts = account_id_map or self._get_active_accounts()

        for acct_def in bundle.accounts.accounts:
            acct_name = acct_def.name
            acct_id = bundle.resolve_account_id(acct_name, accts) or ""
            budget_name = f"{acct_name}-monthly-budget"

            if not acct_id:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=budget_name,
                        account_name=acct_name,
                        account_id="",
                        action="SKIPPED",
                        message="Account not resolved in active accounts",
                    )
                )
                continue

            try:
                cfn_client = self.session_mgr.get_member_client(
                    acct_id, "cloudformation", region_name=self.session_mgr.default_region
                )
                status = self.cfn_service._get_stack_status(cfn_client, budget_name)
                if status and status != "DELETE_COMPLETE":
                    if dry_run:
                        results.append(
                            TeardownItemReport(
                                resource_type="CloudFormation Stack",
                                resource_name=budget_name,
                                account_name=acct_name,
                                account_id=acct_id,
                                action="SIMULATED",
                                message=f"Would delete budget stack (status: {status})",
                            )
                        )
                    else:
                        self._notify_progress(
                            f"Deleting budget stack '{budget_name}' in {acct_name} (waiting for AWS)..."
                        )
                        self.cfn_service.delete_stack(cfn_client, budget_name, on_progress=self.on_progress)
                        results.append(
                            TeardownItemReport(
                                resource_type="CloudFormation Stack",
                                resource_name=budget_name,
                                account_name=acct_name,
                                account_id=acct_id,
                                action="DELETED",
                                message="Deleted budget stack",
                            )
                        )
                else:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=budget_name,
                            account_name=acct_name,
                            account_id=acct_id,
                            action="NOT_FOUND",
                            message="Budget stack does not exist",
                        )
                    )

                # Direct AWS Budgets API cleanup
                budgets_client = self.session_mgr.get_member_client(
                    acct_id, "budgets", region_name="us-east-1"
                )
                try:
                    budgets_client.describe_budget(AccountId=acct_id, BudgetName=budget_name)
                    if dry_run:
                        results.append(
                            TeardownItemReport(
                                resource_type="AWS Budget",
                                resource_name=budget_name,
                                account_name=acct_name,
                                account_id=acct_id,
                                action="SIMULATED",
                                message="Would delete direct AWS Budget",
                            )
                        )
                    else:
                        self._notify_progress(f"Deleting direct AWS Budget '{budget_name}' in {acct_name}...")
                        budgets_client.delete_budget(AccountId=acct_id, BudgetName=budget_name)
                        results.append(
                            TeardownItemReport(
                                resource_type="AWS Budget",
                                resource_name=budget_name,
                                account_name=acct_name,
                                account_id=acct_id,
                                action="DELETED",
                                message="Deleted direct AWS Budget",
                            )
                        )
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code not in ("NotFoundException", "ResourceNotFoundException"):
                        logger.debug("Direct budget inspection in %s: %s", acct_name, e)

                # Direct Cost Anomaly Detection cleanup
                try:
                    ce_client = self.session_mgr.get_member_client(acct_id, "ce", region_name="us-east-1")
                    mon_resp = ce_client.get_anomaly_monitors()
                    for mon in mon_resp.get("AnomalyMonitors", []):
                        m_name = str(mon.get("MonitorName", ""))
                        m_arn = str(mon.get("MonitorArn", ""))
                        if acct_name.lower() in m_name.lower() or "tarmac" in m_name.lower():
                            if dry_run:
                                results.append(
                                    TeardownItemReport(
                                        resource_type="Cost Anomaly Monitor",
                                        resource_name=m_name,
                                        account_name=acct_name,
                                        account_id=acct_id,
                                        action="SIMULATED",
                                        message="Would delete anomaly monitor",
                                    )
                                )
                            else:
                                self._notify_progress(
                                    f"Deleting anomaly monitor '{m_name}' in {acct_name}..."
                                )
                                ce_client.delete_anomaly_monitor(MonitorArn=m_arn)
                                results.append(
                                    TeardownItemReport(
                                        resource_type="Cost Anomaly Monitor",
                                        resource_name=m_name,
                                        account_name=acct_name,
                                        account_id=acct_id,
                                        action="DELETED",
                                        message="Deleted anomaly monitor",
                                    )
                                )
                except Exception as e:
                    logger.debug("Cost anomaly monitor check in %s: %s", acct_name, e)

            except Exception as e:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=budget_name,
                        account_name=acct_name,
                        account_id=acct_id,
                        action="FAILED",
                        message=str(e),
                    )
                )

        return results

    def teardown_backend(
        self,
        bundle: ConfigBundle,
        target_region: str,
        dry_run: bool = False,
        account_id_map: dict[str, str] | None = None,
    ) -> list[TeardownItemReport]:
        """Empty Terraform backend state bucket and delete backend stack."""
        results: list[TeardownItemReport] = self._new_results_list()
        accts = account_id_map or self._get_active_accounts()
        backend_acct_name = bundle.get_backend_account_name() or "deployment"
        backend_acct_id = bundle.resolve_account_id(backend_acct_name, accts) or ""
        stack_name = f"{bundle.org.organization.name}-terraform-backend"

        if not backend_acct_id:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name=backend_acct_name,
                    account_id="",
                    action="SKIPPED",
                    message="Deployment/backend account not resolved in active accounts",
                )
            )
            return results

        try:
            cfn_client = self.session_mgr.get_member_client(
                backend_acct_id, "cloudformation", region_name=target_region
            )
            s3_client = self.session_mgr.get_member_client(backend_acct_id, "s3", region_name=target_region)
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)

            buckets_to_empty: set[str] = {
                f"{bundle.org.terraform_backend.bucket_prefix}-{backend_acct_id}",
            }
            if status:
                outputs = self.cfn_service._fetch_stack_outputs(cfn_client, stack_name)
                for k, v in outputs.items():
                    if "Bucket" in k and v:
                        clean_b = normalize_bucket_name(v)
                        if clean_b:
                            buckets_to_empty.add(clean_b)

            for b in sorted(buckets_to_empty):
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="S3 Bucket",
                            resource_name=b,
                            account_name=backend_acct_name,
                            account_id=backend_acct_id,
                            action="SIMULATED",
                            message="Would purge state bucket",
                        )
                    )
                else:
                    self._notify_progress(f"Purging state bucket '{b}' in {backend_acct_name}...")
                    try:
                        purged_count = empty_s3_bucket(s3_client, b, on_progress=self.on_progress)
                        results.append(
                            TeardownItemReport(
                                resource_type="S3 Bucket",
                                resource_name=b,
                                account_name=backend_acct_name,
                                account_id=backend_acct_id,
                                action="EMPTY",
                                message=f"Purged {purged_count} objects from state bucket",
                            )
                        )
                    except Exception as e:
                        logger.warning("Failed to purge bucket '%s': %s", b, e)
                        results.append(
                            TeardownItemReport(
                                resource_type="S3 Bucket",
                                resource_name=b,
                                account_name=backend_acct_name,
                                account_id=backend_acct_id,
                                action="FAILED",
                                message=f"Failed to purge bucket: {e}",
                            )
                        )

            if status and status != "DELETE_COMPLETE":
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name=backend_acct_name,
                            account_id=backend_acct_id,
                            action="SIMULATED",
                            message=f"Would delete backend stack (status: {status})",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Deleting CloudFormation stack '{stack_name}' in {backend_acct_name} (waiting for AWS)..."
                    )
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name=backend_acct_name,
                            account_id=backend_acct_id,
                            action="DELETED",
                            message="Deleted Terraform backend stack",
                        )
                    )
            else:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=stack_name,
                        account_name=backend_acct_name,
                        account_id=backend_acct_id,
                        action="NOT_FOUND",
                        message="Stack does not exist",
                    )
                )

            # Delete the emptied backend S3 buckets that CloudFormation retained
            if not dry_run:
                for b in sorted(buckets_to_empty):
                    try:
                        s3_client.delete_bucket(Bucket=b)
                        logger.info("Deleted retained backend state bucket '%s' in %s.", b, backend_acct_name)
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "")
                        if code not in ("NoSuchBucket", "NotFound"):
                            logger.debug("Bucket '%s' deletion after stack teardown: %s", b, e)
                    except Exception as e:
                        logger.debug("Bucket '%s' deletion error: %s", b, e)

        except Exception as e:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name=backend_acct_name,
                    account_id=backend_acct_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        return results

    def teardown_audit(
        self,
        bundle: ConfigBundle,
        target_region: str,
        dry_run: bool = False,
        account_id_map: dict[str, str] | None = None,
    ) -> list[TeardownItemReport]:
        """Tear down Audit account hardening stack."""
        results: list[TeardownItemReport] = self._new_results_list()
        accts = account_id_map or self._get_active_accounts()
        audit_acct_name = bundle.get_audit_account_name() or "audit"
        audit_acct_id = bundle.resolve_account_id(audit_acct_name, accts) or ""
        stack_name = f"{bundle.org.organization.name}-audit-account-hardening"

        if not audit_acct_id:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name=audit_acct_name,
                    account_id="",
                    action="SKIPPED",
                    message="Audit account not resolved in active accounts",
                )
            )
            return results

        try:
            cfn_client = self.session_mgr.get_member_client(
                audit_acct_id, "cloudformation", region_name=target_region
            )
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)
            if status and status != "DELETE_COMPLETE":
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name=audit_acct_name,
                            account_id=audit_acct_id,
                            action="SIMULATED",
                            message=f"Would delete Audit hardening stack (status: {status})",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Deleting CloudFormation stack '{stack_name}' in {audit_acct_name} (waiting for AWS)..."
                    )
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name=audit_acct_name,
                            account_id=audit_acct_id,
                            action="DELETED",
                            message="Deleted Audit hardening stack",
                        )
                    )
            else:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=stack_name,
                        account_name=audit_acct_name,
                        account_id=audit_acct_id,
                        action="NOT_FOUND",
                        message="Stack does not exist",
                    )
                )
        except Exception as e:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name=audit_acct_name,
                    account_id=audit_acct_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        return results

    def teardown_scps(self, bundle: ConfigBundle, dry_run: bool = False) -> list[TeardownItemReport]:
        """Tear down SCP CloudFormation stack and detach/delete direct SCPs."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_name = f"{bundle.org.organization.name}-organization-scps"

        try:
            cfn_client = self.session_mgr.get_client(
                "cloudformation", region_name=self.session_mgr.default_region
            )
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)
            if status and status != "DELETE_COMPLETE":
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name="Management",
                            account_id=mgmt_id,
                            action="SIMULATED",
                            message=f"Would delete SCP stack (status: {status})",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Deleting CloudFormation stack '{stack_name}' in Management (waiting for AWS)..."
                    )
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name="Management",
                            account_id=mgmt_id,
                            action="DELETED",
                            message="Deleted SCP CloudFormation stack",
                        )
                    )
        except Exception as e:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name="Management",
                    account_id=mgmt_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        # Cleanup direct SCP policies
        try:
            scp_service = SCPService(self.session_mgr)
            existing = scp_service.list_existing_scps()
            policies_to_remove: set[str] = {
                "FoundationalGuardrails",
                "DenyMemberRootActivity",
                "DenyLeaveOrganization",
            }
            if bundle.org.service_control_policies:
                for p in bundle.org.service_control_policies.policies:
                    policies_to_remove.add(p.name)

            org_client = self.session_mgr.get_client("organizations")
            for p_name in sorted(policies_to_remove):
                if p_name in existing:
                    pol_id = str(existing[p_name]["Id"])
                    targets = scp_service.list_targets_for_policy(pol_id)
                    if dry_run:
                        results.append(
                            TeardownItemReport(
                                resource_type="Service Control Policy",
                                resource_name=p_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="SIMILATED" if hasattr(self, "_typo") else "SIMULATED",
                                message=f"Would detach from {len(targets)} target(s) and delete",
                            )
                        )
                    else:
                        self._notify_progress(
                            f"Detaching and deleting Service Control Policy '{p_name}' in Management..."
                        )
                        for t in targets:
                            try:
                                org_client.detach_policy(PolicyId=pol_id, TargetId=t)
                            except ClientError as e:
                                logger.debug("Could not detach policy %s from %s: %s", pol_id, t, e)
                        try:
                            org_client.delete_policy(PolicyId=pol_id)
                            results.append(
                                TeardownItemReport(
                                    resource_type="Service Control Policy",
                                    resource_name=p_name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="DELETED",
                                    message=f"Detached from {len(targets)} targets and deleted",
                                )
                            )
                        except ClientError as e:
                            results.append(
                                TeardownItemReport(
                                    resource_type="Service Control Policy",
                                    resource_name=p_name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="FAILED",
                                    message=str(e),
                                )
                            )
        except Exception as e:
            logger.debug("Direct SCP cleanup inspection: %s", e)

        return results

    def teardown_identity(
        self, bundle: ConfigBundle, target_region: str, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Tear down Permission Sets CloudFormation stacks and clean up retained permission sets."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_names = [
            f"{bundle.org.organization.name}-sso-permission-sets",
            f"{bundle.org.organization.name}-permission-sets",
        ]

        for stack_name in stack_names:
            try:
                cfn_client = self.session_mgr.get_client("cloudformation", region_name=target_region)
                status = self.cfn_service._get_stack_status(cfn_client, stack_name)
                if status and status != "DELETE_COMPLETE":
                    if dry_run:
                        results.append(
                            TeardownItemReport(
                                resource_type="CloudFormation Stack",
                                resource_name=stack_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="SIMULATED",
                                message=f"Would delete permission sets stack (status: {status})",
                            )
                        )
                    else:
                        self._notify_progress(
                            f"Deleting CloudFormation stack '{stack_name}' in Management (waiting for AWS)..."
                        )
                        self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                        results.append(
                            TeardownItemReport(
                                resource_type="CloudFormation Stack",
                                resource_name=stack_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="DELETED",
                                message="Deleted permission sets CloudFormation stack",
                            )
                        )
            except Exception as e:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=stack_name,
                        account_name="Management",
                        account_id=mgmt_id,
                        action="FAILED",
                        message=str(e),
                    )
                )

        # Direct cleanup of declared permission sets in IAM Identity Center (retained by CloudFormation DeletionPolicy)
        if bundle.identity and bundle.identity.identity_center:
            try:
                identity_service = IdentityService(self.session_mgr, preferred_region=target_region)
                inst_arn, _ = identity_service.get_instance_details()
                existing_ps = identity_service.list_permission_sets(inst_arn)
                for ps_def in bundle.identity.identity_center.permission_sets:
                    if ps_def.name in existing_ps:
                        ps_arn = existing_ps[ps_def.name]
                        if dry_run:
                            results.append(
                                TeardownItemReport(
                                    resource_type="Permission Set",
                                    resource_name=ps_def.name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="SIMULATED",
                                    message=f"Would delete retained Permission Set '{ps_def.name}' ({ps_arn})",
                                )
                            )
                        else:
                            self._notify_progress(
                                f"Deleting retained Permission Set '{ps_def.name}' in IAM Identity Center..."
                            )
                            identity_service.delete_permission_set(inst_arn, ps_arn)
                            results.append(
                                TeardownItemReport(
                                    resource_type="Permission Set",
                                    resource_name=ps_def.name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="DELETED",
                                    message=f"Deleted retained Permission Set '{ps_def.name}'",
                                )
                            )
            except Exception as e:
                logger.debug("Identity Center direct cleanup: %s", e)

        return results

    def reset_milestones(self, mgmt_account_id: str, dry_run: bool = False) -> list[TeardownItemReport]:
        """Remove tarmac deployment tags and reset milestones on the Management Account."""
        results: list[TeardownItemReport] = self._new_results_list()
        if not mgmt_account_id:
            return results

        tag_keys = [
            "tarmac:completed-phases",
            "tarmac:status",
            "tarmac:version",
            "tarmac:deployment-ready",
        ]

        if dry_run:
            results.append(
                TeardownItemReport(
                    resource_type="Organization Tag",
                    resource_name="tarmac:* tags",
                    account_name="Management",
                    account_id=mgmt_account_id,
                    action="SIMULATED",
                    message="Would remove milestone and status tags",
                )
            )
            return results

        try:
            self._notify_progress("Resetting deployment milestone and status tags on Management Account...")
            org_client = self.session_mgr.get_client("organizations")
            org_client.untag_resource(ResourceId=mgmt_account_id, TagKeys=tag_keys)
            results.append(
                TeardownItemReport(
                    resource_type="Organization Tag",
                    resource_name="tarmac:* tags",
                    account_name="Management",
                    account_id=mgmt_account_id,
                    action="DELETED",
                    message="Removed deployment milestone and status tags",
                )
            )
        except ClientError as e:
            results.append(
                TeardownItemReport(
                    resource_type="Organization Tag",
                    resource_name="tarmac:* tags",
                    account_name="Management",
                    account_id=mgmt_account_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        return results

    def teardown_phase(
        self,
        phase: int,
        bundle: ConfigBundle,
        target_region: str,
        dry_run: bool = False,
        account_id_map: dict[str, str] | None = None,
    ) -> list[TeardownItemReport]:
        """Tear down resources belonging to a specific phase."""
        accts = account_id_map or self._get_active_accounts()
        if phase == 2:
            self._notify_phase("Phase 2 | Organizational Units & Guardrails (SCPs)")
            return self.teardown_scps(bundle, dry_run=dry_run)
        if phase == 3:
            self._notify_phase("Phase 3 | CloudTrail & Central Logging")
            items: list[TeardownItemReport] = []
            items.extend(self.teardown_cloudtrail(bundle, target_region, dry_run=dry_run))
            items.extend(
                self.teardown_log_archive(bundle, target_region, dry_run=dry_run, account_id_map=accts)
            )
            return items
        if phase == 4:
            self._notify_phase("Phase 4 | Account Factory Provisioning & Baselining (Budgets)")
            return self.teardown_budgets(bundle, dry_run=dry_run, account_id_map=accts)
        if phase == 5:
            self._notify_phase("Phase 5 | Backend & Security Services Deployments")
            items = []
            items.extend(self.teardown_backend(bundle, target_region, dry_run=dry_run, account_id_map=accts))
            items.extend(self.teardown_audit(bundle, target_region, dry_run=dry_run, account_id_map=accts))
            return items
        if phase == 6:
            self._notify_phase("Phase 6 | IAM Identity Center (SSO)")
            return self.teardown_identity(bundle, target_region, dry_run=dry_run)
        return []

    def teardown_all(
        self,
        bundle: ConfigBundle,
        target_region: str | None = None,
        dry_run: bool = False,
        phases: Sequence[int] | None = None,
        preserve_backend: bool = False,
    ) -> TeardownReport:
        """Tear down all deployment resources across all phases in safe dependency order."""
        region = target_region or bundle.org.organization.primary_region
        accts = self._get_active_accounts()
        mgmt_id = self._get_management_account_id()
        items: list[TeardownItemReport] = []

        phases_set = set(phases) if phases is not None else {2, 3, 4, 5, 6}

        # 1. CloudTrail trail & stack (must stop logging before emptying S3 bucket)
        if 3 in phases_set:
            self._notify_phase("Phase 3 | Organization CloudTrail")
            items.extend(self.teardown_cloudtrail(bundle, region, dry_run=dry_run))

        # 2. Log-Archive S3 buckets & hardening stack
        if 3 in phases_set or 5 in phases_set:
            self._notify_phase("Phase 3/5 | Log Archive Hardening & Buckets")
            items.extend(self.teardown_log_archive(bundle, region, dry_run=dry_run, account_id_map=accts))

        # 3. Member Account Budgets & Cost Anomaly Monitors
        if 4 in phases_set:
            self._notify_phase("Phase 4 | Budgets & Cost Monitors")
            items.extend(self.teardown_budgets(bundle, dry_run=dry_run, account_id_map=accts))

        # 4. Terraform Backend S3 bucket & stack
        if 5 in phases_set:
            self._notify_phase("Phase 5 | Terraform Backend & Audit Hardening")
            if not preserve_backend:
                items.extend(self.teardown_backend(bundle, region, dry_run=dry_run, account_id_map=accts))
            else:
                self._notify_progress("Preserving Terraform remote state backend S3 bucket and lock table.")
                items.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=f"{bundle.org.organization.name}-terraform-backend",
                        account_name=bundle.get_backend_account_name() or "deployment",
                        account_id="",
                        action="SKIPPED",
                        message="Preserved by --preserve-backend flag",
                    )
                )
            items.extend(self.teardown_audit(bundle, region, dry_run=dry_run, account_id_map=accts))

        # 5. Identity Center Permission Sets
        if 6 in phases_set:
            self._notify_phase("Phase 6 | IAM Identity Center Permission Sets")
            items.extend(self.teardown_identity(bundle, region, dry_run=dry_run))

        # 6. Service Control Policies stack & direct policies
        if 2 in phases_set:
            self._notify_phase("Phase 2 | Service Control Policies")
            items.extend(self.teardown_scps(bundle, dry_run=dry_run))

        # 7. Milestone tags
        if phases is None and mgmt_id:
            self._notify_phase("Milestones | Resetting Deployment Tags")
            items.extend(self.reset_milestones(mgmt_id, dry_run=dry_run))

        status = (
            "SIMULATED"
            if dry_run
            else ("FAILED" if any(i.action == "FAILED" for i in items) else "COMPLETED")
        )
        return TeardownReport(items=items, status=status)


def teardown_deployment(
    bundle: ConfigBundle,
    session_mgr: AwsSessionManager | None = None,
    region: str | None = None,
    phases: Sequence[int] | None = None,
    dry_run: bool = False,
    on_progress: Callable[[str], None] | None = None,
    on_item: Callable[[TeardownItemReport], None] | None = None,
    on_phase: Callable[[str], None] | None = None,
    preserve_backend: bool = False,
) -> TeardownReport:
    """Convenience function to tear down deployment resources."""
    target_region = region or bundle.org.organization.primary_region
    manager = session_mgr or AwsSessionManager(region_name=target_region)
    service = TeardownService(
        manager,
        on_progress=on_progress,
        on_item=on_item,
        on_phase=on_phase,
    )
    return service.teardown_all(
        bundle=bundle,
        target_region=target_region,
        dry_run=dry_run,
        phases=phases,
        preserve_backend=preserve_backend,
    )
