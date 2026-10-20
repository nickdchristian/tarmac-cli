"""Teardown of budgets, cost anomaly monitors and the Terraform backend."""

import logging

from botocore.exceptions import ClientError

from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import TeardownItemReport
from .teardown_base import TeardownBase
from .teardown_s3 import empty_s3_bucket, normalize_bucket_name

logger = logging.getLogger(__name__)


class WorkloadTeardown(TeardownBase):
    """Teardown of budgets, cost anomaly monitors and the Terraform backend."""

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

                try:
                    ce_client = self.session_mgr.get_member_client(acct_id, "ce", region_name="us-east-1")
                    mon_resp = ce_client.get_anomaly_monitors()
                    for mon in mon_resp.get("AnomalyMonitors", []):
                        m_name = str(mon.get("MonitorName", ""))
                        m_arn = str(mon.get("MonitorArn", ""))
                        if m_name in (f"{acct_name}-cost-anomaly-monitor", f"{acct_name}-services-monitor"):
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
                except AWS_ERRORS as e:
                    logger.debug("Cost anomaly monitor check in %s: %s", acct_name, e)

            except AWS_ERRORS as e:
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
                    except AWS_ERRORS as e:
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

            if not dry_run:
                for b in sorted(buckets_to_empty):
                    results.extend(
                        self._delete_retained_bucket(s3_client, b, backend_acct_name, backend_acct_id)
                    )

        except AWS_ERRORS as e:
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
