"""Teardown of budgets, cost anomaly monitors and the Terraform backend."""

import logging
from typing import Any

from botocore.exceptions import ClientError

from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import TeardownItemReport
from ..core.stack_names import Stack
from .baseline import budget_stack_name
from .teardown_base import STACK, TeardownBase
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
        """Tear down budget stacks, standalone AWS Budgets, and Cost Anomaly Monitors of the declared accounts."""
        results: list[TeardownItemReport] = self._new_results_list()
        accts = account_id_map or self._get_active_accounts()

        for acct_def in bundle.accounts.accounts:
            acct_id = bundle.resolve_account_id(acct_def.name, accts) or ""
            if not acct_id:
                message = "Account not resolved in active accounts"
                results.append(
                    TeardownItemReport(
                        STACK, budget_stack_name(acct_def.name), acct_def.name, "", "SKIPPED", message
                    )
                )
                continue
            results.extend(self.teardown_account_budget(acct_def.name, acct_id, dry_run))
        resolved = {a.name: bundle.resolve_account_id(a.name, accts) or "" for a in bundle.accounts.accounts}
        results.extend(self.teardown_anomaly_monitors({n: i for n, i in resolved.items() if i}, dry_run))
        return results

    def teardown_account_budget(
        self, acct_name: str, acct_id: str, dry_run: bool
    ) -> list[TeardownItemReport]:
        """The account's budget stack, and a budget of the same name created directly by older releases."""
        results: list[TeardownItemReport] = []
        budget_name = budget_stack_name(acct_name)
        try:
            cfn_client = self.session_mgr.get_member_client(
                acct_id, "cloudformation", region_name=self.session_mgr.default_region
            )
            status = self.cfn_service._get_stack_status(cfn_client, budget_name)
            if item := self._remove_stack(
                cfn_client,
                budget_name,
                status,
                acct_name,
                acct_id,
                dry_run,
                would="Would delete budget stack",
                deleted="Deleted budget stack",
                missing="Budget stack does not exist",
                noun="budget stack",
            ):
                results.append(item)

            budgets_client = self.session_mgr.get_member_client(acct_id, "budgets", region_name="us-east-1")
            try:
                budgets_client.describe_budget(AccountId=acct_id, BudgetName=budget_name)
                if dry_run:
                    action, message = "SIMULATED", "Would delete direct AWS Budget"
                else:
                    self._notify_progress(f"Deleting direct AWS Budget '{budget_name}' in {acct_name}...")
                    budgets_client.delete_budget(AccountId=acct_id, BudgetName=budget_name)
                    action, message = "DELETED", "Deleted direct AWS Budget"
                results.append(
                    TeardownItemReport("AWS Budget", budget_name, acct_name, acct_id, action, message)
                )
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code not in ("NotFoundException", "ResourceNotFoundException"):
                    logger.debug("Direct budget inspection in %s: %s", acct_name, e)
        except AWS_ERRORS as e:
            results.append(TeardownItemReport(STACK, budget_name, acct_name, acct_id, "FAILED", str(e)))
        return results

    def teardown_anomaly_monitors(self, accounts: dict[str, str], dry_run: bool) -> list[TeardownItemReport]:
        """The cost anomaly monitors tarmac created for these accounts ({name: id}): the monitor and alert subscription
        in the management account, then the account's own services monitor. Reads the management account once, and a
        member account only when it has a monitor there, since every Cost Explorer request is billed."""
        results: list[TeardownItemReport] = []
        try:
            ce = self.session_mgr.get_client("ce", region_name="us-east-1")
            monitors = {
                str(m["MonitorName"]): m for m in ce.get_anomaly_monitors().get("AnomalyMonitors", [])
            }
            subs = {
                str(s["SubscriptionName"]): s
                for s in ce.get_anomaly_subscriptions().get("AnomalySubscriptions", [])
            }
        except AWS_ERRORS as e:
            logger.debug("Cost anomaly monitor check in the management account: %s", e)
            return results
        for name, acct_id in accounts.items():
            if f"{name}-cost-anomaly-monitor" not in monitors:
                continue
            found = [("Management", ce, "Cost Anomaly Subscription", subs.get(f"{name}-anomaly-alerts"))]
            found.append(("Management", ce, "Cost Anomaly Monitor", monitors[f"{name}-cost-anomaly-monitor"]))
            try:
                member_ce = self.session_mgr.get_member_client(acct_id, "ce", region_name="us-east-1")
                own = [m for m in member_ce.get_anomaly_monitors().get("AnomalyMonitors", [])]
                found += [
                    (name, member_ce, "Cost Anomaly Monitor", m)
                    for m in own
                    if m.get("MonitorName") == f"{name}-services-monitor"
                ]
            except AWS_ERRORS as e:
                logger.debug("Cost anomaly monitor check in %s: %s", name, e)
            for where, client, kind, entry in found:
                if entry:
                    results.append(self._delete_anomaly(client, kind, entry, where, acct_id, dry_run))
        return results

    def _delete_anomaly(
        self, ce: Any, kind: str, entry: dict[str, Any], where: str, acct_id: str, dry_run: bool
    ) -> TeardownItemReport:
        name = str(entry.get("SubscriptionName") or entry.get("MonitorName"))
        if dry_run:
            return TeardownItemReport(
                kind, name, where, acct_id, "SIMULATED", f"Would delete the {kind.lower()}"
            )
        try:
            self._notify_progress(f"Deleting {kind.lower()} '{name}' in {where}...")
            if "SubscriptionArn" in entry:
                ce.delete_anomaly_subscription(SubscriptionArn=entry["SubscriptionArn"])
            else:
                ce.delete_anomaly_monitor(MonitorArn=entry["MonitorArn"])
        except AWS_ERRORS as e:
            return TeardownItemReport(kind, name, where, acct_id, "FAILED", str(e))
        return TeardownItemReport(kind, name, where, acct_id, "DELETED", f"Deleted the {kind.lower()}")

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
        stack_name = Stack.TERRAFORM_BACKEND.for_org(bundle.org.organization.name)

        if not backend_acct_id:
            message = "Deployment/backend account not resolved in active accounts"
            results.append(TeardownItemReport(STACK, stack_name, backend_acct_name, "", "SKIPPED", message))
            return results

        try:
            cfn_client = self.session_mgr.get_member_client(
                backend_acct_id, "cloudformation", region_name=target_region
            )
            s3_client = self.session_mgr.get_member_client(backend_acct_id, "s3", region_name=target_region)
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)

            buckets_to_empty: set[str] = set()
            if status:
                outputs = self.cfn_service._fetch_stack_outputs(cfn_client, stack_name)
                for k, v in outputs.items():
                    if "Bucket" in k and v:
                        clean_b = normalize_bucket_name(v)
                        if clean_b:
                            buckets_to_empty.add(clean_b)

            for b in sorted(buckets_to_empty):
                if dry_run:
                    action, message = "SIMULATED", "Would purge state bucket"
                else:
                    self._notify_progress(f"Purging state bucket '{b}' in {backend_acct_name}...")
                    try:
                        purged_count = empty_s3_bucket(s3_client, b, on_progress=self.on_progress)
                        action, message = "EMPTY", f"Purged {purged_count} objects from state bucket"
                    except AWS_ERRORS as e:
                        logger.warning("Failed to purge bucket '%s': %s", b, e)
                        action, message = "FAILED", f"Failed to purge bucket: {e}"
                results.append(
                    TeardownItemReport("S3 Bucket", b, backend_acct_name, backend_acct_id, action, message)
                )

            if item := self._remove_stack(
                cfn_client,
                stack_name,
                status,
                backend_acct_name,
                backend_acct_id,
                dry_run,
                would="Would delete backend stack",
                deleted="Deleted Terraform backend stack",
                release_protection=True,
            ):
                results.append(item)

            if not dry_run:
                for b in sorted(buckets_to_empty):
                    results.extend(
                        self._delete_retained_bucket(s3_client, b, backend_acct_name, backend_acct_id)
                    )

        except AWS_ERRORS as e:
            results.append(
                TeardownItemReport(STACK, stack_name, backend_acct_name, backend_acct_id, "FAILED", str(e))
            )

        return results
