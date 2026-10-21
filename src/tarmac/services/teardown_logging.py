"""Teardown of CloudTrail, the log archive and the audit account."""

import contextlib
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import TAG_MANAGED_BY, TeardownItemReport
from .teardown_base import STACK, TeardownBase
from .teardown_s3 import empty_s3_bucket, normalize_bucket_name

logger = logging.getLogger(__name__)

TRAIL = "CloudTrail Trail"


class LoggingTeardown(TeardownBase):
    """Teardown of CloudTrail, the log archive and the audit account."""

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
            if item := self._remove_stack(
                cfn_client,
                stack_name,
                status,
                "Management",
                mgmt_id,
                dry_run,
                would="Would delete CloudTrail stack",
                deleted="Deleted CloudTrail CloudFormation stack",
                release_protection=True,
            ):
                results.append(item)
        except AWS_ERRORS as e:
            results.append(TeardownItemReport(STACK, stack_name, "Management", mgmt_id, "FAILED", str(e)))

        try:
            trail_client = self.session_mgr.get_client("cloudtrail", region_name=target_region)
            trail_arn = self._find_tarmac_trail_arn(trail_client, trail_name)
            if trail_arn == "":
                results.append(
                    TeardownItemReport(
                        TRAIL,
                        trail_name,
                        "Management",
                        mgmt_id,
                        "SKIPPED",
                        f"Trail exists but lacks the {TAG_MANAGED_BY}=tarmac tag; not deleting it",
                    )
                )
            elif trail_arn and dry_run:
                results.append(
                    TeardownItemReport(
                        TRAIL,
                        trail_name,
                        "Management",
                        mgmt_id,
                        "SIMULATED",
                        "Would stop logging and delete standalone CloudTrail trail",
                    )
                )
            elif trail_arn:
                with contextlib.suppress(ClientError):
                    trail_client.stop_logging(Name=trail_name)
                self._notify_progress(f"Deleting standalone CloudTrail trail '{trail_name}' in Management...")
                trail_client.delete_trail(Name=trail_name)
                results.append(
                    TeardownItemReport(
                        TRAIL,
                        trail_name,
                        "Management",
                        mgmt_id,
                        "DELETED",
                        "Deleted standalone CloudTrail trail",
                    )
                )
        except (ClientError, BotoCoreError) as e:
            code = e.response.get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""
            if code not in ("TrailNotFoundException", "ResourceNotFoundException"):
                logger.warning("Standalone trail cleanup for '%s' failed: %s", trail_name, e)
                results.append(TeardownItemReport(TRAIL, trail_name, "Management", mgmt_id, "FAILED", str(e)))

        return results

    @staticmethod
    def _find_tarmac_trail_arn(trail_client: Any, trail_name: str) -> str | None:
        """Return the trail ARN if it exists and is tarmac-tagged, "" if it exists untagged, else None."""
        try:
            trail = trail_client.get_trail(Name=trail_name).get("Trail", {})
        except ClientError as e:
            if e.response.get("Error", {}).get("Code", "") in (
                "TrailNotFoundException",
                "ResourceNotFoundException",
            ):
                return None
            raise
        arn = str(trail.get("TrailARN", ""))
        if not arn:
            return ""
        resp = trail_client.list_tags(ResourceIdList=[arn])
        for entry in resp.get("ResourceTagList", []):
            for tag in entry.get("TagsList", []):
                if tag.get("Key") == TAG_MANAGED_BY and tag.get("Value") == "tarmac":
                    return arn
        return ""

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
        acct_name = bundle.get_log_archive_account_name() or "log-archive"
        acct_id = bundle.resolve_account_id(acct_name, accts) or ""
        stack_name = f"{bundle.org.organization.name}-log-archive-hardening"

        if not acct_id:
            results.append(
                TeardownItemReport(
                    STACK,
                    stack_name,
                    acct_name,
                    "",
                    "SKIPPED",
                    "Log Archive account not resolved in active accounts",
                )
            )
            return results

        try:
            cfn_client = self.session_mgr.get_member_client(
                acct_id, "cloudformation", region_name=target_region
            )
            s3_client = self.session_mgr.get_member_client(acct_id, "s3", region_name=target_region)
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)

            buckets_to_empty: set[str] = {
                f"{bundle.org.cloudtrail.bucket_prefix}-{acct_id}",
                f"{bundle.org.organization.name}-org-cloudtrail-logs-{acct_id}",
                f"{bundle.org.organization.name}-org-config-logs-{acct_id}",
                f"{bundle.org.organization.name}-log-archive-access-logs-{acct_id}",
            }
            key_id = self._log_archive_key_id(cfn_client, stack_name) if status else None
            if status:
                buckets_to_empty |= self._output_buckets(cfn_client, stack_name)

            for b in sorted(buckets_to_empty):
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            "S3 Bucket",
                            b,
                            acct_name,
                            acct_id,
                            "SIMULATED",
                            "Would purge all object versions and delete markers",
                        )
                    )
                    continue
                self._notify_progress(f"Purging object versions from S3 bucket '{b}' in {acct_name}...")
                try:
                    purged_count = empty_s3_bucket(s3_client, b, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            "S3 Bucket",
                            b,
                            acct_name,
                            acct_id,
                            "EMPTY",
                            f"Purged {purged_count} objects/versions/markers",
                        )
                    )
                except AWS_ERRORS as e:
                    logger.warning("Failed to purge bucket '%s': %s", b, e)
                    results.append(
                        TeardownItemReport(
                            "S3 Bucket", b, acct_name, acct_id, "FAILED", f"Failed to purge bucket: {e}"
                        )
                    )

            if item := self._remove_stack(
                cfn_client,
                stack_name,
                status,
                acct_name,
                acct_id,
                dry_run,
                would="Would delete Log-Archive hardening stack",
                deleted="Deleted Log-Archive hardening stack",
                release_protection=True,
            ):
                results.append(item)

            if not dry_run:
                for b in sorted(buckets_to_empty):
                    results.extend(self._delete_retained_bucket(s3_client, b, acct_name, acct_id))

            if key_id:
                results.extend(
                    self._schedule_log_key_deletion(
                        acct_id,
                        acct_name,
                        key_id,
                        target_region,
                        dry_run,
                        any_failed=any(r.action == "FAILED" for r in results),
                    )
                )

        except AWS_ERRORS as e:
            results.append(TeardownItemReport(STACK, stack_name, acct_name, acct_id, "FAILED", str(e)))

        return results

    def _output_buckets(self, cfn_client: Any, stack_name: str) -> set[str]:
        """Bucket names the stack reports in its outputs."""
        buckets: set[str] = set()
        for k, v in self.cfn_service._fetch_stack_outputs(cfn_client, stack_name).items():
            if "Bucket" in k and v and (clean := normalize_bucket_name(v)):
                buckets.add(clean)
        return buckets

    @staticmethod
    def _log_archive_key_id(cfn_client: Any, stack_name: str) -> str | None:
        """Physical ID of the log-archive KMS key (it is retained when the stack is deleted)."""
        try:
            detail = cfn_client.describe_stack_resource(
                StackName=stack_name, LogicalResourceId="LogArchiveKmsKey"
            )
            return str(detail["StackResourceDetail"].get("PhysicalResourceId") or "") or None
        except (ClientError, KeyError):
            return None

    def _schedule_log_key_deletion(
        self,
        account_id: str,
        account_name: str,
        key_id: str,
        region: str,
        dry_run: bool,
        any_failed: bool,
    ) -> list[TeardownItemReport]:
        """Schedule the retained log-archive key for deletion (30-day window, cancellable).

        Only done when the log buckets were purged and deleted cleanly, because the key is what makes
        any remaining archived logs readable.
        """
        name = f"KMS key {key_id}"
        if any_failed:
            message = "Kept: log archive cleanup had failures, so archived logs may still need this key"
            return [TeardownItemReport("KMS Key", name, account_name, account_id, "SKIPPED", message)]
        if dry_run:
            message = "Would schedule deletion in 30 days (cancellable)"
            return [TeardownItemReport("KMS Key", name, account_name, account_id, "SIMULATED", message)]
        try:
            kms = self.session_mgr.get_member_client(account_id, "kms", region_name=region)
            if kms.describe_key(KeyId=key_id)["KeyMetadata"].get("KeyState") == "PendingDeletion":
                return []
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=30)
        except ClientError as e:
            message = f"Could not schedule deletion: {e}"
            return [TeardownItemReport("KMS Key", name, account_name, account_id, "FAILED", message)]
        message = "Scheduled for deletion in 30 days (cancel with `aws kms cancel-key-deletion`)"
        return [TeardownItemReport("KMS Key", name, account_name, account_id, "DELETED", message)]

    def teardown_root_alert(
        self, bundle: ConfigBundle, target_region: str, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Delete the management account root activity alert stack in every Region it may have been deployed to."""
        results: list[TeardownItemReport] = []
        mgmt_id = self._get_management_account_id()
        stack_name = f"{bundle.org.organization.name}-management-root-alert"
        regions = list(
            dict.fromkeys(["us-east-1", target_region, *bundle.org.organization.additional_regions])
        )
        for region in regions:
            try:
                cfn_client = self.session_mgr.get_client("cloudformation", region_name=region)
                status = self.cfn_service._get_stack_status(cfn_client, stack_name)
                if not status or status == "DELETE_COMPLETE":
                    continue
                if dry_run:
                    action, message = (
                        "SIMULATED",
                        f"Would delete root alert stack in {region} (status: {status})",
                    )
                else:
                    self._notify_progress(f"Deleting CloudFormation stack '{stack_name}' in {region}...")
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    action, message = "DELETED", f"Deleted root alert stack in {region}"
            except AWS_ERRORS as e:
                action, message = "FAILED", f"{region}: {e}"
            results.append(TeardownItemReport(STACK, stack_name, "Management", mgmt_id, action, message))
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
        acct_name = bundle.get_audit_account_name() or "audit"
        acct_id = bundle.resolve_account_id(acct_name, accts) or ""
        stack_name = f"{bundle.org.organization.name}-audit-account-hardening"

        if not acct_id:
            results.append(
                TeardownItemReport(
                    STACK,
                    stack_name,
                    acct_name,
                    "",
                    "SKIPPED",
                    "Audit account not resolved in active accounts",
                )
            )
            return results

        try:
            cfn_client = self.session_mgr.get_member_client(
                acct_id, "cloudformation", region_name=target_region
            )
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)
            if item := self._remove_stack(
                cfn_client,
                stack_name,
                status,
                acct_name,
                acct_id,
                dry_run,
                would="Would delete Audit hardening stack",
                deleted="Deleted Audit hardening stack",
                release_protection=True,
            ):
                results.append(item)
        except AWS_ERRORS as e:
            results.append(TeardownItemReport(STACK, stack_name, acct_name, acct_id, "FAILED", str(e)))

        return results
