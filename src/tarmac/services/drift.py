"""Landing zone drift detection engine.

Audits live AWS Organization state against declared configurations across:
- Organizational Units (existence and hierarchy)
- Member Accounts (existence and OU placement)
- Account Tags (governance and custom tag drift)
- Service Control Policies (existence, content hashing, target attachment)
- Core Infrastructure Stacks (CloudTrail, Terraform Backend, Hardening)
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, normalize_account_name
from ..core.templates import resolve_resource_path
from .accounts import AccountService
from .ou import OUService
from .scp import SCPService

logger = logging.getLogger(__name__)


@dataclass
class DriftItem:
    """Individual governance component drift outcome."""

    category: str
    name: str
    declared: str
    live: str
    status: str  # "IN_SYNC", "DRIFTED", "MISSING"
    remediation: str


@dataclass
class DriftReport:
    """Consolidated landing zone drift audit report."""

    items: list[DriftItem] = field(default_factory=list)
    has_drift: bool = False
    in_sync_count: int = 0
    drift_count: int = 0
    missing_count: int = 0


class DriftService:
    """Performs read-only drift audit comparing declared configs to live AWS state."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr = session_mgr
        self.org_client: Any = session_mgr.get_client("organizations")

    def inspect_drift(
        self,
        bundle: ConfigBundle,
        target_region: str,
        project_root: Path | None = None,
    ) -> DriftReport:
        """Audit all declared governance pillars against live AWS Organization state."""
        root_dir = project_root or Path.cwd()
        report = DriftReport()

        ou_service = OUService(self.session_mgr)
        acct_service = AccountService(self.session_mgr)
        scp_service = SCPService(self.session_mgr)

        root_id = ou_service.get_root_id()
        live_ous = ou_service.list_all_ous(root_id) if root_id else {}
        live_accts = acct_service.list_existing_accounts()

        # 1. OU Hierarchy Drift
        self._audit_ous(bundle, live_ous, report)

        # 2. Account Inventory & OU Placement Drift
        self._audit_accounts(bundle, live_accts, live_ous, acct_service, report)

        # 3. Account Tags Drift
        self._audit_tags(bundle, live_accts, acct_service, report)

        # 4. Service Control Policies Drift
        self._audit_scps(bundle, scp_service, root_id, live_ous, root_dir, report)

        # 5. Core Infrastructure CloudFormation Stacks Drift
        self._audit_stacks(bundle, live_accts, target_region, report)

        # 6. Member Account Budgets Drift
        self._audit_budgets(bundle, live_accts, target_region, report)

        # 7. IAM Identity Center Permission Sets Drift
        self._audit_identity_center(bundle, target_region, report)

        report.in_sync_count = sum(1 for i in report.items if i.status == "IN_SYNC")
        report.drift_count = sum(1 for i in report.items if i.status == "DRIFTED")
        report.missing_count = sum(1 for i in report.items if i.status == "MISSING")
        report.has_drift = (report.drift_count + report.missing_count) > 0

        return report

    def _audit_ous(
        self,
        bundle: ConfigBundle,
        live_ous: dict[str, str],
        report: DriftReport,
    ) -> None:
        """Check if all declared OUs exist in live AWS Organizations."""
        for ou_name in sorted(bundle._collect_ou_names(bundle.org.ou_structure)):
            in_sync = ou_name in live_ous
            report.items.append(
                DriftItem(
                    category="OU",
                    name=ou_name,
                    declared="Present",
                    live=f"Present ({live_ous[ou_name]})" if in_sync else "Missing",
                    status="IN_SYNC" if in_sync else "MISSING",
                    remediation="" if in_sync else "tarmac ou apply",
                )
            )

    def _audit_accounts(
        self,
        bundle: ConfigBundle,
        live_accts: dict[str, dict[str, Any]],
        live_ous: dict[str, str],
        acct_service: AccountService,
        report: DriftReport,
    ) -> None:
        """Check if declared accounts exist and reside in their designated OU."""
        for acct in bundle.accounts.accounts:
            live_data = acct_service.find_existing_account(acct.name, live_accts)
            if not live_data:
                report.items.append(
                    DriftItem(
                        category="Account",
                        name=acct.name,
                        declared=f"OU: {acct.ou}",
                        live="Not Provisioned",
                        status="MISSING",
                        remediation="tarmac account apply",
                    )
                )
                continue

            acct_id = str(live_data["Id"])
            parent_id = acct_service.get_account_parent_id(acct_id)
            target_ou_id = live_ous.get(acct.ou)

            if target_ou_id and parent_id != target_ou_id:
                parent_name = next((k for k, v in live_ous.items() if v == parent_id), parent_id or "Root")
                report.items.append(
                    DriftItem(
                        category="Account",
                        name=acct.name,
                        declared=f"OU: {acct.ou}",
                        live=f"OU: {parent_name}",
                        status="DRIFTED",
                        remediation="tarmac account apply",
                    )
                )
            else:
                report.items.append(
                    DriftItem(
                        category="Account",
                        name=acct.name,
                        declared=f"OU: {acct.ou}",
                        live=f"OU: {acct.ou} ({acct_id})",
                        status="IN_SYNC",
                        remediation="",
                    )
                )

    def _audit_tags(
        self,
        bundle: ConfigBundle,
        live_accts: dict[str, dict[str, Any]],
        acct_service: AccountService,
        report: DriftReport,
    ) -> None:
        """Check if account tags in AWS Organizations match declared/inherited tags."""
        for acct in bundle.accounts.accounts:
            live_data = acct_service.find_existing_account(acct.name, live_accts)
            if not live_data:
                continue

            acct_id = str(live_data["Id"])
            expected_tags = bundle.get_resolved_tags(account_name=acct.name)
            if not expected_tags:
                continue

            live_tags = self._get_account_tags(acct_id)
            drifted_keys = [k for k, expected_v in expected_tags.items() if live_tags.get(k) != expected_v]

            status = "DRIFTED" if drifted_keys else "IN_SYNC"
            live_desc = (
                f"{len(drifted_keys)} drifted ({', '.join(drifted_keys[:3])})"
                if drifted_keys
                else f"{len(expected_tags)} tags"
            )
            report.items.append(
                DriftItem(
                    category="Tag",
                    name=f"{acct.name} tags",
                    declared=f"{len(expected_tags)} tags",
                    live=live_desc,
                    status=status,
                    remediation="tarmac account sync-tags" if drifted_keys else "",
                )
            )

    def _audit_scps(
        self,
        bundle: ConfigBundle,
        scp_service: SCPService,
        root_id: str,
        live_ous: dict[str, str],
        root_dir: Path,
        report: DriftReport,
    ) -> None:
        """Check if declared SCPs exist, match content hashes, and are attached to targets."""
        scp_config = bundle.org.service_control_policies
        if not scp_config.enabled:
            return

        live_policies = scp_service.list_existing_scps()

        for policy_def in scp_config.policies:
            pol_data = live_policies.get(policy_def.name)
            if not pol_data:
                report.items.append(
                    DriftItem(
                        category="SCP",
                        name=policy_def.name,
                        declared="Attached",
                        live="Missing in AWS",
                        status="MISSING",
                        remediation="tarmac org scp sync",
                    )
                )
                continue

            pol_id = str(pol_data.get("Id", ""))

            try:
                resolved_path = resolve_resource_path(policy_def.policy_file, root_dir)
                declared_content = resolved_path.read_text(encoding="utf-8")
                live_content = self._get_live_policy_content(pol_id)

                normalized_declared = json.dumps(json.loads(declared_content), sort_keys=True)
                normalized_live = json.dumps(json.loads(live_content), sort_keys=True)

                if normalized_declared != normalized_live:
                    report.items.append(
                        DriftItem(
                            category="SCP",
                            name=policy_def.name,
                            declared="File content",
                            live="Policy drifted",
                            status="DRIFTED",
                            remediation="tarmac org scp sync",
                        )
                    )
                    continue
            except Exception as e:
                logger.debug("Could not verify SCP %s content hash: %s", policy_def.name, e)

            attached_targets = scp_service.list_targets_for_policy(pol_id)
            missing_targets: list[str] = []

            for tgt in policy_def.targets:
                target_id = root_id if tgt.lower() == "root" else live_ous.get(tgt)
                if target_id and target_id not in attached_targets:
                    missing_targets.append(tgt)

            if missing_targets:
                report.items.append(
                    DriftItem(
                        category="SCP",
                        name=policy_def.name,
                        declared=f"Attached to {policy_def.targets}",
                        live=f"Unattached to {missing_targets}",
                        status="DRIFTED",
                        remediation="tarmac org scp sync",
                    )
                )
            else:
                report.items.append(
                    DriftItem(
                        category="SCP",
                        name=policy_def.name,
                        declared="Attached & In-sync",
                        live="Attached & In-sync",
                        status="IN_SYNC",
                        remediation="",
                    )
                )

    def _audit_member_stack(
        self,
        friendly_name: str,
        account_name: str,
        stack_suffix: str,
        live_accts: dict[str, dict[str, Any]],
        target_region: str,
        prefix: str,
        report: DriftReport,
    ) -> None:
        """Audit status of a member account CloudFormation stack."""
        stack_name = f"{prefix}-{stack_suffix}"
        acct_id = self._resolve_id(account_name, live_accts)
        if not acct_id:
            status = "ACCOUNT_MISSING"
        else:
            try:
                client = self.session_mgr.get_member_client(
                    acct_id, "cloudformation", region_name=target_region
                )
                status = self._get_stack_status(client, stack_name)
            except Exception:
                status = "ACCESS_ERROR"
        self._record_stack_drift(friendly_name, stack_name, status, report)

    def _audit_stacks(
        self,
        bundle: ConfigBundle,
        live_accts: dict[str, dict[str, Any]],
        target_region: str,
        report: DriftReport,
    ) -> None:
        """Check status of core CloudFormation stacks."""
        prefix = bundle.org.organization.name
        mgmt_cfn = self.session_mgr.get_client("cloudformation", region_name=target_region)

        ct_stack = f"{prefix}-organization-cloudtrail"
        ct_status = self._get_stack_status(mgmt_cfn, ct_stack)
        self._record_stack_drift("CloudTrail", ct_stack, ct_status, report)

        sso_stack = f"{prefix}-sso-permission-sets"
        sso_status = self._get_stack_status(mgmt_cfn, sso_stack)
        self._record_stack_drift("SSOPermissionSets", sso_stack, sso_status, report)

        stacks_to_check = [
            ("TerraformBackend", bundle.get_backend_account_name() or "deployment", "terraform-backend"),
            (
                "LogArchiveHardening",
                bundle.get_log_archive_account_name() or "log-archive",
                "log-archive-hardening",
            ),
            ("AuditHardening", bundle.get_audit_account_name() or "audit", "audit-account-hardening"),
        ]
        for friendly_name, acct_name, suffix in stacks_to_check:
            self._audit_member_stack(
                friendly_name, acct_name, suffix, live_accts, target_region, prefix, report
            )

    def _audit_budgets(
        self,
        bundle: ConfigBundle,
        live_accts: dict[str, dict[str, Any]],
        target_region: str,
        report: DriftReport,
    ) -> None:
        """Check if declared member account monthly budgets are deployed."""
        for acct in bundle.accounts.accounts:
            if not (acct.baseline and acct.baseline.budget):
                continue
            budget_name = f"{acct.name}-monthly-budget"
            acct_id = self._resolve_id(acct.name, live_accts)
            if not acct_id:
                status = "ACCOUNT_MISSING"
            else:
                try:
                    client = self.session_mgr.get_member_client(
                        acct_id, "cloudformation", region_name=target_region
                    )
                    status = self._get_stack_status(client, budget_name)
                except Exception:
                    status = "ACCESS_ERROR"
            self._record_stack_drift(f"Budget ({acct.name})", budget_name, status, report)

    def _audit_identity_center(
        self,
        bundle: ConfigBundle,
        target_region: str,
        report: DriftReport,
    ) -> None:
        """Check if declared IAM Identity Center permission sets exist in live AWS state."""
        if not (bundle.identity and bundle.identity.identity_center):
            return
        try:
            sso_client = self.session_mgr.get_client("sso-admin", region_name=target_region)
            instances = sso_client.list_instances().get("Instances", [])
            if not instances:
                return
            inst_arn = instances[0]["InstanceArn"]
            paginator = sso_client.get_paginator("list_permission_sets")
            live_ps_arns = [
                arn
                for page in paginator.paginate(InstanceArn=inst_arn)
                for arn in page.get("PermissionSets", [])
            ]
            live_ps_names: dict[str, str] = {}
            for arn in live_ps_arns:
                try:
                    desc = sso_client.describe_permission_set(InstanceArn=inst_arn, PermissionSetArn=arn)
                    ps_data = desc.get("PermissionSet", {})
                    live_ps_names[ps_data.get("Name", "")] = arn
                except Exception:
                    pass

            for ps_def in bundle.identity.identity_center.permission_sets:
                in_sync = ps_def.name in live_ps_names
                report.items.append(
                    DriftItem(
                        category="PermissionSet",
                        name=ps_def.name,
                        declared="Present",
                        live=f"Present ({live_ps_names[ps_def.name]})"
                        if in_sync
                        else "Missing in Identity Center",
                        status="IN_SYNC" if in_sync else "MISSING",
                        remediation="" if in_sync else "tarmac identity sync",
                    )
                )
        except Exception as e:
            logger.debug("Identity Center drift inspection skipped: %s", e)

    def _record_stack_drift(
        self,
        friendly_name: str,
        stack_name: str,
        status: str,
        report: DriftReport,
    ) -> None:
        """Helper to classify CloudFormation stack status as IN_SYNC, DRIFTED, or MISSING."""
        if status in ["CREATE_COMPLETE", "UPDATE_COMPLETE"]:
            item_status, remediation = "IN_SYNC", ""
            declared = "CREATE_COMPLETE"
        elif status in ["NOT_FOUND", "ACCOUNT_MISSING"]:
            item_status, remediation = "MISSING", "tarmac deploy run"
            declared = "Deployed"
        else:
            item_status, remediation = "DRIFTED", "tarmac deploy run"
            declared = "CREATE_COMPLETE"

        report.items.append(
            DriftItem(
                category="Stack",
                name=friendly_name,
                declared=declared,
                live=status,
                status=item_status,
                remediation=remediation,
            )
        )

    def _get_account_tags(self, account_id: str) -> dict[str, str]:
        """Fetch live tags on an AWS Organizations account."""
        try:
            paginator = self.org_client.get_paginator("list_tags_for_resource")
            tags: dict[str, str] = {}
            for page in paginator.paginate(ResourceId=account_id):
                for t in page.get("Tags", []):
                    tags[t["Key"]] = t["Value"]
            return tags
        except ClientError:
            return {}

    def _get_live_policy_content(self, policy_id: str) -> str:
        """Fetch content string of a live SCP."""
        resp = self.org_client.describe_policy(PolicyId=policy_id)
        return str(resp.get("Policy", {}).get("Content", "{}"))

    def _get_stack_status(self, client: Any, stack_name: str) -> str:
        """Fetch stack status string or NOT_FOUND."""
        try:
            resp = client.describe_stacks(StackName=stack_name)
            stacks = resp.get("Stacks", [])
            return str(stacks[0]["StackStatus"]) if stacks else "NOT_FOUND"
        except ClientError:
            return "NOT_FOUND"

    def _resolve_id(self, account_name: str, live_accts: dict[str, dict[str, Any]]) -> str | None:
        """Resolve account ID from name case- and separator-insensitively."""
        norm_target = normalize_account_name(account_name)
        for k, v in live_accts.items():
            if normalize_account_name(k) == norm_target:
                return str(v.get("Id", ""))
        return None
