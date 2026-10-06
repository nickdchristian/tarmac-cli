"""Service Control Policy (SCP) management service."""

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_schema import SCPDef, ServiceControlPoliciesConfig
from ..core.exceptions import GovernanceError
from ..core.models import SCPReconciliationResult
from ..core.templates import resolve_resource_path
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)


class SCPService:
    """Manages AWS Organizations Service Control Policies (SCPs)."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr = session_mgr
        self.org_client: Any = session_mgr.get_client("organizations")

    def _is_scp_enabled_on_root(self, root_id: str) -> bool:
        """Check if SERVICE_CONTROL_POLICY is in ENABLED status on the root."""
        roots = self.org_client.list_roots().get("Roots", [])
        for r in roots:
            if r["Id"] == root_id:
                for pt in r.get("PolicyTypes", []):
                    if pt.get("Type") == "SERVICE_CONTROL_POLICY" and pt.get("Status") == "ENABLED":
                        return True
        return False

    def ensure_scp_enabled(self, root_id: str, max_wait_seconds: int = 60) -> bool:
        """Enable SERVICE_CONTROL_POLICY policy type on the organization root if needed."""
        if self._is_scp_enabled_on_root(root_id):
            logger.debug("SCPs are already enabled on root %s", root_id)
            return True

        try:
            self.org_client.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
            logger.info("Initiated enabling SERVICE_CONTROL_POLICY on root %s", root_id)
        except ClientError as e:
            code = e.response["Error"].get("Code", "")
            if code not in ["PolicyTypeAlreadyEnabledException", "ConcurrentModificationException"]:
                raise GovernanceError("Failed to enable Service Control Policies", details=str(e)) from e

        start_time = time.time()
        while time.time() - start_time < max_wait_seconds:
            if self._is_scp_enabled_on_root(root_id):
                logger.info("SERVICE_CONTROL_POLICY is now ENABLED on root %s", root_id)
                return True
            time.sleep(2)

        raise GovernanceError(
            f"Timed out waiting for SERVICE_CONTROL_POLICY to become ENABLED on root {root_id}"
        )

    def list_existing_scps(self) -> dict[str, dict[str, Any]]:
        """List all customer-managed and AWS-managed SCPs. Returns {PolicyName: PolicyDict}."""
        policies: dict[str, dict[str, Any]] = {}
        try:
            paginator = self.org_client.get_paginator("list_policies")
            for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
                for pol in page.get("Policies", []):
                    policies[pol["Name"]] = pol
            return policies
        except ClientError as e:
            raise GovernanceError("Failed to list Service Control Policies", details=str(e)) from e

    def get_policy_content(self, policy_id: str) -> str:
        """Fetch the JSON content string of an existing policy."""
        try:
            resp = self.org_client.describe_policy(PolicyId=policy_id)
            return str(resp.get("Policy", {}).get("Content", ""))
        except ClientError as e:
            logger.warning("Could not describe policy %s: %s", policy_id, e)
            return ""

    def list_targets_for_policy(self, policy_id: str) -> list[str]:
        """List target IDs (Root or OU IDs) attached to this policy."""
        targets: list[str] = []
        try:
            paginator = self.org_client.get_paginator("list_targets_for_policy")
            for page in paginator.paginate(PolicyId=policy_id):
                for t in page.get("Targets", []):
                    targets.append(str(t["TargetId"]))
            return targets
        except ClientError as e:
            logger.warning("Could not list targets for policy %s: %s", policy_id, e)
            return targets

    def _normalize_json(self, content: str) -> str:
        """Parse and re-dump JSON to normalize spacing/keys for comparison."""
        try:
            return json.dumps(json.loads(content), sort_keys=True)
        except Exception:
            return content.strip()

    def sync_policy(
        self,
        name: str,
        description: str,
        content: str,
        existing_scps: dict[str, dict[str, Any]],
        dry_run: bool = False,
    ) -> tuple[str, str]:
        """Create or update SCP document. Returns (policy_id, action_taken)."""
        normalized_new = self._normalize_json(content)

        if name in existing_scps:
            pol_id = existing_scps[name]["Id"]
            current_content = self.get_policy_content(pol_id)
            normalized_current = self._normalize_json(current_content)

            if normalized_new == normalized_current:
                logger.debug("SCP '%s' (%s) is up-to-date.", name, pol_id)
                return pol_id, "NOOP"

            if dry_run:
                logger.info("[DRY-RUN] Would update SCP '%s' (%s)", name, pol_id)
                return pol_id, "SIMULATED_UPDATE"

            try:
                self.org_client.update_policy(
                    PolicyId=pol_id,
                    Name=name,
                    Description=description,
                    Content=content,
                )
                logger.info("Updated SCP '%s' (%s)", name, pol_id)
                return pol_id, "UPDATED"
            except ClientError as e:
                raise GovernanceError(f"Failed to update SCP '{name}'", details=str(e)) from e

        if dry_run:
            logger.info("[DRY-RUN] Would create SCP '%s'", name)
            return "DRY-RUN-POLICY-ID", "SIMULATED_CREATE"

        try:
            resp = self.org_client.create_policy(
                Name=name,
                Description=description,
                Type="SERVICE_CONTROL_POLICY",
                Content=content,
            )
            new_id = resp["Policy"]["PolicySummary"]["Id"]
            logger.info("Created SCP '%s' (%s)", name, new_id)
            return new_id, "CREATED"
        except ClientError as e:
            raise GovernanceError(f"Failed to create SCP '{name}'", details=str(e)) from e

    def attach_policy_if_needed(
        self,
        policy_id: str,
        target_id: str,
        target_name: str,
        attached_targets: list[str],
        dry_run: bool = False,
        retries: int = 5,
        delay: float = 2.0,
    ) -> bool:
        """Attach policy to target if not already attached. Returns True if attached."""
        if target_id in attached_targets:
            logger.debug("Policy %s already attached to target '%s' (%s)", policy_id, target_name, target_id)
            return False

        if dry_run:
            logger.info(
                "[DRY-RUN] Would attach policy %s to target '%s' (%s)", policy_id, target_name, target_id
            )
            return True

        for attempt in range(retries):
            try:
                self.org_client.attach_policy(PolicyId=policy_id, TargetId=target_id)
                logger.info("Attached policy %s to target '%s' (%s)", policy_id, target_name, target_id)
                return True
            except ClientError as e:
                code = e.response["Error"].get("Code", "")
                if code == "PolicyTypeNotEnabledException" and attempt < retries - 1:
                    logger.warning(
                        "Policy type not yet active on %s (%s). Retrying in %.1fs... (attempt %d/%d)",
                        target_name,
                        target_id,
                        delay,
                        attempt + 1,
                        retries,
                    )
                    time.sleep(delay)
                    continue
                if code == "DuplicatePolicyAttachmentException":
                    logger.debug("Policy %s already attached to %s", policy_id, target_name)
                    return False
                raise GovernanceError(
                    f"Failed to attach policy {policy_id} to {target_name} ({target_id})",
                    details=str(e),
                ) from e
        return False

    def _resolve_target_id(self, target: str, root_id: str, ou_map: dict[str, str]) -> tuple[str, str] | None:
        """Resolve target string ('root' or OU name) to (target_id, target_name)."""
        if target.lower() in ["root", "organization_root"]:
            return root_id, "Root"
        if target in ou_map:
            return ou_map[target], target
        for k, v in ou_map.items():
            if k.lower() == target.lower():
                return v, k
        return None

    def reconcile_scp(
        self,
        scp_def: SCPDef,
        existing_scps: dict[str, dict[str, Any]],
        root_id: str,
        ou_map: dict[str, str],
        project_root: Path,
        dry_run: bool = False,
    ) -> SCPReconciliationResult:
        """Reconcile a single declared SCP and its target attachments."""
        policy_path = resolve_resource_path(scp_def.policy_file, project_root=project_root)
        content = policy_path.read_text(encoding="utf-8")
        policy_id, action = self.sync_policy(
            scp_def.name, scp_def.description, content, existing_scps, dry_run=dry_run
        )

        attached_now: list[str] = []
        newly_attached: list[str] = []

        live_targets = self.list_targets_for_policy(policy_id) if policy_id != "DRY-RUN-POLICY-ID" else []

        for target in scp_def.targets:
            resolved = self._resolve_target_id(target, root_id, ou_map)
            if not resolved:
                logger.warning("Target '%s' not found in Root or OUs for policy %s", target, scp_def.name)
                continue
            tid, tname = resolved
            attached_now.append(f"{tname} ({tid})")
            was_new = self.attach_policy_if_needed(policy_id, tid, tname, live_targets, dry_run=dry_run)
            if was_new:
                newly_attached.append(tname)

        return SCPReconciliationResult(
            name=scp_def.name,
            policy_id=policy_id,
            action_taken=action,
            attached_targets=attached_now,
            newly_attached_targets=newly_attached,
            status="SUCCEEDED",
        )

    def reconcile_all(
        self,
        config: ServiceControlPoliciesConfig,
        root_id: str,
        ou_map: dict[str, str],
        project_root: Path,
        dry_run: bool = False,
    ) -> list[SCPReconciliationResult]:
        """Reconcile all declared SCPs in order."""
        if not config.enabled:
            logger.info("Service Control Policies are disabled in configuration.")
            return []

        if not dry_run:
            self.ensure_scp_enabled(root_id)

        existing_scps = self.list_existing_scps()
        results: list[SCPReconciliationResult] = []

        for scp_def in config.policies:
            res = self.reconcile_scp(scp_def, existing_scps, root_id, ou_map, project_root, dry_run=dry_run)
            results.append(res)

        return results

    def synthesize_template(
        self,
        config: ServiceControlPoliciesConfig,
        root_id: str,
        ou_map: dict[str, str],
        project_root: Path,
    ) -> dict[str, Any]:
        """Synthesize a CloudFormation template from declared SCP definitions."""
        resources: dict[str, Any] = {}
        for scp_def in config.policies:
            policy_path = resolve_resource_path(scp_def.policy_file, project_root=project_root)
            content_str = policy_path.read_text(encoding="utf-8")
            content_obj = json.loads(content_str)

            target_ids: list[str] = []
            for target in scp_def.targets:
                resolved = self._resolve_target_id(target, root_id, ou_map)
                if resolved:
                    target_ids.append(resolved[0])
                else:
                    logger.warning(
                        "Target '%s' for policy '%s' not found in OUs or Root", target, scp_def.name
                    )

            resource_logical_id = "Scp" + re.sub(r"[^a-zA-Z0-9]", "", scp_def.name)
            resources[resource_logical_id] = {
                "Type": "AWS::Organizations::Policy",
                "DeletionPolicy": "Retain",
                "Properties": {
                    "Name": scp_def.name,
                    "Description": scp_def.description or f"Managed SCP {scp_def.name}",
                    "Type": "SERVICE_CONTROL_POLICY",
                    "Content": content_obj,
                    "TargetIds": target_ids,
                },
            }

        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AWS Governance - Managed Service Control Policies",
            "Resources": resources,
        }

    def reconcile_via_cloudformation(
        self,
        config: ServiceControlPoliciesConfig,
        root_id: str,
        ou_map: dict[str, str],
        project_root: Path,
        org_name: str = "organization",
        org_tags: dict[str, str] | None = None,
        tags: dict[str, str] | None = None,
        dry_run: bool = False,
    ) -> list[SCPReconciliationResult]:
        """Reconcile all declared SCPs natively via a single CloudFormation stack."""
        if not config.enabled or not config.policies:
            logger.info("No Service Control Policies declared or enabled.")
            return []

        if not dry_run:
            self.ensure_scp_enabled(root_id)

        template_dict = self.synthesize_template(config, root_id, ou_map, project_root)
        template_body = yaml.dump(template_dict, sort_keys=False)

        outputs_dir = project_root / "outputs"
        if not dry_run:
            outputs_dir.mkdir(parents=True, exist_ok=True)
            (outputs_dir / "managed-scps.yaml").write_text(template_body, encoding="utf-8")

        stack_name = f"{org_name}-organization-scps"
        cfn_client = self.session_mgr.get_client("cloudformation")
        cfn_service = CloudFormationService(self.session_mgr)

        if not dry_run:
            existing_scps = self.list_existing_scps()
            declared_names = {p.name for p in config.policies}
            pre_existing = declared_names.intersection(existing_scps.keys())

            if pre_existing:
                stack_status = cfn_service._get_stack_status(cfn_client, stack_name)
                if stack_status in (None, "DELETE_COMPLETE", "ROLLBACK_COMPLETE", "REVIEW_IN_PROGRESS"):
                    resources_to_import: list[dict[str, Any]] = []
                    for scp_def in config.policies:
                        if scp_def.name in existing_scps:
                            logical_id = "Scp" + re.sub(r"[^a-zA-Z0-9]", "", scp_def.name)
                            policy_id = existing_scps[scp_def.name]["Id"]
                            resources_to_import.append(
                                {
                                    "ResourceType": "AWS::Organizations::Policy",
                                    "LogicalResourceId": logical_id,
                                    "ResourceIdentifier": {"Id": policy_id},
                                }
                            )

                    logger.info(
                        "Importing pre-existing SCPs %s into CloudFormation stack '%s'...",
                        sorted(pre_existing),
                        stack_name,
                    )
                    cfn_report = cfn_service.import_resources_and_deploy_stack(
                        cfn_client=cfn_client,
                        stack_name=stack_name,
                        template_body=template_body,
                        resources_to_import=resources_to_import,
                        tags=tags,
                        org_tags=org_tags,
                        dry_run=dry_run,
                    )
                    import_results: list[SCPReconciliationResult] = []
                    for scp_def in config.policies:
                        targets_for_policy: list[str] = []
                        for target in scp_def.targets:
                            resolved = self._resolve_target_id(target, root_id, ou_map)
                            if resolved:
                                targets_for_policy.append(f"{resolved[1]} ({resolved[0]})")
                        import_results.append(
                            SCPReconciliationResult(
                                name=scp_def.name,
                                policy_id=existing_scps.get(scp_def.name, {}).get("Id"),
                                action_taken=cfn_report.action,
                                attached_targets=targets_for_policy,
                                newly_attached_targets=[],
                                status="SUCCEEDED",
                            )
                        )
                    return import_results

        cfn_report = cfn_service.deploy_stack(
            cfn_client=cfn_client,
            stack_name=stack_name,
            parameters={},
            tags=tags,
            org_tags=org_tags,
            dry_run=dry_run,
            template_body=template_body,
        )

        results: list[SCPReconciliationResult] = []
        action = cfn_report.action
        for scp_def in config.policies:
            attached_targets: list[str] = []
            for target in scp_def.targets:
                resolved = self._resolve_target_id(target, root_id, ou_map)
                if resolved:
                    attached_targets.append(f"{resolved[1]} ({resolved[0]})")
            results.append(
                SCPReconciliationResult(
                    name=scp_def.name,
                    policy_id=None,
                    action_taken=action,
                    attached_targets=attached_targets,
                    newly_attached_targets=attached_targets if action == "CREATED" else [],
                    status="SUCCEEDED",
                )
            )
        return results
