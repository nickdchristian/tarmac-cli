"""Service Control Policy (SCP) management service."""

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import ClientError

from ..core.adoption import ADOPT_HINT, adopt_existing
from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_schema import SCPDef, ServiceControlPoliciesConfig
from ..core.exceptions import GovernanceError, aws_error_code
from ..core.models import TAG_MANAGED_BY, SCPReconciliationResult
from ..core.stack_names import Stack
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

    def ensure_scp_enabled(self, root_id: str) -> bool:
        """Enable SERVICE_CONTROL_POLICY policy type on the organization root if needed."""
        if self._is_scp_enabled_on_root(root_id):
            logger.debug("SCPs are already enabled on root %s", root_id)
            return True

        try:
            self.org_client.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
            audit(
                "enable",
                f"policy-type:SERVICE_CONTROL_POLICY@{root_id}",
                Outcome.SUCCEEDED,
                f"Enabled service control policies on organization root {root_id}",
                root_id=root_id,
            )
        except ClientError as e:
            code = aws_error_code(e)
            if code not in ["PolicyTypeAlreadyEnabledException", "ConcurrentModificationException"]:
                raise GovernanceError("Failed to enable Service Control Policies", details=str(e)) from e

        start_time = time.time()
        while time.time() - start_time < 60:
            if self._is_scp_enabled_on_root(root_id):
                logger.debug("SERVICE_CONTROL_POLICY is now ENABLED on root %s", root_id)
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

    def is_tarmac_managed(self, policy_id: str) -> bool:
        """True only if the policy carries the tarmac ownership tag. Fails closed on lookup errors."""
        try:
            paginator = self.org_client.get_paginator("list_tags_for_resource")
            for page in paginator.paginate(ResourceId=policy_id):
                for tag in page.get("Tags", []):
                    if tag.get("Key") == TAG_MANAGED_BY and tag.get("Value") == "tarmac":
                        return True
        except ClientError as e:
            logger.warning("Could not read tags for policy %s: %s", policy_id, e)
        return False

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
        except ValueError:
            return content.strip()

    def require_adoptable(
        self, name: str, policy_id: str, normalized_current: str, normalized_new: str
    ) -> None:
        """Refuse to overwrite an SCP tarmac did not create, unless its content already matches or --adopt-existing.

        A policy that happens to share the name could be someone else's guardrail attached elsewhere; replacing
        its content silently changes what it allows or denies.
        """
        if adopt_existing() or normalized_current == normalized_new or self.is_tarmac_managed(policy_id):
            return
        raise GovernanceError(
            f"SCP '{name}' ({policy_id}) already exists, was not created by tarmac, and differs from the policy file.",
            details=f"{self._describe_difference(normalized_current, normalized_new)}\n{ADOPT_HINT}",
        )

    @staticmethod
    def _describe_difference(normalized_current: str, normalized_new: str) -> str:
        def sids(doc: str) -> list[str]:
            try:
                stmts = json.loads(doc).get("Statement", [])
            except (ValueError, AttributeError):
                return []
            stmts = [stmts] if isinstance(stmts, dict) else stmts
            return sorted(str(st.get("Sid", "(no Sid)")) for st in stmts if isinstance(st, dict))

        return f"Live statements: {sids(normalized_current) or 'unreadable'}; policy file statements: {sids(normalized_new)}."

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

    @staticmethod
    def _logical_ids_for_policies(policies: list[SCPDef]) -> dict[str, str]:
        """Build unique, CloudFormation-valid logical resource IDs for declared SCPs."""
        bases: dict[str, str] = {p.name: "Scp" + re.sub(r"[^a-zA-Z0-9]", "", p.name) for p in policies}
        counts: dict[str, int] = {}
        for base in bases.values():
            counts[base] = counts.get(base, 0) + 1
        result: dict[str, str] = {}
        for p in policies:
            base = bases[p.name]
            if base == "Scp" or counts[base] > 1:
                digest = hashlib.sha256(p.name.encode("utf-8")).hexdigest()[:8].capitalize()
                result[p.name] = f"{base}{digest}"
            else:
                result[p.name] = base
        return result

    def synthesize_template(
        self,
        config: ServiceControlPoliciesConfig,
        root_id: str,
        ou_map: dict[str, str],
        project_root: Path,
        include_ownership_tag: bool = True,
    ) -> dict[str, Any]:
        """Synthesize a CloudFormation template from declared SCP definitions.

        include_ownership_tag=False is used for IMPORT change sets, which cannot modify tags; the tag is
        applied by a normal stack update right after the import.
        """
        resources: dict[str, Any] = {}
        logical_ids = self._logical_ids_for_policies(config.policies)
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

            resource_logical_id = logical_ids[scp_def.name]
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
            if include_ownership_tag:
                resources[resource_logical_id]["Properties"]["Tags"] = [
                    {"Key": TAG_MANAGED_BY, "Value": "tarmac"}
                ]

        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "AWS Governance - Managed Service Control Policies",
            "Resources": resources,
        }

    def _require_declared_policies_adoptable(
        self,
        config: ServiceControlPoliciesConfig,
        existing_scps: dict[str, dict[str, Any]],
        project_root: Path,
    ) -> None:
        """Before importing pre-existing SCPs into the stack, check each one may be taken over."""
        for scp_def in config.policies:
            if scp_def.name not in existing_scps:
                continue
            policy_id = existing_scps[scp_def.name]["Id"]
            file_content = resolve_resource_path(scp_def.policy_file, project_root=project_root).read_text(
                encoding="utf-8"
            )
            self.require_adoptable(
                scp_def.name,
                policy_id,
                self._normalize_json(self.get_policy_content(policy_id)),
                self._normalize_json(file_content),
            )

    def reconcile_via_cloudformation(
        self,
        config: ServiceControlPoliciesConfig,
        root_id: str,
        ou_map: dict[str, str],
        project_root: Path,
        org_name: str = "organization",
        org_tags: dict[str, str] | None = None,
        tags: dict[str, str] | None = None,
    ) -> list[SCPReconciliationResult]:
        """Reconcile all declared SCPs natively via a single CloudFormation stack."""
        if not config.enabled or not config.policies:
            logger.info("No Service Control Policies declared or enabled.")
            return []

        self.ensure_scp_enabled(root_id)

        logical_ids = self._logical_ids_for_policies(config.policies)
        template_dict = self.synthesize_template(config, root_id, ou_map, project_root)
        template_body = yaml.dump(template_dict, sort_keys=False)

        outputs_dir = project_root / "outputs"
        outputs_dir.mkdir(parents=True, exist_ok=True)
        (outputs_dir / "managed-scps.yaml").write_text(template_body, encoding="utf-8")

        stack_name = Stack.ORGANIZATION_SCPS.for_org(org_name)
        cfn_client = self.session_mgr.get_client("cloudformation")
        cfn_service = CloudFormationService(self.session_mgr)

        existing_scps = self.list_existing_scps()
        declared_names = {p.name for p in config.policies}
        pre_existing = declared_names.intersection(existing_scps.keys())

        in_stack = (
            cfn_service.resource_ids(cfn_client, stack_name)
            if pre_existing and cfn_service.is_usable(cfn_client, stack_name)
            else set()
        )
        to_adopt = [
            p for p in config.policies if p.name in pre_existing and logical_ids[p.name] not in in_stack
        ]
        if to_adopt:
            adopting = {p.name: existing_scps[p.name] for p in to_adopt}
            self._require_declared_policies_adoptable(config, adopting, project_root)
            logger.debug("Importing pre-existing SCPs %s into stack '%s'...", sorted(adopting), stack_name)
            import_template_dict = self.synthesize_template(
                config, root_id, ou_map, project_root, include_ownership_tag=False
            )
            adopted = {
                logical_ids[p.name]: import_template_dict["Resources"][logical_ids[p.name]] for p in to_adopt
            }
            cfn_service.import_resources_and_deploy_stack(
                cfn_client=cfn_client,
                stack_name=stack_name,
                template_body=cfn_service.import_template(
                    cfn_client, stack_name, import_template_dict, adopted
                ),
                resources_to_import=[
                    {
                        "ResourceType": "AWS::Organizations::Policy",
                        "LogicalResourceId": logical_ids[p.name],
                        "ResourceIdentifier": {"Id": existing_scps[p.name]["Id"]},
                    }
                    for p in to_adopt
                ],
                tags=tags,
                org_tags=org_tags,
            )

        cfn_report = cfn_service.deploy_stack(
            cfn_client=cfn_client,
            stack_name=stack_name,
            parameters={},
            tags=tags,
            org_tags=org_tags,
            template_body=template_body,
        )

        results: list[SCPReconciliationResult] = []
        action = "IMPORTED" if to_adopt else cfn_report.action
        for scp_def in config.policies:
            unresolved_targets = [
                t for t in scp_def.targets if not self._resolve_target_id(t, root_id, ou_map)
            ]
            results.append(
                SCPReconciliationResult(
                    name=scp_def.name,
                    action_taken=action,
                    status="FAILED" if unresolved_targets else "SUCCEEDED",
                    unresolved_targets=unresolved_targets,
                )
            )
        return results
