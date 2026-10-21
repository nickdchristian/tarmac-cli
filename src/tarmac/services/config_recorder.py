"""AWS Config recorders for the whole organization.

Member accounts get the recorder from a service-managed StackSet targeting the organization root, so accounts
created later receive it automatically. StackSets cannot target the management account, which gets the same
template as an ordinary stack in each Region. Both deliver to the central log archive bucket.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code, aws_error_message
from ..core.models import TAG_MANAGED_BY, StackDeployReport
from ..core.org_accounts import is_active, iter_accounts
from ..core.stack_names import Stack
from ..core.tagging import merge_tags, to_cfn_tags
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)

TERMINAL_OPERATION_STATUSES = frozenset({"SUCCEEDED", "FAILED", "STOPPED"})
# Failures in one account or Region must not stop the others; they are collected and reported together.
OPERATION_PREFERENCES = {
    "RegionConcurrencyType": "PARALLEL",
    "MaxConcurrentPercentage": 100,
    "FailureTolerancePercentage": 100,
}


def service_linked_role_arn(session_mgr: AwsSessionManager, management_account_id: str) -> str:
    """The ARN of AWSServiceRoleForConfig in the management account, in the caller's partition."""
    arn = str(session_mgr.get_caller_identity().get("Arn", ""))
    partition = arn.split(":")[1] if arn.startswith("arn:") else "aws"
    return (
        f"arn:{partition}:iam::{management_account_id}:role/aws-service-role/"
        "config.amazonaws.com/AWSServiceRoleForConfig"
    )


@dataclass
class ConfigRecorderReport:
    stack_set_action: str = "UNCHANGED"
    regions: list[str] = field(default_factory=list)
    management_stacks: list[StackDeployReport] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)


class ConfigRecorderService:
    """Deploys and removes the organization's AWS Config recorders."""

    def __init__(
        self,
        session_mgr: AwsSessionManager,
        cfn_service: CloudFormationService | None = None,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 15,
        timeout_seconds: float = 3600,
    ) -> None:
        self.session_mgr = session_mgr
        self.cfn_service = cfn_service or CloudFormationService(session_mgr)
        self._sleep = sleep
        self._poll_seconds = poll_seconds
        self._timeout_seconds = timeout_seconds

    def deploy(
        self,
        *,
        org_name: str,
        template_file: Path,
        parameters: dict[str, str],
        regions: list[str],
        primary_region: str,
        management_account_id: str,
        tags: dict[str, str] | None = None,
        org_tags: dict[str, str] | None = None,
    ) -> ConfigRecorderReport:
        """Create or update the StackSet, its instances, and the management account stacks."""
        name = Stack.CONFIG_RECORDER.for_org(org_name)
        report = ConfigRecorderReport(regions=list(regions))

        template_body = template_file.read_text(encoding="utf-8")
        cfn_tags = merge_tags(org_tags, tags, {TAG_MANAGED_BY: "tarmac"})
        cf = self.session_mgr.get_client("cloudformation", region_name=primary_region)
        try:
            self._activate_organizations_access(cf)
            root_id = self._root_id()
            targets = self._targets(root_id, management_account_id)
            report.stack_set_action = self._ensure_stack_set(cf, name, template_body, parameters, cfn_tags)
            report.failures.extend(self._sync_instances(cf, name, regions, targets))
        except ClientError as e:
            raise GovernanceError(
                f"Could not deploy AWS Config recorders through StackSet '{name}'",
                details=aws_error_message(e),
            ) from e

        # The deployment role may not create IAM roles, so the management account records with the service-linked role.
        management_parameters = {
            **parameters,
            "RecorderRoleArn": self._ensure_service_linked_role(management_account_id),
        }
        for region in regions:
            report.management_stacks.append(
                self._deploy_management_stack(
                    org_name,
                    template_file,
                    management_parameters,
                    region,
                    management_account_id,
                    tags,
                    org_tags,
                )
            )
        return report

    def _ensure_service_linked_role(self, management_account_id: str) -> str:
        """Create AWSServiceRoleForConfig if the management account does not have it yet; return its ARN."""
        iam = self.session_mgr.get_client("iam")
        try:
            return str(iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"])
        except ClientError as e:
            if aws_error_code(e) not in ("InvalidInput", "EntityAlreadyExists"):
                raise GovernanceError(
                    "Could not create the AWS Config service-linked role", details=aws_error_message(e)
                ) from e  # InvalidInput is IAM's answer when the service-linked role already exists
        return service_linked_role_arn(self.session_mgr, management_account_id)

    def _activate_organizations_access(self, cf: Any) -> None:
        """Trusted access for service-managed StackSets; safe to repeat."""
        cf.activate_organizations_access()

    def _root_id(self) -> str:
        roots = self.session_mgr.get_client("organizations").list_roots().get("Roots", [])
        if not roots:
            raise GovernanceError("The organization has no root to deploy AWS Config recorders to.")
        return str(roots[0]["Id"])

    def _targets(self, root_id: str, management_account_id: str) -> dict[str, Any]:
        """The organization root without the management account (StackSets cannot deploy there) and without
        suspended accounts (their roles cannot be assumed)."""
        excluded = {management_account_id}
        for account in iter_accounts(self.session_mgr.get_client("organizations")):
            if not is_active(account):
                excluded.add(str(account["Id"]))
        return {
            "OrganizationalUnitIds": [root_id],
            "AccountFilterType": "DIFFERENCE",
            "Accounts": sorted(a for a in excluded if a),
        }

    @staticmethod
    def _owned(stack_set: dict[str, Any]) -> bool:
        return any(
            t.get("Key") == TAG_MANAGED_BY and t.get("Value") == "tarmac" for t in stack_set.get("Tags", [])
        )

    def _describe(self, cf: Any, name: str) -> dict[str, Any] | None:
        try:
            return dict(cf.describe_stack_set(StackSetName=name)["StackSet"])
        except ClientError as e:
            if aws_error_code(e) == "StackSetNotFoundException":
                return None
            raise

    def _ensure_stack_set(
        self, cf: Any, name: str, template_body: str, parameters: dict[str, str], tags: dict[str, str]
    ) -> str:
        cfn_parameters = [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in parameters.items()]
        settings = {
            "TemplateBody": template_body,
            "Parameters": cfn_parameters,
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Tags": to_cfn_tags(tags),
            "PermissionModel": "SERVICE_MANAGED",
            "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False},
        }
        existing = self._describe(cf, name)
        if existing is None:
            cf.create_stack_set(
                StackSetName=name,
                Description="AWS Config recorders managed by tarmac",
                **settings,
            )
            audit("create", f"stackset:{name}", Outcome.SUCCEEDED, f"Created StackSet '{name}'")
            return "CREATED"

        if not self._owned(existing):
            raise GovernanceError(
                f"StackSet '{name}' exists but was not created by tarmac (no {TAG_MANAGED_BY}=tarmac tag).",
                details="tarmac will not update a StackSet it does not own. Rename or remove it, then re-run.",
            )
        if self._unchanged(existing, template_body, cfn_parameters, tags):
            audit("update", f"stackset:{name}", Outcome.UNCHANGED, f"StackSet '{name}' is already up to date")
            return "UNCHANGED"

        response = cf.update_stack_set(
            StackSetName=name, OperationPreferences=OPERATION_PREFERENCES, **settings
        )
        self._wait(cf, name, response["OperationId"])
        audit("update", f"stackset:{name}", Outcome.SUCCEEDED, f"Updated StackSet '{name}'")
        return "UPDATED"

    @staticmethod
    def _unchanged(
        existing: dict[str, Any], template_body: str, parameters: list[dict[str, str]], tags: dict[str, str]
    ) -> bool:
        def params(items: list[dict[str, Any]]) -> dict[str, str]:
            return {str(p["ParameterKey"]): str(p["ParameterValue"]) for p in items}

        def tag_map(items: list[dict[str, Any]]) -> dict[str, str]:
            return {str(t["Key"]): str(t["Value"]) for t in items}

        return (
            existing.get("TemplateBody") == template_body
            and params(existing.get("Parameters", [])) == params(parameters)
            and tag_map(existing.get("Tags", [])) == tags
            and existing.get("Status") == "ACTIVE"
        )

    def _list_instances(self, cf: Any, name: str) -> list[dict[str, Any]]:
        instances: list[dict[str, Any]] = []
        for page in cf.get_paginator("list_stack_instances").paginate(StackSetName=name):
            instances.extend(page.get("Summaries", []))
        return instances

    def _sync_instances(self, cf: Any, name: str, regions: list[str], targets: dict[str, Any]) -> list[str]:
        """Add instances for Regions that have none, drop Regions no longer configured, report what is not
        current. Template and parameter changes reach existing instances through the StackSet update."""
        present = {str(i["Region"]) for i in self._list_instances(cf, name)}
        missing = [r for r in regions if r not in present]
        surplus = sorted(present - set(regions))
        if missing:
            response = cf.create_stack_instances(
                StackSetName=name,
                DeploymentTargets=targets,
                Regions=missing,
                OperationPreferences=OPERATION_PREFERENCES,
            )
            self._wait(cf, name, response["OperationId"])
            audit(
                "create",
                f"stackset-instances:{name}",
                Outcome.SUCCEEDED,
                f"Deployed StackSet '{name}' to Region(s) {', '.join(missing)}",
                regions=missing,
            )
        if surplus:
            response = cf.delete_stack_instances(
                StackSetName=name,
                DeploymentTargets=targets,
                Regions=surplus,
                RetainStacks=False,
                OperationPreferences=OPERATION_PREFERENCES,
            )
            self._wait(cf, name, response["OperationId"])
            audit(
                "delete",
                f"stackset-instances:{name}",
                Outcome.SUCCEEDED,
                f"Removed StackSet '{name}' from Region(s) {', '.join(surplus)}",
                regions=surplus,
            )
        return self._instance_failures(cf, name)

    def _instance_failures(self, cf: Any, name: str) -> list[str]:
        failures = []
        for inst in self._list_instances(cf, name):
            if inst.get("Status") == "CURRENT":
                continue
            reason = inst.get("StatusReason") or inst.get("StackInstanceStatus", {}).get("DetailedStatus", "")
            failures.append(
                f"{inst.get('Account')} {inst.get('Region')}: {inst.get('Status')} {reason}".strip()
            )
        if failures:
            audit(
                "create",
                f"stackset-instances:{name}",
                Outcome.FAILED,
                f"{len(failures)} instance(s) of StackSet '{name}' are not current",
                failures=failures,
            )
        return failures

    def _wait(self, cf: Any, name: str, operation_id: str) -> str:
        deadline = time.monotonic() + self._timeout_seconds
        while True:
            status = str(
                cf.describe_stack_set_operation(StackSetName=name, OperationId=operation_id)[
                    "StackSetOperation"
                ]["Status"]
            )
            if status in TERMINAL_OPERATION_STATUSES:
                return status
            if time.monotonic() >= deadline:
                raise GovernanceError(
                    f"StackSet operation {operation_id} on '{name}' did not finish in "
                    f"{int(self._timeout_seconds)} seconds (last status {status}). "
                    "It keeps running in AWS; re-run tarmac when it has finished."
                )
            self._sleep(self._poll_seconds)

    def _deploy_management_stack(
        self,
        org_name: str,
        template_file: Path,
        parameters: dict[str, str],
        region: str,
        management_account_id: str,
        tags: dict[str, str] | None,
        org_tags: dict[str, str] | None,
    ) -> StackDeployReport:
        cfn_client = self.session_mgr.get_member_client(
            management_account_id, "cloudformation", region_name=region
        )
        return self.cfn_service.deploy_stack(
            cfn_client,
            Stack.CONFIG_RECORDER.for_org(org_name),
            template_file,
            parameters,
            tags=tags,
            org_tags=org_tags,
        )

    def remove(
        self,
        *,
        org_name: str,
        regions: list[str],
        primary_region: str,
        management_account_id: str,
        dry_run: bool = False,
    ) -> list[tuple[str, str, str]]:
        """Remove the StackSet (with its instances) and the management account stacks.

        Returns (resource, action, message) rows where action is DELETED, NOT_FOUND, SIMULATED or FAILED.
        """
        rows = self._remove_stack_set(org_name, primary_region, management_account_id, dry_run)
        for region in regions:
            rows.append(self._remove_management_stack(org_name, region, management_account_id, dry_run))
        return rows

    def _remove_stack_set(
        self, org_name: str, primary_region: str, management_account_id: str, dry_run: bool
    ) -> list[tuple[str, str, str]]:
        name = Stack.CONFIG_RECORDER.for_org(org_name)
        resource = f"StackSet {name}"
        cf = self.session_mgr.get_client("cloudformation", region_name=primary_region)
        try:
            existing = self._describe(cf, name)
            if existing is None:
                return [(resource, "NOT_FOUND", "StackSet does not exist")]
            if not self._owned(existing):
                return [(resource, "SKIPPED", f"Not created by tarmac (no {TAG_MANAGED_BY}=tarmac tag)")]
            if dry_run:
                return [(resource, "SIMULATED", "Would delete the StackSet and its stack instances")]
            instances = self._list_instances(cf, name)
            regions = sorted({str(i["Region"]) for i in instances})
            if regions:
                targets = self._targets(self._root_id(), management_account_id)
                response = cf.delete_stack_instances(
                    StackSetName=name,
                    DeploymentTargets=targets,
                    Regions=regions,
                    RetainStacks=False,
                    OperationPreferences=OPERATION_PREFERENCES,
                )
                self._wait(cf, name, response["OperationId"])
                left = self._list_instances(cf, name)
                if left:
                    return [(resource, "FAILED", f"{len(left)} stack instance(s) could not be deleted")]
            cf.delete_stack_set(StackSetName=name)
            audit("delete", f"stackset:{name}", Outcome.SUCCEEDED, f"Deleted StackSet '{name}'")
            return [(resource, "DELETED", f"Deleted the StackSet and {len(instances)} stack instance(s)")]
        except AWS_ERRORS as e:
            return [(resource, "FAILED", str(e))]

    def _remove_management_stack(
        self, org_name: str, region: str, management_account_id: str, dry_run: bool
    ) -> tuple[str, str, str]:
        stack = Stack.CONFIG_RECORDER.for_org(org_name)
        resource = f"Stack {stack} ({region})"
        try:
            cfn_client = self.session_mgr.get_member_client(
                management_account_id, "cloudformation", region_name=region
            )
            status = self.cfn_service._get_stack_status(cfn_client, stack)
            if status is None or status == "DELETE_COMPLETE":
                return (resource, "NOT_FOUND", "Stack does not exist")
            if dry_run:
                return (resource, "SIMULATED", f"Would delete the stack (status: {status})")
            self.cfn_service.delete_stack(cfn_client, stack)
            return (resource, "DELETED", "Deleted the management account recorder stack")
        except AWS_ERRORS as e:
            return (resource, "FAILED", str(e))
