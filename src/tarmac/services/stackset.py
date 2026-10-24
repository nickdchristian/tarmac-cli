"""Service-managed StackSets that tarmac owns: create or update them, keep their Region instances in sync, and
remove them."""

import time
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code
from ..core.models import TAG_MANAGED_BY
from ..core.tagging import to_cfn_tags

TERMINAL_OPERATION_STATUSES = frozenset({"SUCCEEDED", "FAILED", "STOPPED"})
# Failures in one account or Region must not stop the others; they are collected and reported together.
OPERATION_PREFERENCES = {
    "RegionConcurrencyType": "PARALLEL",
    "MaxConcurrentPercentage": 100,
    "FailureTolerancePercentage": 100,
}


class StackSetService:
    def __init__(
        self,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 15,
        timeout_seconds: float = 3600,
    ) -> None:
        self._sleep = sleep
        self._poll_seconds = poll_seconds
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def owned(stack_set: dict[str, Any]) -> bool:
        return any(
            t.get("Key") == TAG_MANAGED_BY and t.get("Value") == "tarmac" for t in stack_set.get("Tags", [])
        )

    def describe(self, cf: Any, name: str) -> dict[str, Any] | None:
        try:
            return dict(cf.describe_stack_set(StackSetName=name)["StackSet"])
        except ClientError as e:
            if aws_error_code(e) == "StackSetNotFoundException":
                return None
            raise

    def ensure(
        self,
        cf: Any,
        name: str,
        description: str,
        template_body: str,
        parameters: dict[str, str],
        tags: dict[str, str],
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
        existing = self.describe(cf, name)
        if existing is None:
            cf.create_stack_set(StackSetName=name, Description=description, **settings)
            audit("create", f"stackset:{name}", Outcome.SUCCEEDED, f"Created StackSet '{name}'")
            return "CREATED"

        if not self.owned(existing):
            raise GovernanceError(
                f"StackSet '{name}' exists but was not created by tarmac (no {TAG_MANAGED_BY}=tarmac tag).",
                details="tarmac will not update a StackSet it does not own. Rename or remove it, then re-run.",
            )
        if self.unchanged(existing, template_body, cfn_parameters, tags):
            audit("update", f"stackset:{name}", Outcome.UNCHANGED, f"StackSet '{name}' is already up to date")
            return "UNCHANGED"

        response = cf.update_stack_set(
            StackSetName=name, OperationPreferences=OPERATION_PREFERENCES, **settings
        )
        self.wait(cf, name, response["OperationId"])
        audit("update", f"stackset:{name}", Outcome.SUCCEEDED, f"Updated StackSet '{name}'")
        return "UPDATED"

    @staticmethod
    def unchanged(
        existing: dict[str, Any], template_body: str, parameters: list[dict[str, str]], tags: dict[str, str]
    ) -> bool:
        def params(items: list[dict[str, Any]]) -> dict[str, str]:
            return {str(p["ParameterKey"]): str(p["ParameterValue"]) for p in items}

        def tag_map(items: list[dict[str, Any]]) -> dict[str, str]:
            return {str(t["Key"]): str(t["Value"]) for t in items}

        return (
            existing.get("TemplateBody") == template_body
            # AWS also lists parameters left at their template default, so compare only ours.
            and {k: v for k, v in params(existing.get("Parameters", [])).items() if k in params(parameters)}
            == params(parameters)
            and tag_map(existing.get("Tags", [])) == tags
            and existing.get("Status") == "ACTIVE"
        )

    def list_instances(self, cf: Any, name: str) -> list[dict[str, Any]]:
        instances: list[dict[str, Any]] = []
        for page in cf.get_paginator("list_stack_instances").paginate(StackSetName=name):
            instances.extend(page.get("Summaries", []))
        return instances

    def sync_instances(self, cf: Any, name: str, regions: list[str], targets: dict[str, Any]) -> list[str]:
        """Add instances for Regions that have none, drop Regions no longer configured, report what is not
        current. Template and parameter changes reach existing instances through the StackSet update."""
        present = {str(i["Region"]) for i in self.list_instances(cf, name)}
        missing = [r for r in regions if r not in present]
        surplus = sorted(present - set(regions))
        if missing:
            self._create_instances(cf, name, targets, missing)
        if surplus:
            self._delete_instances(cf, name, targets, surplus)
        return self._instance_failures(cf, name)

    def sync_targets(self, cf: Any, name: str, ou_ids: list[str], regions: list[str]) -> list[str]:
        """For a StackSet targeting OUs: give each OU instances in exactly ``regions``, remove the instances of
        OUs no longer targeted, and report what is not current. Each instance records the OU it was deployed
        for, so an OU without accounts has none and is targeted again on every run, which changes nothing."""
        present: dict[str, set[str]] = {}
        for instance in self.list_instances(cf, name):
            present.setdefault(str(instance["OrganizationalUnitId"]), set()).add(str(instance["Region"]))
        for ou in sorted(set(present) - set(ou_ids)):
            self._delete_instances(cf, name, {"OrganizationalUnitIds": [ou]}, sorted(present[ou]))
        for ou in ou_ids:
            have = present.get(ou, set())
            missing = [r for r in regions if r not in have]
            surplus = sorted(have - set(regions))
            if missing:
                self._create_instances(cf, name, {"OrganizationalUnitIds": [ou]}, missing)
            if surplus:
                self._delete_instances(cf, name, {"OrganizationalUnitIds": [ou]}, surplus)
        return self._instance_failures(cf, name)

    def _create_instances(self, cf: Any, name: str, targets: dict[str, Any], regions: list[str]) -> None:
        response = cf.create_stack_instances(
            StackSetName=name,
            DeploymentTargets=targets,
            Regions=regions,
            OperationPreferences=OPERATION_PREFERENCES,
        )
        self.wait(cf, name, response["OperationId"])
        audit(
            "create",
            f"stackset-instances:{name}",
            Outcome.SUCCEEDED,
            f"Deployed StackSet '{name}' to Region(s) {', '.join(regions)}",
            regions=regions,
        )

    def _delete_instances(self, cf: Any, name: str, targets: dict[str, Any], regions: list[str]) -> None:
        response = cf.delete_stack_instances(
            StackSetName=name,
            DeploymentTargets=targets,
            Regions=regions,
            RetainStacks=False,
            OperationPreferences=OPERATION_PREFERENCES,
        )
        self.wait(cf, name, response["OperationId"])
        audit(
            "delete",
            f"stackset-instances:{name}",
            Outcome.SUCCEEDED,
            f"Removed StackSet '{name}' from Region(s) {', '.join(regions)}",
            regions=regions,
        )

    def _instance_failures(self, cf: Any, name: str) -> list[str]:
        failures = []
        for inst in self.list_instances(cf, name):
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

    def wait(self, cf: Any, name: str, operation_id: str) -> str:
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

    def remove(
        self, cf: Any, name: str, targets: Callable[[], dict[str, Any]], dry_run: bool
    ) -> tuple[str, str, str]:
        """Delete the StackSet and its instances. Returns (resource, action, message) where action is DELETED,
        NOT_FOUND, SKIPPED, SIMULATED or FAILED."""
        resource = f"StackSet {name}"
        try:
            existing = self.describe(cf, name)
            if existing is None:
                return (resource, "NOT_FOUND", "StackSet does not exist")
            if not self.owned(existing):
                return (resource, "SKIPPED", f"Not created by tarmac (no {TAG_MANAGED_BY}=tarmac tag)")
            if dry_run:
                return (resource, "SIMULATED", "Would delete the StackSet and its stack instances")
            instances = self.list_instances(cf, name)
            regions = sorted({str(i["Region"]) for i in instances})
            if regions:
                response = cf.delete_stack_instances(
                    StackSetName=name,
                    DeploymentTargets=targets(),
                    Regions=regions,
                    RetainStacks=False,
                    OperationPreferences=OPERATION_PREFERENCES,
                )
                self.wait(cf, name, response["OperationId"])
                left = self.list_instances(cf, name)
                if left:
                    return (resource, "FAILED", f"{len(left)} stack instance(s) could not be deleted")
            cf.delete_stack_set(StackSetName=name)
            audit("delete", f"stackset:{name}", Outcome.SUCCEEDED, f"Deleted StackSet '{name}'")
            return (resource, "DELETED", f"Deleted the StackSet and {len(instances)} stack instance(s)")
        except AWS_ERRORS as e:
            return (resource, "FAILED", str(e))
