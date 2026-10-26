"""Service-managed StackSets that tarmac owns: create or update them, keep their Region instances in sync, and
remove them."""

import time
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.aws_audit import retry_notice
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code
from ..core.models import TAG_MANAGED_BY
from ..core.tagging import to_cfn_tags
from ..core.text import plural

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

        response = self._start(
            cf,
            name,
            lambda: cf.update_stack_set(
                StackSetName=name, OperationPreferences=OPERATION_PREFERENCES, **settings
            ),
        )
        ok = self._finish(
            cf, name, response["OperationId"], "update", f"stackset:{name}", f"Updated StackSet '{name}'"
        )
        return "UPDATED" if ok else "FAILED"

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

    def auto_deployment_regions(self, cf: Any, name: str) -> set[str]:
        """The Regions new accounts in the targeted OUs are given instances in."""
        regions: set[str] = set()
        token: str | None = None
        while True:
            page = cf.list_stack_set_auto_deployment_targets(
                StackSetName=name, **({"NextToken": token} if token else {})
            )
            for summary in page.get("Summaries", []):
                regions.update(str(r) for r in summary.get("Regions", []))
            token = page.get("NextToken")
            if not token:
                return regions

    def release(self, cf: Any, name: str, accounts: set[str], instances: list[dict[str, Any]]) -> bool:
        """Remove the instances in ``accounts``, keeping their stacks.

        For closed and suspended accounts: AWS can no longer reach them, so their instances stay OUTDATED and block
        every later operation until they are removed with RetainStacks. Each instance is removed through the OU it
        was deployed for, the only target AWS accepts for it. Returns whether any were removed.
        """
        stuck: dict[str, tuple[set[str], set[str]]] = {}
        for inst in instances:
            if str(inst.get("Account")) in accounts:
                found = stuck.setdefault(str(inst["OrganizationalUnitId"]), (set(), set()))
                found[0].add(str(inst["Account"]))
                found[1].add(str(inst["Region"]))
        for ou, (ids, regions) in sorted(stuck.items()):
            response = self._start(
                cf,
                name,
                lambda ou=ou, ids=ids, regions=regions: cf.delete_stack_instances(
                    StackSetName=name,
                    DeploymentTargets={
                        "OrganizationalUnitIds": [ou],
                        "Accounts": sorted(ids),
                        "AccountFilterType": "INTERSECTION",
                    },
                    Regions=sorted(regions),
                    RetainStacks=True,
                    OperationPreferences=OPERATION_PREFERENCES,
                ),
            )
            self._finish(
                cf,
                name,
                response["OperationId"],
                "delete",
                f"stackset-instances:{name}",
                f"Removed StackSet '{name}' from closed {plural(len(ids), 'account')} {', '.join(sorted(ids))}",
                regions=sorted(regions),
            )
        return bool(stuck)

    def _released(self, cf: Any, name: str, closed: set[str] | None) -> list[dict[str, Any]]:
        """The StackSet's instances, after removing those in ``closed`` accounts."""
        instances = self.list_instances(cf, name)
        if closed and self.release(cf, name, closed, instances):
            instances = self.list_instances(cf, name)
        return instances

    def sync_instances(
        self, cf: Any, name: str, regions: list[str], targets: dict[str, Any], closed: set[str] | None = None
    ) -> list[str]:
        """Add instances for Regions that have none, drop Regions no longer configured, report what is not
        current. Template and parameter changes reach existing instances through the StackSet update.

        A dropped Region is removed through the targeted OUs alone: removing it with an account filter would leave
        it among the Regions new accounts are deployed to.
        """
        present = {str(i["Region"]) for i in self._released(cf, name, closed)}
        present |= self.auto_deployment_regions(cf, name)
        missing = [r for r in regions if r not in present]
        surplus = sorted(present - set(regions))
        if missing:
            self._create_instances(cf, name, targets, missing)
        if surplus:
            ous = {"OrganizationalUnitIds": targets["OrganizationalUnitIds"]}
            self._delete_instances(cf, name, ous, surplus)
        return self._instance_failures(cf, name)

    def sync_targets(
        self, cf: Any, name: str, ou_ids: list[str], regions: list[str], closed: set[str] | None = None
    ) -> list[str]:
        """For a StackSet targeting OUs: give each OU instances in exactly ``regions``, remove the instances of
        OUs no longer targeted, and report what is not current. Each instance records the OU it was deployed
        for, so an OU without accounts has none and is targeted again on every run, which changes nothing."""
        present: dict[str, set[str]] = {}
        for instance in self._released(cf, name, closed):
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
        response = self._start(
            cf,
            name,
            lambda: cf.create_stack_instances(
                StackSetName=name,
                DeploymentTargets=targets,
                Regions=regions,
                OperationPreferences=OPERATION_PREFERENCES,
            ),
        )
        self._finish(
            cf,
            name,
            response["OperationId"],
            "create",
            f"stackset-instances:{name}",
            f"Deployed StackSet '{name}' to {', '.join(regions)}",
            regions=regions,
        )

    def _delete_instances(self, cf: Any, name: str, targets: dict[str, Any], regions: list[str]) -> None:
        response = self._start(
            cf,
            name,
            lambda: cf.delete_stack_instances(
                StackSetName=name,
                DeploymentTargets=targets,
                Regions=regions,
                RetainStacks=False,
                OperationPreferences=OPERATION_PREFERENCES,
            ),
        )
        self._finish(
            cf,
            name,
            response["OperationId"],
            "delete",
            f"stackset-instances:{name}",
            f"Removed StackSet '{name}' from {', '.join(regions)}",
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
                f"StackSet '{name}' has {plural(len(failures), 'out-of-date instance')}",
                failures=failures,
            )
        return failures

    def _finish(
        self, cf: Any, name: str, operation_id: str, action: str, resource: str, done: str, **details: Any
    ) -> bool:
        """Wait for the operation and record ``done`` only if it succeeded; otherwise record how it ended."""
        status = self.wait(cf, name, operation_id)
        if status == "SUCCEEDED":
            audit(action, resource, Outcome.SUCCEEDED, done, **details)
            return True
        audit(
            action,
            resource,
            Outcome.FAILED,
            f"StackSet operation {operation_id} on '{name}' ended {status}",
            **details,
        )
        return False

    def _start(self, cf: Any, name: str, call: Callable[[], Any]) -> Any:
        """Start an operation on the StackSet, first waiting for one already running.

        AWS runs one operation per StackSet at a time, and starts some itself: moving a new account into a
        targeted OU starts an automatic deployment to it.
        """
        for attempt in range(3):
            try:
                return call()
            except ClientError as e:
                if aws_error_code(e) != "OperationInProgressException" or attempt == 2:
                    raise
                running = [
                    str(o["OperationId"])
                    for o in cf.list_stack_set_operations(StackSetName=name).get("Summaries", [])
                    if o.get("Status") in ("RUNNING", "QUEUED", "STOPPING")
                ]
                retry_notice(
                    f"StackSet '{name}'", "another operation on it is still running", self._poll_seconds
                )
                for operation_id in running:
                    self.wait(cf, name, operation_id)
        raise AssertionError("unreachable")

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
        self,
        cf: Any,
        name: str,
        targets: Callable[[], dict[str, Any]],
        dry_run: bool,
        closed: Callable[[], set[str]] = set,
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
            instances = self._released(cf, name, closed())
            regions = sorted({str(i["Region"]) for i in instances})
            if regions:
                response = self._start(
                    cf,
                    name,
                    lambda: cf.delete_stack_instances(
                        StackSetName=name,
                        DeploymentTargets=targets(),
                        Regions=regions,
                        RetainStacks=False,
                        OperationPreferences=OPERATION_PREFERENCES,
                    ),
                )
                self.wait(cf, name, response["OperationId"])
                left = self.list_instances(cf, name)
                if left:
                    return (resource, "FAILED", f"{plural(len(left), 'stack instance')} could not be deleted")
            self._start(cf, name, lambda: cf.delete_stack_set(StackSetName=name))
            audit("delete", f"stackset:{name}", Outcome.SUCCEEDED, f"Deleted StackSet '{name}'")
            return (
                resource,
                "DELETED",
                f"Deleted the StackSet and {plural(len(instances), 'stack instance')}",
            )
        except AWS_ERRORS as e:
            return (resource, "FAILED", str(e))
