"""CloudFormation templates from ``baseline_stacks`` deployed to OUs through service-managed StackSets.

Each becomes the StackSet "<organization.name>-baseline-<name>". Owned StackSets with that prefix that are no longer
declared are deleted, so removing an entry removes its stacks.
"""

from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_schema import BaselineStackDef
from ..core.exceptions import GovernanceError, aws_error_message
from ..core.templates import resolve_resource_path
from .stackset import StackSetService


def stack_set_name(org_name: str, name: str) -> str:
    return f"{org_name}-baseline-{name}"


class BaselineStacksService:
    def __init__(
        self, session_mgr: AwsSessionManager, region: str, stack_sets: StackSetService | None = None
    ):
        self.cf: Any = session_mgr.get_client("cloudformation", region_name=region)
        self.stack_sets = stack_sets or StackSetService()

    def undeclared(self, org_name: str, stacks: list[BaselineStackDef]) -> list[str]:
        """Baseline StackSets of this organization that are no longer declared."""
        prefix = stack_set_name(org_name, "")
        declared = {stack_set_name(org_name, s.name) for s in stacks}
        return sorted(
            str(summary["StackSetName"])
            for page in self.cf.get_paginator("list_stack_sets").paginate(Status="ACTIVE")
            for summary in page.get("Summaries", [])
            if str(summary["StackSetName"]).startswith(prefix) and summary["StackSetName"] not in declared
        )

    def deploy(
        self,
        org_name: str,
        stacks: list[BaselineStackDef],
        project_root: Path,
        ou_ids: dict[str, str],
        tags: dict[str, str],
    ) -> list[str]:
        """Create or update every declared StackSet and its instances, delete undeclared ones. Returns the
        problems found. ``ou_ids`` maps OU names, and "root", to their IDs."""
        failures: list[str] = []
        try:
            if stacks:
                self.cf.activate_organizations_access()
            for stack in stacks:
                name = stack_set_name(org_name, stack.name)
                self.stack_sets.ensure(
                    self.cf,
                    name,
                    f"Baseline stack '{stack.name}' managed by tarmac",
                    resolve_resource_path(stack.template_file, project_root=project_root).read_text(
                        encoding="utf-8"
                    ),
                    stack.parameters,
                    tags,
                )
                targets = [ou_ids["root" if t.lower() == "root" else t] for t in stack.target_ous]
                failures.extend(self.stack_sets.sync_targets(self.cf, name, targets, stack.regions))
            for resource, action, message in self.remove(self.undeclared(org_name, stacks)):
                if action == "FAILED":
                    failures.append(f"{resource}: {message}")
        except ClientError as e:
            raise GovernanceError("Could not deploy the baseline stacks", details=aws_error_message(e)) from e
        return failures

    def remove(self, names: list[str], dry_run: bool = False) -> list[tuple[str, str, str]]:
        return [
            self.stack_sets.remove(
                self.cf,
                name,
                lambda name=name: {
                    "OrganizationalUnitIds": (self.stack_sets.describe(self.cf, name) or {}).get(
                        "OrganizationalUnitIds", []
                    )
                },
                dry_run,
            )
            for name in names
        ]
