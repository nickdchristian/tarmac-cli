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

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code, aws_error_message
from ..core.models import TAG_MANAGED_BY, StackDeployReport
from ..core.org_accounts import inactive_account_ids
from ..core.stack_names import Stack
from ..core.tagging import merge_tags
from .cloudformation import CloudFormationService
from .stackset import StackSetService

logger = logging.getLogger(__name__)


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
        self.stack_sets = StackSetService(sleep, poll_seconds, timeout_seconds)

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
        report = ConfigRecorderReport()

        template_body = template_file.read_text(encoding="utf-8")
        cfn_tags = merge_tags(org_tags, tags, {TAG_MANAGED_BY: "tarmac"})
        cf = self.session_mgr.get_client("cloudformation", region_name=primary_region)
        try:
            cf.activate_organizations_access()
            root_id = self._root_id()
            closed = inactive_account_ids(self.session_mgr.get_client("organizations"))
            targets = self._targets(root_id, management_account_id, closed)
            report.stack_set_action = self.stack_sets.ensure(
                cf, name, "AWS Config recorders managed by tarmac", template_body, parameters, cfn_tags
            )
            report.failures.extend(self.stack_sets.sync_instances(cf, name, regions, targets, closed))
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
            return str(iam.get_role(RoleName="AWSServiceRoleForConfig")["Role"]["Arn"])
        except ClientError as e:
            if aws_error_code(e) != "NoSuchEntity":
                raise GovernanceError(
                    "Could not look up the AWS Config service-linked role", details=aws_error_message(e)
                ) from e
        try:
            return str(iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"])
        except ClientError as e:
            raise GovernanceError(
                "Could not create the AWS Config service-linked role", details=aws_error_message(e)
            ) from e

    def _root_id(self) -> str:
        roots = self.session_mgr.get_client("organizations").list_roots().get("Roots", [])
        if not roots:
            raise GovernanceError("The organization has no root to deploy AWS Config recorders to.")
        return str(roots[0]["Id"])

    @staticmethod
    def _targets(root_id: str, management_account_id: str, closed: set[str]) -> dict[str, Any]:
        """The organization root without the management account (StackSets cannot deploy there) and without
        suspended accounts (their roles cannot be assumed)."""
        return {
            "OrganizationalUnitIds": [root_id],
            "AccountFilterType": "DIFFERENCE",
            "Accounts": sorted(a for a in {management_account_id, *closed} if a),
        }

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
        stack_set: bool = True,
    ) -> list[tuple[str, str, str]]:
        """Remove the StackSet (with its instances, unless ``stack_set`` is False) and the management account stacks
        in ``regions``.

        Returns (resource, action, message) rows where action is DELETED, NOT_FOUND, SIMULATED or FAILED.
        """
        rows = self._remove_stack_set(org_name, primary_region, dry_run) if stack_set else []
        for region in regions:
            rows.append(self._remove_management_stack(org_name, region, management_account_id, dry_run))
        return rows

    def _remove_stack_set(
        self, org_name: str, primary_region: str, dry_run: bool
    ) -> list[tuple[str, str, str]]:
        cf = self.session_mgr.get_client("cloudformation", region_name=primary_region)
        return [
            self.stack_sets.remove(
                cf,
                Stack.CONFIG_RECORDER.for_org(org_name),
                lambda: {"OrganizationalUnitIds": [self._root_id()]},
                dry_run,
                closed=lambda: inactive_account_ids(self.session_mgr.get_client("organizations")),
            )
        ]

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
