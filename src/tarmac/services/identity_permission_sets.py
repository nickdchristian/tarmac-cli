"""IAM Identity Center permission sets: the CloudFormation stack, and deleting retained ones."""

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.config_schema import PermissionSetDef
from ..core.exceptions import DeploymentError, IdentityCenterError
from ..core.models import TAG_MANAGED_BY
from ..core.stack_names import Stack
from ..core.templates import resolve_resource_path
from .cloudformation import CloudFormationService
from .identity_base import IdentityBase

logger = logging.getLogger(__name__)


class PermissionSetMixin(IdentityBase):
    """Permission sets and their account assignments."""

    def list_permission_sets(self, instance_arn: str) -> dict[str, str]:
        """List all permission sets in the instance. Returns {Name: Arn}."""
        ps_map: dict[str, str] = {}
        try:
            paginator = self.sso_client.get_paginator("list_permission_sets")
            for page in paginator.paginate(InstanceArn=instance_arn):
                for ps_arn in page.get("PermissionSets", []):
                    desc = self.sso_client.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn,
                    )
                    ps_map[desc["PermissionSet"]["Name"]] = ps_arn
            return ps_map
        except ClientError as e:
            raise IdentityCenterError("Failed listing permission sets", details=str(e)) from e

    def permission_sets_in_stack(self, org_name: str) -> set[str]:
        """Names of the permission sets tarmac's stack declares now, from identity.yaml at the last deploy.

        Empty when there is no stack or its template can't be read, so callers that delete fail closed.
        """
        try:
            cfn_client = self.session_mgr.get_client("cloudformation", region_name=self.region)
            body = cfn_client.get_template(
                StackName=Stack.PERMISSION_SETS.for_org(org_name), TemplateStage="Original"
            )["TemplateBody"]
            template = body if isinstance(body, dict) else yaml.safe_load(body)
            return {
                str(res["Properties"]["Name"])
                for res in (template.get("Resources") or {}).values()
                if res.get("Type") == "AWS::SSO::PermissionSet"
            }
        except (ClientError, yaml.YAMLError, KeyError, AttributeError, TypeError) as e:
            logger.debug("Could not read the permission set stack's template: %s", e)
            return set()

    def is_tarmac_managed_permission_set(self, instance_arn: str, permission_set_arn: str) -> bool:
        """True only if the permission set carries the tarmac ownership tag.

        Fails closed: any lookup error is treated as "not managed" so destructive callers skip it.
        """
        try:
            paginator = self.sso_client.get_paginator("list_tags_for_resource")
            for page in paginator.paginate(InstanceArn=instance_arn, ResourceArn=permission_set_arn):
                for tag in page.get("Tags", []):
                    if tag.get("Key") == TAG_MANAGED_BY and tag.get("Value") == "tarmac":
                        return True
        except ClientError as e:
            logger.warning("Could not read tags for permission set %s: %s", permission_set_arn, e)
        return False

    @staticmethod
    def _logical_ids_for_permission_sets(permission_sets: list[PermissionSetDef]) -> dict[str, str]:
        """Build unique, CloudFormation-valid logical resource IDs for declared Permission Sets."""
        bases: dict[str, str] = {
            ps.name: "PermissionSet" + re.sub(r"[^a-zA-Z0-9]", "", ps.name) for ps in permission_sets
        }
        counts: dict[str, int] = {}
        for base in bases.values():
            counts[base] = counts.get(base, 0) + 1
        result: dict[str, str] = {}
        for ps in permission_sets:
            base = bases[ps.name]
            if base == "PermissionSet" or counts[base] > 1:
                digest = hashlib.sha256(ps.name.encode("utf-8")).hexdigest()[:8].capitalize()
                result[ps.name] = f"{base}{digest}"
            else:
                result[ps.name] = base
        return result

    def synthesize_permission_sets_template(
        self,
        instance_arn: str,
        permission_sets: list[PermissionSetDef],
        project_root: Path | None = None,
        include_ownership_tag: bool = True,
    ) -> dict[str, Any]:
        """Synthesize a CloudFormation template from declared PermissionSet definitions.

        include_ownership_tag=False is used for IMPORT change sets, which cannot modify tags;
        the tag is applied by a normal stack update right after the import.
        """
        resources: dict[str, Any] = {}
        logical_ids = self._logical_ids_for_permission_sets(permission_sets)
        for ps_def in permission_sets:
            res_id = logical_ids[ps_def.name]
            props: dict[str, Any] = {
                "InstanceArn": instance_arn,
                "Name": ps_def.name,
                "Description": ps_def.description or f"Managed Permission Set {ps_def.name}",
                "SessionDuration": ps_def.session_duration,
                "ManagedPolicies": ps_def.managed_policies,
            }
            if include_ownership_tag:
                props["Tags"] = [{"Key": TAG_MANAGED_BY, "Value": "tarmac"}]
            if ps_def.inline_policy_file:
                p_path = resolve_resource_path(ps_def.inline_policy_file, project_root=project_root)
                props["InlinePolicy"] = json.loads(p_path.read_text(encoding="utf-8"))

            resources[res_id] = {
                "Type": "AWS::SSO::PermissionSet",
                "DeletionPolicy": "Retain",
                "Properties": props,
            }

        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "IAM Identity Center permission sets managed by tarmac",
            "Resources": resources,
        }

    def _poll_assignment_deletion_status(self, instance_arn: str, request_id: str) -> bool:
        """Poll AccountAssignmentDeletionStatus. Returns True on SUCCEEDED, False on FAILED or timeout."""
        for _ in range(30):
            try:
                resp = self.sso_client.describe_account_assignment_deletion_status(
                    InstanceArn=instance_arn,
                    AccountAssignmentDeletionRequestId=request_id,
                )
                status_obj = resp.get("AccountAssignmentDeletionStatus", {})
                status = status_obj.get("Status")
                if status == "SUCCEEDED":
                    return True
                if status == "FAILED":
                    reason = status_obj.get("FailureReason", "Unknown failure")
                    logger.warning("Assignment deletion failed: %s", reason)
                    return False
            except ClientError as e:
                logger.warning("Error checking deletion status: %s", e)
            time.sleep(2)
        return False

    def delete_account_assignment(
        self,
        instance_arn: str,
        account_id: str,
        permission_set_arn: str,
        principal_type: str,
        principal_id: str,
    ) -> bool:
        """Delete an account assignment in IAM Identity Center; False when it was not removed."""
        try:
            resp = self.sso_client.delete_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType="AWS_ACCOUNT",
                PermissionSetArn=permission_set_arn,
                PrincipalType=principal_type,
                PrincipalId=principal_id,
            )
            status_obj = resp.get("AccountAssignmentDeletionStatus", {})
            req_id = status_obj.get("RequestId")
            status = status_obj.get("Status")
            succeeded = True
            if status == "IN_PROGRESS" and req_id:
                succeeded = self._poll_assignment_deletion_status(instance_arn, req_id)
            audit(
                "delete",
                f"sso-assignment:{account_id}:{permission_set_arn}:{principal_id}",
                Outcome.SUCCEEDED if succeeded else Outcome.FAILED,
                f"Removed {principal_type.lower()} {principal_id} from permission set {permission_set_arn} "
                f"on account {account_id}"
                if succeeded
                else f"Removing {principal_type.lower()} {principal_id} from account {account_id} did not complete",
                account_id=account_id,
            )
            return succeeded
        except ClientError as e:
            if "ConflictException" not in e.response.get("Error", {}).get("Code", ""):
                audit(
                    "delete",
                    f"sso-assignment:{account_id}:{permission_set_arn}:{principal_id}",
                    Outcome.FAILED,
                    f"Could not remove {principal_type.lower()} {principal_id} from account {account_id}: {e}",
                    account_id=account_id,
                )
            return False

    def get_assignments_for_permission_set(
        self, instance_arn: str, permission_set_arn: str
    ) -> list[dict[str, Any]]:
        """List all account assignments for a permission set across all provisioned accounts."""
        assignments: list[dict[str, Any]] = []
        try:
            paginator = self.sso_client.get_paginator("list_accounts_for_provisioned_permission_set")
            for page in paginator.paginate(InstanceArn=instance_arn, PermissionSetArn=permission_set_arn):
                for account_id in page.get("AccountIds", []):
                    assign_paginator = self.sso_client.get_paginator("list_account_assignments")
                    for a_page in assign_paginator.paginate(
                        InstanceArn=instance_arn,
                        AccountId=account_id,
                        PermissionSetArn=permission_set_arn,
                    ):
                        assignments.extend(a_page.get("AccountAssignments", []))
        except ClientError as e:
            logger.debug("Error checking assignments for permission set %s: %s", permission_set_arn, e)
        return assignments

    def delete_permission_set(self, instance_arn: str, permission_set_arn: str) -> bool:
        """Delete all assignments and delete the permission set from IAM Identity Center."""
        assignments = self.get_assignments_for_permission_set(instance_arn, permission_set_arn)
        for a in assignments:
            self.delete_account_assignment(
                instance_arn=instance_arn,
                account_id=a["AccountId"],
                permission_set_arn=permission_set_arn,
                principal_type=a["PrincipalType"],
                principal_id=a["PrincipalId"],
            )
        try:
            self.sso_client.delete_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
            )
            audit(
                "delete",
                f"permission-set:{permission_set_arn}",
                Outcome.SUCCEEDED,
                f"Deleted permission set {permission_set_arn} from IAM Identity Center",
            )
            return True
        except ClientError as e:
            audit(
                "delete",
                f"permission-set:{permission_set_arn}",
                Outcome.FAILED,
                f"Could not delete permission set {permission_set_arn}: {e}",
            )
            return False

    def sync_permission_sets_via_cloudformation(
        self,
        permission_sets: list[PermissionSetDef],
        project_root: Path | None = None,
        org_name: str = "organization",
        org_tags: dict[str, str] | None = None,
        tags: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Deploy declared permission sets via a native CloudFormation stack. Returns {Name: Arn}."""
        if not permission_sets:
            return {}

        instance_arn, _ = self.get_instance_details()
        logical_ids = self._logical_ids_for_permission_sets(permission_sets)
        template_dict = self.synthesize_permission_sets_template(
            instance_arn, permission_sets, project_root=project_root
        )
        template_body = yaml.dump(template_dict, sort_keys=False)

        if project_root:
            outputs_dir = project_root / "outputs"
            outputs_dir.mkdir(parents=True, exist_ok=True)
            (outputs_dir / "sso-permission-sets.yaml").write_text(template_body, encoding="utf-8")

        stack_name = Stack.PERMISSION_SETS.for_org(org_name)
        cfn_client = self.session_mgr.get_client("cloudformation", region_name=self.region)
        cfn_service = CloudFormationService(self.session_mgr)

        existing_ps = self.list_permission_sets(instance_arn)
        declared_names = {ps_def.name for ps_def in permission_sets}
        pre_existing = declared_names.intersection(existing_ps.keys())

        in_stack = (
            cfn_service.resource_ids(cfn_client, stack_name)
            if pre_existing and cfn_service.is_usable(cfn_client, stack_name)
            else set()
        )
        to_adopt = [
            ps for ps in permission_sets if ps.name in pre_existing and logical_ids[ps.name] not in in_stack
        ]
        if to_adopt:
            adopting = sorted(ps.name for ps in to_adopt)
            resources_to_import: list[dict[str, Any]] = [
                {
                    "ResourceType": "AWS::SSO::PermissionSet",
                    "LogicalResourceId": logical_ids[ps.name],
                    "ResourceIdentifier": {
                        "InstanceArn": instance_arn,
                        "PermissionSetArn": existing_ps[ps.name],
                    },
                }
                for ps in to_adopt
            ]
            import_template_dict = self.synthesize_permission_sets_template(
                instance_arn, permission_sets, project_root=project_root, include_ownership_tag=False
            )
            adopted = {
                logical_ids[ps.name]: import_template_dict["Resources"][logical_ids[ps.name]]
                for ps in to_adopt
            }
            logger.debug("Importing pre-existing Permission Sets %s into stack '%s'...", adopting, stack_name)
            try:
                cfn_service.import_resources_and_deploy_stack(
                    cfn_client=cfn_client,
                    stack_name=stack_name,
                    template_body=cfn_service.import_template(
                        cfn_client, stack_name, import_template_dict, adopted
                    ),
                    resources_to_import=resources_to_import,
                    tags=tags,
                    org_tags=org_tags,
                )
            except (DeploymentError, ClientError) as e:
                # Never delete permission sets we did not create: removing one also removes every
                # account assignment on it, which can lock people out of AWS accounts.
                raise IdentityCenterError(
                    f"Could not adopt existing permission sets into stack '{stack_name}': {adopting}.",
                    details=(
                        f"{e}\nNo permission sets were deleted. Resolve the CloudFormation import "
                        "error, or rename the permission sets in identity.yaml so tarmac creates "
                        "new ones alongside the existing ones."
                    ),
                ) from e

        cfn_service.deploy_stack(
            cfn_client=cfn_client,
            stack_name=stack_name,
            parameters={},
            tags=tags,
            template_body=template_body,
            org_tags=org_tags,
        )

        return self.list_permission_sets(instance_arn)
