import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import BotoCoreError, ClientError

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import GroupDef, IdentityCenterConfig, PermissionSetDef, UserDef
from ..core.exceptions import DeploymentError, IdentityCenterError, aws_error_code
from ..core.models import TAG_MANAGED_BY, IdentitySyncReport
from ..core.org_accounts import active_account_ids
from ..core.stack_names import Stack
from ..core.templates import resolve_resource_path
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)

DEPLOYMENT_PERMISSION_SET = "TarmacDeployment"


def deployment_policy() -> str:
    """The least-privilege inline policy of the permission set tarmac runs as."""
    return resolve_resource_path("policies/iam/tarmac-deployment.json").read_text(encoding="utf-8")


SUPPORTED_SSO_REGIONS: list[str] = [
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "eu-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "sa-east-1",
    "ap-south-1",
]


def _build_candidate_regions(session_mgr: AwsSessionManager, preferred_region: str | None) -> list[str]:
    """Build unique ordered list of candidate regions to probe for Identity Center."""
    candidates: list[str] = []
    if preferred_region:
        candidates.append(preferred_region)
    if session_mgr.default_region and session_mgr.default_region not in candidates:
        candidates.append(session_mgr.default_region)
    for r in SUPPORTED_SSO_REGIONS:
        if r not in candidates:
            candidates.append(r)
    return candidates


def _probe_region_for_instance(session_mgr: AwsSessionManager, region: str) -> tuple[str, str] | None:
    """Probe a single region for an IAM Identity Center instance."""
    try:
        client = session_mgr.get_client("sso-admin", region_name=region)
        instances = client.list_instances().get("Instances", [])
        if instances:
            arn = instances[0].get("InstanceArn")
            store_id = instances[0].get("IdentityStoreId")
            if arn and store_id:
                return str(arn), str(store_id)
    except (ClientError, BotoCoreError) as e:
        logger.debug("Could not probe sso-admin in region %s: %s", region, e)
    return None


class IdentityService:
    """Manages IAM Identity Center permission sets, users, groups, and multi-account assignments.

    Coordinates between AWS SSO Admin (Permission Sets, Account Assignments)
    and AWS Identity Store (Users, Groups, Group Memberships).
    """

    def __init__(self, session_mgr: AwsSessionManager, preferred_region: str | None = None):
        self.session_mgr: AwsSessionManager = session_mgr
        self.preferred_region: str | None = preferred_region
        self._discovered_region: str = preferred_region or session_mgr.default_region
        self.sso_client: Any = session_mgr.get_client("sso-admin", region_name=self._discovered_region)
        self.identitystore_client: Any = session_mgr.get_client(
            "identitystore", region_name=self._discovered_region
        )
        self._instance_arn: str | None = None
        self._identity_store_id: str | None = None

    @classmethod
    def discover_instance(
        cls,
        session_mgr: AwsSessionManager,
        preferred_region: str | None = None,
    ) -> tuple[str, str, str]:
        """Discover the active IAM Identity Center instance across candidate AWS regions.

        Returns:
            tuple[str, str, str]: (instance_arn, identity_store_id, region)
        """
        candidates = _build_candidate_regions(session_mgr, preferred_region)
        for region in candidates:
            found = _probe_region_for_instance(session_mgr, region)
            if found:
                arn, store_id = found
                logger.debug("Discovered active IAM Identity Center in '%s' (ARN: %s)", region, arn)
                return arn, store_id, region

        raise IdentityCenterError(
            "No IAM Identity Center instance found across AWS regions.",
            details="Ensure IAM Identity Center is enabled in the AWS Console (in any supported region).",
        )

    @property
    def region(self) -> str:
        """Return the active region of the IAM Identity Center instance."""
        if not self._instance_arn:
            self.get_instance_details()
        return self._discovered_region

    def get_instance_details(self) -> tuple[str, str]:
        """Fetch the SSO Instance ARN and Identity Store ID, auto-discovering region if needed."""
        if self._instance_arn and self._identity_store_id:
            return self._instance_arn, self._identity_store_id

        arn, store_id, discovered_region = self.discover_instance(
            self.session_mgr, preferred_region=self.preferred_region
        )
        self._instance_arn = arn
        self._identity_store_id = store_id
        if discovered_region != self._discovered_region:
            self._discovered_region = discovered_region
            self.sso_client = self.session_mgr.get_client("sso-admin", region_name=discovered_region)
            self.identitystore_client = self.session_mgr.get_client(
                "identitystore", region_name=discovered_region
            )

        return self._instance_arn, self._identity_store_id

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
            "Description": "AWS Governance - IAM Identity Center Permission Sets",
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
    ) -> None:
        """Delete an account assignment in IAM Identity Center."""
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
        except ClientError as e:
            if "ConflictException" not in e.response.get("Error", {}).get("Code", ""):
                audit(
                    "delete",
                    f"sso-assignment:{account_id}:{permission_set_arn}:{principal_id}",
                    Outcome.FAILED,
                    f"Could not remove {principal_type.lower()} {principal_id} from account {account_id}: {e}",
                    account_id=account_id,
                )

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
                    f"Could not adopt pre-existing permission set(s) {adopting} into stack '{stack_name}'.",
                    details=(
                        f"{e}\nNo permission sets were deleted. Resolve the CloudFormation import "
                        "error, or rename the permission set(s) in identity.yaml so tarmac creates "
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

    def get_or_create_user(self, user_def: UserDef) -> str | None:
        """Fetch or create a user in Identity Store. Returns UserId."""
        _, store_id = self.get_instance_details()

        try:
            resp = self.identitystore_client.list_users(
                IdentityStoreId=store_id,
                Filters=[{"AttributePath": "UserName", "AttributeValue": user_def.username}],
            )
            users = resp.get("Users", [])
            if users:
                logger.debug("User '%s' already exists.", user_def.username)
                audit(
                    "create",
                    f"identity-user:{user_def.username}",
                    Outcome.UNCHANGED,
                    f"Identity Center user '{user_def.username}' already exists",
                )
                return users[0]["UserId"]
        except ClientError as e:
            logger.warning("Error checking user '%s': %s", user_def.username, e)

        try:
            resp = self.identitystore_client.create_user(
                IdentityStoreId=store_id,
                UserName=user_def.username,
                DisplayName=f"{user_def.first_name} {user_def.last_name}",
                Name={"GivenName": user_def.first_name, "FamilyName": user_def.last_name},
                Emails=[{"Value": user_def.email, "Type": "work", "Primary": True}],
            )
            user_id: str = resp["UserId"]
            audit(
                "create",
                f"identity-user:{user_def.username}",
                Outcome.SUCCEEDED,
                f"Created Identity Center user '{user_def.username}' ({user_def.email})",
                user_id=user_id,
            )
            return user_id
        except ClientError as e:
            audit(
                "create",
                f"identity-user:{user_def.username}",
                Outcome.FAILED,
                f"Could not create Identity Center user '{user_def.username}': {e}",
            )
            raise IdentityCenterError(f"Failed to create user '{user_def.username}'", details=str(e)) from e

    def get_or_create_group(self, group_def: GroupDef) -> str | None:
        """Fetch or create a group in Identity Store. Returns GroupId."""
        _, store_id = self.get_instance_details()

        try:
            resp = self.identitystore_client.list_groups(
                IdentityStoreId=store_id,
                Filters=[{"AttributePath": "DisplayName", "AttributeValue": group_def.name}],
            )
            groups = resp.get("Groups", [])
            if groups:
                logger.debug("Group '%s' already exists.", group_def.name)
                audit(
                    "create",
                    f"identity-group:{group_def.name}",
                    Outcome.UNCHANGED,
                    f"Identity Center group '{group_def.name}' already exists",
                )
                return groups[0]["GroupId"]
        except ClientError as e:
            logger.warning("Error checking group '%s': %s", group_def.name, e)

        try:
            resp = self.identitystore_client.create_group(
                IdentityStoreId=store_id,
                DisplayName=group_def.name,
                Description=group_def.description or "",
            )
            group_id: str = resp["GroupId"]
            audit(
                "create",
                f"identity-group:{group_def.name}",
                Outcome.SUCCEEDED,
                f"Created Identity Center group '{group_def.name}'",
                group_id=group_id,
            )
            return group_id
        except ClientError as e:
            audit(
                "create",
                f"identity-group:{group_def.name}",
                Outcome.FAILED,
                f"Could not create Identity Center group '{group_def.name}': {e}",
            )
            raise IdentityCenterError(f"Failed to create group '{group_def.name}'", details=str(e)) from e

    def get_group_id_by_name(self, name: str) -> str | None:
        """Fetch GroupId for a group display name from Identity Store (None when absent). AWS errors propagate."""
        _, store_id = self.get_instance_details()
        groups = self.identitystore_client.list_groups(
            IdentityStoreId=store_id, Filters=[{"AttributePath": "DisplayName", "AttributeValue": name}]
        ).get("Groups", [])
        return str(groups[0]["GroupId"]) if groups else None

    def is_group_member(self, group_id: str, user_id: str) -> bool:
        """Whether the user is already in the group. AWS errors other than not-found propagate."""
        _, store_id = self.get_instance_details()
        try:
            self.identitystore_client.get_group_membership_id(
                IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
            )
        except ClientError as e:
            if aws_error_code(e) == "ResourceNotFoundException":
                return False
            raise
        return True

    def get_user_id_by_username(self, username: str) -> str | None:
        """Fetch UserId for a given username from Identity Store."""
        _, store_id = self.get_instance_details()
        try:
            resp = self.identitystore_client.list_users(
                IdentityStoreId=store_id,
                Filters=[{"AttributePath": "UserName", "AttributeValue": username}],
            )
            users = resp.get("Users", [])
            if users:
                return users[0]["UserId"]
            return None
        except ClientError as e:
            logger.warning("Error looking up user '%s': %s", username, e)
            return None

    def add_user_to_group(
        self,
        group_id: str,
        user_id: str,
        group_name: str = "",
        username: str = "",
    ) -> bool:
        """Add a user to a group in Identity Store. Returns True if newly added, False if already a member."""
        _, store_id = self.get_instance_details()
        u_label = username or user_id
        g_label = group_name or group_id

        try:
            self.identitystore_client.create_group_membership(
                IdentityStoreId=store_id,
                GroupId=group_id,
                MemberId={"UserId": user_id},
            )
            audit(
                "add-member",
                f"identity-group:{g_label}",
                Outcome.SUCCEEDED,
                f"Added user '{u_label}' to group '{g_label}'",
            )
            return True
        except ClientError as e:
            if "ConflictException" in aws_error_code(e):
                audit(
                    "add-member",
                    f"identity-group:{g_label}",
                    Outcome.UNCHANGED,
                    f"User '{u_label}' is already a member of group '{g_label}'",
                )
                return False
            audit(
                "add-member",
                f"identity-group:{g_label}",
                Outcome.FAILED,
                f"Could not add user '{u_label}' to group '{g_label}': {e}",
            )
            raise IdentityCenterError(
                f"Failed adding user '{u_label}' to group '{g_label}'",
                details=str(e),
            ) from e

    def _poll_assignment_status(
        self,
        instance_arn: str,
        request_id: str,
        group_name: str,
        acct_id: str,
        timeout_seconds: float = 30.0,
        poll_interval: float = 2.0,
    ) -> None:
        """Poll DescribeAccountAssignmentCreationStatus until SUCCEEDED or FAILED."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                resp = self.sso_client.describe_account_assignment_creation_status(
                    InstanceArn=instance_arn,
                    AccountAssignmentCreationRequestId=request_id,
                )
                status_obj = resp.get("AccountAssignmentCreationStatus", {})
                status = status_obj.get("Status")
                if status == "SUCCEEDED":
                    logger.debug("Assignment of group '%s' to account %s succeeded.", group_name, acct_id)
                    return
                if status == "FAILED":
                    reason = status_obj.get("FailureReason", "Unknown failure")
                    raise IdentityCenterError(
                        f"Assignment of group '{group_name}' to account {acct_id} failed in AWS",
                        details=reason,
                    )
            except ClientError as e:
                logger.warning("Error checking assignment status for account %s: %s", acct_id, e)
            time.sleep(poll_interval)

        logger.warning(
            "Timed out waiting for assignment of group '%s' to account %s (still IN_PROGRESS in AWS)",
            group_name,
            acct_id,
        )

    def _assignment_exists(
        self, instance_arn: str, account_id: str, permission_set_arn: str, group_id: str
    ) -> bool:
        """True when this group already holds this permission set on the account (False if unreadable)."""
        try:
            paginator = self.sso_client.get_paginator("list_account_assignments")
            for page in paginator.paginate(
                InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=permission_set_arn
            ):
                for item in page.get("AccountAssignments", []):
                    if item.get("PrincipalType") == "GROUP" and item.get("PrincipalId") == group_id:
                        return True
        except (ClientError, BotoCoreError, TypeError, AttributeError):
            return False
        return False

    def assign_group_to_accounts(
        self,
        group_id: str,
        group_name: str,
        permission_set_arn: str,
        account_ids: list[str],
    ) -> int:
        """Assign a group to specific accounts with a given permission set. Returns count of assignments."""
        instance_arn, _ = self.get_instance_details()
        count = 0

        for acct_id in account_ids:
            if self._assignment_exists(instance_arn, acct_id, permission_set_arn, group_id):
                audit(
                    "assign",
                    f"sso-assignment:{acct_id}:{group_name}",
                    Outcome.UNCHANGED,
                    f"Group '{group_name}' is already assigned to account {acct_id}",
                    permission_set_arn=permission_set_arn,
                )
                count += 1
                continue

            try:
                resp = self.sso_client.create_account_assignment(
                    InstanceArn=instance_arn,
                    TargetId=acct_id,
                    TargetType="AWS_ACCOUNT",
                    PermissionSetArn=permission_set_arn,
                    PrincipalType="GROUP",
                    PrincipalId=group_id,
                )
                status_info = resp.get("AccountAssignmentCreationStatus", {})
                req_id = status_info.get("RequestId")
                status = status_info.get("Status")

                if status == "IN_PROGRESS" and req_id:
                    self._poll_assignment_status(instance_arn, req_id, group_name, acct_id)
                elif status == "FAILED":
                    reason = status_info.get("FailureReason", "Unknown failure")
                    raise IdentityCenterError(
                        f"Assignment of group '{group_name}' to account {acct_id} failed",
                        details=reason,
                    )

                audit(
                    "assign",
                    f"sso-assignment:{acct_id}:{group_name}",
                    Outcome.SUCCEEDED,
                    f"Assigned group '{group_name}' to account {acct_id}",
                    permission_set_arn=permission_set_arn,
                )
                count += 1
            except ClientError as e:
                if "ConflictException" in aws_error_code(e):
                    logger.debug("Group '%s' already assigned to %s", group_name, acct_id)
                    count += 1
                else:
                    audit(
                        "assign",
                        f"sso-assignment:{acct_id}:{group_name}",
                        Outcome.FAILED,
                        f"Could not assign group '{group_name}' to account {acct_id}: {e}",
                    )
                    raise IdentityCenterError(
                        f"Failed assigning group '{group_name}' to account {acct_id}",
                        details=str(e),
                    ) from e

        return count

    def _resolve_target_account_ids(
        self,
        target_accounts: list[str],
        active_accts: dict[str, str],
        all_acct_ids: list[str],
    ) -> list[str]:
        """Resolve account names or direct IDs to list of 12-digit AWS account IDs."""
        if "all" in target_accounts:
            return all_acct_ids
        norm_map = {normalize_account_name(k): v for k, v in active_accts.items()}
        resolved: list[str] = []
        for t in target_accounts:
            norm_t = normalize_account_name(t)
            if norm_t in norm_map:
                resolved.append(norm_map[norm_t])
            elif t.isdigit() and len(t) == 12:
                resolved.append(t)
        return resolved

    def sync_groups_and_assignments(
        self,
        groups: list[GroupDef],
        ps_map: dict[str, str],
        active_accts: dict[str, str],
    ) -> tuple[int, dict[str, str], list[str]]:
        """Synchronize declared groups and their multi-account permission set assignments."""
        all_acct_ids = list(active_accts.values())
        total_assignments = 0
        group_map: dict[str, str] = {}
        synced_groups: list[str] = []

        for grp_def in groups:
            group_id = self.get_or_create_group(grp_def)
            if not group_id:
                continue
            group_map[grp_def.name] = group_id
            synced_groups.append(grp_def.name)

            for assignment in grp_def.assignments:
                ps_arn = ps_map.get(assignment.permission_set)
                if not ps_arn:
                    continue
                target_ids = self._resolve_target_account_ids(assignment.accounts, active_accts, all_acct_ids)
                total_assignments += self.assign_group_to_accounts(
                    group_id=group_id,
                    group_name=grp_def.name,
                    permission_set_arn=ps_arn,
                    account_ids=target_ids,
                )

        return total_assignments, group_map, synced_groups

    def sync_group_memberships(
        self,
        groups: list[GroupDef],
        user_map: dict[str, str],
        group_map: dict[str, str],
    ) -> int:
        """Synchronize declared user memberships into groups."""
        added_count = 0
        for grp_def in groups:
            group_id = group_map.get(grp_def.name)
            if not group_id:
                continue

            for member_name in grp_def.members:
                user_id = user_map.get(member_name) or self.get_user_id_by_username(member_name)
                if not user_id:
                    logger.warning(
                        "Member '%s' not found in Identity Store for group '%s'",
                        member_name,
                        grp_def.name,
                    )
                    continue

                if self.add_user_to_group(
                    group_id=group_id,
                    user_id=user_id,
                    group_name=grp_def.name,
                    username=member_name,
                ):
                    added_count += 1

        return added_count

    def sync_identity(
        self,
        id_cfg: IdentityCenterConfig,
        project_root: Path | None = None,
        active_accounts: dict[str, str] | None = None,
        org_name: str = "organization",
        org_tags: dict[str, str] | None = None,
        custom_tags: dict[str, str] | None = None,
    ) -> IdentitySyncReport:
        """Complete end-to-end synchronization of permission sets, users, groups, assignments, and memberships."""
        report = IdentitySyncReport()

        ps_map = self.sync_permission_sets_via_cloudformation(
            id_cfg.permission_sets,
            project_root=project_root,
            org_name=org_name,
            org_tags=org_tags,
            tags=custom_tags,
        )
        declared_sets = {ps.name for ps in id_cfg.permission_sets}
        report.permission_sets_synced = [name for name in ps_map if name in declared_sets]

        users = [id_cfg.admin_user, id_cfg.breakglass_user, *id_cfg.additional_users]
        user_map: dict[str, str] = {}
        for u in users:
            uid = self.get_or_create_user(u)
            if uid:
                user_map[u.username] = uid
                report.users_synced.append(u.username)

        accts = (
            active_accounts
            if active_accounts is not None
            else active_account_ids(self.session_mgr.get_client("organizations"))
        )

        total_assignments, group_map, synced_groups = self.sync_groups_and_assignments(
            id_cfg.groups, ps_map, accts
        )
        report.groups_synced = synced_groups
        report.assignments_created = total_assignments

        report.memberships_added = self.sync_group_memberships(id_cfg.groups, user_map, group_map)

        return report
