import json
import logging
import re
import time
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import GroupDef, IdentityCenterConfig, PermissionSetDef, UserDef
from ..core.exceptions import DeploymentError, IdentityCenterError
from ..core.models import IdentitySyncReport
from ..core.templates import resolve_resource_path
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)


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
    except ClientError as e:
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
                logger.info("Discovered active IAM Identity Center in '%s' (ARN: %s)", region, arn)
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

    def synthesize_permission_sets_template(
        self,
        instance_arn: str,
        permission_sets: list[PermissionSetDef],
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        """Synthesize a CloudFormation template from declared PermissionSet definitions."""
        resources: dict[str, Any] = {}
        for ps_def in permission_sets:
            res_id = "PermissionSet" + re.sub(r"[^a-zA-Z0-9]", "", ps_def.name)
            props: dict[str, Any] = {
                "InstanceArn": instance_arn,
                "Name": ps_def.name,
                "Description": ps_def.description or f"Managed Permission Set {ps_def.name}",
                "SessionDuration": ps_def.session_duration,
                "ManagedPolicies": ps_def.managed_policies,
            }
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

    def _poll_assignment_deletion_status(
        self,
        instance_arn: str,
        request_id: str,
        max_attempts: int = 30,
        poll_interval: float = 2.0,
    ) -> None:
        """Poll AccountAssignmentDeletionStatus until SUCCEEDED or FAILED."""
        for _ in range(max_attempts):
            try:
                resp = self.sso_client.describe_account_assignment_deletion_status(
                    InstanceArn=instance_arn,
                    AccountAssignmentDeletionRequestId=request_id,
                )
                status_obj = resp.get("AccountAssignmentDeletionStatus", {})
                status = status_obj.get("Status")
                if status == "SUCCEEDED":
                    return
                if status == "FAILED":
                    reason = status_obj.get("FailureReason", "Unknown failure")
                    logger.warning("Assignment deletion failed: %s", reason)
                    return
            except ClientError as e:
                logger.warning("Error checking deletion status: %s", e)
            time.sleep(poll_interval)

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
            if status == "IN_PROGRESS" and req_id:
                self._poll_assignment_deletion_status(instance_arn, req_id)
        except ClientError as e:
            if "ConflictException" not in e.response.get("Error", {}).get("Code", ""):
                logger.warning("Error deleting assignment on %s: %s", account_id, e)

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

    def delete_permission_set(self, instance_arn: str, permission_set_arn: str) -> None:
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
            logger.info("Deleted Permission Set %s from IAM Identity Center", permission_set_arn)
        except ClientError as e:
            logger.warning("Failed deleting permission set %s: %s", permission_set_arn, e)

    def sync_permission_sets_via_cloudformation(
        self,
        permission_sets: list[PermissionSetDef],
        project_root: Path | None = None,
        org_name: str = "organization",
        dry_run: bool = False,
        org_tags: dict[str, str] | None = None,
        tags: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Deploy declared permission sets via a native CloudFormation stack. Returns {Name: Arn}."""
        if not permission_sets:
            return {}

        instance_arn, _ = self.get_instance_details()
        if dry_run:
            for ps_def in permission_sets:
                logger.info("[DRY-RUN] Would deploy PermissionSet '%s' via CloudFormation", ps_def.name)
            return {
                ps_def.name: f"arn:aws:sso:::permissionSet/simulated/{ps_def.name}"
                for ps_def in permission_sets
            }

        template_dict = self.synthesize_permission_sets_template(
            instance_arn, permission_sets, project_root=project_root
        )
        template_body = yaml.dump(template_dict, sort_keys=False)

        if project_root:
            outputs_dir = project_root / "outputs"
            outputs_dir.mkdir(parents=True, exist_ok=True)
            (outputs_dir / "sso-permission-sets.yaml").write_text(template_body, encoding="utf-8")

        stack_name = f"{org_name}-sso-permission-sets"
        cfn_client = self.session_mgr.get_client("cloudformation", region_name=self.region)
        cfn_service = CloudFormationService(self.session_mgr)

        existing_ps = self.list_permission_sets(instance_arn)
        declared_names = {ps_def.name for ps_def in permission_sets}
        pre_existing = declared_names.intersection(existing_ps.keys())

        if pre_existing:
            stack_status = cfn_service._get_stack_status(cfn_client, stack_name)
            if stack_status in (None, "DELETE_COMPLETE", "ROLLBACK_COMPLETE", "REVIEW_IN_PROGRESS"):
                resources_to_import: list[dict[str, Any]] = []
                for ps_def in permission_sets:
                    if ps_def.name in existing_ps:
                        logical_id = "PermissionSet" + re.sub(r"[^a-zA-Z0-9]", "", ps_def.name)
                        resources_to_import.append(
                            {
                                "ResourceType": "AWS::SSO::PermissionSet",
                                "LogicalResourceId": logical_id,
                                "ResourceIdentifier": {
                                    "InstanceArn": instance_arn,
                                    "PermissionSetArn": existing_ps[ps_def.name],
                                },
                            }
                        )

                logger.info(
                    "Importing pre-existing Permission Sets %s into CloudFormation stack '%s'...",
                    sorted(pre_existing),
                    stack_name,
                )
                try:
                    cfn_service.import_resources_and_deploy_stack(
                        cfn_client=cfn_client,
                        stack_name=stack_name,
                        template_body=template_body,
                        resources_to_import=resources_to_import,
                        tags=tags,
                        org_tags=org_tags,
                        dry_run=dry_run,
                    )
                    return self.list_permission_sets(instance_arn)
                except (DeploymentError, ClientError) as e:
                    logger.warning(
                        "CloudFormation import for stack '%s' failed (%s). Reconciling conflicting permission set(s) directly...",
                        stack_name,
                        e,
                    )
                    for ps_name in pre_existing:
                        ps_arn = existing_ps[ps_name]
                        logger.info(
                            "Cleaning up conflicting pre-existing Permission Set '%s' (%s)...",
                            ps_name,
                            ps_arn,
                        )
                        self.delete_permission_set(instance_arn, ps_arn)

        cfn_service.deploy_stack(
            cfn_client=cfn_client,
            stack_name=stack_name,
            parameters={},
            tags=tags,
            dry_run=dry_run,
            template_body=template_body,
            org_tags=org_tags,
        )

        return self.list_permission_sets(instance_arn)

    def get_or_create_user(self, user_def: UserDef, dry_run: bool = False) -> str | None:
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
                return users[0]["UserId"]
        except ClientError as e:
            logger.warning("Error checking user '%s': %s", user_def.username, e)

        if dry_run:
            logger.info("[DRY-RUN] Would create user '%s' (%s)", user_def.username, user_def.email)
            return None

        try:
            resp = self.identitystore_client.create_user(
                IdentityStoreId=store_id,
                UserName=user_def.username,
                DisplayName=f"{user_def.first_name} {user_def.last_name}",
                Name={"GivenName": user_def.first_name, "FamilyName": user_def.last_name},
                Emails=[{"Value": user_def.email, "Type": "work", "Primary": True}],
            )
            user_id: str = resp["UserId"]
            logger.info("Created user '%s' (%s)", user_def.username, user_def.email)
            return user_id
        except ClientError as e:
            raise IdentityCenterError(f"Failed to create user '{user_def.username}'", details=str(e)) from e

    def get_or_create_group(self, group_def: GroupDef, dry_run: bool = False) -> str | None:
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
                return groups[0]["GroupId"]
        except ClientError as e:
            logger.warning("Error checking group '%s': %s", group_def.name, e)

        if dry_run:
            logger.info("[DRY-RUN] Would create group '%s'", group_def.name)
            return None

        try:
            resp = self.identitystore_client.create_group(
                IdentityStoreId=store_id,
                DisplayName=group_def.name,
                Description=group_def.description or "",
            )
            group_id: str = resp["GroupId"]
            logger.info("Created group '%s'", group_def.name)
            return group_id
        except ClientError as e:
            raise IdentityCenterError(f"Failed to create group '{group_def.name}'", details=str(e)) from e

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
        dry_run: bool = False,
    ) -> bool:
        """Add a user to a group in Identity Store. Returns True if newly added, False if already a member."""
        _, store_id = self.get_instance_details()
        u_label = username or user_id
        g_label = group_name or group_id

        if dry_run:
            logger.info("[DRY-RUN] Would add user '%s' to group '%s'", u_label, g_label)
            return True

        try:
            self.identitystore_client.create_group_membership(
                IdentityStoreId=store_id,
                GroupId=group_id,
                MemberId={"UserId": user_id},
            )
            logger.info("Added user '%s' to group '%s'", u_label, g_label)
            return True
        except ClientError as e:
            if "ConflictException" in e.response["Error"]["Code"]:
                logger.debug("User '%s' is already a member of group '%s'", u_label, g_label)
                return False
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
                    logger.info("Assignment of group '%s' to account %s succeeded.", group_name, acct_id)
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

    def assign_group_to_accounts(
        self,
        group_id: str,
        group_name: str,
        permission_set_arn: str,
        account_ids: list[str],
        dry_run: bool = False,
    ) -> int:
        """Assign a group to specific accounts with a given permission set. Returns count of assignments."""
        instance_arn, _ = self.get_instance_details()
        count = 0

        for acct_id in account_ids:
            if dry_run:
                logger.info("[DRY-RUN] Would assign group '%s' to account %s", group_name, acct_id)
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

                logger.info("Assigned group '%s' to account %s", group_name, acct_id)
                count += 1
            except ClientError as e:
                if "ConflictException" in e.response["Error"]["Code"]:
                    logger.debug("Group '%s' already assigned to %s", group_name, acct_id)
                    count += 1
                else:
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
        dry_run: bool = False,
    ) -> tuple[int, dict[str, str], list[str]]:
        """Synchronize declared groups and their multi-account permission set assignments."""
        all_acct_ids = list(active_accts.values())
        total_assignments = 0
        group_map: dict[str, str] = {}
        synced_groups: list[str] = []

        for grp_def in groups:
            group_id = self.get_or_create_group(grp_def, dry_run=dry_run)
            if not group_id:
                continue
            group_map[grp_def.name] = group_id
            synced_groups.append(grp_def.name)

            for assignment in grp_def.assignments:
                ps_arn = ps_map.get(assignment.permission_set)
                if not ps_arn:
                    continue
                target_ids = self._resolve_target_account_ids(assignment.accounts, active_accts, all_acct_ids)
                if not dry_run:
                    total_assignments += self.assign_group_to_accounts(
                        group_id=group_id,
                        group_name=grp_def.name,
                        permission_set_arn=ps_arn,
                        account_ids=target_ids,
                        dry_run=dry_run,
                    )

        return total_assignments, group_map, synced_groups

    def sync_group_memberships(
        self,
        groups: list[GroupDef],
        user_map: dict[str, str],
        group_map: dict[str, str],
        dry_run: bool = False,
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
                    dry_run=dry_run,
                ):
                    added_count += 1

        return added_count

    def _fetch_active_accounts(self) -> dict[str, str]:
        """Fetch all ACTIVE AWS accounts from Organizations as {Name: Id}."""
        org_client: Any = self.session_mgr.get_client("organizations")
        active_accts: dict[str, str] = {}
        for page in org_client.get_paginator("list_accounts").paginate():
            for a in page.get("Accounts", []):
                if a.get("Status") == "ACTIVE":
                    active_accts[a["Name"]] = str(a["Id"])
        return active_accts

    def sync_identity(
        self,
        id_cfg: IdentityCenterConfig,
        project_root: Path | None = None,
        active_accounts: dict[str, str] | None = None,
        org_name: str = "organization",
        dry_run: bool = False,
        org_tags: dict[str, str] | None = None,
        custom_tags: dict[str, str] | None = None,
    ) -> IdentitySyncReport:
        """Complete end-to-end synchronization of permission sets, users, groups, assignments, and memberships."""
        report = IdentitySyncReport()

        ps_map = self.sync_permission_sets_via_cloudformation(
            id_cfg.permission_sets,
            project_root=project_root,
            org_name=org_name,
            dry_run=dry_run,
            org_tags=org_tags,
            tags=custom_tags,
        )
        report.permission_sets_synced = list(ps_map.keys())

        users = [id_cfg.admin_user, id_cfg.breakglass_user] + id_cfg.additional_users
        user_map: dict[str, str] = {}
        for u in users:
            uid = self.get_or_create_user(u, dry_run=dry_run)
            if uid:
                user_map[u.username] = uid
                report.users_synced.append(u.username)

        accts = active_accounts if active_accounts is not None else self._fetch_active_accounts()

        total_assignments, group_map, synced_groups = self.sync_groups_and_assignments(
            id_cfg.groups, ps_map, accts, dry_run=dry_run
        )
        report.groups_synced = synced_groups
        report.assignments_created = total_assignments

        report.memberships_added = self.sync_group_memberships(
            id_cfg.groups, user_map, group_map, dry_run=dry_run
        )

        return report
