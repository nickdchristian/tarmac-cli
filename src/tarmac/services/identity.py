import logging
import time
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from ..core.audit import Outcome, audit
from ..core.config_loader import normalize_account_name
from ..core.config_schema import GroupDef, IdentityCenterConfig, UserDef
from ..core.exceptions import IdentityCenterError, aws_error_code
from ..core.models import IdentitySyncReport
from ..core.org_accounts import active_account_ids
from ..core.templates import resolve_resource_path
from ..core.text import plural
from .identity_permission_sets import PermissionSetMixin

logger = logging.getLogger(__name__)

DEPLOYMENT_PERMISSION_SET = "TarmacDeployment"
MANAGEMENT_ADMIN_PERMISSION_SET = "ManagementAdministrator"
BOOTSTRAP_PERMISSION_SETS = (DEPLOYMENT_PERMISSION_SET, MANAGEMENT_ADMIN_PERMISSION_SET)


def deployment_policy() -> str:
    """The least-privilege inline policy of the permission set tarmac runs as."""
    return resolve_resource_path("policies/iam/tarmac-deployment.json").read_text(encoding="utf-8")


class IdentityService(PermissionSetMixin):
    """Manages IAM Identity Center permission sets, users, groups, and multi-account assignments.

    Coordinates between AWS SSO Admin (Permission Sets, Account Assignments)
    and AWS Identity Store (Users, Groups, Group Memberships).
    """

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
            # Identity Store rejects an empty Description, so it is only sent when the group has one.
            description = {"Description": group_def.description} if group_def.description else {}
            resp = self.identitystore_client.create_group(
                IdentityStoreId=store_id, DisplayName=group_def.name, **description
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

    def group_members(self, group_id: str) -> dict[str, str]:
        """{username: membership id} for every user in the group. AWS errors propagate."""
        _, store_id = self.get_instance_details()
        members: dict[str, str] = {}
        pages = self.identitystore_client.get_paginator("list_group_memberships").paginate(
            IdentityStoreId=store_id, GroupId=group_id
        )
        for membership in (m for page in pages for m in page.get("GroupMemberships", [])):
            user_id = membership.get("MemberId", {}).get("UserId")
            if user_id:
                user = self.identitystore_client.describe_user(IdentityStoreId=store_id, UserId=user_id)
                members[str(user["UserName"])] = str(membership["MembershipId"])
        return members

    def group_assignments(self, instance_arn: str, group_id: str) -> set[tuple[str, str]]:
        """(account id, permission set ARN) for every assignment the group holds. AWS errors propagate."""
        pages = self.sso_client.get_paginator("list_account_assignments_for_principal").paginate(
            InstanceArn=instance_arn, PrincipalId=group_id, PrincipalType="GROUP"
        )
        return {
            (str(a["AccountId"]), str(a["PermissionSetArn"]))
            for page in pages
            for a in page.get("AccountAssignments", [])
        }

    def undeclared_access(
        self,
        instance_arn: str,
        group: GroupDef,
        group_id: str,
        ps_map: dict[str, str],
        active_accts: dict[str, str],
        managed_ids: set[str],
    ) -> tuple[list[tuple[str, str]], dict[str, str]]:
        """The group's assignments on ``managed_ids`` (the accounts in accounts.yaml) and its members that
        identity.yaml does not declare. Assignments on other accounts, such as the management account, are left alone.
        """
        all_ids = list(active_accts.values())
        wanted = {
            (account_id, ps_map[a.permission_set])
            for a in group.assignments
            if a.permission_set in ps_map
            for account_id in self._resolve_target_account_ids(a.accounts, active_accts, all_ids)
        }
        assignments = sorted(
            a for a in self.group_assignments(instance_arn, group_id) - wanted if a[0] in managed_ids
        )
        members = {name: m for name, m in self.group_members(group_id).items() if name not in group.members}
        return assignments, members

    def remove_user_from_group(self, membership_id: str, group_name: str, username: str) -> None:
        _, store_id = self.get_instance_details()
        try:
            self.identitystore_client.delete_group_membership(
                IdentityStoreId=store_id, MembershipId=membership_id
            )
        except ClientError as e:
            audit(
                "remove-member",
                f"identity-group:{group_name}",
                Outcome.FAILED,
                f"Could not remove user '{username}' from group '{group_name}': {e}",
            )
            raise IdentityCenterError(
                f"Failed removing '{username}' from group '{group_name}'", details=str(e)
            ) from e
        audit(
            "remove-member",
            f"identity-group:{group_name}",
            Outcome.SUCCEEDED,
            f"Removed user '{username}' from group '{group_name}'",
        )

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
        except (ClientError, BotoCoreError):
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
        management_id = str(self.session_mgr.get_caller_identity().get("Account", ""))

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
                if management_id in target_ids and not self._assignment_exists(
                    self.get_instance_details()[0], management_id, ps_arn, group_id
                ):
                    target_ids = [a for a in target_ids if a != management_id]
                    self._skip_management_assignment(grp_def.name, assignment.permission_set, management_id)
                total_assignments += self.assign_group_to_accounts(
                    group_id=group_id,
                    group_name=grp_def.name,
                    permission_set_arn=ps_arn,
                    account_ids=target_ids,
                )

        return total_assignments, group_map, synced_groups

    @staticmethod
    def _skip_management_assignment(group_name: str, permission_set: str, management_id: str) -> None:
        """Identity Center creates the management account's role with the caller's own IAM rights. Tarmac's role is
        deliberately not allowed to create IAM roles, so that one assignment is left for an administrator."""
        audit(
            "create",
            f"sso-assignment:{management_id}:{permission_set}:{group_name}",
            Outcome.SKIPPED,
            f"Not giving '{group_name}' {permission_set} in the management account: tarmac's role can't create the "
            "IAM role Identity Center needs there. Assign it once as an administrator (AWSSSOMasterAccountAdministrator "
            "and IAMFullAccess); tarmac leaves it in place after that.",
            account_id=management_id,
        )
        logger.warning(
            "Skipped giving '%s' %s in the management account %s: assign it once as an administrator.",
            group_name,
            permission_set,
            management_id,
        )

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
        managed_accounts: list[str] | None = None,
        owned_groups: set[str] | None = None,
    ) -> IdentitySyncReport:
        """Complete end-to-end synchronization of permission sets, users, groups, assignments, and memberships.

        ``owned_groups`` are the groups tarmac created or imported (the inventory's identity-group entries). They
        end up with exactly the declared members, and exactly the declared assignments on ``managed_accounts``
        (account names from accounts.yaml): anything else is removed. Other declared groups only get additions.
        """
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

        managed = {normalize_account_name(name) for name in managed_accounts or []}
        managed_ids = {acct_id for name, acct_id in accts.items() if normalize_account_name(name) in managed}
        instance_arn, _ = self.get_instance_details()
        failed: list[str] = []
        for group in id_cfg.groups:
            group_id = group_map.get(group.name)
            if not group_id or group.name not in (owned_groups or set()):
                continue
            assignments, members = self.undeclared_access(
                instance_arn, group, group_id, ps_map, accts, managed_ids
            )
            for account_id, ps_arn in assignments:
                if self.delete_account_assignment(instance_arn, account_id, ps_arn, "GROUP", group_id):
                    report.assignments_removed += 1
                else:
                    failed.append(f"{group.name} on {account_id}")
            for username, membership_id in members.items():
                self.remove_user_from_group(membership_id, group.name, username)
                report.memberships_removed += 1
        if failed:
            raise IdentityCenterError(
                f"Could not remove {plural(len(failed), 'undeclared assignment')}", details="; ".join(failed)
            )

        return report
