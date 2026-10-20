"""Teardown of what ``tarmac deploy destroy`` normally keeps, used by ``--everything``.

Only things recorded in the inventory (see ``core/inventory.py``) or tagged as Tarmac's are removed. Member
accounts are never closed here: ``tarmac account suspend --close`` does that one account at a time.
"""

import contextlib
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..core.audit import Outcome, audit
from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS, aws_error_code, aws_error_message
from ..core.inventory import Inventory
from ..core.models import TAG_MANAGED_BY, TeardownItemReport
from .identity import IdentityService
from .teardown_base import TeardownBase

logger = logging.getLogger(__name__)

ACCESS_STACK = "tarmac-access"
BOOTSTRAP_USER = "tarmac-bootstrap"
ACCESS_ROLE = "TarmacDeploymentRole"
# Disabling this would delete the Identity Center instance created through Organizations.
NEVER_AUTO_DISABLE = frozenset({"sso.amazonaws.com"})
_MISSING = {
    "NoSuchEntity",
    "NoSuchEntityException",
    "ResourceNotFoundException",
    "AWSOrganizationsNotInUseException",
}


def _item(
    kind: str, name: str, action: str, message: str, account: str = "Management", account_id: str = ""
) -> TeardownItemReport:
    return TeardownItemReport(
        resource_type=kind,
        resource_name=name,
        account_name=account,
        account_id=account_id,
        action=action,
        message=message,
    )


class EverythingTeardown(TeardownBase):
    """Identity principals, OUs, organization settings and the access role that Tarmac created."""

    # ------------------------------------------------------------------ Identity Center users and groups

    def teardown_identity_principals(
        self, bundle: ConfigBundle, target_region: str, inventory: Inventory, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        results: list[TeardownItemReport] = self._new_results_list()
        users, groups = inventory.get("identity-user"), inventory.get("identity-group")
        if not users and not groups:
            return results
        mgmt_id = self._get_management_account_id()
        try:
            service = IdentityService(self.session_mgr, preferred_region=target_region)
            instance_arn, store_id = service.get_instance_details()
        except AWS_ERRORS as exc:
            for name in groups:
                results.append(
                    _item("Identity Group", name, "SKIPPED", f"Identity Center unavailable: {exc}")
                )
            for name in users:
                results.append(_item("Identity User", name, "SKIPPED", f"Identity Center unavailable: {exc}"))
            return results
        store = service.identitystore_client

        for name in groups:
            results.append(
                self._delete_group(service, store, instance_arn, store_id, name, inventory, dry_run, mgmt_id)
            )
        for name in users:
            results.append(self._delete_user(store, store_id, name, inventory, dry_run, mgmt_id))
        return results

    def _delete_group(
        self,
        service: IdentityService,
        store: Any,
        instance_arn: str,
        store_id: str,
        name: str,
        inventory: Inventory,
        dry_run: bool,
        mgmt_id: str,
    ) -> TeardownItemReport:
        try:
            group_id = store.get_group_id(
                IdentityStoreId=store_id,
                AlternateIdentifier={
                    "UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": name}
                },
            )["GroupId"]
        except ClientError as exc:
            if aws_error_code(exc) in _MISSING:
                inventory.forget("identity-group", name)
                return _item("Identity Group", name, "NOT_FOUND", "Already gone", account_id=mgmt_id)
            return _item("Identity Group", name, "FAILED", aws_error_message(exc), account_id=mgmt_id)
        if dry_run:
            return _item(
                "Identity Group",
                name,
                "SIMULATED",
                "Would remove its assignments, then delete it",
                account_id=mgmt_id,
            )
        try:
            self._remove_principal_assignments(service, instance_arn, "GROUP", group_id)
            store.delete_group(IdentityStoreId=store_id, GroupId=group_id)
        except AWS_ERRORS as exc:
            return _item("Identity Group", name, "FAILED", str(exc), account_id=mgmt_id)
        audit(
            "delete", f"identity-group:{name}", Outcome.SUCCEEDED, f"Deleted Identity Center group '{name}'"
        )
        inventory.forget("identity-group", name)
        return _item("Identity Group", name, "DELETED", "Deleted group created by tarmac", account_id=mgmt_id)

    def _delete_user(
        self, store: Any, store_id: str, name: str, inventory: Inventory, dry_run: bool, mgmt_id: str
    ) -> TeardownItemReport:
        try:
            user_id = store.get_user_id(
                IdentityStoreId=store_id,
                AlternateIdentifier={
                    "UniqueAttribute": {"AttributePath": "userName", "AttributeValue": name}
                },
            )["UserId"]
        except ClientError as exc:
            if aws_error_code(exc) in _MISSING:
                inventory.forget("identity-user", name)
                return _item("Identity User", name, "NOT_FOUND", "Already gone", account_id=mgmt_id)
            return _item("Identity User", name, "FAILED", aws_error_message(exc), account_id=mgmt_id)
        if dry_run:
            return _item(
                "Identity User",
                name,
                "SIMULATED",
                "Would delete the user created by tarmac",
                account_id=mgmt_id,
            )
        try:
            store.delete_user(IdentityStoreId=store_id, UserId=user_id)
        except ClientError as exc:
            return _item("Identity User", name, "FAILED", aws_error_message(exc), account_id=mgmt_id)
        audit("delete", f"identity-user:{name}", Outcome.SUCCEEDED, f"Deleted Identity Center user '{name}'")
        inventory.forget("identity-user", name)
        return _item("Identity User", name, "DELETED", "Deleted user created by tarmac", account_id=mgmt_id)

    @staticmethod
    def _remove_principal_assignments(
        service: IdentityService, instance_arn: str, principal_type: str, principal_id: str
    ) -> None:
        paginator = service.sso_client.get_paginator("list_account_assignments_for_principal")
        for page in paginator.paginate(
            InstanceArn=instance_arn, PrincipalId=principal_id, PrincipalType=principal_type
        ):
            for a in page.get("AccountAssignments", []):
                service.delete_account_assignment(
                    instance_arn, a["AccountId"], a["PermissionSetArn"], principal_type, principal_id
                )

    # ------------------------------------------------------------------ OUs

    def teardown_ous(self, inventory: Inventory, dry_run: bool = False) -> list[TeardownItemReport]:
        """Delete OUs Tarmac created, deepest first, and only while they hold no accounts or OUs."""
        results: list[TeardownItemReport] = self._new_results_list()
        recorded = inventory.get("ou")
        if not recorded:
            return results
        org: Any = self.session_mgr.get_client("organizations")
        mgmt_id = self._get_management_account_id()
        depth = {name: self._ou_depth(org, d.get("ou_id", "")) for name, d in recorded.items()}
        for name in sorted(recorded, key=lambda n: -depth[n]):
            ou_id = recorded[name].get("ou_id", "")
            if not ou_id:
                results.append(
                    _item("Organizational Unit", name, "SKIPPED", "No OU id was recorded", account_id=mgmt_id)
                )
                continue
            try:
                org.describe_organizational_unit(OrganizationalUnitId=ou_id)
                occupants = self._ou_occupants(org, ou_id)
            except ClientError as exc:
                if aws_error_code(exc) == "OrganizationalUnitNotFoundException":
                    inventory.forget("ou", name)
                    results.append(
                        _item("Organizational Unit", name, "NOT_FOUND", "Already gone", account_id=mgmt_id)
                    )
                else:
                    results.append(
                        _item(
                            "Organizational Unit", name, "FAILED", aws_error_message(exc), account_id=mgmt_id
                        )
                    )
                continue
            if occupants:
                results.append(
                    _item(
                        "Organizational Unit",
                        name,
                        "SKIPPED",
                        f"Not empty ({', '.join(occupants[:3])}{'...' if len(occupants) > 3 else ''}); "
                        "move or close those first",
                        account_id=mgmt_id,
                    )
                )
                continue
            if dry_run:
                results.append(
                    _item(
                        "Organizational Unit",
                        name,
                        "SIMULATED",
                        f"Would delete empty OU {ou_id}",
                        account_id=mgmt_id,
                    )
                )
                continue
            try:
                org.delete_organizational_unit(OrganizationalUnitId=ou_id)
            except ClientError as exc:
                results.append(
                    _item("Organizational Unit", name, "FAILED", aws_error_message(exc), account_id=mgmt_id)
                )
                continue
            audit(
                "delete",
                f"ou:{name}",
                Outcome.SUCCEEDED,
                f"Deleted empty organizational unit '{name}' ({ou_id})",
            )
            inventory.forget("ou", name)
            results.append(
                _item("Organizational Unit", name, "DELETED", f"Deleted empty OU {ou_id}", account_id=mgmt_id)
            )
        return results

    @staticmethod
    def _ou_depth(org: Any, ou_id: str) -> int:
        depth, current = 0, ou_id
        while current and current.startswith("ou-") and depth < 10:
            try:
                parents = org.list_parents(ChildId=current).get("Parents", [])
            except (ClientError, BotoCoreError):
                break
            if not parents:
                break
            current = parents[0]["Id"]
            depth += 1
        return depth

    @staticmethod
    def _ou_occupants(org: Any, ou_id: str) -> list[str]:
        names: list[str] = []
        for child_type in ("ACCOUNT", "ORGANIZATIONAL_UNIT"):
            for page in org.get_paginator("list_children").paginate(ParentId=ou_id, ChildType=child_type):
                names.extend(c["Id"] for c in page.get("Children", []))
        return names

    # ------------------------------------------------------------------ organization settings (phase 1)

    def teardown_org_settings(
        self, bundle: ConfigBundle, inventory: Inventory, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Undo phase 1: delegation, root-access features, trusted access, contacts and cost tags."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        org: Any = self.session_mgr.get_client("organizations")

        for key in inventory.get("delegated-admin"):
            service, _, account_id = key.rpartition(":")
            results.append(
                self._act(
                    inventory,
                    "delegated-admin",
                    key,
                    "Delegated Administrator",
                    f"{service} → {account_id}",
                    dry_run,
                    lambda s=service, a=account_id: org.deregister_delegated_administrator(
                        AccountId=a, ServicePrincipal=s
                    ),
                    mgmt_id,
                )
            )

        iam: Any = self.session_mgr.get_client("iam")
        for kind, call, label in (
            ("root-sessions", "disable_organizations_root_sessions", "Privileged root sessions"),
            (
                "root-credentials-management",
                "disable_organizations_root_credentials_management",
                "Root credentials management",
            ),
        ):
            for key in inventory.get(kind):
                results.append(
                    self._act(
                        inventory,
                        kind,
                        key,
                        "Root Access Feature",
                        label,
                        dry_run,
                        lambda c=call: getattr(iam, c)(),
                        mgmt_id,
                    )
                )

        for key in inventory.get("trusted-access"):
            if key in NEVER_AUTO_DISABLE:
                results.append(
                    _item(
                        "Trusted Service Access",
                        key,
                        "SKIPPED",
                        "Left enabled: disabling it can delete the Identity Center instance. Disable it in the "
                        "console if you really want that.",
                        account_id=mgmt_id,
                    )
                )
                continue
            results.append(
                self._act(
                    inventory,
                    "trusted-access",
                    key,
                    "Trusted Service Access",
                    key,
                    dry_run,
                    lambda s=key: org.disable_aws_service_access(ServicePrincipal=s),
                    mgmt_id,
                )
            )

        account: Any = self.session_mgr.get_client("account")
        for key in inventory.get("alternate-contact"):
            results.append(
                self._act(
                    inventory,
                    "alternate-contact",
                    key,
                    "Alternate Contact",
                    key,
                    dry_run,
                    lambda k=key: account.delete_alternate_contact(AlternateContactType=k.upper()),
                    mgmt_id,
                )
            )

        for key, details in inventory.get("cost-allocation-tags").items():
            tags = [str(t) for t in details.get("tag_keys", [])]
            if not tags:
                continue
            results.append(
                self._act(
                    inventory,
                    "cost-allocation-tags",
                    key,
                    "Cost Allocation Tags",
                    ", ".join(tags),
                    dry_run,
                    lambda t=tags: self.session_mgr.get_client(
                        "ce", region_name="us-east-1"
                    ).update_cost_allocation_tags_status(
                        CostAllocationTagsStatus=[{"TagKey": k, "Status": "Inactive"} for k in t]
                    ),
                    mgmt_id,
                )
            )
        return results

    def _act(
        self,
        inventory: Inventory,
        kind: str,
        key: str,
        label: str,
        name: str,
        dry_run: bool,
        call: Any,
        mgmt_id: str,
    ) -> TeardownItemReport:
        if dry_run:
            return _item(label, name, "SIMULATED", "Would revert (enabled by tarmac)", account_id=mgmt_id)
        try:
            call()
        except ClientError as exc:
            code = aws_error_code(exc)
            if code in _MISSING or code in {"AccountNotRegisteredException", "ServiceNotInUseException"}:
                inventory.forget(kind, key)
                return _item(label, name, "NOT_FOUND", "Already reverted", account_id=mgmt_id)
            return _item(label, name, "FAILED", aws_error_message(exc), account_id=mgmt_id)
        except BotoCoreError as exc:
            return _item(label, name, "FAILED", str(exc), account_id=mgmt_id)
        audit("delete", f"{kind}:{key}", Outcome.SUCCEEDED, f"Reverted {label.lower()} '{name}'")
        inventory.forget(kind, key)
        return _item(label, name, "DELETED", "Reverted a setting tarmac enabled", account_id=mgmt_id)

    # ------------------------------------------------------------------ accounts (never closed)

    def report_accounts_kept(self, dry_run: bool = False) -> list[TeardownItemReport]:
        """List the member accounts tarmac manages; closing them stays a deliberate, per-account step."""
        results: list[TeardownItemReport] = self._new_results_list()
        if not self._has_credentials():
            return results
        org: Any = self.session_mgr.get_client("organizations")
        try:
            for page in org.get_paginator("list_accounts").paginate():
                for acct in page.get("Accounts", []):
                    if acct.get("Status") != "ACTIVE" or acct["Id"] == self._get_management_account_id():
                        continue
                    if not self._has_tag(org, acct["Id"]):
                        continue
                    results.append(
                        _item(
                            "Member Account",
                            acct["Name"],
                            "SKIPPED",
                            f"Never closed automatically. To close: tarmac account suspend {acct['Name']} --close",
                            account=acct["Name"],
                            account_id=acct["Id"],
                        )
                    )
        except AWS_ERRORS as exc:
            logger.debug("Could not list managed accounts: %s", exc)
        return results

    @staticmethod
    def _has_tag(org: Any, resource_id: str) -> bool:
        try:
            for page in org.get_paginator("list_tags_for_resource").paginate(ResourceId=resource_id):
                if any(
                    t.get("Key") == TAG_MANAGED_BY and t.get("Value") == "tarmac"
                    for t in page.get("Tags", [])
                ):
                    return True
        except (ClientError, BotoCoreError):
            return False
        return False

    # ------------------------------------------------------------------ access role and bootstrap user

    def teardown_access(self, region: str, dry_run: bool = False) -> list[TeardownItemReport]:
        """Remove the access stack (role, policy, bootstrap user) from `tarmac access bootstrap`.

        This is the last step: when the run itself uses the role, the stack deletion is started but not awaited.
        """
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        caller_arn = ""
        with contextlib.suppress(*AWS_ERRORS):
            caller_arn = str(self.session_mgr.get_caller_identity().get("Arn", ""))
        using_role = f"/{ACCESS_ROLE}/" in caller_arn or f"role/{ACCESS_ROLE}" in caller_arn

        self._delete_bootstrap_user(results, dry_run, mgmt_id)

        for stack_region in dict.fromkeys([region, "us-east-1"]):
            try:
                cfn = self.session_mgr.get_client("cloudformation", region_name=stack_region)
                status = self.cfn_service._get_stack_status(cfn, ACCESS_STACK)
            except AWS_ERRORS:
                continue
            if not status or status == "DELETE_COMPLETE":
                continue
            if dry_run:
                results.append(
                    _item(
                        "CloudFormation Stack",
                        ACCESS_STACK,
                        "SIMULATED",
                        f"Would delete in {stack_region} ({status})",
                        account_id=mgmt_id,
                    )
                )
                break
            try:
                self.cfn_service.delete_stack(
                    cfn, ACCESS_STACK, wait=not using_role, on_progress=self.on_progress
                )
            except AWS_ERRORS as exc:
                results.append(
                    _item("CloudFormation Stack", ACCESS_STACK, "FAILED", str(exc), account_id=mgmt_id)
                )
                break
            note = (
                "Deletion started; this session uses the role, so it may end now. Sign in as an administrator for anything further."
                if using_role
                else f"Deleted access stack in {stack_region}"
            )
            results.append(_item("CloudFormation Stack", ACCESS_STACK, "DELETED", note, account_id=mgmt_id))
            break
        else:
            results.append(
                _item(
                    "CloudFormation Stack",
                    ACCESS_STACK,
                    "NOT_FOUND",
                    "No access stack found",
                    account_id=mgmt_id,
                )
            )
        return results

    def _delete_bootstrap_user(self, results: list[TeardownItemReport], dry_run: bool, mgmt_id: str) -> None:
        """The stack cannot delete a user that still has keys or MFA, so empty it first."""
        try:
            iam: Any = self.session_mgr.get_client("iam")
            iam.get_user(UserName=BOOTSTRAP_USER)
        except ClientError as exc:
            if aws_error_code(exc) in _MISSING:
                return
            results.append(
                _item(
                    "IAM User",
                    BOOTSTRAP_USER,
                    "SKIPPED",
                    f"Could not inspect ({aws_error_message(exc)}); remove it as an administrator",
                    account_id=mgmt_id,
                )
            )
            return
        except BotoCoreError:
            return
        if dry_run:
            results.append(
                _item(
                    "IAM User",
                    BOOTSTRAP_USER,
                    "SIMULATED",
                    "Would delete its access keys, MFA devices and the user",
                    account_id=mgmt_id,
                )
            )
            return
        try:
            for key in iam.list_access_keys(UserName=BOOTSTRAP_USER).get("AccessKeyMetadata", []):
                iam.delete_access_key(UserName=BOOTSTRAP_USER, AccessKeyId=key["AccessKeyId"])
            for mfa in iam.list_mfa_devices(UserName=BOOTSTRAP_USER).get("MFADevices", []):
                iam.deactivate_mfa_device(UserName=BOOTSTRAP_USER, SerialNumber=mfa["SerialNumber"])
                iam.delete_virtual_mfa_device(SerialNumber=mfa["SerialNumber"])
            for policy_name in iam.list_user_policies(UserName=BOOTSTRAP_USER).get("PolicyNames", []):
                iam.delete_user_policy(UserName=BOOTSTRAP_USER, PolicyName=policy_name)
            for policy in iam.list_attached_user_policies(UserName=BOOTSTRAP_USER).get(
                "AttachedPolicies", []
            ):
                iam.detach_user_policy(UserName=BOOTSTRAP_USER, PolicyArn=policy["PolicyArn"])
            iam.delete_user(UserName=BOOTSTRAP_USER)
        except ClientError as exc:
            results.append(
                _item(
                    "IAM User",
                    BOOTSTRAP_USER,
                    "SKIPPED" if aws_error_code(exc) == "AccessDenied" else "FAILED",
                    f"{aws_error_message(exc)}. Delete its access keys and the user as an administrator.",
                    account_id=mgmt_id,
                )
            )
            return
        audit(
            "delete", f"iam-user:{BOOTSTRAP_USER}", Outcome.SUCCEEDED, f"Deleted IAM user '{BOOTSTRAP_USER}'"
        )
        results.append(
            _item(
                "IAM User",
                BOOTSTRAP_USER,
                "DELETED",
                "Deleted bootstrap user, keys and MFA",
                account_id=mgmt_id,
            )
        )
