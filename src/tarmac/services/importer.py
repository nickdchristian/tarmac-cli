"""Brown-field import: read a live AWS Organization and describe it as Tarmac configuration.

Everything here is read-only. The result is a set of YAML files (plus SCP and permission-set policy
documents) that match what already exists, so the first `tarmac deploy` adopts the organization
instead of fighting it. Anything that cannot be derived is written as a clearly marked placeholder and
reported in `ImportReport.todos`.
"""

import contextlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import load_all_configs
from ..core.org_accounts import account_state, is_active, iter_accounts
from ..core.placeholders import PLACEHOLDER_PHONE
from ..core.stack_names import TARMAC_STACK_SUFFIXES
from ..core.tagging import validate_tags
from .identity import IdentityService
from .preflight import _LIVE_STACK_STATUSES

logger = logging.getLogger(__name__)

_FULL_ACCESS_POLICY = "FullAWSAccess"
_READ_ERRORS = (ClientError, BotoCoreError)


@dataclass
class ImportReport:
    """What the import found, wrote and could not work out."""

    organization_id: str = ""
    organization_name: str = ""
    ou_count: int = 0
    accounts: list[str] = field(default_factory=list)
    skipped_accounts: list[str] = field(default_factory=list)
    scps: list[str] = field(default_factory=list)
    permission_sets: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    existing_trails: list[str] = field(default_factory=list)
    existing_stacks: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "policy"


def _clean_tags(tags: dict[str, str], todos: list[str], owner: str) -> dict[str, str]:
    """Keep tags Tarmac's schema accepts; AWS-reserved, ownership and invalid tags are dropped."""
    kept: dict[str, str] = {}
    for key, value in tags.items():
        if key.lower().startswith(("aws:", "tarmac:")):  # AWS-reserved and tarmac's own bookkeeping tags
            continue
        try:
            kept.update(validate_tags({key: value}))
        except ValueError as exc:
            todos.append(f"Tag '{key}' on {owner} was not imported: {exc}")
    return kept


class ImportService:
    """Discovers a live organization and renders Tarmac configuration for it."""

    def __init__(self, session_mgr: AwsSessionManager, region: str):
        self.session_mgr = session_mgr
        self.region = region
        self.project_root = Path(".")
        self.imported_accounts: dict[str, str] = {}  # {AccountId: Name} of accounts written to accounts.yaml
        self.org: Any = session_mgr.get_client("organizations")
        self.report = ImportReport()

    def _organization(self) -> dict[str, Any]:
        org: dict[str, Any] = self.org.describe_organization()["Organization"]
        self.report.organization_id = str(org.get("Id", ""))
        return org

    def _ou_tree(self, parent_id: str, names: dict[str, str]) -> list[dict[str, Any]]:
        """Nested ou_structure under a parent. `names` collects {OuId: Name}."""
        tree: list[dict[str, Any]] = []
        paginator = self.org.get_paginator("list_organizational_units_for_parent")
        for page in paginator.paginate(ParentId=parent_id):
            for ou in sorted(page.get("OrganizationalUnits", []), key=lambda o: o["Name"]):
                if ou["Name"] in names.values():
                    self.report.todos.append(
                        f"Two OUs are named '{ou['Name']}'. Tarmac identifies OUs by name, so rename one in "
                        "AWS Organizations before deploying."
                    )
                names[ou["Id"]] = ou["Name"]
                node: dict[str, Any] = {"name": ou["Name"], "description": ""}
                children = self._ou_tree(ou["Id"], names)
                if children:
                    node["children"] = children
                tree.append(node)
        return tree

    def _tags(self, resource_id: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        try:
            for page in self.org.get_paginator("list_tags_for_resource").paginate(ResourceId=resource_id):
                for tag in page.get("Tags", []):
                    tags[str(tag["Key"])] = str(tag["Value"])
        except _READ_ERRORS as exc:
            logger.debug("Could not read tags for %s: %s", resource_id, exc)
        return tags

    def _accounts(self, mgmt_id: str, ou_names: dict[str, str], root_id: str) -> list[dict[str, Any]]:
        accounts: list[dict[str, Any]] = []
        for acct in sorted(iter_accounts(self.org), key=lambda a: a["Name"]):
            if acct["Id"] == mgmt_id:
                continue
            if not is_active(acct):
                self.report.skipped_accounts.append(f"{acct['Name']} ({account_state(acct)})")
                continue
            parents = self.org.list_parents(ChildId=acct["Id"]).get("Parents", [])
            parent_id = parents[0]["Id"] if parents else root_id
            ou_name = ou_names.get(parent_id)
            if ou_name is None:
                self.report.skipped_accounts.append(f"{acct['Name']} (directly under the root)")
                self.report.todos.append(
                    f"Account '{acct['Name']}' sits directly under the organization root. Tarmac accounts "
                    "must belong to an OU: move it into one, then re-run the import."
                )
                continue
            entry: dict[str, Any] = {"name": acct["Name"], "email": acct["Email"], "ou": ou_name}
            tags = _clean_tags(self._tags(acct["Id"]), self.report.todos, f"account '{acct['Name']}'")
            if tags:
                entry["tags"] = tags
            # Brown-field accounts keep their existing network layout.
            entry["baseline"] = {"delete_default_vpc": False}
            accounts.append(entry)
            self.report.accounts.append(acct["Name"])
            self.imported_accounts[str(acct["Id"])] = str(acct["Name"])
        return accounts

    def _scps(self, root_id: str, ou_names: dict[str, str], config_dir: Path) -> list[dict[str, Any]]:
        policies: list[dict[str, Any]] = []
        used_files: set[str] = set()
        paginator = self.org.get_paginator("list_policies")
        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            for summary in sorted(page.get("Policies", []), key=lambda p: p["Name"]):
                if summary.get("AwsManaged") or summary["Name"] == _FULL_ACCESS_POLICY:
                    continue
                detail = self.org.describe_policy(PolicyId=summary["Id"])["Policy"]
                targets: list[str] = []
                for tpage in self.org.get_paginator("list_targets_for_policy").paginate(
                    PolicyId=summary["Id"]
                ):
                    for target in tpage.get("Targets", []):
                        if target["Type"] == "ROOT":
                            targets.append("root")
                        elif target["Type"] == "ORGANIZATIONAL_UNIT" and target["TargetId"] in ou_names:
                            targets.append(ou_names[target["TargetId"]])
                        else:
                            self.report.todos.append(
                                f"SCP '{summary['Name']}' is attached to {target['Type'].lower()} "
                                f"'{target.get('Name', target['TargetId'])}', which Tarmac cannot express. "
                                "That attachment is left alone."
                            )
                if not targets:
                    # Declaring it would attach it to the root and so change who it applies to.
                    self.report.todos.append(
                        f"SCP '{summary['Name']}' was not imported: it is not attached to the root or an OU. "
                        "Tarmac would attach it to the root. Add it to organization.yaml yourself if that is intended."
                    )
                    continue
                base = _slug(summary["Name"])
                filename, n = base, 2
                while filename in used_files:
                    filename, n = f"{base}-{n}", n + 1
                used_files.add(filename)
                rel = f"policies/scp/{filename}.json"
                target_path = self.project_root / rel
                target_path.parent.mkdir(parents=True, exist_ok=True)
                content = detail.get("Content", "{}")
                with contextlib.suppress(ValueError):
                    content = json.dumps(json.loads(content), indent=2)
                target_path.write_text(content + "\n", encoding="utf-8")
                self.report.files.append(target_path)
                policies.append(
                    {
                        "name": summary["Name"],
                        "description": summary.get("Description", "") or "",
                        "policy_file": rel,
                        "targets": sorted(set(targets)),
                    }
                )
                self.report.scps.append(summary["Name"])
        return policies

    def _trails(self) -> str | None:
        """Names of organization trails; returns the first for cloudtrail.trail_name."""
        try:
            trails = self.session_mgr.get_client("cloudtrail", region_name=self.region).describe_trails(
                includeShadowTrails=False
            )["trailList"]
        except _READ_ERRORS as exc:
            logger.debug("Could not list trails: %s", exc)
            return None
        names = [str(t["Name"]) for t in trails if t.get("IsOrganizationTrail")]
        self.report.existing_trails = names
        if names:
            self.report.todos.append(
                f"Organization trail(s) already exist: {', '.join(names)}. Tarmac creates its own trail and log "
                "bucket in phase 3, which AWS rejects while another organization trail exists. Delete or "
                "replace the old trail first, or disable CloudTrail management for this deployment."
            )
        return names[0] if names else None

    def _stack_prefix(self) -> str | None:
        """organization.name implied by Tarmac stacks that already exist, if any."""
        try:
            cfn = self.session_mgr.get_client("cloudformation", region_name=self.region)
            found: dict[str, int] = {}
            for page in cfn.get_paginator("list_stacks").paginate(StackStatusFilter=_LIVE_STACK_STATUSES):
                for summary in page.get("StackSummaries", []):
                    stack = str(summary.get("StackName", ""))
                    for suffix in TARMAC_STACK_SUFFIXES:
                        if stack.endswith(f"-{suffix}"):
                            self.report.existing_stacks.append(stack)
                            prefix = stack[: -len(suffix) - 1]
                            found[prefix] = found.get(prefix, 0) + 1
        except _READ_ERRORS as exc:
            logger.debug("Could not list stacks: %s", exc)
            return None
        return max(found, key=lambda k: found[k]) if found else None

    def _contacts(self, mgmt_email: str) -> dict[str, Any]:
        account = self.session_mgr.get_client("account")
        contacts: dict[str, Any] = {}
        for key, kind in (("billing", "BILLING"), ("operations", "OPERATIONS"), ("security", "SECURITY")):
            try:
                c = account.get_alternate_contact(AlternateContactType=kind)["AlternateContact"]
                contacts[key] = {
                    "name": c.get("Name") or "Unknown",
                    "title": c.get("Title") or "Unknown",
                    "email": c.get("EmailAddress") or mgmt_email,
                    "phone": c.get("PhoneNumber") or PLACEHOLDER_PHONE,
                }
            except _READ_ERRORS:
                contacts[key] = {
                    "name": f"{key.title()} Contact",
                    "title": f"{key.title()} Administrator",
                    "email": mgmt_email,
                    "phone": PLACEHOLDER_PHONE,
                }
                self.report.todos.append(
                    f"No {key} alternate contact is set on the management account. A placeholder using "
                    f"{mgmt_email} was written: replace the name, title and phone."
                )
        return contacts

    def _trusted_services(self) -> set[str]:
        try:
            return {
                str(s["ServicePrincipal"])
                for page in self.org.get_paginator("list_aws_service_access_for_organization").paginate()
                for s in page.get("EnabledServicePrincipals", [])
            }
        except _READ_ERRORS:
            return set()

    def _identity(self, config_dir: Path, account_names: dict[str, str]) -> dict[str, Any] | None:
        try:
            service = IdentityService(self.session_mgr, preferred_region=self.region)
            instance_arn, store_id = service.get_instance_details()
        except Exception as exc:
            logger.debug("No Identity Center: %s", exc)
            self.report.todos.append(
                "IAM Identity Center was not found, so identity.yaml holds placeholders. Enable it first, or "
                "skip phase 6."
            )
            return None
        sso, store = service.sso_client, service.identitystore_client
        try:
            users = self._list_users(store, store_id)
            groups = self._list_groups(store, store_id)
            permission_sets = self._permission_sets(sso, instance_arn, config_dir)
            for group in groups:
                group["members"] = self._members(store, store_id, group["_id"], users)
            self._assignments(sso, instance_arn, groups, permission_sets, account_names)
            for group in groups:
                group.pop("_id", None)
        except _READ_ERRORS as exc:
            self.report.todos.append(f"Identity Center could only be partly read ({exc}).")
            return None

        usernames = list(users.values())
        self.report.users = [u["username"] for u in usernames]
        self.report.groups = [g["name"] for g in groups]
        admin = next((u for u in usernames if "admin" in u["username"].lower()), None)
        breakglass = next((u for u in usernames if "break" in u["username"].lower()), None)
        rest = [u for u in usernames if u is not admin and u is not breakglass]
        if admin is None and rest:
            admin = rest.pop(0)
        if breakglass is None and rest:
            breakglass = rest.pop(0)
        for label, value in (("admin_user", admin), ("breakglass_user", breakglass)):
            if value is None:
                self.report.todos.append(
                    f"Identity Center has no user to use as identity_center.{label}: edit identity.yaml."
                )
        placeholder = {
            "username": "REPLACE-ME",
            "email": "replace-me@example.com",
            "first_name": "User",
            "last_name": "Account",
        }
        return {
            "identity_center": {
                "region": service.region,
                "admin_user": admin or placeholder,
                "breakglass_user": breakglass or placeholder,
                "additional_users": rest,
                "permission_sets": [p["definition"] for p in permission_sets.values()],
                "groups": groups,
            }
        }

    @staticmethod
    def _list_users(store: Any, store_id: str) -> dict[str, dict[str, str]]:
        users: dict[str, dict[str, str]] = {}
        for page in store.get_paginator("list_users").paginate(IdentityStoreId=store_id):
            for u in page.get("Users", []):
                emails = u.get("Emails") or []
                primary = next((e for e in emails if e.get("Primary")), emails[0] if emails else {})
                name = u.get("Name") or {}
                users[u["UserId"]] = {
                    "username": u["UserName"],
                    "email": primary.get("Value", ""),
                    "first_name": name.get("GivenName") or "User",
                    "last_name": name.get("FamilyName") or "Account",
                }
        return users

    @staticmethod
    def _list_groups(store: Any, store_id: str) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        for page in store.get_paginator("list_groups").paginate(IdentityStoreId=store_id):
            for g in page.get("Groups", []):
                groups.append(
                    {
                        "_id": g["GroupId"],
                        "name": g["DisplayName"],
                        "description": g.get("Description", "") or "",
                        "members": [],
                        "assignments": [],
                    }
                )
        return sorted(groups, key=lambda g: g["name"])

    @staticmethod
    def _members(store: Any, store_id: str, group_id: str, users: dict[str, dict[str, str]]) -> list[str]:
        members: list[str] = []
        for page in store.get_paginator("list_group_memberships").paginate(
            IdentityStoreId=store_id, GroupId=group_id
        ):
            for m in page.get("GroupMemberships", []):
                user = users.get(m.get("MemberId", {}).get("UserId", ""))
                if user:
                    members.append(user["username"])
        return sorted(members)

    def _permission_sets(self, sso: Any, instance_arn: str, config_dir: Path) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for page in sso.get_paginator("list_permission_sets").paginate(InstanceArn=instance_arn):
            for arn in page.get("PermissionSets", []):
                ps = sso.describe_permission_set(InstanceArn=instance_arn, PermissionSetArn=arn)[
                    "PermissionSet"
                ]
                managed = [
                    p["Arn"]
                    for mp in sso.get_paginator("list_managed_policies_in_permission_set").paginate(
                        InstanceArn=instance_arn, PermissionSetArn=arn
                    )
                    for p in mp.get("AttachedManagedPolicies", [])
                ]
                definition: dict[str, Any] = {
                    "name": ps["Name"],
                    "description": ps.get("Description", "") or "",
                    "session_duration": ps.get("SessionDuration", "PT1H"),
                    "managed_policies": managed,
                }
                inline = sso.get_inline_policy_for_permission_set(
                    InstanceArn=instance_arn, PermissionSetArn=arn
                ).get("InlinePolicy")
                if inline:
                    rel = f"policies/permission-sets/{_slug(ps['Name'])}.json"
                    path = self.project_root / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(json.loads(inline), indent=2) + "\n", encoding="utf-8")
                    self.report.files.append(path)
                    definition["inline_policy_file"] = rel
                result[arn] = {"definition": definition}
                self.report.permission_sets.append(ps["Name"])
        return result

    def _assignments(
        self,
        sso: Any,
        instance_arn: str,
        groups: list[dict[str, Any]],
        permission_sets: dict[str, dict[str, Any]],
        account_names: dict[str, str],
    ) -> None:
        """Group assignments on imported accounts. Anything tarmac cannot express is counted and reported."""
        by_id = {g["_id"]: g for g in groups}
        outside: dict[str, int] = {}  # assignments to accounts that are not in accounts.yaml
        user_assignments = 0
        for ps_arn, ps in permission_sets.items():
            for apage in sso.get_paginator("list_accounts_for_provisioned_permission_set").paginate(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn
            ):
                for account_id in apage.get("AccountIds", []):
                    imported = account_id in account_names
                    for ppage in sso.get_paginator("list_account_assignments").paginate(
                        InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=ps_arn
                    ):
                        for a in ppage.get("AccountAssignments", []):
                            if a.get("PrincipalType") != "GROUP":
                                user_assignments += 1
                            elif not imported:
                                outside[account_id] = outside.get(account_id, 0) + 1
                            elif (group := by_id.get(a["PrincipalId"])) is not None:
                                _add_assignment(group, ps["definition"]["name"], account_names[account_id])
        if outside:
            self.report.todos.append(
                f"{sum(outside.values())} group assignment(s) on {len(outside)} account(s) that are not in "
                f"accounts.yaml were left out ({', '.join(sorted(outside))}), usually the management account. "
                "Tarmac only assigns permission sets on the member accounts it manages."
            )
        if user_assignments:
            self.report.todos.append(
                f"{user_assignments} permission-set assignment(s) made directly to users were left out: tarmac "
                "assigns through groups only."
            )

    def discover_and_write(
        self,
        config_dir: Path,
        *,
        name: str | None = None,
        include_identity: bool = True,
        force: bool = False,
    ) -> ImportReport:
        """Inspect the organization and write organization/accounts/identity YAML into config_dir."""
        targets = [config_dir / f"{base}.yaml" for base in ("organization", "accounts", "identity")]
        existing = [p for p in targets if p.exists()]
        if existing and not force:
            raise FileExistsError(", ".join(p.name for p in existing))
        config_dir.mkdir(parents=True, exist_ok=True)
        # Same convention as `tarmac init --with-templates`: policy files sit beside a "config" directory.
        self.project_root = config_dir.parent if config_dir.name == "config" else config_dir

        org = self._organization()
        mgmt_id = str(org["MasterAccountId"])
        mgmt_email = str(org["MasterAccountEmail"])
        root_id = self.org.list_roots()["Roots"][0]["Id"]

        ou_names: dict[str, str] = {}
        ou_structure = self._ou_tree(root_id, ou_names)
        self.report.ou_count = len(ou_names)

        stack_prefix = self._stack_prefix()
        org_name = name or stack_prefix or _slug(mgmt_email.split("@", 1)[1].split(".", 1)[0])
        org_name = org_name[:32]
        if not name and not stack_prefix:
            self.report.todos.append(
                f"organization.name was set to '{org_name}' (from the management email domain). Tarmac names "
                "its CloudFormation stacks after it and it must not change after the first deploy."
            )
        self.report.organization_name = org_name

        accounts = self._accounts(mgmt_id, ou_names, root_id)
        scps = self._scps(root_id, ou_names, config_dir)
        trail_name = self._trails()
        contacts = self._contacts(mgmt_email)
        trusted = self._trusted_services()

        by_lower = {a["name"].lower(): a["name"] for a in accounts}
        security_account = by_lower.get("audit")
        log_account = by_lower.get("log-archive")
        deploy_account = by_lower.get("deployment")

        organization: dict[str, Any] = {
            "organization": {
                "name": org_name,
                "domain": mgmt_email.split("@", 1)[1],
                "primary_region": self.region,
                "additional_regions": [],
                "delete_default_vpc": False,
            },
            "contacts": contacts,
            "root_access_management": {
                "enabled": "iam.amazonaws.com" in trusted,
                "enable_root_credentials_management": "iam.amazonaws.com" in trusted,
                "enable_root_sessions": "iam.amazonaws.com" in trusted,
                "delegated_admin_account": security_account,
            },
            "service_control_policies": {"enabled": bool(scps), "policies": scps},
            "ou_structure": ou_structure,
            "cloudtrail": {
                "trail_name": trail_name or "organization-trail",
                "log_archive_account": log_account,
            },
            "terraform_backend": {"account": deploy_account},
            "security_services": {"delegated_account": security_account or "audit"},
        }
        org_tags = _clean_tags(self._tags(root_id), self.report.todos, "the organization root")
        if org_tags:
            organization["tags"] = org_tags

        for label, value in (
            ("Audit", security_account),
            ("Log-Archive", log_account),
            ("Deployment", deploy_account),
        ):
            if value is None:
                self.report.todos.append(
                    f"No account named '{label}' exists. Tarmac expects one for its security, logging or "
                    f"Terraform backend role: add it to accounts.yaml, or change the matching setting in "
                    "organization.yaml."
                )

        identity = self._identity(config_dir, self.imported_accounts) if include_identity else None

        self._dump(
            config_dir / "organization.yaml",
            organization,
            "Organization configuration imported from a live AWS Organization",
        )
        self._dump(
            config_dir / "accounts.yaml",
            {"accounts": accounts},
            "Accounts imported from a live AWS Organization",
        )
        if identity is not None:
            self._dump(
                config_dir / "identity.yaml",
                identity,
                "Identity Center configuration imported from a live instance",
            )
        elif include_identity:
            self._dump(config_dir / "identity.yaml", _identity_placeholder(), "Identity Center placeholders")
        else:
            self._dump(
                config_dir / "identity.yaml",
                _identity_placeholder(),
                "Identity Center placeholders (import skipped)",
            )

        self._validate(config_dir)
        return self.report

    def _dump(self, path: Path, data: dict[str, Any], title: str) -> None:
        header = (
            f"# {title}.\n"
            "# Review before deploying: Tarmac will reconcile the organization to match this file.\n\n"
        )
        path.write_text(
            header + yaml.safe_dump(data, sort_keys=False, default_flow_style=False), encoding="utf-8"
        )
        self.report.files.append(path)

    def _validate(self, config_dir: Path) -> None:
        with contextlib.chdir(self.project_root):
            bundle, errors = load_all_configs(config_dir.resolve())
            self.report.validation_errors = list(errors)
            if bundle is not None:
                self.report.validation_errors.extend(bundle.validate_cross_references())


def _add_assignment(group: dict[str, Any], permission_set: str, account: str) -> None:
    for entry in group["assignments"]:
        if entry["permission_set"] == permission_set:
            if account not in entry["accounts"]:
                entry["accounts"].append(account)
                entry["accounts"].sort()
            return
    group["assignments"].append({"permission_set": permission_set, "accounts": [account]})


def _identity_placeholder() -> dict[str, Any]:
    user = {
        "username": "REPLACE-ME",
        "email": "replace-me@example.com",
        "first_name": "User",
        "last_name": "Account",
    }
    return {
        "identity_center": {
            "admin_user": user,
            "breakglass_user": dict(user, username="REPLACE-ME-TOO"),
            "permission_sets": [],
            "groups": [],
        }
    }
