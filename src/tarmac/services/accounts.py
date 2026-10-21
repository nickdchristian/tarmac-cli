"""Declarative AWS Account Management and Provisioning Service."""

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Literal

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import AccountBaselineConfig, AccountDef, AccountsCatalog
from ..core.exceptions import AWS_ERRORS, AccountProvisioningError, GovernanceError, aws_error_message
from ..core.models import (
    STATUS_SUSPENDED,
    TAG_MANAGED_BY,
    TAG_STATUS,
    AccountPlanItem,
    AccountProvisionResult,
    AccountSuspensionResult,
)
from ..core.org_accounts import account_state, is_active, is_closed, iter_accounts
from ..core.placeholders import is_placeholder_email

logger = logging.getLogger(__name__)


def _make_result(
    acct: AccountDef,
    account_id: str = "",
    ou_id: str = "",
    action: str = "FAILED",
    status: str = "FAILED",
) -> AccountProvisionResult:
    return AccountProvisionResult(
        name=acct.name,
        email=acct.email,
        account_id=account_id,
        ou_name=acct.ou,
        ou_id=ou_id,
        action_taken=action,
        status=status,
    )


class AccountService:
    """Provisions, organizes, and manages member accounts across the organization."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr: AwsSessionManager = session_mgr
        self.org_client: Any = session_mgr.get_client("organizations")
        self._parent_cache: dict[str, str | None] = {}
        self._tags_cache: dict[str, dict[str, str]] = {}

    def list_all_accounts(self) -> list[dict[str, Any]]:
        """Fetch all accounts across all pages from AWS Organizations."""
        try:
            return list(iter_accounts(self.org_client))
        except AWS_ERRORS as e:
            raise AccountProvisioningError("Failed to list existing AWS accounts", details=str(e)) from e

    def list_existing_accounts(self) -> dict[str, dict[str, Any]]:
        """List all accounts in the organization. Returns {AccountName: AccountDict}.

        If an ACTIVE and a SUSPENDED account share the same name, the ACTIVE account takes precedence.
        """
        all_accts = self.list_all_accounts()
        accounts: dict[str, dict[str, Any]] = {}
        for acct in all_accts:
            name = acct["Name"]
            if name in accounts and is_active(accounts[name]) and not is_active(acct):
                continue
            accounts[name] = acct
        return accounts

    def find_existing_account(
        self, name: str, existing: dict[str, dict[str, Any]], email: str | None = None
    ) -> dict[str, Any] | None:
        """Find an existing account, preferring the email (AWS's unique key) over the name.

        Falls back to a case- and separator-insensitive name match. Callers that adopt the result
        should check `email_conflicts` first, because a name match with a different email is a
        different account.
        """
        if email:
            wanted = email.strip().lower()
            for v in existing.values():
                if str(v.get("Email", "")).strip().lower() == wanted:
                    return v
        if name in existing:
            return existing[name]
        norm = normalize_account_name(name)
        for k, v in existing.items():
            if normalize_account_name(k) == norm:
                return v
        return None

    @staticmethod
    def email_conflicts(existing_acct: dict[str, Any], email: str) -> bool:
        """True when an existing account's email is known and differs from the declared one."""
        current = str(existing_acct.get("Email", "")).strip().lower()
        return bool(current) and current != email.strip().lower()

    def get_account_parent_id(self, account_id: str) -> str | None:
        """Fetch the current parent (OU or Root) ID for an account."""
        if account_id in self._parent_cache:
            return self._parent_cache[account_id]
        try:
            resp = self.org_client.list_parents(ChildId=account_id)
            parents = resp.get("Parents", [])
            parent_id: str | None = parents[0]["Id"] if parents else None
            self._parent_cache[account_id] = parent_id
            return parent_id
        except ClientError as e:
            logger.warning("Could not query parent for account %s: %s", account_id, e)
            return None

    def _detect_removed_accounts(
        self,
        catalog: AccountsCatalog,
        ou_map: dict[str, str],
        existing: dict[str, dict[str, Any]],
    ) -> list[AccountPlanItem]:
        """Detect active accounts previously managed by Tarmac that are omitted from the catalog,
        and report already suspended or quarantined accounts."""
        caller = self.session_mgr.get_caller_identity()
        mgmt_id = caller.get("Account", "")
        declared_names = {normalize_account_name(a.name) for a in catalog.accounts}
        suspended_ou_id = ou_map.get("Suspended")

        suspend_items: list[AccountPlanItem] = []
        for name, acct in existing.items():
            if normalize_account_name(name) in declared_names:
                continue
            acct_id = str(acct["Id"])
            if acct_id == mgmt_id:
                continue

            current_parent = self.get_account_parent_id(acct_id)

            is_aws_suspended = is_closed(acct)
            is_in_suspended_ou = bool(suspended_ou_id and current_parent == suspended_ou_id)

            action: Literal["CREATE", "MOVE", "NOOP", "SUSPEND", "SUSPENDED"]
            if is_aws_suspended or is_in_suspended_ou:
                action = "SUSPENDED"
                reason = (
                    f"Account ({acct_id}) is SUSPENDED (closed) in AWS Organizations"
                    if is_aws_suspended
                    else f"Account ({acct_id}) is quarantined in Suspended OU"
                )
            else:
                if not catalog.quarantine_removed_accounts:
                    continue
                tags = self.get_account_tags(acct_id)
                if tags.get(TAG_MANAGED_BY) != "tarmac" and tags.get("ManagedBy") != "tarmac":
                    continue
                action = "SUSPEND"
                reason = (
                    "Account was removed from accounts.yaml; will be quarantined into Suspended OU and tagged"
                )

            suspend_items.append(
                AccountPlanItem(
                    name=name,
                    email=str(acct.get("Email", "")),
                    ou="Suspended",
                    action=action,
                    account_id=acct_id,
                    reason=reason,
                    baseline=AccountBaselineConfig(),
                )
            )
        return suspend_items

    def plan(self, catalog: AccountsCatalog, ou_map: dict[str, str]) -> list[AccountPlanItem]:
        """Generate an execution plan comparing declared accounts with actual AWS state."""
        existing = self.list_existing_accounts()
        plan_items: list[AccountPlanItem] = []

        for acct_def in catalog.accounts:
            name = acct_def.name
            target_ou_id = ou_map.get(acct_def.ou)

            current_acct = self.find_existing_account(name, existing, email=acct_def.email)
            action: Literal["CREATE", "MOVE", "NOOP", "SUSPEND", "SUSPENDED"]
            if current_acct:
                acct_id = current_acct["Id"]
                if is_closed(current_acct):
                    action = "SUSPENDED"
                    reason = f"Account declared in accounts.yaml but is SUSPENDED (closed) in AWS Organizations ({acct_id})"
                else:
                    current_parent = self.get_account_parent_id(acct_id)
                    if current_parent != target_ou_id:
                        action = "MOVE"
                        reason = (
                            f"Account exists ({acct_id}) but in wrong OU "
                            f"(current: {current_parent}, target: {target_ou_id})"
                        )
                    else:
                        action = "NOOP"
                        reason = f"Account exists ({acct_id}) and is correctly placed in {acct_def.ou}"
            else:
                acct_id = None
                action = "CREATE"
                reason = f"Account does not exist; will be created and moved to {acct_def.ou}"

            plan_items.append(
                AccountPlanItem(
                    name=name,
                    email=acct_def.email,
                    ou=acct_def.ou,
                    action=action,
                    account_id=acct_id,
                    reason=reason,
                    baseline=acct_def.baseline,
                )
            )

        plan_items.extend(self._detect_removed_accounts(catalog, ou_map, existing))
        return plan_items

    def suspend_account(
        self,
        account_id: str,
        account_name: str,
        suspended_ou_id: str | None,
        dry_run: bool = False,
        close: bool = False,
    ) -> AccountSuspensionResult:
        """Suspend an account by moving it to the Suspended OU, tagging it, and optionally closing it."""
        if not suspended_ou_id:
            raise GovernanceError(
                "No 'Suspended' OU exists in the organization, so the account cannot be quarantined.",
                details="Declare a 'Suspended' OU in organization.yaml and run 'tarmac deploy --phase 2' first.",
            )

        if dry_run:
            audit(
                "suspend",
                f"account:{account_id}",
                Outcome.SUCCEEDED,
                f"Would move account '{account_name}' ({account_id}) to the Suspended OU"
                + (" and close it" if close else ""),
                dry_run=True,
                account_id=account_id,
                close=close,
            )
            return AccountSuspensionResult(
                name=account_name,
                account_id=account_id,
                tags_updated=True,
                closed=close,
                status="SIMULATED",
                message=f"[DRY-RUN] Would quarantine {account_name} in Suspended OU and tag as suspended",
            )

        moved = False
        if suspended_ou_id:
            moved = self.move_account_if_needed(account_id, account_name, suspended_ou_id)

        tags_to_apply = {
            TAG_MANAGED_BY: "tarmac",
            TAG_STATUS: STATUS_SUSPENDED,
            "Status": "Suspended",
        }
        tags_updated = self.sync_account_tags(account_id, account_name, tags_to_apply)

        closed = False
        close_error: str | None = None
        if close:
            try:
                self.org_client.close_account(AccountId=account_id)
                closed = True
                audit(
                    "close",
                    f"account:{account_id}",
                    Outcome.SUCCEEDED,
                    f"Requested closure of account '{account_name}' ({account_id}); "
                    "AWS suspends it and removes it after 90 days",
                    account_id=account_id,
                )
            except ClientError as e:
                close_error = e.response.get("Error", {}).get("Message", str(e))
                audit(
                    "close",
                    f"account:{account_id}",
                    Outcome.FAILED,
                    f"Could not close account '{account_name}' ({account_id}): {close_error}",
                    account_id=account_id,
                )

        msg = (
            f"Account {account_name} moved to Suspended OU and tagged."
            if moved
            else f"Account {account_name} already in Suspended OU and tagged."
        )
        if closed:
            msg += " Account closure initiated."
        elif close and close_error:
            msg += f" Account closure failed: {close_error}"

        return AccountSuspensionResult(
            name=account_name,
            account_id=account_id,
            tags_updated=tags_updated,
            closed=closed,
            status="SUCCEEDED" if (not close or closed) else "CLOSE_FAILED",
            message=msg,
        )

    def move_account_if_needed(self, account_id: str, account_name: str, target_ou_id: str) -> bool:
        """Move account to target OU if not already placed there. Returns True if moved."""
        current_parent = self.get_account_parent_id(account_id)
        if current_parent == target_ou_id:
            logger.debug(
                "Account '%s' (%s) is already in target OU %s", account_name, account_id, target_ou_id
            )
            return False

        if not current_parent:
            raise AccountProvisioningError(
                f"Cannot move account '{account_name}': unable to determine current parent."
            )

        try:
            self.org_client.move_account(
                AccountId=account_id,
                SourceParentId=current_parent,
                DestinationParentId=target_ou_id,
            )
            self._parent_cache[account_id] = target_ou_id
            audit(
                "move",
                f"account:{account_id}",
                Outcome.SUCCEEDED,
                f"Moved account '{account_name}' ({account_id}) from {current_parent} to OU {target_ou_id}",
                account_id=account_id,
                from_parent=current_parent,
                to_parent=target_ou_id,
            )
            return True
        except ClientError as e:
            audit(
                "move",
                f"account:{account_id}",
                Outcome.FAILED,
                f"Could not move account '{account_name}' ({account_id}) to OU {target_ou_id}: "
                f"{aws_error_message(e)}",
                account_id=account_id,
            )
            raise AccountProvisioningError(
                f"Failed to move account '{account_name}' to OU '{target_ou_id}'",
                details=aws_error_message(e),
            ) from e

    def get_account_tags(self, account_id: str) -> dict[str, str]:
        """Fetch current tags for an account from AWS Organizations."""
        if account_id in self._tags_cache:
            return dict(self._tags_cache[account_id])
        tags: dict[str, str] = {}
        try:
            paginator = self.org_client.get_paginator("list_tags_for_resource")
            for page in paginator.paginate(ResourceId=account_id):
                for tag in page.get("Tags", []):
                    tags[tag["Key"]] = str(tag["Value"])
            self._tags_cache[account_id] = dict(tags)
            return tags
        except ClientError as e:
            logger.warning("Could not list tags for account %s: %s", account_id, e)
            return tags

    def sync_account_tags(
        self,
        account_id: str,
        account_name: str,
        declared_tags: dict[str, str],
    ) -> bool:
        """Reconcile declared tags on an account in AWS Organizations. Returns True if tags were updated."""
        if not declared_tags:
            return False

        current_tags = self.get_account_tags(account_id)
        tags_to_apply = {k: str(v) for k, v in declared_tags.items() if current_tags.get(k) != str(v)}

        if not tags_to_apply:
            logger.debug("Tags for account '%s' (%s) are up-to-date.", account_name, account_id)
            return False

        try:
            tag_list = [{"Key": k, "Value": v} for k, v in tags_to_apply.items()]
            self.org_client.tag_resource(ResourceId=account_id, Tags=tag_list)
            merged_tags = dict(current_tags)
            merged_tags.update(tags_to_apply)
            self._tags_cache[account_id] = merged_tags
            audit(
                "tag",
                f"account:{account_id}",
                Outcome.SUCCEEDED,
                f"Applied {len(tags_to_apply)} tag(s) to account '{account_name}' ({account_id})",
                account_id=account_id,
                tags=tags_to_apply,
            )
            return True
        except ClientError as e:
            msg = aws_error_message(e)
            if "pattern" in msg.lower():
                msg += (
                    " (Note: AWS Organizations tags only permit letters, numbers, spaces, "
                    "and _ . : / = + - @; commas and other punctuation are not allowed)"
                )
            audit(
                "tag",
                f"account:{account_id}",
                Outcome.FAILED,
                f"Could not tag account '{account_name}' ({account_id}): {msg}",
                account_id=account_id,
            )
            raise AccountProvisioningError(
                f"Failed to apply tags to account '{account_name}' ({account_id})",
                details=msg,
            ) from e

    def _describe_create_status(self, request_id: str) -> tuple[str, str, str]:
        """Fetch creation state, account ID, and failure reason from AWS."""
        resp = self.org_client.describe_create_account_status(CreateAccountRequestId=request_id)
        status = resp["CreateAccountStatus"]
        return (
            str(status.get("State", "")),
            str(status.get("AccountId", "")),
            str(status.get("FailureReason", "")),
        )

    def provision_accounts(
        self,
        accounts: list[AccountDef],
        ou_map: dict[str, str],
        poll_delay_sec: int = 15,
        max_poll_attempts: int = 40,
        org_tags: dict[str, str] | None = None,
    ) -> list[AccountProvisionResult]:
        """Idempotently create and reconcile multiple member accounts in batch.

        Dispatches all new account creation requests in parallel, then polls
        in-flight creation statuses in a unified polling loop. This minimizes
        total wait time when provisioning multiple accounts simultaneously.
        """
        existing = self.list_existing_accounts()
        results: list[AccountProvisionResult | None] = [None] * len(accounts)
        pending_creations: list[dict[str, Any]] = []
        failures: list[str] = []

        for idx, acct_def in enumerate(accounts):
            name, email = acct_def.name, acct_def.email
            target_ou_id = ou_map.get(acct_def.ou)
            desired_tags = {**(org_tags or {}), **acct_def.tags}

            if not target_ou_id:
                logger.warning("Target OU '%s' not found for account '%s'", acct_def.ou, name)
                results[idx] = _make_result(acct_def)
                continue

            existing_acct = self.find_existing_account(name, existing, email=email)
            if existing_acct and self.email_conflicts(existing_acct, email):
                msg = (
                    f"Account '{name}': an account with that name exists ({existing_acct['Id']}) but its email "
                    f"differs from the declared '{email}'. Refusing to adopt or move it."
                )
                logger.error(msg)
                failures.append(msg)
                continue
            if existing_acct:
                acct_id = str(existing_acct["Id"])
                if is_closed(existing_acct):
                    logger.warning("Account '%s' (%s) is SUSPENDED; skipping.", name, acct_id)
                    results[idx] = _make_result(
                        acct_def, acct_id, target_ou_id, "SUSPENDED_SKIPPED", "SKIPPED"
                    )
                    continue

                logger.debug("Account '%s' exists (ID: %s)", name, acct_id)
                moved = self.move_account_if_needed(acct_id, name, target_ou_id)
                tags_updated = self.sync_account_tags(acct_id, name, desired_tags)
                action = "MOVED" if moved else ("TAGGED" if tags_updated else "REUSED")
                results[idx] = _make_result(acct_def, acct_id, target_ou_id, action, "SUCCEEDED")
                continue

            if is_placeholder_email(email):
                msg = (
                    f"Account '{name}': refusing to create an account with the sample email '{email}'. "
                    "AWS never lets an email be reused once an account has used it, even after the account "
                    "is closed. Set a real, unique address in accounts.yaml."
                )
                audit("create", f"account:{name}", Outcome.FAILED, msg, email=email)
                failures.append(msg)
                continue

            try:
                create_params: dict[str, Any] = {
                    "Email": email,
                    "AccountName": name,
                    "RoleName": "OrganizationAccountAccessRole",
                }
                if desired_tags:
                    create_params["Tags"] = [{"Key": k, "Value": str(v)} for k, v in desired_tags.items()]
                resp = self.org_client.create_account(**create_params)
                audit(
                    "create",
                    f"account:{name}",
                    Outcome.SUCCEEDED,
                    f"Requested creation of account '{name}' ({email}); waiting for AWS to finish",
                    email=email,
                    ou_id=target_ou_id,
                    request_id=str(resp["CreateAccountStatus"]["Id"]),
                )
                pending_creations.append(
                    {
                        "index": idx,
                        "acct_def": acct_def,
                        "desired_tags": desired_tags,
                        "target_ou_id": target_ou_id,
                        "request_id": str(resp["CreateAccountStatus"]["Id"]),
                    }
                )
            except ClientError as e:
                detail = aws_error_message(e)
                audit(
                    "create",
                    f"account:{name}",
                    Outcome.FAILED,
                    f"Could not request creation of account '{name}': {detail}",
                    email=email,
                )
                failures.append(f"Failed to request creation of account '{name}': {detail}")

        if pending_creations:
            self._poll_pending_creations(
                pending_creations, results, failures, poll_delay_sec, max_poll_attempts
            )

        if failures:
            raise AccountProvisioningError(
                f"{len(failures)} account(s) could not be provisioned; the others were completed.",
                details="\n".join(failures),
            )

        return [r for r in results if r is not None]

    def _poll_pending_creations(
        self,
        pending_creations: list[dict[str, Any]],
        results: list[AccountProvisionResult | None],
        failures: list[str],
        poll_delay_sec: int,
        max_poll_attempts: int,
    ) -> None:
        """Poll in-flight CreateAccount requests, finishing (move + tag) each as it succeeds.

        Per-account problems are appended to `failures` so one bad account never abandons the rest.
        """
        in_flight = list(pending_creations)
        for attempt in range(1, max_poll_attempts + 1):
            if not in_flight:
                break
            time.sleep(poll_delay_sec)
            in_flight = [
                item
                for item in in_flight
                if self._poll_one_creation(item, attempt, max_poll_attempts, results, failures)
            ]

        if in_flight:
            timed_out_names = [it["acct_def"].name for it in in_flight]
            failures.append(f"Timed out waiting for account creation for: {', '.join(timed_out_names)}")

    def _poll_one_creation(
        self,
        item: dict[str, Any],
        attempt: int,
        max_attempts: int,
        results: list[AccountProvisionResult | None],
        failures: list[str],
    ) -> bool:
        """Check one request. Returns True if it is still pending and should be polled again."""
        name = item["acct_def"].name
        try:
            state, new_id, reason = self._describe_create_status(item["request_id"])
        except ClientError as e:
            logger.warning("Error querying creation status for '%s': %s", name, e)
            return True
        logger.info("Creation status for '%s': %s (attempt %d/%d)", name, state, attempt, max_attempts)

        if state == "IN_PROGRESS":
            return True
        if state != "SUCCEEDED":
            failures.append(
                f"Account creation for '{name}' failed with status: {state} ({reason or 'no reason given'})"
            )
            return False
        if not new_id:
            failures.append(f"Account creation for '{name}' succeeded but AccountId was not returned.")
            return False

        try:
            self.move_account_if_needed(new_id, name, item["target_ou_id"])
            tags_to_sync = item.get("desired_tags", item["acct_def"].tags)
            self.sync_account_tags(new_id, name, tags_to_sync)
        except ClientError as e:
            logger.warning("Error finishing account '%s' (%s): %s", name, new_id, e)
            failures.append(f"Account '{name}' ({new_id}) was created but could not be finished: {e}")
            return False
        results[item["index"]] = _make_result(
            item["acct_def"], new_id, item["target_ou_id"], "CREATED", "SUCCEEDED"
        )
        return False

    def export_inventory(self, catalog: AccountsCatalog, ou_map: dict[str, str], output_dir: Path) -> Path:
        """Export current organization account inventory to JSON and environment shell script."""
        existing = self.list_existing_accounts()
        inventory: list[dict[str, Any]] = []
        env_vars: dict[str, str] = {}

        output_dir.mkdir(parents=True, exist_ok=True)

        for acct_def in catalog.accounts:
            name = acct_def.name
            acct_data = self.find_existing_account(name, existing)
            acct_id = acct_data["Id"] if acct_data else None
            status = account_state(acct_data) if acct_data else "NOT_PROVISIONED"
            ou_id = ou_map.get(acct_def.ou, "")

            entry = {
                "name": name,
                "email": acct_def.email,
                "ou_name": acct_def.ou,
                "ou_id": ou_id,
                "account_id": acct_id,
                "status": status,
                "tags": acct_def.tags,
            }
            inventory.append(entry)

            if acct_id:
                safe_name = re.sub(r"[^A-Z0-9_]+", "_", name.upper()).strip("_") or "ACCOUNT"
                if safe_name[0].isdigit():
                    safe_name = f"ACCT_{safe_name}"
                env_vars[f"{safe_name}_ACCOUNT_ID"] = str(acct_id)

        declared_names = {normalize_account_name(a.name) for a in catalog.accounts}
        for name, acct_data in existing.items():
            if normalize_account_name(name) in declared_names:
                continue
            acct_id = str(acct_data["Id"])
            status = account_state(acct_data)
            parent_id = self.get_account_parent_id(acct_id) or ""
            ou_name = next((k for k, v in ou_map.items() if v == parent_id), "Unknown")
            if parent_id == ou_map.get("Suspended"):
                ou_name = "Suspended"
            inventory.append(
                {
                    "name": name,
                    "email": str(acct_data.get("Email", "")),
                    "ou_name": ou_name,
                    "ou_id": parent_id,
                    "account_id": acct_id,
                    "status": status,
                    "tags": self.get_account_tags(acct_id),
                }
            )

        json_path = output_dir / "accounts.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2)

        env_path = output_dir / "accounts.env"
        with env_path.open("w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n# Generated by tarmac deploy (phase 4); do not edit\n")
            for k, v in env_vars.items():
                escaped_v = (
                    str(v).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
                )
                f.write(f'export {k}="{escaped_v}"\n')

        logger.info("Exported account inventory to %s and %s", json_path, env_path)
        return json_path
