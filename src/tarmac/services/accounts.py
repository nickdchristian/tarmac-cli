"""Declarative AWS Account Management and Provisioning Service."""

import json
import logging
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import AccountBaselineConfig, AccountDef, AccountsCatalog
from ..core.exceptions import AccountProvisioningError
from ..core.models import (
    STATUS_SUSPENDED,
    TAG_MANAGED_BY,
    TAG_STATUS,
    AccountPlanItem,
    AccountProvisionResult,
    AccountSuspensionResult,
)

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

    def list_all_accounts(self) -> list[dict[str, Any]]:
        """Fetch all accounts across all pages from AWS Organizations."""
        accounts: list[dict[str, Any]] = []
        try:
            paginator = self.org_client.get_paginator("list_accounts")
            for page in paginator.paginate():
                acct_list = page.get("Accounts", [])
                if isinstance(acct_list, list):
                    accounts.extend([a for a in acct_list if isinstance(a, dict)])
            if accounts:
                return accounts
        except (AttributeError, ClientError, KeyError):
            pass
        try:
            resp = self.org_client.list_accounts()
            if isinstance(resp, dict):
                return [a for a in resp.get("Accounts", []) if isinstance(a, dict)]
            return []
        except Exception as e:
            raise AccountProvisioningError("Failed to list existing AWS accounts", details=str(e)) from e

    def list_existing_accounts(self) -> dict[str, dict[str, Any]]:
        """List all accounts in the organization. Returns {AccountName: AccountDict}.

        If an ACTIVE and a SUSPENDED account share the same name, the ACTIVE account takes precedence.
        """
        all_accts = self.list_all_accounts()
        accounts: dict[str, dict[str, Any]] = {}
        for acct in all_accts:
            name = acct["Name"]
            if (
                name in accounts
                and accounts[name].get("Status") == "ACTIVE"
                and acct.get("Status") != "ACTIVE"
            ):
                continue
            accounts[name] = acct
        return accounts

    def find_existing_account(self, name: str, existing: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
        """Find account by name with case- and separator-insensitive fallback."""
        if name in existing:
            return existing[name]
        norm = normalize_account_name(name)
        for k, v in existing.items():
            if normalize_account_name(k) == norm:
                return v
        return None

    def get_account_parent_id(self, account_id: str) -> str | None:
        """Fetch the current parent (OU or Root) ID for an account."""
        try:
            resp = self.org_client.list_parents(ChildId=account_id)
            parents = resp.get("Parents", [])
            return parents[0]["Id"] if parents else None
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

            status = acct.get("Status", "ACTIVE")
            current_parent = self.get_account_parent_id(acct_id)

            is_aws_suspended = status == "SUSPENDED"
            is_in_suspended_ou = bool(suspended_ou_id and current_parent == suspended_ou_id)

            if is_aws_suspended or is_in_suspended_ou:
                action = "SUSPENDED"
                reason = (
                    f"Account ({acct_id}) is SUSPENDED (closed) in AWS Organizations"
                    if is_aws_suspended
                    else f"Account ({acct_id}) is quarantined in Suspended OU"
                )
            else:
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

            current_acct = self.find_existing_account(name, existing)
            if current_acct:
                acct_id = current_acct["Id"]
                acct_status = current_acct.get("Status", "ACTIVE")

                if acct_status == "SUSPENDED":
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
        if dry_run:
            logger.info(
                "[DRY-RUN] Would suspend account '%s' (%s) into Suspended OU (close=%s)",
                account_name,
                account_id,
                close,
            )
            return AccountSuspensionResult(
                name=account_name,
                account_id=account_id,
                moved_to_ou=suspended_ou_id,
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
        tags_updated = self.sync_account_tags(account_id, account_name, tags_to_apply, dry_run=dry_run)

        closed = False
        if close:
            try:
                self.org_client.close_account(AccountId=account_id)
                closed = True
                logger.info("Closed AWS account '%s' (%s) via Organizations API.", account_name, account_id)
            except ClientError as e:
                logger.warning("Could not close account '%s' (%s): %s", account_name, account_id, e)

        msg = (
            f"Account {account_name} moved to Suspended OU and tagged."
            if moved
            else f"Account {account_name} already in Suspended OU and tagged."
        )
        if closed:
            msg += " Account closure initiated."

        return AccountSuspensionResult(
            name=account_name,
            account_id=account_id,
            moved_to_ou=suspended_ou_id,
            tags_updated=tags_updated,
            closed=closed,
            status="SUCCEEDED",
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

        logger.info(
            "Moving account '%s' from parent %s to OU %s...", account_name, current_parent, target_ou_id
        )
        try:
            self.org_client.move_account(
                AccountId=account_id,
                SourceParentId=current_parent,
                DestinationParentId=target_ou_id,
            )
            logger.info("Moved account '%s' to target OU %s", account_name, target_ou_id)
            return True
        except ClientError as e:
            raise AccountProvisioningError(
                f"Failed to move account '{account_name}' to OU '{target_ou_id}'",
                details=e.response["Error"].get("Message", str(e)),
            ) from e

    def get_account_tags(self, account_id: str) -> dict[str, str]:
        """Fetch current tags for an account from AWS Organizations."""
        tags: dict[str, str] = {}
        try:
            paginator = self.org_client.get_paginator("list_tags_for_resource")
            for page in paginator.paginate(ResourceId=account_id):
                for tag in page.get("Tags", []):
                    tags[tag["Key"]] = str(tag["Value"])
            return tags
        except ClientError as e:
            logger.warning("Could not list tags for account %s: %s", account_id, e)
            return tags

    def sync_account_tags(
        self,
        account_id: str,
        account_name: str,
        declared_tags: dict[str, str],
        dry_run: bool = False,
    ) -> bool:
        """Reconcile declared tags on an account in AWS Organizations. Returns True if tags were updated."""
        if not declared_tags:
            return False

        current_tags = self.get_account_tags(account_id)
        tags_to_apply = {k: str(v) for k, v in declared_tags.items() if current_tags.get(k) != str(v)}

        if not tags_to_apply:
            logger.debug("Tags for account '%s' (%s) are up-to-date.", account_name, account_id)
            return False

        if dry_run:
            logger.info(
                "[DRY-RUN] Would apply %d tags to account '%s' (%s): %s",
                len(tags_to_apply),
                account_name,
                account_id,
                tags_to_apply,
            )
            return True

        logger.info(
            "Applying %d tags to account '%s' (%s)...",
            len(tags_to_apply),
            account_name,
            account_id,
        )
        try:
            tag_list = [{"Key": k, "Value": v} for k, v in tags_to_apply.items()]
            self.org_client.tag_resource(ResourceId=account_id, Tags=tag_list)
            logger.info("Successfully updated tags on account '%s'", account_name)
            return True
        except ClientError as e:
            msg = str(e.response["Error"].get("Message", str(e)))
            if "pattern" in msg.lower():
                msg += (
                    " (Note: AWS Organizations tags only permit letters, numbers, spaces, "
                    "and _ . : / = + - @; commas and other punctuation are not allowed)"
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
        dry_run: bool = False,
        poll_delay_sec: int = 15,
        max_poll_attempts: int = 40,
    ) -> list[AccountProvisionResult]:
        """Idempotently create and reconcile multiple member accounts in batch.

        Dispatches all new account creation requests in parallel, then polls
        in-flight creation statuses in a unified polling loop. This minimizes
        total wait time when provisioning multiple accounts simultaneously.
        """
        existing = self.list_existing_accounts()
        results: list[AccountProvisionResult | None] = [None] * len(accounts)
        pending_creations: list[dict[str, Any]] = []

        for idx, acct_def in enumerate(accounts):
            name, email = acct_def.name, acct_def.email
            target_ou_id = ou_map.get(acct_def.ou)

            if not target_ou_id:
                logger.warning("Target OU '%s' not found for account '%s'", acct_def.ou, name)
                results[idx] = _make_result(acct_def)
                continue

            existing_acct = self.find_existing_account(name, existing)
            if existing_acct:
                acct_id = str(existing_acct["Id"])
                if existing_acct.get("Status") == "SUSPENDED":
                    logger.warning("Account '%s' (%s) is SUSPENDED; skipping.", name, acct_id)
                    results[idx] = _make_result(
                        acct_def, acct_id, target_ou_id, "SUSPENDED_SKIPPED", "SKIPPED"
                    )
                    continue

                logger.info("Account '%s' exists (ID: %s)", name, acct_id)
                moved = not dry_run and self.move_account_if_needed(acct_id, name, target_ou_id)
                tags_updated = self.sync_account_tags(acct_id, name, acct_def.tags, dry_run=dry_run)
                action = "MOVED" if moved else ("TAGGED" if tags_updated else "REUSED")
                results[idx] = _make_result(acct_def, acct_id, target_ou_id, action, "SUCCEEDED")
                continue

            if dry_run:
                logger.info("[DRY-RUN] Would create account '%s' (%s) in OU %s", name, email, target_ou_id)
                results[idx] = _make_result(
                    acct_def, "DRY-RUN-ID", target_ou_id, "SIMULATED_CREATE", "SIMULATED"
                )
                continue

            logger.info("Requesting creation of account '%s' (%s)...", name, email)
            try:
                create_params: dict[str, Any] = {
                    "Email": email,
                    "AccountName": name,
                    "RoleName": "OrganizationAccountAccessRole",
                }
                if acct_def.tags:
                    create_params["Tags"] = [{"Key": k, "Value": str(v)} for k, v in acct_def.tags.items()]
                resp = self.org_client.create_account(**create_params)
                pending_creations.append(
                    {
                        "index": idx,
                        "acct_def": acct_def,
                        "target_ou_id": target_ou_id,
                        "request_id": str(resp["CreateAccountStatus"]["Id"]),
                    }
                )
            except ClientError as e:
                raise AccountProvisioningError(
                    f"Failed to request creation of account '{name}'",
                    details=e.response["Error"].get("Message", str(e)),
                ) from e

        if pending_creations:
            in_flight = list(pending_creations)
            for attempt in range(1, max_poll_attempts + 1):
                if not in_flight:
                    break
                time.sleep(poll_delay_sec)
                still_pending: list[dict[str, Any]] = []

                for item in in_flight:
                    name = item["acct_def"].name
                    try:
                        state, new_id, reason = self._describe_create_status(item["request_id"])
                        logger.info(
                            "Creation status for '%s': %s (attempt %d/%d)",
                            name,
                            state,
                            attempt,
                            max_poll_attempts,
                        )

                        if state == "SUCCEEDED":
                            if not new_id:
                                raise AccountProvisioningError(
                                    f"Account creation for '{name}' succeeded but AccountId was not returned."
                                )
                            self.move_account_if_needed(new_id, name, item["target_ou_id"])
                            self.sync_account_tags(new_id, name, item["acct_def"].tags, dry_run=False)
                            results[item["index"]] = _make_result(
                                item["acct_def"], new_id, item["target_ou_id"], "CREATED", "SUCCEEDED"
                            )
                        elif state == "IN_PROGRESS":
                            still_pending.append(item)
                        else:
                            raise AccountProvisioningError(
                                f"Account creation for '{name}' failed with status: {state}",
                                details=reason or f"Status ended in {state}",
                            )
                    except ClientError as e:
                        logger.warning("Error querying creation status for '%s': %s", name, e)
                        still_pending.append(item)

                in_flight = still_pending

            if in_flight:
                timed_out_names = [it["acct_def"].name for it in in_flight]
                raise AccountProvisioningError(
                    f"Timed out waiting for account creation for: {', '.join(timed_out_names)}"
                )

        return [r for r in results if r is not None]

    def provision_account(
        self,
        acct_def: AccountDef,
        target_ou_id: str,
        dry_run: bool = False,
    ) -> AccountProvisionResult:
        """Idempotently create an account and ensure placement in the target OU."""
        results = self.provision_accounts([acct_def], {acct_def.ou: target_ou_id}, dry_run=dry_run)
        return results[0]

    def _poll_create_account_status(
        self, request_id: str, account_name: str, max_attempts: int = 40, delay_sec: int = 15
    ) -> str:
        """Poll account creation status until SUCCEEDED or failed."""
        last_state = "IN_PROGRESS"
        last_reason = ""
        for attempt in range(1, max_attempts + 1):
            time.sleep(delay_sec)
            try:
                last_state, account_id, last_reason = self._describe_create_status(request_id)
                logger.info(
                    "Creation status for '%s': %s (attempt %d/%d)",
                    account_name,
                    last_state,
                    attempt,
                    max_attempts,
                )
                if last_state == "SUCCEEDED":
                    if not account_id:
                        raise AccountProvisioningError(
                            f"Account creation for '{account_name}' succeeded but AccountId was not returned."
                        )
                    return account_id
                if last_state != "IN_PROGRESS":
                    raise AccountProvisioningError(
                        f"Account creation for '{account_name}' failed with status: {last_state}",
                        details=last_reason or f"Status ended in {last_state}",
                    )
            except ClientError as e:
                logger.warning("Error querying creation status: %s", e)

        raise AccountProvisioningError(
            f"Account creation for '{account_name}' failed with status: {last_state}",
            details=last_reason or f"Status timed out or ended in {last_state}",
        )

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
            status = acct_data["Status"] if acct_data else "NOT_PROVISIONED"
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
                safe_name = name.upper().replace("-", "_")
                env_vars[f"{safe_name}_ACCOUNT_ID"] = str(acct_id)

        declared_names = {normalize_account_name(a.name) for a in catalog.accounts}
        for name, acct_data in existing.items():
            if normalize_account_name(name) in declared_names:
                continue
            acct_id = str(acct_data["Id"])
            status = str(acct_data.get("Status", "UNKNOWN"))
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

        json_path = output_dir / "inventory.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(inventory, f, indent=2)

        env_path = output_dir / "env.sh"
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n# Generated by tarmac account export - DO NOT EDIT MANUALLY\n")
            for k, v in env_vars.items():
                f.write(f'export {k}="{v}"\n')

        logger.info("Exported account inventory to %s and %s", json_path, env_path)
        return json_path
