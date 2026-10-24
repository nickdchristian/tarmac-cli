"""The `tarmac account` commands."""

import json
from typing import Annotated

import typer

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.org_accounts import CLOSED_STATES, account_state, is_closed
from ..services.accounts import AccountService
from ..services.ou import OUService
from .common import (
    ConfigDirOption,
    JsonOption,
    RegionOption,
    YesOption,
    confirm_or_exit,
    exit_on_error,
    load_configs_or_exit,
)
from .ui import console, create_table, error_console, print_header, print_info, print_success, print_warning

app = typer.Typer(
    help="Inspect and suspend member accounts (`tarmac deploy --phase 4` creates and updates them)."
)


@app.command("suspend")
def suspend_account_cmd(
    account_name_or_id: Annotated[str, typer.Argument(help="Account name or 12-digit account ID")],
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    close: Annotated[
        bool, typer.Option("--close", help="Also close the account (permanent after 90 days)")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would change, without changing it")
    ] = False,
    yes: YesOption = False,
) -> None:
    """Quarantine an account into the Suspended OU and apply governance tags."""
    action_desc = (
        f"suspend and close account '{account_name_or_id}'"
        if close
        else f"suspend account '{account_name_or_id}' into Suspended OU"
    )
    confirm_or_exit(
        f"Are you sure you want to {action_desc}?",
        yes=yes,
        dry_run=dry_run,
        cancelled="Account suspension cancelled by user.",
    )

    print_header(f"Account Factory: Suspend Account '{account_name_or_id}'")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Account Suspension Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        norm_target = normalize_account_name(account_name_or_id)
        matched_acct = next(
            (
                acct
                for name, acct in service.list_existing_accounts().items()
                if normalize_account_name(name) == norm_target or str(acct["Id"]) == account_name_or_id
            ),
            None,
        )
        if not matched_acct:
            error_console.print(f"[red]✗[/red] Account '{account_name_or_id}' not found in AWS Organization.")
            raise typer.Exit(code=1)

        ou_map = ou_service.list_all_ous(ou_service.get_root_id())
        res = service.suspend_account(
            account_id=str(matched_acct["Id"]),
            account_name=str(matched_acct["Name"]),
            suspended_ou_id=ou_map.get("Suspended"),
            dry_run=dry_run,
            close=close,
        )

        if res.status == "CLOSE_FAILED":
            print_warning(f"Account {res.name} ({res.account_id}): {res.message}")
            raise typer.Exit(code=1)
        print_success(f"Account {res.name} ({res.account_id}): {res.message}")


@app.command("list")
def list_accounts_cmd(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    suspended: Annotated[
        bool, typer.Option("--suspended", help="Show only suspended or quarantined accounts")
    ] = False,
    active: Annotated[bool, typer.Option("--active", help="Show only active accounts")] = False,
    json_output: JsonOption = False,
) -> None:
    """List all accounts in the AWS Organization with their status and parent OU."""
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("List Accounts Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        root_id = ou_service.get_root_id()
        ou_id_to_name = {v: k for k, v in ou_service.list_all_ous(root_id).items()}
        ou_id_to_name[root_id] = "Root"

        acct_rows = []
        for acct in service.list_all_accounts():
            acct_id = str(acct["Id"])
            status = account_state(acct)
            parent_id = service.get_account_parent_id(acct_id) or ""
            parent_name = ou_id_to_name.get(parent_id, parent_id or "Unknown")

            is_suspended = is_closed(acct) or parent_name == "Suspended"
            if (suspended and not is_suspended) or (active and is_suspended):
                continue

            acct_rows.append(
                {
                    "name": str(acct["Name"]),
                    "id": acct_id,
                    "email": str(acct.get("Email", "")),
                    "status": status,
                    "parent_ou": parent_name,
                }
            )

        if json_output:
            print(json.dumps(acct_rows, indent=2))
            return

        title_suffix = " (Suspended Only)" if suspended else (" (Active Only)" if active else "")
        print_header(f"AWS Organization Accounts{title_suffix}")

        table = create_table(title="Accounts Inventory")
        table.add_column("Account Name", style="cyan")
        table.add_column("Account ID", style="green")
        table.add_column("Email", style="white")
        table.add_column("Parent OU", style="magenta")
        table.add_column("Status", style="bold")

        for row in acct_rows:
            status_style = "green" if row["status"] == "ACTIVE" else "magenta"
            table.add_row(
                row["name"],
                row["id"],
                row["email"],
                row["parent_ou"],
                f"[{status_style}]{row['status']}[/{status_style}]",
            )

        console.print(table)
        suspended_count = sum(
            1 for r in acct_rows if r["status"] in CLOSED_STATES or r["parent_ou"] == "Suspended"
        )
        if not suspended and suspended_count > 0:
            print_info(f"Total accounts: {len(acct_rows)} ({suspended_count} suspended / quarantined)")
