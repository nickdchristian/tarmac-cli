"""CLI commands for the AWS Account Factory."""

import json
from typing import Annotated

import typer

from ..core.adoption import set_adopt_existing
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import AccountDef
from ..core.models import BaselineReport
from ..services.accounts import AccountService
from ..services.baseline import BaselineService
from ..services.ou import OUService
from .common import (
    AdoptExistingOption,
    ConfigDirOption,
    JsonOption,
    RegionOption,
    YesOption,
    confirm_or_exit,
    exit_on_error,
    load_configs_or_exit,
)
from .ui import console, create_table, error_console, print_header, print_info, print_success, print_warning

app = typer.Typer(help="Declarative AWS Account Factory commands.")


def _get_tag_sync_status(dry_run: bool, updated: bool) -> str:
    if dry_run and updated:
        return "[yellow]WOULD_UPDATE[/yellow]"
    return "[green]UPDATED[/green]" if updated else "[dim]IN_SYNC[/dim]"


@app.command("sync-tags")
def sync_account_tags_cmd(
    account_name: Annotated[
        str | None, typer.Argument(help="Specific account name to sync tags for, or all")
    ] = None,
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate tag sync without making changes")
    ] = False,
) -> None:
    """Synchronize declared tags with AWS Organizations member accounts."""
    print_header("Account Factory: Sync Account Tags")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Tag Sync Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = AccountService(session_mgr)
        existing = service.list_existing_accounts()

        table = create_table(title="Account Tag Sync")
        table.add_column("Account Name", style="cyan")
        table.add_column("Account ID", style="green")
        table.add_column("Declared Tags", style="magenta")
        table.add_column("Status", style="bold")

        for acct_def in bundle.accounts.accounts:
            if account_name and acct_def.name != account_name:
                continue

            declared_tags = {**bundle.get_organization_tags(), **acct_def.tags}
            acct_data = service.find_existing_account(acct_def.name, existing)
            if not acct_data:
                table.add_row(acct_def.name, "-", str(len(declared_tags)), "[yellow]NOT_FOUND[/yellow]")
                continue

            acct_id = str(acct_data["Id"])
            updated = service.sync_account_tags(acct_id, acct_def.name, declared_tags, dry_run=dry_run)
            table.add_row(
                acct_def.name, acct_id, str(len(declared_tags)), _get_tag_sync_status(dry_run, updated)
            )

        console.print(table)


def _baseline_single_account(
    acct_def: AccountDef,
    acct_id: str,
    baseliner: BaselineService,
    service: AccountService,
    dry_run: bool,
    org_tags: dict[str, str] | None = None,
) -> None:
    """Baseline a single account: sync tags, delete default VPCs across all enabled regions, setup budgets."""
    declared_tags = {**(org_tags or {}), **acct_def.tags}
    service.sync_account_tags(acct_id, acct_def.name, declared_tags, dry_run=dry_run)
    report = baseliner.baseline_account(acct_def, acct_id, regions=None, dry_run=dry_run, org_tags=org_tags)
    _print_baseline_summary(report)


@app.command("baseline")
def baseline_accounts(
    account_name: Annotated[
        str | None, typer.Argument(help="Specific account name to baseline, or all")
    ] = None,
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate baselining without making changes")
    ] = False,
    yes: YesOption = False,
    adopt_existing: AdoptExistingOption = False,
) -> None:
    """Run security and operational baselines (default VPC purge, budgets, anomaly alerts)."""
    set_adopt_existing(adopt_existing)
    confirm_or_exit(
        "Are you sure you want to baseline accounts (delete default VPCs & setup budgets)?",
        yes=yes,
        dry_run=dry_run,
        cancelled="Account baselining cancelled by user.",
    )

    print_header("Account Factory: Baselining")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Baselining Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = AccountService(session_mgr)
        baseliner = BaselineService(session_mgr)

        existing = service.list_existing_accounts()

        for acct_def in bundle.accounts.accounts:
            if account_name and acct_def.name != account_name:
                continue

            acct_data = service.find_existing_account(acct_def.name, existing)
            if not acct_data:
                print_info(f"Skipping {acct_def.name}: not present in AWS Organizations.")
                continue

            _baseline_single_account(
                acct_def,
                str(acct_data["Id"]),
                baseliner,
                service,
                dry_run,
                org_tags=bundle.get_organization_tags(),
            )


@app.command("export")
def export_inventory(config_dir: ConfigDirOption = None, region: RegionOption = None):
    """Export current account inventory to JSON and shell environment formats."""
    print_header("Export Account Inventory")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Export Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        ou_map = ou_service.list_all_ous(ou_service.get_root_id())
        json_path = service.export_inventory(bundle.accounts, ou_map, bundle.config_dir.parent / "outputs")
        print_success(f"Exported account inventory to [cyan]{json_path}[/cyan]")


def _print_baseline_summary(report: BaselineReport) -> None:
    for vpc_rep in report.vpc_reports:
        if vpc_rep.deleted_vpc:
            print_success(
                f"[{report.account_name}] Purged default VPC ({vpc_rep.vpc_id}) in {vpc_rep.region}"
            )
        elif not vpc_rep.skipped:
            print_info(f"[{report.account_name}] {vpc_rep.message}")

    if report.budget_report:
        br = report.budget_report
        color = "green" if br.status in ["CREATED", "UPDATED", "EXISTING"] else "yellow"
        console.print(
            f"[{report.account_name}] Budget {br.budget_name}: [{color}]{br.status}[/{color}] (${br.limit_usd:.2f}/mo)"
        )

    if report.anomaly_report:
        ar = report.anomaly_report
        color = "green" if ar.status in ["CREATED", "EXISTING"] else "yellow"
        console.print(
            f"[{report.account_name}] Anomaly Monitor: [{color}]{ar.status}[/{color}] (Threshold: ${ar.threshold_usd:.2f})"
        )


@app.command("suspend")
def suspend_account_cmd(
    account_name_or_id: Annotated[str, typer.Argument(help="Account Name or 12-digit Account ID to suspend")],
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    close: Annotated[
        bool, typer.Option("--close", help="Also initiate permanent account closure via CloseAccount API")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate suspension without making changes")
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
        bool, typer.Option("--suspended", "-s", help="Show only suspended or quarantined accounts")
    ] = False,
    active: Annotated[bool, typer.Option("--active", "-a", help="Show only active accounts")] = False,
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
            status = str(acct.get("Status", "ACTIVE"))
            parent_id = service.get_account_parent_id(acct_id) or ""
            parent_name = ou_id_to_name.get(parent_id, parent_id or "Unknown")

            is_suspended = status == "SUSPENDED" or parent_name == "Suspended"
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
            1 for r in acct_rows if r["status"] == "SUSPENDED" or r["parent_ou"] == "Suspended"
        )
        if not suspended and suspended_count > 0:
            print_info(f"Total accounts: {len(acct_rows)} ({suspended_count} suspended / quarantined)")


@app.command("anomaly-status")
def anomaly_status(config_dir: ConfigDirOption = None, region: RegionOption = None):
    """List all Cost Anomaly Detection monitors and subscriptions in the Management Account."""
    print_header("Cost Anomaly Detection Status")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Anomaly Status Check Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        monitors, subs = BaselineService(session_mgr).get_anomaly_overview()

        table = create_table(title="Cost Anomaly Monitors")
        table.add_column("Monitor Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Scope / Linked Account", style="green")
        for m in monitors:
            spec = m.get("MonitorSpecification", {})
            dim_values = spec.get("Dimensions", {}).get("Values", ["All Linked Accounts / Dimensional"])
            table.add_row(
                m.get("MonitorName", "Unknown"), m.get("MonitorType", "Unknown"), ", ".join(dim_values)
            )
        console.print(table)

        sub_table = create_table(title="Alert Subscriptions")
        sub_table.add_column("Subscription Name", style="cyan")
        sub_table.add_column("Threshold", style="yellow")
        sub_table.add_column("Frequency", style="magenta")
        sub_table.add_column("Subscribers", style="green")
        for s in subs:
            sub_table.add_row(
                s.get("SubscriptionName", "Unknown"),
                f"${s.get('Threshold', 0):.2f}",
                s.get("Frequency", "Unknown"),
                ", ".join(sub.get("Address", "") for sub in s.get("Subscribers", [])),
            )
        console.print(sub_table)
