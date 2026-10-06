"""CLI commands for the AWS Account Factory."""

from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import AccountDef
from ..core.exceptions import GovernanceError
from ..core.models import BaselineReport
from ..services.accounts import AccountService
from ..services.baseline import BaselineService
from ..services.ou import OUService
from .common import load_configs_or_exit
from .ui import console, create_table, error_console, print_header, print_info, print_success

app = typer.Typer(help="Declarative AWS Account Factory commands.")


@app.command("plan")
def plan_accounts(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
):
    """Generate and display the account provisioning plan."""
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        root_id = ou_service.get_root_id()
        ou_map = ou_service.list_all_ous(root_id)
        plan_items = service.plan(bundle.accounts, ou_map)

        if json_output:
            import json

            plan_dicts = [
                {
                    "name": item.name,
                    "email": item.email,
                    "ou": item.ou,
                    "action": item.action,
                    "account_id": item.account_id,
                    "reason": item.reason,
                    "baseline": item.baseline.model_dump(),
                }
                for item in plan_items
            ]
            print(json.dumps(plan_dicts, indent=2))
            return

        print_header("Account Factory: Execution Plan")
        table = create_table(title="Account Factory Plan")
        table.add_column("Account Name", style="cyan")
        table.add_column("Email", style="white")
        table.add_column("Target OU", style="magenta")
        table.add_column("Action", style="bold")
        table.add_column("Details", style="dim")

        for item in plan_items:
            if item.action == "CREATE":
                action_style = "green"
            elif item.action == "MOVE":
                action_style = "yellow"
            elif item.action == "SUSPEND":
                action_style = "bold red"
            elif item.action == "SUSPENDED":
                action_style = "magenta"
            else:
                action_style = "dim"

            table.add_row(
                item.name,
                item.email,
                item.ou,
                f"[{action_style}]{item.action}[/{action_style}]",
                item.reason,
            )

        console.print(table)
        suspended_items = [i for i in plan_items if i.action == "SUSPENDED"]
        if suspended_items:
            print_info(
                f"Discovered {len(suspended_items)} suspended or quarantined account(s) in AWS Organizations."
            )
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Account Plan Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


def _provision_declared_accounts(
    bundle: Any,
    service: AccountService,
    baseliner: BaselineService,
    ou_map: dict[str, str],
    target_region: str,
    dry_run: bool,
    skip_baseline: bool,
    results_table: Table,
) -> None:
    results = service.provision_accounts(bundle.accounts.accounts, ou_map=ou_map, dry_run=dry_run)
    acct_def_map = {a.name: a for a in bundle.accounts.accounts}

    for result in results:
        status_style = "green" if result.status == "SUCCEEDED" else "dim"
        results_table.add_row(
            result.name,
            result.account_id or "-",
            result.ou_name,
            result.action_taken,
            f"[{status_style}]{result.status}[/{status_style}]",
        )

        acct_def = acct_def_map.get(result.name)
        if (
            acct_def
            and result.account_id
            and result.account_id != "DRY-RUN-ID"
            and not skip_baseline
            and not dry_run
        ):
            baseline_report = baseliner.baseline_account(
                acct_def,
                result.account_id,
                regions=None,
                dry_run=dry_run,
                org_tags=bundle.get_organization_tags(),
            )
            _print_baseline_summary(baseline_report)

    suspended_ou_id = ou_map.get("Suspended")
    plan_items = service.plan(bundle.accounts, ou_map)
    for item in plan_items:
        if item.action == "SUSPEND" and item.account_id:
            sus_res = service.suspend_account(
                account_id=item.account_id,
                account_name=item.name,
                suspended_ou_id=suspended_ou_id,
                dry_run=dry_run,
            )
            status_style = "yellow" if sus_res.status == "SUCCEEDED" else "dim"
            results_table.add_row(
                sus_res.name,
                sus_res.account_id,
                "Suspended",
                "SUSPEND",
                f"[{status_style}]{sus_res.status}[/{status_style}]",
            )


@app.command("apply")
def apply_accounts(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate provisioning without making changes"),
    skip_baseline: bool = typer.Option(False, "--skip-baseline", help="Skip running post-creation baselines"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt for automated run"),
):
    """Provision declared accounts and place them into target OUs."""
    if not _confirm_action("Are you sure you want to provision/move accounts in AWS?", yes, dry_run):
        print_info("Account provisioning cancelled by user.")
        raise typer.Exit(code=0)

    print_header("Account Factory: Provisioning Accounts")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)
        baseliner = BaselineService(session_mgr)

        ou_report = ou_service.sync_ou_structure(bundle.org.ou_structure)
        ou_map = ou_report.synced_ous

        results_table = create_table(title="Provisioning Summary")
        results_table.add_column("Account Name", style="cyan")
        results_table.add_column("Account ID", style="green")
        results_table.add_column("OU", style="magenta")
        results_table.add_column("Action", style="yellow")
        results_table.add_column("Status", style="bold")

        _provision_declared_accounts(
            bundle, service, baseliner, ou_map, target_region, dry_run, skip_baseline, results_table
        )

        console.print(results_table)
        project_root = bundle.config_dir.parent
        output_dir = project_root / "outputs"
        export_path = service.export_inventory(bundle.accounts, ou_map, output_dir)
        print_success(f"Updated inventory export at [cyan]{export_path}[/cyan]")

    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Account Provisioning Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


def _get_tag_sync_status(dry_run: bool, updated: bool) -> str:
    """Format status label for tag sync."""
    if dry_run and updated:
        return "[yellow]WOULD_UPDATE[/yellow]"
    return "[green]UPDATED[/green]" if updated else "[dim]IN_SYNC[/dim]"


@app.command("sync-tags")
def sync_account_tags_cmd(
    account_name: str | None = typer.Argument(None, help="Specific account name to sync tags for, or all"),
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate tag sync without making changes"),
) -> None:
    """Synchronize declared tags with AWS Organizations member accounts."""
    print_header("Account Factory: Sync Account Tags")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
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

            acct_data = service.find_existing_account(acct_def.name, existing)
            if not acct_data:
                table.add_row(acct_def.name, "-", str(len(acct_def.tags)), "[yellow]NOT_FOUND[/yellow]")
                continue

            acct_id = str(acct_data["Id"])
            updated = service.sync_account_tags(acct_id, acct_def.name, acct_def.tags, dry_run=dry_run)
            table.add_row(
                acct_def.name,
                acct_id,
                str(len(acct_def.tags)),
                _get_tag_sync_status(dry_run, updated),
            )

        console.print(table)
    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]Tag Sync Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)


def _baseline_single_account(
    acct_def: AccountDef,
    acct_id: str,
    baseliner: BaselineService,
    service: AccountService,
    dry_run: bool,
    org_tags: dict[str, str] | None = None,
    regions: list[str] | None = None,
) -> None:
    """Baseline a single account: sync tags, delete default VPCs across all enabled regions, setup budgets."""
    service.sync_account_tags(acct_id, acct_def.name, acct_def.tags, dry_run=dry_run)
    report = baseliner.baseline_account(
        acct_def, acct_id, regions=regions, dry_run=dry_run, org_tags=org_tags
    )
    _print_baseline_summary(report)


def _confirm_action(prompt: str, yes: bool, dry_run: bool) -> bool:
    """Prompt for user confirmation unless yes or dry_run is set."""
    if dry_run or yes:
        return True
    return bool(typer.confirm(prompt, default=False))


@app.command("baseline")
def baseline_accounts(
    account_name: str | None = typer.Argument(None, help="Specific account name to baseline, or all"),
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate baselining without making changes"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt for automated run"),
) -> None:
    """Run security and operational baselines (default VPC purge, budgets, anomaly alerts)."""
    msg = "Are you sure you want to baseline accounts (delete default VPCs & setup budgets)?"
    if not _confirm_action(msg, yes, dry_run):
        print_info("Account baselining cancelled by user.")
        raise typer.Exit(code=0)

    print_header("Account Factory: Baselining")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
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

            acct_id = str(acct_data["Id"])
            _baseline_single_account(
                acct_def,
                acct_id,
                baseliner,
                service,
                dry_run,
                org_tags=bundle.get_organization_tags(),
                regions=None,
            )

    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]Baselining Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)


@app.command("export")
def export_inventory(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """Export current account inventory to JSON and shell environment formats."""
    print_header("Export Account Inventory")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        root_id = ou_service.get_root_id()
        ou_map = ou_service.list_all_ous(root_id)

        project_root = bundle.config_dir.parent
        output_dir = project_root / "outputs"
        json_path = service.export_inventory(bundle.accounts, ou_map, output_dir)
        print_success(f"Exported account inventory to [cyan]{json_path}[/cyan]")
    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]Export Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)


def _print_baseline_summary(report: BaselineReport) -> None:
    """Helper to render baseline report summaries."""
    for vpc_rep in report.vpc_reports:
        if vpc_rep.deleted_vpc:
            print_success(
                f"[{report.account_name}] Purged default VPC ({vpc_rep.vpc_id}) in {vpc_rep.region}"
            )
        elif not vpc_rep.skipped:
            print_info(f"[{report.account_name}] {vpc_rep.message}")

    if report.budget_report:
        br = report.budget_report
        status_color = "green" if br.status in ["CREATED", "UPDATED", "EXISTING"] else "yellow"
        console.print(
            f"[{report.account_name}] Budget {br.budget_name}: [{status_color}]{br.status}[/{status_color}] (${br.limit_usd:.2f}/mo)"
        )

    if report.anomaly_report:
        ar = report.anomaly_report
        status_color = "green" if ar.status in ["CREATED", "EXISTING"] else "yellow"
        console.print(
            f"[{report.account_name}] Anomaly Monitor: [{status_color}]{ar.status}[/{status_color}] (Threshold: ${ar.threshold_usd:.2f})"
        )


@app.command("suspend")
def suspend_account_cmd(
    account_name_or_id: str = typer.Argument(..., help="Account Name or 12-digit Account ID to suspend"),
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    close: bool = typer.Option(
        False, "--close", help="Also initiate permanent account closure via CloseAccount API"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate suspension without making changes"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Quarantine an account into the Suspended OU and apply governance tags."""
    action_desc = (
        f"suspend and close account '{account_name_or_id}'"
        if close
        else f"suspend account '{account_name_or_id}' into Suspended OU"
    )
    if not _confirm_action(f"Are you sure you want to {action_desc}?", yes, dry_run):
        print_info("Account suspension cancelled by user.")
        raise typer.Exit(code=0)

    print_header(f"Account Factory: Suspend Account '{account_name_or_id}'")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        existing = service.list_existing_accounts()
        matched_acct = None
        norm_target = normalize_account_name(account_name_or_id)
        for name, acct in existing.items():
            if normalize_account_name(name) == norm_target or str(acct["Id"]) == account_name_or_id:
                matched_acct = acct
                break

        if not matched_acct:
            error_console.print(f"[red]✗[/red] Account '{account_name_or_id}' not found in AWS Organization.")
            raise typer.Exit(code=1)

        root_id = ou_service.get_root_id()
        ou_map = ou_service.list_all_ous(root_id)
        suspended_ou_id = ou_map.get("Suspended")

        res = service.suspend_account(
            account_id=str(matched_acct["Id"]),
            account_name=str(matched_acct["Name"]),
            suspended_ou_id=suspended_ou_id,
            dry_run=dry_run,
            close=close,
        )

        print_success(f"Account {res.name} ({res.account_id}): {res.message}")

    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Account Suspension Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("list")
def list_accounts_cmd(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    suspended: bool = typer.Option(
        False, "--suspended", "-s", help="Show only suspended or quarantined accounts"
    ),
    active: bool = typer.Option(False, "--active", "-a", help="Show only active accounts"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
) -> None:
    """List all accounts in the AWS Organization with their status and parent OU."""
    import json

    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        service = AccountService(session_mgr)

        root_id = ou_service.get_root_id()
        ou_map = ou_service.list_all_ous(root_id)
        ou_id_to_name = {v: k for k, v in ou_map.items()}
        ou_id_to_name[root_id] = "Root"

        all_accts = service.list_all_accounts()

        acct_rows = []
        for acct in all_accts:
            acct_id = str(acct["Id"])
            status = str(acct.get("Status", "ACTIVE"))
            parent_id = service.get_account_parent_id(acct_id) or ""
            parent_name = ou_id_to_name.get(parent_id, parent_id or "Unknown")

            is_suspended = status == "SUSPENDED" or parent_name == "Suspended"
            if suspended and not is_suspended:
                continue
            if active and is_suspended:
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

    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]List Accounts Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)
