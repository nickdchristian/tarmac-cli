"""CLI commands for AWS Organizations and Management Account bootstrap."""

from pathlib import Path

import typer
from rich.panel import Panel

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import GovernanceError
from ..core.models import SCPReconciliationResult, VpcCleanupReport
from ..services.baseline import BaselineService
from ..services.organization import OrganizationService
from ..services.ou import OUService
from ..services.scp import SCPService
from .common import get_active_account_id_map, load_configs_or_exit
from .ui import (
    console,
    create_table,
    error_console,
    print_header,
    print_info,
    print_success,
    print_warning,
)

app = typer.Typer(help="AWS Organizations and Management Account governance.")


@app.command("bootstrap")
def bootstrap(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """Bootstrap AWS Organizations with ALL features, alternate contacts, and trusted services."""
    print_header("AWS Organizations Bootstrap")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OrganizationService(session_mgr)

        org_id = service.ensure_organization()
        service.set_account_contacts(bundle.org.contacts)
        services = service.enable_trusted_services()
        print_success(f"Organization bootstrap complete (Org ID: [cyan]{org_id}[/cyan])")
        print_success(f"Enabled {len(services)} trusted services for Organization.")

        target_cost_tags = bundle.get_cost_allocation_tags()
        if target_cost_tags:
            activated = service.activate_cost_allocation_tags(target_cost_tags)
            if activated:
                print_success(
                    f"Activated {len(activated)} Cost Allocation Tag(s) in Cost Explorer: {', '.join(activated)}"
                )

        if bundle.org.organization.delete_default_vpc:
            baseliner = BaselineService(session_mgr)
            caller = session_mgr.get_caller_identity()
            mgmt_id = caller.get("Account", "")
            if mgmt_id:
                vpc_reports = baseliner.cleanup_default_vpcs(mgmt_id, "management", regions=None)
                for r in vpc_reports:
                    if not r.skipped and r.deleted_vpc:
                        print_success(f"Purged default VPC ({r.vpc_id}) in {r.region}")

    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]Bootstrap Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)


def _render_vpc_reports(reports: list[VpcCleanupReport], dry_run: bool) -> None:
    """Render VPC cleanup outcomes to console."""
    any_found = False
    for r in reports:
        if r.skipped:
            if dry_run and r.vpc_id:
                print_info(
                    f"[DRY-RUN] Would delete default VPC [cyan]{r.vpc_id}[/cyan] in [yellow]{r.region}[/yellow]"
                )
                any_found = True
            else:
                print_info(f"Region [yellow]{r.region}[/yellow]: {r.message}")
        elif r.deleted_vpc:
            any_found = True
            print_success(f"Purged default VPC [cyan]{r.vpc_id}[/cyan] in [yellow]{r.region}[/yellow]")

    if not any_found and not dry_run:
        print_success("Management Account is clean. No default VPCs exist in enabled regions.")


@app.command("cleanup-vpc")
def cleanup_management_vpc(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate cleanup without deleting resources"),
):
    """Scan and purge default VPCs in the AWS Management Account across all enabled regions."""
    print_header("Management Account: Default VPC Cleanup")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        baseliner = BaselineService(session_mgr)
        caller = session_mgr.get_caller_identity()
        mgmt_id = caller.get("Account", "")
        if not mgmt_id:
            error_console.print("[red]✗[/red] Unable to determine Management Account ID.")
            raise typer.Exit(code=1)

        print_info(f"Scanning Management Account ({mgmt_id}) across all enabled regions...")

        reports = baseliner.cleanup_default_vpcs(mgmt_id, "management", regions=None, dry_run=dry_run)
        _render_vpc_reports(reports, dry_run)

    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]VPC Cleanup Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("contacts")
def set_contacts(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """Set alternate contacts (Billing, Operations, Security) on the Management Account."""
    print_header("Set Account Alternate Contacts")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OrganizationService(session_mgr)
        updated = service.set_account_contacts(bundle.org.contacts)
        print_success(f"Successfully configured contacts: {', '.join(updated)}")
    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]Contacts Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)


@app.command("root-access")
def enable_root_access(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """Enable centralized root access management and privileged root sessions."""
    print_header("Enable Centralized Root Access Management")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OrganizationService(session_mgr)
        acct_id_map = get_active_account_id_map(session_mgr)
        results = service.configure_root_access(bundle.org.root_access_management, account_id_map=acct_id_map)
        for feature, status in results.items():
            feature_title = feature.replace("_", " ").title()
            if status:
                print_success(f"Enabled {feature_title}")
            else:
                err_msg = service.last_error.get(feature)
                if err_msg:
                    print_warning(f"{feature_title}: {err_msg}")
                else:
                    print_warning(f"{feature_title}: Skipped or disabled in configuration")
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Root Access Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("activate-cost-tags")
def activate_cost_tags_command(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
) -> None:
    """Activate user-defined and AWS-generated cost allocation tags in AWS Cost Explorer."""
    print_header("Cost Allocation Tags: Activation")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OrganizationService(session_mgr)
        target_cost_tags = bundle.get_cost_allocation_tags()
        if not target_cost_tags:
            print_info("No cost allocation tags configured or feature is disabled.")
            return

        activated = service.activate_cost_allocation_tags(target_cost_tags)
        if activated:
            print_success(
                f"Activated {len(activated)} Cost Allocation Tag(s) in Cost Explorer: {', '.join(activated)}"
            )
        else:
            print_info("No inactive cost allocation tags matching target keys found to activate.")
    except GovernanceError as e:
        error_console.print(
            Panel(
                str(e), title="[bold red]Cost Allocation Tag Activation Failed[/bold red]", border_style="red"
            )
        )
        raise typer.Exit(code=1)


scp_app = typer.Typer(help="Manage Service Control Policies (SCPs).", no_args_is_help=True)
app.add_typer(scp_app, name="scp")


def _render_scp_results(results: list[SCPReconciliationResult]) -> None:
    """Render SCP reconciliation table to console."""
    table = create_table(title="Service Control Policies Reconciliation")
    table.add_column("Policy Name", style="cyan", no_wrap=True)
    table.add_column("Action", style="bold")
    table.add_column("Policy ID", style="green")
    table.add_column("Targets", style="yellow")
    table.add_column("Status", style="bold")

    for r in results:
        status_style = "[green]SUCCEEDED[/green]" if r.status == "SUCCEEDED" else "[red]FAILED[/red]"
        is_active = any(w in r.action_taken.upper() for w in ("CREATE", "UPDATE"))
        action_color = "green" if is_active else "dim"
        targets_str = ", ".join(r.attached_targets) if r.attached_targets else "-"
        table.add_row(
            r.name,
            f"[{action_color}]{r.action_taken.upper()}[/{action_color}]",
            r.policy_id or "-",
            targets_str,
            status_style,
        )

    console.print(table)


def _execute_scp_reconciliation(
    config_dir: Path | None,
    region: str | None,
    dry_run: bool,
) -> None:
    """Execute SCP reconciliation logic for plan and apply."""
    bundle = load_configs_or_exit(config_dir)
    scp_config = bundle.org.service_control_policies
    if not scp_config or not scp_config.enabled:
        print_info("Service Control Policies are disabled or not declared in configuration.")
        return

    target_region = region or bundle.org.organization.primary_region
    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        scp_service = SCPService(session_mgr)

        root_id = ou_service.get_root_id()
        ou_map = ou_service.list_all_ous(root_id)

        results = scp_service.reconcile_all(
            config=scp_config,
            root_id=root_id,
            ou_map=ou_map,
            project_root=Path.cwd(),
            dry_run=dry_run,
        )
        _render_scp_results(results)
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]SCP Reconciliation Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@scp_app.command("plan")
def plan_scps(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
) -> None:
    """Preview Service Control Policy changes without applying them."""
    print_header("Service Control Policies Plan (Dry-Run)")
    _execute_scp_reconciliation(config_dir, region, dry_run=True)


@scp_app.command("apply")
def apply_scps(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without applying"),
) -> None:
    """Reconcile and attach declared Service Control Policies."""
    mode = "Dry-Run" if dry_run else "Apply"
    print_header(f"Service Control Policies ({mode})")
    _execute_scp_reconciliation(config_dir, region, dry_run=dry_run)
