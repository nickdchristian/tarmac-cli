"""CLI commands for Organizational Unit (OU) management."""

from pathlib import Path

import typer
from rich.panel import Panel

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import GovernanceError
from ..services.ou import OUService
from .common import load_configs_or_exit
from .ui import console, create_table, error_console, print_header

app = typer.Typer(help="Organizational Unit (OU) tree management.")


@app.command("sync")
def sync_ous(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """Reconcile and idempotently create the declared OU structure."""
    print_header("Sync Organizational Units")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OUService(session_mgr)

        report = service.sync_ou_structure(bundle.org.ou_structure)

        table = create_table(title="Synced Organizational Units")
        table.add_column("OU Name", style="cyan")
        table.add_column("OU ID", style="green")
        table.add_column("Status", style="bold")

        for name, ou_id in report.synced_ous.items():
            status = "[green]CREATED[/green]" if name in report.created_ous else "[dim]EXISTING[/dim]"
            table.add_row(name, ou_id, status)

        console.print(table)
    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]OU Sync Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)


@app.command("list")
def list_ous(
    region: str | None = typer.Option("eu-west-1", "--region", "-r", help="Primary AWS region"),
):
    """List existing Organizational Units in the AWS Organization."""
    print_header("List Organizational Units")
    try:
        session_mgr = AwsSessionManager(region_name=region)
        service = OUService(session_mgr)

        root_id = service.get_root_id()
        ou_map = service.list_all_ous(root_id)

        table = create_table(title=f"Organizational Units (Root: {root_id})")
        table.add_column("OU Name", style="cyan")
        table.add_column("OU ID", style="green")

        for name, ou_id in ou_map.items():
            table.add_row(name, ou_id)

        console.print(table)
    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]List OUs Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)
