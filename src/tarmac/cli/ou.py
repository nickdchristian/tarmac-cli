"""CLI commands for Organizational Unit (OU) management."""

from typing import Annotated

import typer

from ..core.aws_client import AwsSessionManager
from ..services.ou import OUService
from .common import ConfigDirOption, RegionOption, exit_on_error, load_configs_or_exit
from .ui import console, create_table, print_header

app = typer.Typer(help="Organizational Unit (OU) tree management.")


@app.command("sync")
def sync_ous(config_dir: ConfigDirOption = None, region: RegionOption = None):
    """Reconcile and idempotently create the declared OU structure."""
    print_header("Sync Organizational Units")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("OU Sync Failed"):
        service = OUService(AwsSessionManager(region_name=target_region))
        report = service.sync_ou_structure(bundle.org.ou_structure)

        table = create_table(title="Synced Organizational Units")
        table.add_column("OU Name", style="cyan")
        table.add_column("OU ID", style="green")
        table.add_column("Status", style="bold")
        for name, ou_id in report.synced_ous.items():
            status = "[green]CREATED[/green]" if name in report.created_ous else "[dim]EXISTING[/dim]"
            table.add_row(name, ou_id, status)
        console.print(table)


@app.command("list")
def list_ous(
    region: Annotated[str | None, typer.Option("--region", "-r", help="Primary AWS region")] = "eu-west-1",
):
    """List existing Organizational Units in the AWS Organization."""
    print_header("List Organizational Units")
    with exit_on_error("List OUs Failed"):
        service = OUService(AwsSessionManager(region_name=region))
        root_id = service.get_root_id()

        table = create_table(title=f"Organizational Units (Root: {root_id})")
        table.add_column("OU Name", style="cyan")
        table.add_column("OU ID", style="green")
        for name, ou_id in service.list_all_ous(root_id).items():
            table.add_row(name, ou_id)
        console.print(table)
