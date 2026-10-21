"""CLI commands for Organizational Unit (OU) management."""

import typer

from ..core.aws_client import AwsSessionManager
from ..services.ou import OUService
from .common import ConfigDirOption, RegionOption, exit_on_error, load_configs_or_exit
from .ui import console, create_table, print_header

app = typer.Typer(help="Organizational Unit (OU) tree management.")


@app.command("list")
def list_ous(config_dir: ConfigDirOption = None, region: RegionOption = None):
    """List existing Organizational Units in the AWS Organization."""
    print_header("List Organizational Units")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("List OUs Failed"):
        service = OUService(AwsSessionManager(region_name=target_region))
        root_id = service.get_root_id()

        table = create_table(title=f"Organizational Units (Root: {root_id})")
        table.add_column("OU Name", style="cyan")
        table.add_column("OU ID", style="green")
        for name, ou_id in service.list_all_ous(root_id).items():
            table.add_row(name, ou_id)
        console.print(table)
