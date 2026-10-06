from pathlib import Path

import typer
from rich.panel import Panel

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import GovernanceError
from ..services.identity import IdentityService
from .common import load_configs_or_exit
from .ui import console, create_table, error_console, print_header, print_success

app = typer.Typer(help="IAM Identity Center (SSO) governance commands.")


@app.command("status")
def identity_status(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """Check IAM Identity Center instance and store details."""
    print_header("Identity Center Status")
    bundle = load_configs_or_exit(config_dir)
    id_cfg = bundle.identity.identity_center
    target_region = region or id_cfg.region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = IdentityService(session_mgr, preferred_region=target_region)
        arn, store_id = service.get_instance_details()
        table = create_table(title="IAM Identity Center Status")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Instance ARN", arn)
        table.add_row("Identity Store ID", store_id)
        table.add_row("Region", str(service.region))
        table.add_row("Access Portal URL", f"https://{store_id}.awsapps.com/start")
        console.print(table)
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Identity Center Error[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("sync")
def sync_identity(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate sync without making changes"),
):
    """Sync permission sets, groups, users, and multi-account assignments."""
    print_header("Sync IAM Identity Center")
    bundle = load_configs_or_exit(config_dir)
    id_cfg = bundle.identity.identity_center
    target_region = region or id_cfg.region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = IdentityService(session_mgr, preferred_region=target_region)
        project_root = bundle.config_dir.parent

        report = service.sync_identity(
            id_cfg,
            project_root=project_root,
            org_name=bundle.org.organization.name,
            dry_run=dry_run,
            org_tags=bundle.get_organization_tags(),
        )

        print_success(f"Synchronized {len(report.permission_sets_synced)} permission set(s).")
        print_success(f"Synchronized {len(report.users_synced)} user(s).")
        print_success(f"Configured {report.assignments_created} group account assignment(s).")
        print_success(f"Synchronized group memberships ({report.memberships_added} added).")
        print_success("IAM Identity Center synchronization complete!")

    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Identity Center Sync Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)
