"""CLI commands for IAM Identity Center (SSO) governance."""

from typing import Annotated

import typer

from ..core.aws_client import AwsSessionManager
from ..services.identity import IdentityService
from .common import ConfigDirOption, RegionOption, exit_on_error, load_configs_or_exit
from .ui import console, create_table, print_header, print_success

app = typer.Typer(help="IAM Identity Center (SSO) governance commands.")


@app.command("status")
def identity_status(config_dir: ConfigDirOption = None, region: RegionOption = None):
    """Check IAM Identity Center instance and store details."""
    print_header("Identity Center Status")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.identity.identity_center.region or bundle.org.organization.primary_region

    with exit_on_error("Identity Center Error"):
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


@app.command("sync")
def sync_identity(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Simulate sync without making changes")] = False,
):
    """Sync permission sets, groups, users, and multi-account assignments."""
    print_header("Sync IAM Identity Center")
    bundle = load_configs_or_exit(config_dir)
    id_cfg = bundle.identity.identity_center
    target_region = region or id_cfg.region or bundle.org.organization.primary_region

    with exit_on_error("Identity Center Sync Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = IdentityService(session_mgr, preferred_region=target_region)
        report = service.sync_identity(
            id_cfg,
            project_root=bundle.config_dir.parent,
            org_name=bundle.org.organization.name,
            dry_run=dry_run,
            org_tags=bundle.get_organization_tags(),
        )

        print_success(f"Synchronized {len(report.permission_sets_synced)} permission set(s).")
        print_success(f"Synchronized {len(report.users_synced)} user(s).")
        print_success(f"Configured {report.assignments_created} group account assignment(s).")
        print_success(f"Synchronized group memberships ({report.memberships_added} added).")
        print_success("IAM Identity Center synchronization complete!")
