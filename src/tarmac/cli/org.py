"""CLI commands for AWS Organizations and Management Account bootstrap."""

from pathlib import Path
from typing import Annotated

import typer
from botocore.exceptions import ClientError

from ..core.adoption import set_adopt_existing
from ..core.aws_client import AwsSessionManager
from ..core.exceptions import GovernanceError, aws_error_message
from ..core.models import SCPReconciliationResult, VpcCleanupReport
from ..services.baseline import BaselineService
from ..services.organization import OrganizationService
from ..services.ou import OUService
from ..services.scp import SCPService
from .common import (
    AdoptExistingOption,
    ConfigDirOption,
    RegionOption,
    exit_on_error,
    get_active_account_id_map,
    load_configs_or_exit,
)
from .ui import console, create_table, error_console, print_header, print_info, print_success, print_warning

app = typer.Typer(help="AWS Organizations and Management Account governance.")


@app.command("bootstrap")
def bootstrap(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
):
    """Bootstrap AWS Organizations with ALL features, alternate contacts, and trusted services."""
    print_header("AWS Organizations Bootstrap")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Bootstrap Failed"):
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
                failed = [r for r in vpc_reports if r.error]
                for r in failed:
                    print_warning(f"Default VPC cleanup failed in {r.region}: {r.message}")
                if failed:
                    raise GovernanceError(f"Default VPC cleanup failed in {len(failed)} region(s).")


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
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate cleanup without deleting resources")
    ] = False,
):
    """Scan and purge default VPCs in the AWS Management Account across all enabled regions."""
    print_header("Management Account: Default VPC Cleanup")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("VPC Cleanup Failed"):
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


@app.command("contacts")
def set_contacts(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
):
    """Set alternate contacts (Billing, Operations, Security) on the Management Account."""
    print_header("Set Account Alternate Contacts")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Contacts Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OrganizationService(session_mgr)
        updated = service.set_account_contacts(bundle.org.contacts)
        print_success(f"Successfully configured contacts: {', '.join(updated)}")


@app.command("root-access")
def enable_root_access(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
):
    """Enable centralized root access management and privileged root sessions."""
    print_header("Enable Centralized Root Access Management")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Root Access Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = OrganizationService(session_mgr)
        caller = session_mgr.get_caller_identity()
        mgmt_id = str(caller.get("Account", ""))
        acct_id_map = get_active_account_id_map(session_mgr)
        results = service.configure_root_access(
            bundle.org.root_access_management,
            account_id_map=acct_id_map,
            management_account_id=mgmt_id,
        )
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


@app.command("activate-cost-tags")
def activate_cost_tags_command(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
) -> None:
    """Activate user-defined and AWS-generated cost allocation tags in AWS Cost Explorer."""
    print_header("Cost Allocation Tags: Activation")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Cost Allocation Tag Activation Failed"):
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


def _has_active_scp_stack(session_mgr: AwsSessionManager, org_name: str) -> bool:
    """Return True if the organization SCP CloudFormation stack exists in a usable state.

    Only "stack does not exist" means False. Any other error is raised: falling back to changing stack-managed
    policies directly is the drift this check exists to prevent.
    """
    cfn_client = session_mgr.get_client("cloudformation")
    try:
        resp = cfn_client.describe_stacks(StackName=f"{org_name}-organization-scps")
    except ClientError as e:
        if "does not exist" in aws_error_message(e):
            return False
        raise GovernanceError(
            f"Could not check whether the SCP stack '{org_name}-organization-scps' exists", details=str(e)
        ) from e
    stacks = resp.get("Stacks", [])
    if not (stacks and isinstance(stacks, list)):
        return False
    return stacks[0].get("StackStatus") in (
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "IMPORT_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    )


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
    with exit_on_error("SCP Reconciliation Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        ou_service = OUService(session_mgr)
        scp_service = SCPService(session_mgr)

        root_id = ou_service.get_root_id()
        ou_map = ou_service.list_all_ous(root_id)

        stack_managed = _has_active_scp_stack(session_mgr, bundle.org.organization.name)
        if stack_managed and dry_run:
            print_info(
                f"SCPs are managed by the '{bundle.org.organization.name}-organization-scps' stack; apply will "
                "update them through CloudFormation. The plan below shows the differences it will resolve."
            )
        if stack_managed and not dry_run:
            results = scp_service.reconcile_via_cloudformation(
                config=scp_config,
                root_id=root_id,
                ou_map=ou_map,
                project_root=bundle.config_dir.parent,
                org_name=bundle.org.organization.name,
                org_tags=bundle.get_organization_tags(),
                dry_run=dry_run,
            )
        else:
            results = scp_service.reconcile_all(
                config=scp_config,
                root_id=root_id,
                ou_map=ou_map,
                project_root=bundle.config_dir.parent,
                dry_run=dry_run,
            )
        _render_scp_results(results)
        unresolved = {r.name: r.unresolved_targets for r in results if r.unresolved_targets}
        if unresolved:
            details = "; ".join(f"{name}: {', '.join(targets)}" for name, targets in unresolved.items())
            error_console.print(f"[red]✗[/red] SCP targets not found in the organization: {details}")
            raise typer.Exit(code=1)


@scp_app.command("plan")
def plan_scps(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    adopt_existing: AdoptExistingOption = False,
) -> None:
    """Preview Service Control Policy changes without applying them."""
    set_adopt_existing(adopt_existing)
    print_header("Service Control Policies Plan (Dry-Run)")
    _execute_scp_reconciliation(config_dir, region, dry_run=True)


@scp_app.command("apply")
def apply_scps(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview changes without applying")] = False,
    adopt_existing: AdoptExistingOption = False,
) -> None:
    """Reconcile and attach declared Service Control Policies."""
    set_adopt_existing(adopt_existing)
    mode = "Dry-Run" if dry_run else "Apply"
    print_header(f"Service Control Policies ({mode})")
    _execute_scp_reconciliation(config_dir, region, dry_run=dry_run)
