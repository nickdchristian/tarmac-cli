"""End-to-End Orchestrated Pipeline Deployment."""

import json
import logging
from pathlib import Path
from typing import Any

import typer
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from ..core import inventory as inventory_mod
from ..core.adoption import set_adopt_existing
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, get_default_config_dir
from ..core.config_schema import OUDef
from ..core.exceptions import GovernanceError
from ..core.logging import bind
from ..core.models import PreflightCheckStatus, PreflightReport, StackDeployReport
from ..core.templates import resolve_resource_path
from ..services.accounts import AccountService
from ..services.baseline import BaselineService
from ..services.cloudformation import CloudFormationService
from ..services.identity import IdentityService
from ..services.organization import OrganizationService
from ..services.ou import OUService
from ..services.preflight import PreflightService
from ..services.scp import SCPService
from ..services.security import SecurityServicesService
from ..services.teardown import TeardownItemReport, TeardownService
from .common import get_active_account_id_map, load_configs_or_exit, parse_tags_or_exit
from .deploy_dry_run import (
    _build_dry_run_plan_dict,
    _collect_ou_tree,
    _format_policy_name,
    _render_dry_run_summary,
    _render_phase_0_dry_run,
    _render_phase_1_dry_run,
    _render_phase_2_dry_run,
    _render_phase_3_dry_run,
    _render_phase_4_dry_run,
    _render_phase_5_dry_run,
    _render_phase_6_dry_run,
)
from .deploy_phases import (
    _delegate_security_services,
    _deploy_backend_stack,
    _deploy_hardening_stacks,
    _deploy_log_archive_hardening_stack,
    _ensure_delegated_admin,
    _handle_preflight_failures,
    _run_phase_0_preflight,
    _run_phase_1_org,
    _run_phase_2_ou,
    _run_phase_3_cloudtrail,
    _run_phase_4_accounts,
    _run_phase_5_hardening,
    _run_phase_6_identity,
)
from .ui import (
    console,
    create_table,
    error_console,
    print_header,
    print_info,
    print_success,
    print_warning,
)

PHASE_NAMES = {
    0: "preflight",
    1: "organization",
    2: "organizational-units",
    3: "cloudtrail",
    4: "accounts",
    5: "hardening",
    6: "identity",
}

logger = logging.getLogger(__name__)

app = typer.Typer(help="End-to-end orchestrated governance deployment.")

__all__ = [
    "AccountService",
    "AwsSessionManager",
    "BaselineService",
    "CloudFormationService",
    "ConfigBundle",
    "GovernanceError",
    "IdentityService",
    "OUDef",
    "OUService",
    "OrganizationService",
    "PreflightCheckStatus",
    "PreflightReport",
    "PreflightService",
    "SCPService",
    "SecurityServicesService",
    "StackDeployReport",
    "TeardownItemReport",
    "TeardownService",
    "_build_dry_run_plan_dict",
    "_collect_ou_tree",
    "_delegate_security_services",
    "_deploy_backend_stack",
    "_deploy_hardening_stacks",
    "_deploy_log_archive_hardening_stack",
    "_ensure_delegated_admin",
    "_format_policy_name",
    "_handle_preflight_failures",
    "_render_dry_run_summary",
    "_render_phase_0_dry_run",
    "_render_phase_1_dry_run",
    "_render_phase_2_dry_run",
    "_render_phase_3_dry_run",
    "_render_phase_4_dry_run",
    "_render_phase_5_dry_run",
    "_render_phase_6_dry_run",
    "_run_phase_0_preflight",
    "_run_phase_1_org",
    "_run_phase_2_ou",
    "_run_phase_3_cloudtrail",
    "_run_phase_4_accounts",
    "_run_phase_5_hardening",
    "_run_phase_6_identity",
    "app",
    "destroy_pipeline",
    "get_active_account_id_map",
    "load_configs_or_exit",
    "parse_tags_or_exit",
    "resolve_resource_path",
    "run_pipeline",
    "teardown_pipeline",
]


PRODUCTION_ENV_VALUES = frozenset({"production", "prod", "prd"})
PRODUCTION_ENV_TAG_KEYS = ("environment", "env", "stage")


def _is_production_tagged(tags: dict[str, str]) -> bool:
    """Return True if any environment-style tag marks the organization as production."""
    return any(
        str(value).strip().lower() in PRODUCTION_ENV_VALUES
        for key, value in tags.items()
        if key.strip().lower() in PRODUCTION_ENV_TAG_KEYS
    )


def _require_yes_for_json(dry_run: bool, yes: bool, json_output: bool) -> None:
    """--json only changes the output format; it must never stand in for consent on live changes."""
    if json_output and not (dry_run or yes):
        error_console.print(
            "[red]✗ --json cannot prompt for confirmation. Re-run with --yes to confirm a live "
            "operation, or with --dry-run to preview it.[/red]"
        )
        raise typer.Exit(code=2)


def _validate_phase(phase: int | None, allowed: range) -> None:
    """Reject phase numbers outside the supported range instead of silently doing nothing."""
    if phase is not None and phase not in allowed:
        error_console.print(
            f"[red]✗ Invalid phase: {phase}. Must be between {allowed.start} and {allowed.stop - 1}.[/red]"
        )
        raise typer.Exit(code=2)


def _confirm_deployment(dry_run: bool, yes: bool) -> None:
    """Prompt user for confirmation unless bypassed."""
    if dry_run or yes:
        return
    confirmed = typer.confirm(
        "Are you sure you want to run the live multi-account deployment?", default=False
    )
    if not confirmed:
        print_info("Deployment cancelled by user.")
        raise typer.Exit(code=0)


def _refuse_root_identity(session_mgr: AwsSessionManager, dry_run: bool = False) -> None:
    """Stop live runs made with root credentials (they cannot assume member-account roles)."""
    if dry_run:
        return
    try:
        is_root = session_mgr.is_root_identity()
    except Exception as e:  # unauthenticated: let the phases report it in context
        logger.debug("Root identity check skipped: %s", e)
        return
    if is_root is True:
        error_console.print(
            Panel(
                "You are authenticated as the account root user. Root cannot call sts:AssumeRole, "
                "so tarmac cannot reach member accounts.\n"
                "Run [bold]tarmac access template[/bold], deploy it, and re-run as the tarmac role "
                "(see README: Bootstrap access).",
                title="[bold red]Root Credentials Not Supported[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)


def _resolve_phases_to_run(phase: int | None, skip_preflight: bool) -> list[int]:
    """Determine the list of phases to execute based on flags."""
    if phase is not None:
        return [phase]
    return [1, 2, 3, 4, 5, 6] if skip_preflight else [0, 1, 2, 3, 4, 5, 6]


def _resolve_management_account_id(session_mgr: AwsSessionManager, *, dry_run: bool) -> str:
    """Return the caller's account ID; during a dry-run, tolerate missing credentials."""
    if not dry_run:
        return str(session_mgr.get_caller_identity().get("Account", ""))
    try:
        if session_mgr._root_session.get_credentials() is not None:
            return str(session_mgr.get_caller_identity().get("Account", ""))
    except Exception as e:
        logger.debug("Caller identity unavailable during dry-run: %s", e)
    return ""


@app.command("run")
def run_pipeline(
    phase: int | None = typer.Option(None, "--phase", "-p", help="Specific phase to run (0-6)"),
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate pipeline without executing changes"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt for automated deployment"),
    skip_preflight: bool = typer.Option(False, "--skip-preflight", help="Bypass pre-flight readiness checks"),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
    adopt_existing: bool = typer.Option(
        False,
        "--adopt-existing",
        help="Take over existing SCPs and budgets with the same name that tarmac did not create (default: stop)",
    ),
) -> None:
    """Run end-to-end deployment or a specific phase in deterministic order."""
    set_adopt_existing(adopt_existing)
    _validate_phase(phase, range(0, 7))
    _require_yes_for_json(dry_run, yes, json_output)
    _confirm_deployment(dry_run=dry_run, yes=yes)

    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)

    target_region = region or bundle.org.organization.primary_region
    session_mgr = AwsSessionManager(region_name=target_region)
    _refuse_root_identity(session_mgr, dry_run)
    project_root = bundle.config_dir.parent
    org_service = OrganizationService(session_mgr)

    phases_to_run = _resolve_phases_to_run(phase, skip_preflight)

    if json_output and dry_run:
        plan_dict = _build_dry_run_plan_dict(
            phases_to_run,
            bundle,
            session_mgr,
            target_region,
            region_override=region,
        )
        print(json.dumps(plan_dict, indent=2))
        return

    if not json_output:
        if dry_run:
            console.print(
                Panel(
                    "[bold yellow]Tarmac Landing Zone: Dry-Run Execution Plan (Simulation Mode)[/bold yellow]\n"
                    "[dim]Validating configuration files and simulating pipeline actions without modifying AWS resources.[/dim]",
                    border_style="yellow",
                    padding=(0, 2),
                    expand=False,
                )
            )
        else:
            print_header("AWS Governance: End-to-End Deployment")

    mgmt_id = _resolve_management_account_id(session_mgr, dry_run=dry_run)

    if mgmt_id and not dry_run and not json_output:
        completed_milestones = org_service.get_completed_phases(mgmt_id)
        if completed_milestones:
            print_info(f"⚡ Discovered completed milestones: {', '.join(sorted(completed_milestones))}")

    try:
        phase_runners = {
            0: lambda: _run_phase_0_preflight(session_mgr, bundle, dry_run),
            1: lambda: _run_phase_1_org(session_mgr, bundle, dry_run),
            2: lambda: _run_phase_2_ou(session_mgr, bundle, project_root, dry_run, custom_tags=custom_tags),
            3: lambda: _run_phase_3_cloudtrail(
                session_mgr, bundle, target_region, project_root, dry_run, custom_tags=custom_tags
            ),
            4: lambda: _run_phase_4_accounts(
                session_mgr, bundle, project_root, dry_run, custom_tags=custom_tags
            ),
            5: lambda: _run_phase_5_hardening(
                session_mgr,
                bundle,
                target_region,
                project_root,
                dry_run,
                custom_tags=custom_tags,
                skip_log_archive_hardening=(3 in phases_to_run),
            ),
            6: lambda: _run_phase_6_identity(
                session_mgr,
                bundle,
                project_root,
                dry_run,
                region_override=region,
                custom_tags=custom_tags,
            ),
        }

        for p in phases_to_run:
            runner = phase_runners.get(p)
            if runner:
                with bind(phase=PHASE_NAMES.get(p, str(p))):
                    runner()
            else:
                if json_output:
                    print(json.dumps({"status": "FAILED", "error": f"Invalid phase: {p}"}, indent=2))
                else:
                    error_console.print(f"[red]✗[/red] Invalid phase: {p}. Must be 0 to 6.")
                raise typer.Exit(code=1)

        if dry_run:
            _render_dry_run_summary(phases_to_run, bundle)
        elif json_output:
            result_payload = {
                "dry_run": False,
                "status": "COMPLETED",
                "phases_executed": phases_to_run,
                "management_account_id": mgmt_id,
            }
            print(json.dumps(result_payload, indent=2))
        else:
            if mgmt_id:
                completed = org_service.get_completed_phases(mgmt_id)
                required_phases = {"org", "ou", "cloudtrail", "accounts", "hardening", "identity"}
                if required_phases.issubset(completed):
                    org_service.mark_deployment_ready(mgmt_id)
            print_success("Deployment pipeline completed successfully!")

    except GovernanceError as e:
        if json_output:
            print(json.dumps({"status": "FAILED", "error": str(e)}, indent=2))
        else:
            error_console.print(
                Panel(str(e), title="[bold red]Deployment Failed[/bold red]", border_style="red")
            )
        raise typer.Exit(code=1)


_TEARDOWN_FAILED_STYLE = "[bold red]FAILED[/bold red]"
_TEARDOWN_ACTION_STYLES = {
    "DELETED": "[bold green]DELETED[/bold green]",
    "EMPTY": "[bold green]DELETED[/bold green]",
    "SIMULATED": "[bold yellow]WOULD DELETE[/bold yellow]",
    "NOT_FOUND": "[dim]NOT FOUND[/dim]",
    "SKIPPED": "[yellow]SKIPPED[/yellow]",
}


_TEARDOWN_RETAINED = (
    "Organizational Units and member accounts (use `tarmac account suspend --close` per account; "
    "AWS reserves a closed account's email, so reuse needs a new email)",
    "GuardDuty / Security Hub / AWS Config delegation and member detectors "
    "(pass --disable-security-services to remove them; this deletes findings)",
    "IAM Identity Center users and groups (permission sets and their assignments are removed)",
    "Trusted service access and cost-allocation-tag activation in AWS Organizations",
)


_EVERYTHING_REMOVES = (
    "Stacks, buckets, budgets, SCPs, the organization trail and permission sets (as a normal teardown)",
    "Organizational Units tarmac created, if they are empty",
    "Identity Center users and groups tarmac created, with their assignments",
    "Trusted access, delegated administrators, root-access features, alternate contacts and cost tags tarmac enabled",
    "The tarmac-access stack (TarmacDeploymentRole) and the tarmac-bootstrap IAM user",
)


def _print_teardown_retained_notice(security_disabled: bool = False) -> None:
    """Tell the user what a full teardown intentionally does not remove, so 'start over' is predictable."""
    print_info("Not removed by teardown (a redeploy reuses or reconciles these):")
    for line in _TEARDOWN_RETAINED:
        if security_disabled and "GuardDuty" in line:
            continue
        console.print(f"  [dim]• {escape(line)}[/dim]")


def _enforce_production_lock(bundle: Any, *, dry_run: bool, force: bool) -> None:
    """Refuse to tear down an organization tagged as production unless --force is given."""
    is_prod = _is_production_tagged(bundle.get_organization_tags()) or _is_production_tagged(
        dict(bundle.org.organization.tags)
    )
    if is_prod and not dry_run and not force:
        error_console.print(
            "[bold red]⛔ SAFETY LOCK: Organization is tagged as 'production'.[/bold red]\n"
            "[red]Teardown would destroy production infrastructure and logs. "
            "To proceed, re-run with --force.[/red]"
        )
        raise typer.Exit(code=1)


def _print_teardown_item(item: TeardownItemReport) -> None:
    """Render one live teardown progress line."""
    r_type = escape(item.resource_type)
    r_name = escape(item.resource_name)
    acct = escape(item.account_name)
    msg = escape(item.message)
    if item.action in ("DELETED", "EMPTY"):
        console.print(
            f"  [bold green]✓[/bold green] [green]{item.action}[/green] {r_type} "
            f"[bold]{r_name}[/bold] ({acct}): [dim]{msg}[/dim]"
        )
    elif item.action == "SIMULATED":
        console.print(
            f"  [bold yellow]⚡[/bold yellow] [yellow]WOULD DELETE[/yellow] {r_type} "
            f"[bold]{r_name}[/bold] ({acct}): [dim]{msg}[/dim]"
        )
    elif item.action == "NOT_FOUND":
        console.print(f"  [dim]• NOT FOUND {r_type} {r_name} ({acct})[/dim]")
    elif item.action == "SKIPPED":
        console.print(f"  [yellow]• SKIPPED {r_type} {r_name} ({acct}): {msg}[/yellow]")
    elif item.action == "FAILED":
        console.print(
            f"  [bold red]✗ FAILED[/bold red] {r_type} [bold]{r_name}[/bold] ({acct}): [red]{msg}[/red]"
        )


def _teardown_json_payload(report: Any) -> dict[str, Any]:
    return {
        "status": report.status,
        "deleted_count": report.deleted_count,
        "failed_count": report.failed_count,
        "items": [
            {
                "type": i.resource_type,
                "name": i.resource_name,
                "account": i.account_name,
                "action": i.action,
                "message": i.message,
            }
            for i in report.items
        ],
    }


def _load_inventory(config_dir: Path | None, from_log: Path | None) -> inventory_mod.Inventory:
    """The active inventory (recorded by earlier runs), topped up from a run log when one is given."""
    inv = inventory_mod.active() or inventory_mod.activate(config_dir or get_default_config_dir())
    if from_log is not None:
        if not from_log.is_file():
            error_console.print(f"[red]✗[/red] Log file not found: {from_log}")
            raise typer.Exit(code=1)
        found = inv.ingest_log(from_log)
        print_info(f"Read {found} change(s) tarmac made from {from_log}.")
    return inv


def _confirm_everything(bundle: Any, inv: inventory_mod.Inventory) -> None:
    console.print("\n[bold red]FULL TEARDOWN[/bold red] removes everything tarmac created, including:")
    for line in _EVERYTHING_REMOVES:
        console.print(f"  [red]• {escape(line)}[/red]")
    console.print("Member accounts are [bold]never[/bold] closed by this command.")
    if inv.count() == 0:
        print_warning(
            "No record of what tarmac created was found, so OUs, Identity Center users and groups and "
            "organization settings will be left alone. Rebuild it with --inventory-from-log <run log>."
        )
    else:
        console.print(f"[dim]Inventory: {inv.count()} item(s) recorded at {inv.path}[/dim]")
    expected = bundle.org.organization.name
    typed = typer.prompt(
        f"Type the organization name ({expected}) to confirm", default="", show_default=False
    )
    if typed.strip() != expected:
        print_info("Teardown cancelled: the name did not match.")
        raise typer.Exit(code=0)


def _confirm_teardown(
    bundle: Any,
    inv: inventory_mod.Inventory | None,
    *,
    dry_run: bool,
    yes: bool,
    disable_security_services: bool,
) -> None:
    if dry_run or yes:
        return
    if inv is not None:
        _confirm_everything(bundle, inv)
        return
        confirm = typer.confirm(
            "⚠️  This will delete all deployed CloudFormation stacks, purge associated S3 log/state buckets, "
            "remove AWS Budgets, and detach SCPs"
            + (
                ", and DISABLE GuardDuty/Security Hub/Config delegation (finding history is deleted)"
                if disable_security_services
                else ""
            )
            + ". Continue?",
            default=False,
        )
        if not confirm:
            print_info("Teardown cancelled by user.")
            raise typer.Exit(code=0)


def _execute_teardown(
    phase: int | None,
    config_dir: Path | None,
    region: str | None,
    dry_run: bool,
    yes: bool,
    json_output: bool,
    force: bool = False,
    preserve_backend: bool = False,
    disable_security_services: bool = False,
    everything: bool = False,
    inventory_from_log: Path | None = None,
) -> None:
    _validate_phase(phase, range(2, 7))
    _require_yes_for_json(dry_run, yes, json_output)
    if everything and phase is not None:
        error_console.print(
            "[red]✗[/red] --everything removes the whole deployment and cannot be combined with --phase."
        )
        raise typer.Exit(code=2)
    bundle = load_configs_or_exit(config_dir)

    _enforce_production_lock(bundle, dry_run=dry_run, force=force)

    inv = _load_inventory(config_dir, inventory_from_log) if everything else None
    _confirm_teardown(
        bundle, inv, dry_run=dry_run, yes=yes, disable_security_services=disable_security_services
    )

    target_region = region or bundle.org.organization.primary_region
    session_mgr = AwsSessionManager(region_name=target_region)

    def _cli_on_phase(phase_title: str) -> None:
        console.print(f"\n[bold blue]─── {phase_title} ───[/bold blue]")

    def _cli_on_progress(msg: str) -> None:
        console.print(f"  [dim cyan]⏳ {escape(msg)}[/dim cyan]")

    on_phase_cb = _cli_on_phase if not json_output else None
    on_progress_cb = _cli_on_progress if not json_output else None
    on_item_cb = _print_teardown_item if not json_output else None

    service = TeardownService(
        session_mgr,
        on_progress=on_progress_cb,
        on_item=on_item_cb,
        on_phase=on_phase_cb,
    )
    phases = [phase] if phase is not None else None

    if not json_output:
        if dry_run:
            print_header("AWS Governance: Teardown Dry-Run (Simulation)")
        else:
            print_header("AWS Governance: Deleting Deployment Resources")

    report = service.teardown_all(
        bundle,
        target_region=target_region,
        dry_run=dry_run,
        phases=phases,
        preserve_backend=preserve_backend,
        disable_security_services=disable_security_services,
        inventory=inv,
    )

    if not json_output:
        console.print()

    if json_output:
        data = _teardown_json_payload(report)
        print(json.dumps(data, indent=2))
        if report.status == "FAILED":
            raise typer.Exit(code=1)
        return

    table = create_table(title="Teardown Summary")
    table.add_column("Resource Type", style="cyan")
    table.add_column("Resource Name", style="white")
    table.add_column("Account", style="blue")
    table.add_column("Action Taken", justify="center")
    table.add_column("Details", style="dim")

    for item in report.items:
        action_style = _TEARDOWN_ACTION_STYLES.get(item.action, _TEARDOWN_FAILED_STYLE)

        table.add_row(
            Text(item.resource_type),
            Text(item.resource_name),
            Text(item.account_name),
            action_style,
            Text(item.message),
        )

    console.print(table)
    if report.status == "FAILED":
        print_warning(f"Teardown finished with {report.failed_count} failure(s).")
        raise typer.Exit(code=1)
    if dry_run:
        print_info("Teardown dry-run simulation complete.")
    else:
        print_success(f"Teardown complete: {report.deleted_count} resource(s) removed.")
        if phase is None and not everything:
            _print_teardown_retained_notice(security_disabled=disable_security_services)
            print_info("Add --everything to also remove OUs, users, groups, settings and the access role.")


@app.command("teardown")
def teardown_pipeline(
    phase: int | None = typer.Option(None, "--phase", "-p", help="Specific phase to tear down (2-6)"),
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate teardown without deleting resources"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    force: bool = typer.Option(False, "--force", help="Bypass production environment safety lock"),
    preserve_backend: bool = typer.Option(
        False, "--preserve-backend", help="Preserve Terraform backend state bucket and lock table"
    ),
    disable_security_services: bool = typer.Option(
        False,
        "--disable-security-services",
        help=(
            "Also disable GuardDuty/Security Hub/Config delegation tarmac set up (runs with Phase 5). "
            "Deletes finding history."
        ),
    ),
    everything: bool = typer.Option(
        False,
        "--everything",
        help=(
            "Full teardown: also remove OUs, Identity Center users/groups, organization settings and the "
            "access role that tarmac created (never member accounts)"
        ),
    ),
    inventory_from_log: Path | None = typer.Option(
        None,
        "--inventory-from-log",
        help="With --everything: rebuild the record of what tarmac created from a run log (TARMAC_LOG_FILE)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
) -> None:
    """Tear down and delete deployed resources across phases."""
    _execute_teardown(
        phase,
        config_dir,
        region,
        dry_run,
        yes,
        json_output,
        force,
        preserve_backend,
        disable_security_services,
        everything,
        inventory_from_log,
    )


@app.command("destroy")
def destroy_pipeline(
    phase: int | None = typer.Option(None, "--phase", "-p", help="Specific phase to tear down (2-6)"),
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate teardown without deleting resources"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    force: bool = typer.Option(False, "--force", help="Bypass production environment safety lock"),
    preserve_backend: bool = typer.Option(
        False, "--preserve-backend", help="Preserve Terraform backend state bucket and lock table"
    ),
    disable_security_services: bool = typer.Option(
        False,
        "--disable-security-services",
        help=(
            "Also disable GuardDuty/Security Hub/Config delegation tarmac set up (runs with Phase 5). "
            "Deletes finding history."
        ),
    ),
    everything: bool = typer.Option(
        False,
        "--everything",
        help=(
            "Full teardown: also remove OUs, Identity Center users/groups, organization settings and the "
            "access role that tarmac created (never member accounts)"
        ),
    ),
    inventory_from_log: Path | None = typer.Option(
        None,
        "--inventory-from-log",
        help="With --everything: rebuild the record of what tarmac created from a run log (TARMAC_LOG_FILE)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format"),
) -> None:
    """Alias for 'tarmac deploy teardown': delete all deployment resources."""
    _execute_teardown(
        phase,
        config_dir,
        region,
        dry_run,
        yes,
        json_output,
        force,
        preserve_backend,
        disable_security_services,
        everything,
        inventory_from_log,
    )


@app.command("inventory")
def show_inventory(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    from_log: Path | None = typer.Option(
        None, "--from-log", help="Rebuild the inventory from a tarmac run log (TARMAC_LOG_FILE)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output the inventory as JSON"),
) -> None:
    """Show what tarmac recorded as created by it (used by `destroy --everything`)."""
    inv = _load_inventory(config_dir, from_log)
    if json_output:
        print(json.dumps(inv.entries, indent=2, sort_keys=True))
        return
    print_header("Tarmac Inventory")
    if inv.count() == 0:
        print_info(f"Nothing recorded yet ({inv.path}). Changes are recorded as tarmac makes them.")
        return
    table = create_table(title=str(inv.path))
    table.add_column("Kind", style="cyan")
    table.add_column("Item", style="white")
    for kind, entries in sorted(inv.entries.items()):
        for key in sorted(entries):
            table.add_row(kind, key)
    console.print(table)
