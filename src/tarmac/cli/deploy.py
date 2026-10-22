"""The deploy, destroy and inventory commands."""

import json
import logging
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from ..core import inventory as inventory_mod
from ..core.adoption import set_adopt_existing
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, get_default_config_dir
from ..core.exceptions import GovernanceError
from ..core.logging import bind
from ..core.models import PreflightCheckStatus
from ..services.organization import OrganizationService
from ..services.plan import Planner
from ..services.preflight import PreflightService
from ..services.teardown import TeardownItemReport, TeardownService
from .common import (
    AdoptExistingOption,
    ConfigDirOption,
    JsonOption,
    RegionOption,
    TagsOption,
    YesOption,
    confirm_or_exit,
    load_configs_or_exit,
    parse_tags_or_exit,
    require_credentials_or_exit,
)
from .deploy_phases import (
    _run_phase_1_org,
    _run_phase_2_ou,
    _run_phase_3_cloudtrail,
    _run_phase_4_accounts,
    _run_phase_5_hardening,
    _run_phase_6_identity,
)
from .plan_view import render_plan
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
    1: "organization",
    2: "organizational-units",
    3: "cloudtrail",
    4: "accounts",
    5: "hardening",
    6: "identity",
}
ALL_PHASES = list(PHASE_NAMES)
REQUIRED_MILESTONES = {"org", "ou", "cloudtrail", "accounts", "hardening", "identity"}

logger = logging.getLogger(__name__)

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


def _usage_error(message: str) -> typer.Exit:
    error_console.print(f"[red]✗ {message}[/red]")
    return typer.Exit(code=2)


def _validate_phase(phase: int | None, allowed: range) -> None:
    """Reject phase numbers outside the supported range instead of silently doing nothing."""
    if phase is not None and phase not in allowed:
        raise _usage_error(f"Invalid phase: {phase}. Must be between {allowed.start} and {allowed.stop - 1}.")


def _refuse_root_identity(session_mgr: AwsSessionManager) -> None:
    """Stop with unusable credentials, or with root credentials (they cannot assume member roles)."""
    require_credentials_or_exit(session_mgr)
    try:
        is_root = session_mgr.is_root_identity()
    except Exception as e:  # unauthenticated: let the phases report it in context
        logger.debug("Root identity check skipped: %s", e)
        return
    if is_root is True:
        error_console.print(
            Panel(
                "You are signed in as the AWS root user. Root cannot call sts:AssumeRole, so tarmac cannot reach "
                "member accounts. To get non-root credentials, once:\n"
                "  1. In the console, enable IAM Identity Center and turn on Settings → Authentication → "
                "Send email OTP.\n"
                "  2. [bold]tarmac access sso[/bold]\n"
                "  3. [bold]aws sso login --use-device-code --profile tarmac[/bold]\n"
                "  4. [bold]export AWS_PROFILE=tarmac[/bold], then run this command again.",
                title="[bold red]Root Credentials Not Supported[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)


def _preflight_gate(session_mgr: AwsSessionManager, bundle: ConfigBundle, json_output: bool) -> None:
    """Run the `tarmac preflight` checks before a full deployment and stop on blocking failures."""
    report = PreflightService(session_mgr, bundle).run_all_checks()
    if report.failures:
        failures = [c for c in report.checks if c.status == PreflightCheckStatus.FAIL]
        raise GovernanceError(
            f"Pre-flight found {report.failures} blocking problem(s); nothing was deployed.",
            details="\n".join(f"{c.name}: {c.action_required}" for c in failures)
            + "\nRun `tarmac preflight` for the full report, or re-run with --skip-preflight to bypass.",
        )
    if report.warnings and not json_output:
        print_warning(f"Pre-flight passed with {report.warnings} warning(s); `tarmac preflight` lists them.")


def _check_deploy_options(
    phase: int | None, accounts: list[str] | None, skip_preflight: bool, bundle: ConfigBundle
) -> None:
    if accounts and phase != 4:
        raise _usage_error("--account only applies to phase 4; add --phase 4.")
    if skip_preflight and phase is not None:
        raise _usage_error("--skip-preflight applies to a full deployment; --phase never runs pre-flight.")
    unknown = [name for name in accounts or [] if bundle.get_account(name) is None]
    if unknown:
        raise _usage_error(f"Not declared in accounts.yaml: {', '.join(unknown)}.")


def _run_phases(
    phases: list[int],
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    region_override: str | None,
    custom_tags: dict[str, str],
    accounts: list[str] | None,
) -> None:
    project_root = bundle.config_dir.parent
    runners = {
        1: lambda: _run_phase_1_org(session_mgr, bundle),
        2: lambda: _run_phase_2_ou(session_mgr, bundle, project_root, custom_tags=custom_tags),
        3: lambda: _run_phase_3_cloudtrail(
            session_mgr, bundle, target_region, project_root, custom_tags=custom_tags
        ),
        4: lambda: _run_phase_4_accounts(
            session_mgr, bundle, project_root, custom_tags=custom_tags, only=accounts
        ),
        5: lambda: _run_phase_5_hardening(
            session_mgr,
            bundle,
            target_region,
            project_root,
            custom_tags=custom_tags,
            skip_log_archive_hardening=3 in phases,
        ),
        6: lambda: _run_phase_6_identity(
            session_mgr, bundle, project_root, region_override=region_override, custom_tags=custom_tags
        ),
    }
    for number in phases:
        with bind(phase=PHASE_NAMES[number]):
            runners[number]()


def deploy_command(
    phase: Annotated[int | None, typer.Option("--phase", help="Run only this phase (1-6)")] = None,
    accounts: Annotated[
        list[str] | None,
        typer.Option(
            "--account",
            "-a",
            help="With --phase 4: provision, tag and baseline only this declared account (repeatable)",
        ),
    ] = None,
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what each phase would change, using read-only AWS calls")
    ] = False,
    yes: YesOption = False,
    skip_preflight: Annotated[
        bool,
        typer.Option("--skip-preflight", help="Do not run the pre-flight checks before a full deployment"),
    ] = False,
    json_output: JsonOption = False,
    tags: TagsOption = None,
    adopt_existing: AdoptExistingOption = False,
) -> None:
    """Deploy the landing zone: every phase in order, or one phase with --phase."""
    set_adopt_existing(adopt_existing)
    _validate_phase(phase, range(1, 7))
    _require_yes_for_json(dry_run, yes, json_output)
    bundle = load_configs_or_exit(config_dir)
    _check_deploy_options(phase, accounts, skip_preflight, bundle)
    confirm_or_exit(
        "Are you sure you want to run the live multi-account deployment?",
        yes=yes,
        dry_run=dry_run,
        cancelled="Deployment cancelled by user.",
    )
    custom_tags = parse_tags_or_exit(tags)

    target_region = region or bundle.org.organization.primary_region
    session_mgr = AwsSessionManager(region_name=target_region)
    phases = [phase] if phase is not None else ALL_PHASES
    _refuse_root_identity(session_mgr)

    try:
        if dry_run:
            plan = Planner(
                session_mgr,
                bundle,
                target_region,
                bundle.config_dir.parent,
                custom_tags=custom_tags,
                identity_region=region,
                only_accounts=accounts,
            ).build(phases)
            if json_output:
                print(json.dumps(plan.to_dict(), indent=2))
            else:
                render_plan(plan)
            return

        if not json_output:
            print_header("AWS Governance: End-to-End Deployment")
        if phase is None and not skip_preflight:
            _preflight_gate(session_mgr, bundle, json_output)
        _run_phases(phases, session_mgr, bundle, target_region, region, custom_tags, accounts)

        mgmt_id = str(session_mgr.get_caller_identity().get("Account", ""))
        org_service = OrganizationService(session_mgr)
        if mgmt_id and REQUIRED_MILESTONES.issubset(org_service.get_completed_phases(mgmt_id)):
            org_service.mark_deployment_ready(mgmt_id)
        if json_output:
            payload = {"status": "COMPLETED", "phases_executed": phases, "management_account_id": mgmt_id}
            print(json.dumps(payload, indent=2))
        else:
            print_success("Deployment completed successfully!")
    except GovernanceError as e:
        if json_output:
            print(json.dumps({"status": "FAILED", "error": str(e)}, indent=2))
        else:
            title = "Plan Failed" if dry_run else "Deployment Failed"
            error_console.print(Panel(str(e), title=f"[bold red]{title}[/bold red]", border_style="red"))
        raise typer.Exit(code=1) from e


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
    # Check every tag source on its own: a lower-precedence `Environment: dev` must not hide `Environment: prod`.
    sources = [
        bundle.get_organization_tags(),
        dict(bundle.org.tags or {}),
        dict(bundle.org.organization.tags or {}),
        dict(bundle.accounts.tags or {}),
    ]
    is_prod = any(_is_production_tagged(tags) for tags in sources)
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


def destroy_command(
    phase: Annotated[int | None, typer.Option("--phase", help="Tear down only this phase (2-6)")] = None,
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate teardown without deleting resources")
    ] = False,
    yes: YesOption = False,
    force: Annotated[bool, typer.Option("--force", help="Bypass production environment safety lock")] = False,
    preserve_backend: Annotated[
        bool,
        typer.Option("--preserve-backend", help="Preserve Terraform backend state bucket and lock table"),
    ] = False,
    disable_security_services: Annotated[
        bool,
        typer.Option(
            "--disable-security-services",
            help=(
                "Also disable GuardDuty/Security Hub/Config delegation tarmac set up (runs with Phase 5). "
                "Deletes finding history."
            ),
        ),
    ] = False,
    everything: Annotated[
        bool,
        typer.Option(
            "--everything",
            help=(
                "Full teardown: also remove OUs, Identity Center users/groups, organization settings and the "
                "access role that tarmac created (never member accounts)"
            ),
        ),
    ] = False,
    inventory_from_log: Annotated[
        Path | None,
        typer.Option(
            "--inventory-from-log",
            help="With --everything: rebuild the record of what tarmac created from a run log (TARMAC_LOG_FILE)",
        ),
    ] = None,
    json_output: JsonOption = False,
) -> None:
    """Tear down and delete deployed resources across phases."""
    _validate_phase(phase, range(2, 7))
    _require_yes_for_json(dry_run, yes, json_output)
    if everything and phase is not None:
        raise _usage_error("--everything removes the whole deployment and cannot be combined with --phase.")
    bundle = load_configs_or_exit(config_dir)

    _enforce_production_lock(bundle, dry_run=dry_run, force=force)

    inv = _load_inventory(config_dir, inventory_from_log) if everything else None
    _confirm_teardown(
        bundle, inv, dry_run=dry_run, yes=yes, disable_security_services=disable_security_services
    )

    target_region = region or bundle.org.organization.primary_region
    session_mgr = AwsSessionManager(region_name=target_region)
    require_credentials_or_exit(session_mgr)

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

    try:
        report = service.teardown_all(
            bundle,
            target_region=target_region,
            dry_run=dry_run,
            phases=phases,
            preserve_backend=preserve_backend,
            disable_security_services=disable_security_services,
            inventory=inv,
        )
    except GovernanceError as e:
        if json_output:
            print(json.dumps({"status": "FAILED", "error": str(e)}, indent=2))
            raise typer.Exit(code=1) from e
        error_console.print(Panel(str(e), title="[bold red]Teardown Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1) from e

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


def inventory_command(
    config_dir: ConfigDirOption = None,
    from_log: Annotated[
        Path | None,
        typer.Option("--from-log", help="Rebuild the inventory from a tarmac run log (TARMAC_LOG_FILE)"),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output the inventory as JSON")] = False,
) -> None:
    """Show what tarmac recorded as created by it (used by `tarmac destroy --everything`)."""
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
