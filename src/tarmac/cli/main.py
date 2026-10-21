"""Main entrypoint for the tarmac CLI."""

import dataclasses
import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel

from .. import __version__
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, load_all_configs
from ..core.logging import setup_logging, start_run
from ..core.placeholders import find_placeholder_values
from ..services.drift import DriftService
from ..services.identity import SUPPORTED_SSO_REGIONS, _probe_region_for_instance
from ..services.scaffold import scaffold_project
from ..services.status import StatusService
from . import access, account, baseline, deploy, identity, org, ou
from .account import apply_accounts
from .common import (
    ConfigDirOption,
    JsonOption,
    RegionOption,
    YesOption,
    exit_on_error,
    load_configs_or_exit,
    warn_if_example_newer,
)
from .importer import import_command
from .logs import logs_command
from .preflight import run_preflight_checks
from .ui import (
    console,
    create_table,
    error_console,
    print_action_panel,
    print_header,
    print_info,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="tarmac",
    help="Tarmac: Enterprise AWS Governance & Multi-Account Landing Zone CLI.",
    no_args_is_help=True,
)

app.add_typer(access.app, name="access")
app.add_typer(org.app, name="org")
app.add_typer(ou.app, name="ou")
app.add_typer(account.app, name="account")
app.add_typer(identity.app, name="identity")
app.add_typer(baseline.app, name="baseline")
app.add_typer(deploy.app, name="deploy")

app.command(
    "preflight",
    help="Audit management account manual prerequisites and operational readiness.",
)(run_preflight_checks)
app.command(
    "doctor",
    help="Alias for 'tarmac preflight': diagnose environment health and prerequisites.",
)(run_preflight_checks)


app.command(
    "logs",
    help="Summarize runs from a --log-file record and show what each one did.",
)(logs_command)


def version_callback(value: bool) -> None:
    if value:
        console.print(f"tarmac-cli v{__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version", "-V", help="Show tarmac version and exit", callback=version_callback, is_eager=True
        ),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", "-p", help="AWS CLI profile name to use")
    ] = None,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable verbose debug logging and full tracebacks")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Print every recorded action (INFO) to the terminal")
    ] = False,
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file",
            envvar="TARMAC_LOG_FILE",
            help="Append a JSON-lines record of this run (actions, outcomes, errors) to this file",
        ),
    ] = None,
) -> None:
    """Global CLI configuration callback."""
    if profile:
        os.environ["AWS_PROFILE"] = profile

    setup_logging(debug=debug, console=error_console, verbose=verbose, log_file=log_file)

    # Reading a log must not append a run to the file being read.
    if ctx.invoked_subcommand and ctx.invoked_subcommand != "logs":
        run = start_run(ctx.invoked_subcommand, __version__, sys.argv[1:])
        ctx.call_on_close(lambda: run.finish(sys.exc_info()[1]))


app.command("import")(import_command)


@app.command("init")
def init_project(
    directory: Annotated[
        Path | None,
        typer.Argument(
            help="Directory to scaffold configuration files [default: config]", show_default=False
        ),
    ] = None,
    config_dir: Annotated[
        Path | None, typer.Option("--config-dir", "-c", help="Directory to scaffold configuration files")
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing configuration files")
    ] = False,
    with_templates: Annotated[
        bool,
        typer.Option(
            "--with-templates",
            "-t",
            help="Also export default CloudFormation templates and SCP policies locally",
        ),
    ] = False,
) -> None:
    """Scaffold starter YAML configuration files for a new Tarmac project."""

    target_dir = directory or config_dir or Path("config")
    print_header("Initialize Tarmac Configuration")
    created, skipped = scaffold_project(target_dir, force=force, with_templates=with_templates)

    for path in created:
        print_success(f"Created {path}")
    for path in skipped:
        print_info(f"Skipped existing {path} (use --force to overwrite)")

    if created:
        console.print("\n[bold cyan]Next Steps:[/bold cyan]")
        console.print(f"  1. Customize configuration files in [bold]{target_dir}/[/bold]")
        console.print("  2. Validate configuration with [bold]tarmac validate[/bold]")
        console.print("  3. Preview deployment with [bold]tarmac deploy run --dry-run[/bold]\n")


def _build_validation_summary(bundle: Any) -> dict[str, Any]:
    """Build summary dictionary for JSON output."""
    if bundle is None:
        return {}
    return {
        "organization_name": bundle.org.organization.name,
        "primary_region": bundle.org.organization.primary_region,
        "declared_ous": ConfigBundle.count_declared_ous(bundle.org.ou_structure),
        "declared_accounts": len(bundle.accounts.accounts),
        "permission_sets": len(bundle.identity.identity_center.permission_sets),
        "groups": len(bundle.identity.identity_center.groups),
    }


def _print_validation_table(bundle: Any) -> None:
    """Render configuration summary table to console."""
    table = create_table(title="Configuration Summary")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Organization Name", bundle.org.organization.name)
    table.add_row("Primary Region", bundle.org.organization.primary_region)
    table.add_row("Declared OUs", str(ConfigBundle.count_declared_ous(bundle.org.ou_structure)))
    table.add_row("Declared Accounts", str(len(bundle.accounts.accounts)))
    table.add_row("Permission Sets", str(len(bundle.identity.identity_center.permission_sets)))
    table.add_row("Identity Center Groups", str(len(bundle.identity.identity_center.groups)))
    console.print(table)


@app.command("validate")
def validate_config(
    config_dir: ConfigDirOption = None,
    json_output: JsonOption = False,
) -> None:
    """Validate all YAML configuration files and logical cross-references."""

    bundle, errors = load_all_configs(config_dir)

    if json_output:
        payload = {
            "valid": not bool(errors or bundle is None),
            "summary": _build_validation_summary(bundle),
            "errors": errors or [],
            "warnings": find_placeholder_values(bundle) if bundle is not None else [],
        }
        print(json.dumps(payload, indent=2))
        if errors or bundle is None:
            raise typer.Exit(code=1)
        return

    warn_if_example_newer(config_dir)
    print_header("Validating Configuration Files")
    if errors or bundle is None:
        error_text = "\n".join(
            f"[bold red]•[/bold red] {err}" for err in (errors or ["Failed loading configs"])
        )
        error_console.print(
            Panel(
                error_text,
                title="[bold red]Validation Failed[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    _print_validation_table(bundle)
    print_success("All configuration files and logical cross-references are valid!")
    placeholders = find_placeholder_values(bundle)
    if placeholders:
        print_warning(
            "The configuration still contains sample values from 'tarmac init'. Replace them before a real "
            "deployment (AWS never lets a closed account's email be reused):"
        )
        for problem in placeholders:
            console.print(f"  [yellow]•[/yellow] {problem}")


@app.command("apply")
def apply_shortcut(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate provisioning without making changes")
    ] = False,
    skip_baseline: Annotated[
        bool, typer.Option("--skip-baseline", help="Skip running post-creation baselines")
    ] = False,
    yes: YesOption = False,
) -> None:
    """Provision declared accounts (shortcut for 'tarmac account apply').

    To deploy the full end-to-end landing zone, use 'tarmac deploy run'.
    """

    apply_accounts(
        config_dir=config_dir,
        region=region,
        dry_run=dry_run,
        skip_baseline=skip_baseline,
        yes=yes,
    )


def _fetch_org_details(session_mgr: AwsSessionManager) -> tuple[dict[str, str], str]:
    """Fetch org ID, master ID, feature set, and error message if any."""
    try:
        org_client = session_mgr.get_client("organizations")
        org_desc = org_client.describe_organization()["Organization"]
        return {
            "id": str(org_desc.get("Id", "")),
            "master_id": str(org_desc.get("MasterAccountId", "")),
            "feature_set": str(org_desc.get("FeatureSet", "")),
        }, ""
    except Exception as e:
        return {}, str(e)


def _fetch_sso_instance(session_mgr: AwsSessionManager, region: str) -> str:
    """Fetch IAM Identity Center instance ARN or empty string."""
    try:
        sso_client = session_mgr.get_client("sso-admin", region_name=region)
        instances = sso_client.list_instances().get("Instances", [])
        return str(instances[0].get("InstanceArn", "")) if instances else ""
    except Exception:
        return ""


def _find_sso_instance(session_mgr: AwsSessionManager, region: str) -> tuple[str, str]:
    """Find the IAM Identity Center instance, trying the given region first and then the others.

    Identity Center lives in exactly one Region, and it is often not the Region the shell happens to use.
    Returns (instance ARN, Region it was found in), or ("", region) when there is none.
    """
    arn = _fetch_sso_instance(session_mgr, region)
    if arn:
        return arn, region
    for candidate in SUPPORTED_SSO_REGIONS:
        if candidate == region:
            continue
        found = _probe_region_for_instance(session_mgr, candidate)
        if found:
            return found[0], candidate
    return "", region


def _resolve_sso_region(default_region: str) -> str:
    try:
        bundle, _ = load_all_configs()
        if bundle and bundle.identity.identity_center.region:
            return bundle.identity.identity_center.region
    except Exception as exc:
        logger.debug("Could not resolve SSO region from config, using default: %s", exc)
    return default_region


@app.command("info")
def show_info(
    region: Annotated[
        str | None,
        typer.Option(
            "--region", "-r", help="AWS region (default: AWS_REGION / AWS_DEFAULT_REGION, else us-east-1)"
        ),
    ] = None,
    json_output: JsonOption = False,
) -> None:
    """Show current AWS authentication details, caller identity, and Organization status."""

    with exit_on_error("Authentication Error"):
        session_mgr = AwsSessionManager(region_name=region)
        resolved_region = str(session_mgr.default_region)
        caller = session_mgr.get_caller_identity()
        caller_acct = caller.get("Account", "Unknown")
        org_info, org_err = _fetch_org_details(session_mgr)
        sso_region = _resolve_sso_region(resolved_region)
        sso_arn, sso_found_region = _find_sso_instance(session_mgr, sso_region)

        if json_output:
            payload = {
                "account_id": caller_acct,
                "arn": caller.get("Arn", "Unknown"),
                "region": resolved_region,
                "organization_id": org_info.get("id"),
                "master_account_id": org_info.get("master_id"),
                "feature_set": org_info.get("feature_set"),
                "is_management_account": caller_acct == org_info.get("master_id"),
                "identity_center_arn": sso_arn or None,
            }
            print(json.dumps(payload, indent=2))
            return

        print_header("AWS Authentication & Identity Info")
        table = create_table()
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Account ID", caller_acct)
        table.add_row("User / Role ARN", caller.get("Arn", "Unknown"))
        table.add_row("Region", resolved_region)

        if org_info.get("id"):
            table.add_row("Organization ID", org_info["id"])
            table.add_row("Master Account ID", org_info["master_id"])
            table.add_row("Feature Set", org_info["feature_set"])
            is_master = caller_acct == org_info["master_id"]
            role_msg = (
                "[bold green]✓ Authenticated as Management Account[/bold green]"
                if is_master
                else f"[bold red]⚠ Warning: Caller is NOT the Management Account ({org_info['master_id']})[/bold red]"
            )
            table.add_row("Role Verification", role_msg)
        else:
            table.add_row("Organization", f"[yellow]Not accessible / not enabled: {org_err}[/yellow]")

        if sso_arn:
            table.add_row("Identity Center", f"[green]Enabled in {sso_found_region} ({sso_arn})[/green]")
        else:
            table.add_row(
                "Identity Center",
                "[yellow]Not found in any supported Region. Enable it in the console, or check that this "
                "identity may call sso-admin.[/yellow]",
            )

        console.print(table)


def _eval_org_status(status: Any, bundle: Any) -> tuple[str, str, str, str, str | None]:
    active = status.org_id != "Unknown"
    badge = "[bold green]ACTIVE[/bold green]" if active else "[bold red]MISSING[/bold red]"
    action = None if active else "Organization not found. Run: tarmac org bootstrap"
    return ("AWS Organization", bundle.org.organization.name, status.org_id, badge, action)


def _eval_ous_status(status: Any) -> tuple[str, str, str, str, str | None]:
    synced = status.ous_declared <= status.ous_live
    diff = status.ous_declared - status.ous_live
    badge = "[bold green]SYNCED[/bold green]" if synced else "[bold yellow]DRIFT[/bold yellow]"
    action = f"Missing {diff} OU(s). Run: tarmac ou sync" if not synced else None
    return (
        "Organizational Units",
        f"{status.ous_declared} OUs declared",
        f"{status.ous_live} OUs live",
        badge,
        action,
    )


def _eval_accounts_status(status: Any) -> tuple[str, str, str, str, str | None]:
    synced = status.accounts_declared <= status.accounts_live
    diff = status.accounts_declared - status.accounts_live
    badge = "[bold green]SYNCED[/bold green]" if synced else "[bold yellow]PENDING[/bold yellow]"
    action = f"{diff} account(s) pending creation. Run: tarmac account apply" if not synced else None

    live_label = f"{status.accounts_live} accounts live"
    suspended_count = getattr(status, "accounts_suspended", 0)
    if suspended_count > 0:
        live_label += f" ({suspended_count} suspended)"

    return (
        "Member Accounts",
        f"{status.accounts_declared} accounts declared",
        live_label,
        badge,
        action,
    )


def _eval_cloudtrail_status(status: Any, bundle: Any) -> tuple[str, str, str, str, str | None]:
    synced = "COMPLETE" in status.cloudtrail_status
    badge = "[bold green]DEPLOYED[/bold green]" if synced else "[bold yellow]PENDING[/bold yellow]"
    action = "CloudTrail stack not deployed. Run: tarmac baseline cloudtrail" if not synced else None
    return (
        "Organization CloudTrail",
        bundle.org.cloudtrail.trail_name,
        status.cloudtrail_status,
        badge,
        action,
    )


def _eval_backend_status(status: Any, bundle: Any) -> tuple[str, str, str, str, str | None]:
    synced = "COMPLETE" in status.backend_status
    badge = "[bold green]DEPLOYED[/bold green]" if synced else "[bold yellow]PENDING[/bold yellow]"
    action = "Backend stack not deployed. Run: tarmac baseline backend" if not synced else None
    return (
        "Terraform Backend",
        bundle.org.terraform_backend.bucket_prefix,
        status.backend_status,
        badge,
        action,
    )


def _eval_sso_status(status: Any, bundle: Any) -> tuple[str, str, str, str, str | None]:
    declared = (
        f"{len(bundle.identity.identity_center.permission_sets)} sets / "
        f"{len(bundle.identity.identity_center.groups)} grps"
    )
    live = "Configured" if status.sso_configured else "Not Configured"
    badge = (
        "[bold green]SYNCED[/bold green]" if status.sso_configured else "[bold yellow]PENDING[/bold yellow]"
    )
    action = (
        "SSO instance not detected. Enable in AWS Console or run: tarmac identity sync"
        if not status.sso_configured
        else None
    )
    return ("IAM Identity Center", declared, live, badge, action)


def _get_status_components(bundle: Any, status: Any) -> list[tuple[str, str, str, str, str | None]]:
    return [
        _eval_org_status(status, bundle),
        _eval_ous_status(status),
        _eval_accounts_status(status),
        _eval_cloudtrail_status(status, bundle),
        _eval_backend_status(status, bundle),
        _eval_sso_status(status, bundle),
    ]


def _render_status_table(bundle: Any, status: Any) -> None:
    """Render landing zone reconciliation table in a uniform, scannable layout."""
    print_header("Landing Zone Reconciliation Status")
    table = create_table(expand=True)
    table.add_column("Component", style="bold white", no_wrap=True)
    table.add_column("Declared", style="cyan", no_wrap=True)
    table.add_column("Live AWS", style="white", no_wrap=True)
    table.add_column("Status", justify="center", width=10, min_width=10, no_wrap=True)

    components = _get_status_components(bundle, status)
    actions: list[tuple[str, str, str]] = []

    for name, declared, live, badge, action in components:
        table.add_row(name, declared, live, badge)
        if action:
            level = "FAIL" if "MISSING" in badge else "WARN"
            actions.append((level, name, action))

    console.print(table)

    if actions:
        print_action_panel(
            [
                (
                    "[bold red]FAIL[/bold red]" if level == "FAIL" else "[bold yellow]WARN[/bold yellow]",
                    name,
                    action,
                )
                for level, name, action in actions
            ],
            has_failures=any(level == "FAIL" for level, _, _ in actions),
            titles=("Action Required (Missing Prerequisite)", "Pending Actions & Remediation"),
            item_header="Component",
            item_width=26,
            action_header="Action Required / Remediation",
        )
        print_info(
            f"Reconciliation pending ({len(actions)} item(s)). Review actionable steps above or run 'tarmac deploy run'.\n"
        )
    else:
        print_success("Landing zone is fully reconciled and in sync with configuration.\n")


@app.command("status")
def show_status(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    json_output: JsonOption = False,
) -> None:
    """Show reconciliation status between declared YAML and live AWS environment."""

    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Status Inspection Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        status_service = StatusService(session_mgr)
        status = status_service.inspect(bundle, target_region)

        if json_output:
            print(json.dumps(dataclasses.asdict(status), indent=2))
            return

        _render_status_table(bundle, status)


def _render_drift_table(report: Any) -> None:
    print_header("Landing Zone Drift Inspection")
    table = create_table(expand=True)
    table.add_column("Category", style="bold white", width=12, no_wrap=True)
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Declared", style="white")
    table.add_column("Live AWS", style="white")
    table.add_column("Status", justify="center", width=12, no_wrap=True)
    table.add_column("Remediation", style="yellow")

    for item in report.items:
        if item.status == "IN_SYNC":
            status_badge = "[bold green]IN SYNC[/bold green]"
        elif item.status == "DRIFTED":
            status_badge = "[bold yellow]DRIFTED[/bold yellow]"
        else:
            status_badge = "[bold red]MISSING[/bold red]"

        remediation_text = (
            f"[bold yellow]{item.remediation}[/bold yellow]" if item.remediation else "[dim]—[/dim]"
        )
        table.add_row(
            item.category,
            item.name,
            item.declared,
            item.live,
            status_badge,
            remediation_text,
        )

    console.print(table)

    if report.has_drift:
        print_warning(
            f"Drift detected across {report.drift_count + report.missing_count} item(s) "
            f"({report.missing_count} missing, {report.drift_count} drifted). "
            "Execute the recommended remediation commands above or run 'tarmac deploy run'.\n"
        )
    else:
        print_success(
            f"All {report.in_sync_count} governance components are fully in sync with declared manifests.\n"
        )


@app.command("drift")
def show_drift(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    json_output: JsonOption = False,
    strict: Annotated[bool, typer.Option("--strict", help="Exit with code 1 if drift is detected")] = False,
) -> None:
    """Audit live AWS resources against declared YAML manifests across all governance pillars."""

    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Drift Inspection Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        drift_service = DriftService(session_mgr)
        report = drift_service.inspect_drift(bundle, target_region)

        if json_output:
            print(json.dumps(dataclasses.asdict(report), indent=2))
        else:
            _render_drift_table(report)
        if strict and report.has_drift:
            raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
