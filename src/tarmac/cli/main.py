"""Main entrypoint for the tarmac CLI."""

import dataclasses
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel

from .. import __version__
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, load_all_configs
from ..core.exceptions import AWS_ERRORS
from ..core.logging import setup_logging, start_run
from ..core.placeholders import find_placeholder_values
from ..core.stack_names import Stack
from ..core.text import plural
from ..services.baseline import BaselineService
from ..services.drift import DriftService
from ..services.identity_base import SUPPORTED_SSO_REGIONS, _probe_region_for_instance
from ..services.ou import OUService
from ..services.scaffold import scaffold_project
from ..services.status import StatusService
from . import account
from .bootstrap import bootstrap_command
from .common import (
    ConfigDirOption,
    JsonOption,
    RegionOption,
    exit_on_error,
    load_configs_or_exit,
    warn_if_example_newer,
)
from .deploy import _refuse_root_identity, deploy_command, destroy_command, inventory_command, plan_command
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

app = typer.Typer(
    name="tarmac",
    help="Tarmac: set up and maintain a multi-account AWS Organization from YAML.",
    no_args_is_help=True,
)

app.add_typer(account.app, name="account")
app.command("bootstrap")(bootstrap_command)
app.command("plan")(plan_command)
app.command("deploy")(deploy_command)
app.command("destroy")(destroy_command)
app.command("inventory")(inventory_command)

app.command(
    "preflight",
    help="Check the management account is ready for tarmac.",
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
    config_dir: Annotated[
        Path, typer.Option("--config-dir", "-c", help="Directory to write the configuration files to")
    ] = Path("config"),
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing configuration files")
    ] = False,
    with_templates: Annotated[
        bool,
        typer.Option(
            "--with-templates",
            help="Also export default CloudFormation templates and SCP policies locally",
        ),
    ] = False,
) -> None:
    """Write starter configuration files."""

    print_header("Initialize Tarmac Configuration")
    created, skipped = scaffold_project(config_dir, force=force, with_templates=with_templates)

    for path in created:
        print_success(f"Created {path}")
    for path in skipped:
        print_info(f"Skipped existing {path} (use --force to overwrite)")

    if created:
        console.print("\n[bold cyan]Next steps:[/bold cyan]")
        console.print(f"  1. Edit the files in [bold]{config_dir}/[/bold]")
        console.print("  2. Check them with [bold]tarmac validate[/bold]")
        console.print("  3. On a new account, run [bold]tarmac bootstrap[/bold] once, as root, and sign in")
        console.print("  4. Run [bold]tarmac preflight[/bold], then [bold]tarmac deploy --dry-run[/bold]\n")


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
            "warnings": [*find_placeholder_values(bundle), *bundle.deprecated_settings()] if bundle else [],
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
    print_success("Configuration files and cross-references are valid.")
    placeholders = find_placeholder_values(bundle)
    if placeholders:
        print_warning(
            "The configuration still contains sample values from 'tarmac init'. Replace them before a real "
            "deployment (AWS never lets a closed account's email be reused):"
        )
        for problem in placeholders:
            console.print(f"  [yellow]•[/yellow] {problem}")
    for message in bundle.deprecated_settings():
        print_warning(message)


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
    except AWS_ERRORS as e:
        return {}, str(e)


def _find_sso_instance(session_mgr: AwsSessionManager, region: str) -> tuple[str, str, str]:
    """Find the IAM Identity Center instance, trying the given region first and then the others.

    Identity Center lives in exactly one Region, and it is often not the Region the shell happens to use.
    Returns (instance ARN, identity store ID, Region it was found in), or ("", "", region) when there is none.
    """
    for candidate in [region, *(r for r in SUPPORTED_SSO_REGIONS if r != region)]:
        found = _probe_region_for_instance(session_mgr, candidate)
        if found:
            return found[0], found[1], candidate
    return "", "", region


def _resolve_sso_region(default_region: str) -> str:
    bundle, _ = load_all_configs()
    if bundle and bundle.identity.identity_center.region:
        return bundle.identity.identity_center.region
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
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Exit with code 1 unless these credentials can run tarmac (non-root, can read the organization)",
        ),
    ] = False,
) -> None:
    """Show current AWS authentication details, caller identity, and Organization status."""

    with exit_on_error("Authentication Error"):
        session_mgr = AwsSessionManager(region_name=region)
        resolved_region = str(session_mgr.default_region)
        caller = session_mgr.get_caller_identity()
        caller_acct = caller.get("Account", "Unknown")
        org_info, org_err = _fetch_org_details(session_mgr)
        sso_region = _resolve_sso_region(resolved_region)
        sso_arn, store_id, sso_found_region = _find_sso_instance(session_mgr, sso_region)
        portal_url = f"https://{store_id}.awsapps.com/start" if store_id else None
        is_root = session_mgr.is_root_identity() is True
        can_run_tarmac = not is_root and bool(org_info.get("id"))

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
                "identity_center_region": sso_found_region if sso_arn else None,
                "identity_store_id": store_id or None,
                "access_portal_url": portal_url,
                "is_root": is_root,
                "can_run_tarmac": can_run_tarmac,
            }
            print(json.dumps(payload, indent=2))
            if strict and not can_run_tarmac:
                raise typer.Exit(code=1)
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
                "[bold green]Authenticated as Management Account[/bold green]"
                if is_master
                else f"[bold red]Caller is not the Management Account ({org_info['master_id']})[/bold red]"
            )
            table.add_row("Role Verification", role_msg)
        else:
            table.add_row("Organization", f"[yellow]Not accessible / not enabled: {org_err}[/yellow]")

        if sso_arn:
            table.add_row("Identity Center", f"[green]Enabled in {sso_found_region} ({sso_arn})[/green]")
            table.add_row("Identity Store ID", store_id)
            table.add_row("Access Portal URL", str(portal_url))
        else:
            table.add_row(
                "Identity Center",
                "[yellow]Not found in any supported Region. Enable it in the console, or check that this "
                "identity may call sso-admin.[/yellow]",
            )

        table.add_row("Credentials", _credentials_verdict(is_root, can_run_tarmac))
        console.print(table)
        if strict and not can_run_tarmac:
            raise typer.Exit(code=1)


def _credentials_verdict(is_root: bool, can_run_tarmac: bool) -> str:
    if is_root:
        return (
            "[bold red]Not usable: Root credentials cannot assume roles in member accounts. Run "
            "'tarmac bootstrap' to create an IAM Identity Center login, then sign in with it.[/bold red]"
        )
    if not can_run_tarmac:
        return (
            "[yellow]Not usable: Cannot read the organization. Use management account credentials with "
            "Organizations read access, and create the organization with 'tarmac deploy --phase 1' if it "
            "does not exist.[/yellow]"
        )
    return "[green]Usable: Non-root and can read the organization[/green]"


def _eval_org_status(status: Any, bundle: Any) -> tuple[str, str, str, str, str | None]:
    active = status.org_id != "Unknown"
    badge = "[bold green]ACTIVE[/bold green]" if active else "[bold red]MISSING[/bold red]"
    action = None if active else "Organization not found. Run: tarmac deploy --phase 1"
    return ("AWS Organization", bundle.org.organization.name, status.org_id, badge, action)


def _eval_ous_status(status: Any) -> tuple[str, str, str, str, str | None]:
    synced = status.ous_declared <= status.ous_live
    diff = status.ous_declared - status.ous_live
    badge = "[bold green]SYNCED[/bold green]" if synced else "[bold yellow]DRIFT[/bold yellow]"
    action = f"Missing {plural(diff, 'OU')}. Run: tarmac deploy --phase 2" if not synced else None
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
    action = (
        f"{plural(diff, 'account')} pending creation. Run: tarmac deploy --phase 4" if not synced else None
    )

    live_label = f"{status.accounts_live} accounts live"
    if status.accounts_suspended > 0:
        live_label += f" ({status.accounts_suspended} suspended)"

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
    action = "CloudTrail stack not deployed. Run: tarmac deploy --phase 3" if not synced else None
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
    action = "Backend stack not deployed. Run: tarmac deploy --phase 5" if not synced else None
    return (
        "Terraform Backend",
        Stack.TERRAFORM_BACKEND.for_org(bundle.org.organization.name),
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
        "SSO instance not detected. Enable in AWS Console or run: tarmac deploy --phase 6"
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
            f"Reconciliation pending ({plural(len(actions), 'item')}). Review actionable steps above or run 'tarmac deploy'.\n"
        )
    else:
        print_success("Landing zone is fully reconciled and in sync with configuration.\n")


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
            f"Drift detected across {plural(report.drift_count + report.missing_count, 'item')} "
            f"({report.missing_count} missing, {report.drift_count} drifted). "
            "Execute the recommended remediation commands above or run 'tarmac deploy'.\n"
        )
    else:
        print_success(
            f"All {report.in_sync_count} governance components are fully in sync with declared manifests.\n"
        )


def _render_detail_tables(ous: dict[str, str], monitors: list[Any], subscriptions: list[Any]) -> None:
    table = create_table(title="Organizational Units")
    table.add_column("OU Name", style="cyan")
    table.add_column("OU ID", style="green")
    for name, ou_id in ous.items():
        table.add_row(name, ou_id)
    console.print(table)

    table = create_table(title="Cost Anomaly Monitors")
    table.add_column("Monitor Name", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Scope / Linked Account", style="green")
    for m in monitors:
        values = (
            m.get("MonitorSpecification", {}).get("Dimensions", {}).get("Values", ["All linked accounts"])
        )
        table.add_row(m.get("MonitorName", "Unknown"), m.get("MonitorType", "Unknown"), ", ".join(values))
    console.print(table)

    table = create_table(title="Cost Anomaly Alert Subscriptions")
    table.add_column("Subscription Name", style="cyan")
    table.add_column("Threshold", style="yellow")
    table.add_column("Frequency", style="magenta")
    table.add_column("Subscribers", style="green")
    for sub in subscriptions:
        table.add_row(
            sub.get("SubscriptionName", "Unknown"),
            f"${sub.get('Threshold', 0):.2f}",
            sub.get("Frequency", "Unknown"),
            ", ".join(s.get("Address", "") for s in sub.get("Subscribers", [])),
        )
    console.print(table)


@app.command("status")
def show_status(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    json_output: JsonOption = False,
    detail: Annotated[
        bool,
        typer.Option(
            "--detail",
            help="Also check every declared item for drift, and list live OUs and cost anomaly monitors",
        ),
    ] = False,
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit with code 1 if drift is detected (implies --detail)")
    ] = False,
) -> None:
    """Show how the live AWS environment compares with the declared configuration."""

    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Status Inspection Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        _refuse_root_identity(session_mgr)
        status = StatusService(session_mgr).inspect(bundle, target_region)
        report = DriftService(session_mgr).inspect_drift(bundle, target_region) if detail or strict else None
        ous: dict[str, str] = {}
        monitors: list[Any] = []
        subscriptions: list[Any] = []
        if detail:
            ous = OUService(session_mgr).list_all_ous()
            monitors, subscriptions = BaselineService(session_mgr).get_anomaly_overview()

        if json_output:
            payload = dataclasses.asdict(status)
            if report is not None:
                payload["drift"] = dataclasses.asdict(report)
            if detail:
                payload["organizational_units"] = ous
                payload["cost_anomaly"] = {"monitors": monitors, "subscriptions": subscriptions}
            print(json.dumps(payload, indent=2, default=str))
        else:
            _render_status_table(bundle, status)
            if report is not None:
                _render_drift_table(report)
            if detail:
                _render_detail_tables(ous, monitors, subscriptions)
        if strict and report is not None and report.has_drift:
            raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
