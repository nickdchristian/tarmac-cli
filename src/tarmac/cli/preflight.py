"""CLI commands for environment preflight and health diagnostics."""

import json
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import GovernanceError
from ..core.models import PreflightCheckResult, PreflightCheckStatus, PreflightReport
from ..services.preflight import PreflightService
from .common import load_configs_or_exit
from .ui import console, create_table, error_console, print_header, print_info, print_success

app = typer.Typer(help="Pre-flight verification of manual steps and operational readiness.")


def _format_status_badge(status: PreflightCheckStatus) -> str:
    """Format color-coded terminal badge for check status."""
    if status == PreflightCheckStatus.PASS:
        return "[bold green]PASS[/bold green]"
    if status == PreflightCheckStatus.WARN:
        return "[bold yellow]WARN[/bold yellow]"
    if status == PreflightCheckStatus.FAIL:
        return "[bold red]FAIL[/bold red]"
    return "[bold cyan]INFO[/bold cyan]"


def _render_actions_panel(actions: list[PreflightCheckResult]) -> None:
    """Render a dedicated remediation table for checks requiring action."""
    has_failures = any(c.status == PreflightCheckStatus.FAIL for c in actions)
    panel_title = (
        "[bold red]Action Required (Blocking Issues)[/bold red]"
        if has_failures
        else "[bold yellow]Action Items & Recommendations[/bold yellow]"
    )
    border_color = "red" if has_failures else "yellow"

    action_table = Table(
        box=box.SIMPLE,
        header_style=f"bold {border_color}",
        expand=True,
        show_header=True,
    )
    action_table.add_column("Status", justify="center", width=8, min_width=8, no_wrap=True)
    action_table.add_column("Check Item", style="bold white", width=32, no_wrap=True)
    action_table.add_column("Action Required / Guidance", style="white")

    priority = {
        PreflightCheckStatus.FAIL: 0,
        PreflightCheckStatus.WARN: 1,
        PreflightCheckStatus.INFO: 2,
        PreflightCheckStatus.PASS: 3,
    }
    sorted_actions = sorted(actions, key=lambda c: priority.get(c.status, 2))

    for check in sorted_actions:
        badge = _format_status_badge(check.status)
        action_table.add_row(badge, check.name, check.action_required)

    console.print(
        Panel(
            action_table,
            title=panel_title,
            border_style=border_color,
            padding=(0, 1),
            expand=True,
        )
    )


def _render_preflight_table(report: PreflightReport) -> None:
    """Render Rich table of preflight check outcomes in a uniformly spaced layout."""
    table = create_table(title="Pre-Flight Readiness Inspection", expand=True)
    table.add_column("Check Item", style="bold white", no_wrap=True)
    table.add_column("Target Scope", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center", width=8, min_width=8, no_wrap=True)
    table.add_column("Live State / Value", style="white", no_wrap=True)

    for check in report.checks:
        badge = _format_status_badge(check.status)
        table.add_row(check.name, check.target, badge, check.live_value)

    console.print(table)

    actions = [c for c in report.checks if c.action_required]
    if actions:
        _render_actions_panel(actions)


def _build_json_payload(report: PreflightReport) -> dict[str, Any]:
    """Serialize report to a JSON-compatible dictionary."""
    return {
        "can_proceed": report.can_proceed,
        "summary": {
            "passed": report.passed,
            "warnings": report.warnings,
            "failures": report.failures,
            "info": report.info,
            "total": len(report.checks),
        },
        "checks": [
            {
                "name": c.name,
                "target": c.target,
                "status": c.status.value,
                "live_value": c.live_value,
                "action_required": c.action_required,
            }
            for c in report.checks
        ],
    }


def _output_json_report(report: PreflightReport, strict: bool) -> None:
    """Output JSON report and exit with error code if non-compliant."""
    print(json.dumps(_build_json_payload(report), indent=2))
    if report.failures > 0 or (strict and report.warnings > 0):
        raise typer.Exit(code=1)


def _print_followup_message(warnings_count: int) -> None:
    """Print actionable guidance based on warning presence."""
    if warnings_count > 0:
        print_info("Ready to proceed with warnings. Review yellow items above before 'tarmac deploy run'.\n")
    else:
        print_success("All pre-flight checks passed! Environment is fully ready for deployment.\n")


def _evaluate_cli_report(report: PreflightReport, strict: bool) -> None:
    """Render table, format summary, and exit if failures or strict warnings exist."""
    _render_preflight_table(report)

    summary_msg = (
        f"Pre-flight summary: [green]{report.passed} passed[/green], "
        f"[yellow]{report.warnings} warnings[/yellow], "
        f"[red]{report.failures} failures[/red], "
        f"[cyan]{report.info} info[/cyan]"
    )

    if report.failures > 0:
        error_console.print(f"\n[red]✗[/red] {summary_msg}")
        error_console.print(
            "[bold red]Pre-flight checks failed. Resolve blocking issues before deployment.[/bold red]\n"
        )
        raise typer.Exit(code=1)

    if strict and report.warnings > 0:
        error_console.print(f"\n[yellow]![/yellow] {summary_msg}")
        error_console.print(
            "[bold yellow]Strict mode: Aborting due to unresolved pre-flight warnings.[/bold yellow]\n"
        )
        raise typer.Exit(code=1)

    print_success(f"\n{summary_msg}")
    _print_followup_message(report.warnings)


def run_preflight_checks(
    config_dir: Path | None = typer.Option(
        None, "--config-dir", "-c", help="Path to configuration directory"
    ),
    region: str | None = typer.Option(None, "--region", "-r", help="Override target primary AWS region"),
    json_output: bool = typer.Option(False, "--json", help="Output results in machine-readable JSON"),
    strict: bool = typer.Option(
        False, "--strict", help="Fail with exit code 1 if any warnings or failures are detected"
    ),
) -> None:
    """Audit management account manual prerequisites and operational readiness."""
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    if not json_output:
        print_header("Tarmac Pre-Flight Checklist")
        print_info(f"Scanning Management Account and region '{target_region}' prerequisites...")

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = PreflightService(session_mgr, bundle)
        report = service.run_all_checks(region_override=region)

        if json_output:
            _output_json_report(report, strict)
            return

        _evaluate_cli_report(report, strict)

    except GovernanceError as e:
        error_console.print(Panel(str(e), title="[bold red]Pre-flight Failed[/bold red]", border_style="red"))
        raise typer.Exit(code=1)
