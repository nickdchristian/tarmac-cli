"""CLI commands for environment preflight and health diagnostics."""

import json
from typing import Annotated, Any

import typer

from ..core.aws_client import AwsSessionManager
from ..core.models import PreflightCheckStatus, PreflightReport
from ..services.preflight import PreflightService
from .common import ConfigDirOption, JsonOption, RegionOption, exit_on_error, load_configs_or_exit
from .ui import (
    console,
    create_table,
    error_console,
    print_action_panel,
    print_header,
    print_info,
    print_success,
)

_STATUS_BADGES = {
    PreflightCheckStatus.PASS: "[bold green]PASS[/bold green]",
    PreflightCheckStatus.WARN: "[bold yellow]WARN[/bold yellow]",
    PreflightCheckStatus.FAIL: "[bold red]FAIL[/bold red]",
}
_STATUS_PRIORITY = {
    PreflightCheckStatus.FAIL: 0,
    PreflightCheckStatus.WARN: 1,
    PreflightCheckStatus.INFO: 2,
    PreflightCheckStatus.PASS: 3,
}


def _format_status_badge(status: PreflightCheckStatus) -> str:
    return _STATUS_BADGES.get(status, "[bold cyan]INFO[/bold cyan]")


def _render_preflight_table(report: PreflightReport) -> None:
    table = create_table(title="Pre-Flight Readiness Inspection", expand=True)
    table.add_column("Check Item", style="bold white", no_wrap=True)
    table.add_column("Target Scope", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center", width=8, min_width=8, no_wrap=True)
    table.add_column("Live State / Value", style="white", no_wrap=True)
    for check in report.checks:
        table.add_row(check.name, check.target, _format_status_badge(check.status), check.live_value)
    console.print(table)

    actions = sorted(
        (c for c in report.checks if c.action_required), key=lambda c: _STATUS_PRIORITY.get(c.status, 2)
    )
    if actions:
        print_action_panel(
            [(_format_status_badge(c.status), c.name, c.action_required) for c in actions],
            has_failures=any(c.status == PreflightCheckStatus.FAIL for c in actions),
            titles=("Action Required (Blocking Issues)", "Action Items & Recommendations"),
            item_header="Check Item",
            item_width=32,
            action_header="Action Required / Guidance",
        )


def _build_json_payload(report: PreflightReport) -> dict[str, Any]:
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


def _evaluate_cli_report(report: PreflightReport, strict: bool) -> None:
    """Render the table and summary; exit 1 on failures, or on warnings in strict mode."""
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
    if report.warnings > 0:
        print_info("Ready to proceed with warnings. Review yellow items above before 'tarmac deploy run'.\n")
    else:
        print_success("All pre-flight checks passed! Environment is fully ready for deployment.\n")


def run_preflight_checks(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    json_output: JsonOption = False,
    strict: Annotated[
        bool, typer.Option("--strict", help="Fail with exit code 1 if any warnings or failures are detected")
    ] = False,
) -> None:
    """Audit management account manual prerequisites and operational readiness."""
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    if not json_output:
        print_header("Tarmac Pre-Flight Checklist")
        print_info(f"Scanning Management Account and region '{target_region}' prerequisites...")

    with exit_on_error("Pre-flight Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        report = PreflightService(session_mgr, bundle).run_all_checks(region_override=region)

        if json_output:
            print(json.dumps(_build_json_payload(report), indent=2))
            if report.failures > 0 or (strict and report.warnings > 0):
                raise typer.Exit(code=1)
            return

        _evaluate_cli_report(report, strict)
