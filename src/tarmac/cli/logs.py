"""`tarmac logs`: read back a run log written with --log-file."""

import json
import os
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.markup import escape
from rich.panel import Panel

from ..services.logview import (
    Record,
    RunSummary,
    clock,
    filter_records,
    find_run,
    group_runs,
    read_records,
)
from .ui import console, create_table, error_console, print_header, print_info

_OUTCOME_STYLE = {
    "succeeded": "green",
    "simulated": "cyan",
    "unchanged": "dim",
    "skipped": "yellow",
    "failed": "bold red",
}
_STATUS_STYLE = {"succeeded": "green", "failed": "bold red", "incomplete": "yellow"}
_LEVEL_STYLE = {"WARNING": "yellow", "ERROR": "bold red", "CRITICAL": "bold red"}


def _style(table: dict[str, str], key: str) -> str:
    return table.get(key, "white")


def _fail(message: str) -> typer.Exit:
    error_console.print(f"[bold red]✗[/bold red] {escape(message)}")
    return typer.Exit(code=1)


def _list_runs(runs: list[RunSummary], skipped: int) -> None:
    print_header("Tarmac Runs")
    table = create_table()
    table.add_column("Run", no_wrap=True, min_width=24)  # kept whole so it can be copied into --run
    table.add_column("Command")
    table.add_column("Started", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Results")
    for run in runs:
        status = f"[{_style(_STATUS_STYLE, run.status)}]{run.status}[/]"
        mode = " [cyan](dry run)[/cyan]" if run.dry_run else ""
        problems = run.failures + run.errors
        results = [f"{run.changes} changed"]
        if problems:
            results.append(f"[bold red]{problems} failed[/bold red]")
        if run.warnings:
            results.append(f"[yellow]{run.warnings} warning(s)[/yellow]")
        table.add_row(
            run.run_id,
            escape(run.command) + mode,
            run.started[:19].replace("T", " "),
            status,
            ", ".join(results),
        )
    console.print(table)
    if skipped:
        print_info(f"{skipped} line(s) in the file were not valid log records and were skipped.")
    print_info("Use 'tarmac logs FILE --run latest' (or a run id) to see what a run did.")


def _run_header(run: RunSummary) -> None:
    status = f"[{_style(_STATUS_STYLE, run.status)}]{run.status.upper()}[/]"
    duration = f" in {run.duration_seconds:.1f}s" if run.duration_seconds is not None else ""
    lines = [
        f"[bold]tarmac {escape(run.command)}[/bold]  {status}{duration}"
        + ("  [cyan]DRY RUN: nothing was changed[/cyan]" if run.dry_run else ""),
        f"[dim]Run {run.run_id} · started {run.started[:19].replace('T', ' ')} · v{escape(run.version)}[/dim]",
    ]
    if run.argv:
        lines.append(f"[dim]Arguments: {escape(' '.join(run.argv))}[/dim]")
    counts = ", ".join(
        f"[{_style(_OUTCOME_STYLE, name)}]{count} {name}[/]" for name, count in sorted(run.outcomes.items())
    )
    lines.append(f"Actions: {counts or 'none recorded'}")
    if run.warnings or run.errors:
        lines.append(f"[yellow]{run.warnings} warning(s)[/yellow], [red]{run.errors} error(s)[/red]")
    if run.dry_run_violations:
        lines.append(
            f"[bold red]{run.dry_run_violations} state-changing AWS call(s) were made during a dry run[/bold red]"
        )
    console.print(Panel("\n".join(lines), border_style="cyan", padding=(0, 2)))


def _where(record: Record) -> str:
    parts = [str(record[k]) for k in ("phase", "account_name", "region") if record.get(k)]
    return " · ".join(parts)


def _render_records(records: list[Record], show_all: bool) -> None:
    table = create_table()
    table.add_column("Time", no_wrap=True, style="dim")
    table.add_column("Result", no_wrap=True)
    table.add_column("What happened", overflow="fold")
    table.add_column("Where", style="dim", overflow="fold")
    for record in records:
        raw = record.get("data")
        data: dict[str, Any] = raw if isinstance(raw, dict) else {}
        message = escape(str(record.get("message", "")))
        if record.get("event") == "audit":
            outcome = str(data.get("outcome", ""))
            result = f"[{_style(_OUTCOME_STYLE, outcome)}]{outcome}[/]"
        else:
            level = str(record.get("level", ""))
            result = f"[{_style(_LEVEL_STYLE, level)}]{level.lower()}[/]"
        table.add_row(clock(str(record.get("ts", ""))), result, message, escape(_where(record)))
    console.print(table)
    if not show_all:
        print_info("Showing actions and problems. Add --all for every record, including AWS calls.")


def logs_command(
    file: Annotated[
        Path | None,
        typer.Argument(
            help="Log file written with --log-file [default: $TARMAC_LOG_FILE]", show_default=False
        ),
    ] = None,
    run: Annotated[
        str | None, typer.Option("--run", "-r", help="Show one run: 'latest', a run id or an id prefix")
    ] = None,
    outcome: Annotated[
        list[str] | None,
        typer.Option(
            "--outcome", "-o", help="Only actions with this outcome (repeatable): succeeded, failed, ..."
        ),
    ] = None,
    phase: Annotated[
        str | None, typer.Option("--phase", help="Only records from phases matching this text")
    ] = None,
    account: Annotated[
        str | None, typer.Option("--account", "-a", help="Only records for this account id or name")
    ] = None,
    show_all: Annotated[
        bool, typer.Option("--all", help="Include every record (AWS calls, debug output)")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON instead of tables")] = False,
) -> None:
    """Summarize runs from a Tarmac log file and show what each one did."""
    source = file or (Path(os.environ["TARMAC_LOG_FILE"]) if os.environ.get("TARMAC_LOG_FILE") else None)
    if source is None:
        raise _fail("No log file given. Pass a path, or set TARMAC_LOG_FILE.")
    if not source.is_file():
        raise _fail(f"Log file not found: {source}")

    records, skipped = read_records(source)
    runs = group_runs(records)
    filtering = bool(outcome or phase or account)

    if run is None and not filtering:
        if json_output:
            print(json.dumps([r.as_dict() for r in runs], indent=2))
            return
        if not runs:
            print_info("No runs found in this log file.")
            return
        _list_runs(runs, skipped)
        return

    try:
        selected_run = find_run(runs, run or "latest")
    except LookupError as exc:
        raise _fail(str(exc)) from exc

    outcomes = {o.lower() for o in outcome} if outcome else None
    if show_all:
        picked = filter_records(
            records, run_id=selected_run.run_id, outcomes=outcomes, phase=phase, account=account
        )
    else:
        audit_records = filter_records(
            records,
            run_id=selected_run.run_id,
            outcomes=outcomes,
            phase=phase,
            account=account,
            events={"audit"},
        )
        problems = (
            []
            if outcomes
            else [
                r
                for r in filter_records(
                    records, run_id=selected_run.run_id, phase=phase, account=account, min_level="WARNING"
                )
                if r.get("event") != "audit"
            ]
        )
        picked = sorted(audit_records + problems, key=lambda r: str(r.get("ts", "")))

    if json_output:
        for record in picked:
            print(json.dumps(record, ensure_ascii=False))
        return

    _run_header(selected_run)
    if not picked:
        print_info("No records match.")
        return
    _render_records(picked, show_all)
