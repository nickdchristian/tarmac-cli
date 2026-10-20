"""Read a Tarmac JSON-lines run log: group it into runs, summarize them and filter their records."""

import json
import logging
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

Record = dict[str, Any]

_LEVELS = {name: value for name, value in logging.getLevelNamesMapping().items() if isinstance(value, int)}


@dataclass
class RunSummary:
    """What one CLI invocation did, derived from its records."""

    run_id: str
    command: str = ""
    version: str = ""
    argv: list[str] = field(default_factory=list)
    started: str = ""
    ended: str = ""
    exit_code: int | None = None
    duration_seconds: float | None = None
    dry_run: bool = False
    outcomes: Counter[str] = field(default_factory=Counter)
    warnings: int = 0
    errors: int = 0
    dry_run_violations: int = 0
    aws_changes: int = 0

    @property
    def status(self) -> str:
        if self.exit_code is None:
            return "incomplete"
        return "succeeded" if self.exit_code == 0 else "failed"

    @property
    def changes(self) -> int:
        return self.outcomes.get("succeeded", 0)

    @property
    def failures(self) -> int:
        return self.outcomes.get("failed", 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "command": self.command,
            "version": self.version,
            "argv": self.argv,
            "started": self.started,
            "ended": self.ended,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "dry_run": self.dry_run,
            "outcomes": dict(self.outcomes),
            "warnings": self.warnings,
            "errors": self.errors,
            "dry_run_violations": self.dry_run_violations,
            "aws_changes": self.aws_changes,
        }


def read_records(path: Path) -> tuple[list[Record], int]:
    """Parse a JSON-lines log. Returns (records, number of lines skipped because they were not valid)."""
    records: list[Record] = []
    skipped = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
            else:
                skipped += 1
    return records, skipped


def _data(record: Record) -> dict[str, Any]:
    data = record.get("data")
    return data if isinstance(data, dict) else {}


def group_runs(records: Iterable[Record]) -> list[RunSummary]:
    """Summarize each run found in the records, oldest first. Records without a run_id are ignored."""
    runs: dict[str, RunSummary] = {}
    for record in records:
        run_id = record.get("run_id")
        if not isinstance(run_id, str):
            continue
        run = runs.setdefault(run_id, RunSummary(run_id=run_id))
        ts = str(record.get("ts", ""))
        run.started = min(filter(None, [run.started, ts]), default=ts)
        run.ended = max(run.ended, ts)
        run.command = run.command or str(record.get("command", ""))
        run.dry_run = run.dry_run or bool(_data(record).get("dry_run"))
        _apply(run, record)
    return sorted(runs.values(), key=lambda r: r.started)


def _apply(run: RunSummary, record: Record) -> None:
    event = record.get("event")
    data = _data(record)
    if event == "run_start":
        run.version = str(data.get("version", ""))
        run.argv = [str(a) for a in data.get("argv", [])]
        run.dry_run = run.dry_run or "--dry-run" in run.argv or "plan" in run.argv
    elif event == "run_end":
        code = data.get("exit_code")
        run.exit_code = code if isinstance(code, int) else 1
        duration = data.get("duration_seconds")
        run.duration_seconds = float(duration) if isinstance(duration, int | float) else None
    elif event == "audit":
        run.outcomes[str(data.get("outcome", "unknown"))] += 1
    elif event == "dry_run_violation":
        run.dry_run_violations += 1
    elif event == "aws_call" and not data.get("read_only") and data.get("outcome") == "succeeded":
        run.aws_changes += 1
    level = str(record.get("level", ""))
    if event not in ("audit", "dry_run_violation"):
        if level == "WARNING":
            run.warnings += 1
        elif level in ("ERROR", "CRITICAL"):
            run.errors += 1


def find_run(runs: list[RunSummary], ref: str) -> RunSummary:
    """Pick a run by 'latest', exact id or unique id prefix. Raises LookupError with a readable message."""
    if not runs:
        raise LookupError("The log file contains no runs.")
    if ref == "latest":
        return runs[-1]
    exact = [r for r in runs if r.run_id == ref]
    if exact:
        return exact[0]
    matches = [r for r in runs if r.run_id.startswith(ref)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise LookupError(f"No run matches '{ref}'.")
    raise LookupError(f"'{ref}' matches {len(matches)} runs; use a longer id.")


def filter_records(
    records: Iterable[Record],
    *,
    run_id: str | None = None,
    outcomes: set[str] | None = None,
    phase: str | None = None,
    account: str | None = None,
    events: set[str] | None = None,
    min_level: str | None = None,
) -> list[Record]:
    """Select records. Filters combine with AND; outcomes apply to audit events only."""
    floor = _LEVELS.get(min_level.upper(), 0) if min_level else 0
    selected: list[Record] = []
    for record in records:
        if run_id is not None and record.get("run_id") != run_id:
            continue
        if phase and phase.lower() not in str(record.get("phase", "")).lower():
            continue
        if account and not _matches_account(record, account):
            continue
        if events is not None and record.get("event") not in events:
            continue
        if outcomes is not None and _data(record).get("outcome") not in outcomes:
            continue
        if _LEVELS.get(str(record.get("level", "")).upper(), 0) < floor:
            continue
        selected.append(record)
    return selected


def _matches_account(record: Record, needle: str) -> bool:
    lowered = needle.lower()
    return (
        lowered in str(record.get("account_id", "")).lower()
        or lowered in str(record.get("account_name", "")).lower()
    )


def clock(ts: str) -> str:
    """HH:MM:SS from an ISO timestamp, or the input unchanged if it cannot be parsed."""
    try:
        return datetime.fromisoformat(ts).strftime("%H:%M:%S")
    except ValueError:
        return ts
