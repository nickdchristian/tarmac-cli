"""`tarmac logs`: reading, summarizing and filtering a run log."""

import json
import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.audit import Outcome, audit
from tarmac.core.logging import bind, setup_logging, start_run
from tarmac.services.logview import filter_records, find_run, group_runs, read_records

runner = CliRunner()


def _write_run(path: Path, command: str, *, fail: bool = False, dry_run: bool = False) -> str:
    setup_logging(log_file=path)
    run = start_run(command, "1.2.3", ["--dry-run"] if dry_run else [command])
    with bind(phase="organizational-units"):
        audit("create", "ou:Security", Outcome.SUCCEEDED, "Created OU 'Security' (ou-1)", dry_run=dry_run)
        audit("create", "ou:Sandbox", Outcome.UNCHANGED, "OU 'Sandbox' already exists")
    with bind(phase="accounts", account_id="111122223333", account_name="dev"):
        if fail:
            audit("move", "account:111122223333", Outcome.FAILED, "Could not move account 'dev': denied")
            logging.getLogger("tarmac.test").warning("Retrying later")
    run_id = run.run_id
    run.finish(SystemExit(1) if fail else None)
    logging.shutdown()
    return run_id


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    return tmp_path / "tarmac.jsonl"


def test_list_runs_shows_each_run_with_status(log_file):
    ok = _write_run(log_file, "ou")
    bad = _write_run(log_file, "account", fail=True)

    res = runner.invoke(app, ["logs", str(log_file)])

    assert res.exit_code == 0, res.output
    assert ok in res.output
    assert bad in res.output
    assert "succeeded" in res.output
    assert "failed" in res.output


def test_list_runs_json(log_file):
    run_id = _write_run(log_file, "ou", dry_run=True)

    res = runner.invoke(app, ["logs", str(log_file), "--json"])

    [entry] = json.loads(res.stdout)
    assert entry["run_id"] == run_id
    assert entry["dry_run"] is True
    assert entry["outcomes"] == {"simulated": 1, "unchanged": 1}
    assert entry["status"] == "succeeded"


def test_run_detail_shows_actions_and_problems(log_file):
    _write_run(log_file, "ou")
    bad = _write_run(log_file, "account", fail=True)

    res = runner.invoke(app, ["logs", str(log_file), "--run", bad])

    assert res.exit_code == 0, res.output
    assert "FAILED" in res.output
    assert "Created OU" in res.output
    assert "Could not move account" in res.output
    assert "Retrying later" in res.output


def test_latest_run_and_outcome_filter(log_file):
    _write_run(log_file, "ou")
    _write_run(log_file, "account", fail=True)

    res = runner.invoke(app, ["logs", str(log_file), "--run", "latest", "--outcome", "failed"])

    assert "Could not move account" in res.output
    assert "Created OU" not in res.output
    assert "Retrying later" not in res.output


def test_filtering_without_run_uses_latest(log_file):
    _write_run(log_file, "ou")
    _write_run(log_file, "account", fail=True)

    res = runner.invoke(app, ["logs", str(log_file), "--account", "dev"])

    assert res.exit_code == 0, res.output
    assert "Could not move account" in res.output
    assert "Created OU" not in res.output


def test_detail_json_emits_one_record_per_line(log_file):
    _write_run(log_file, "account", fail=True)

    res = runner.invoke(app, ["logs", str(log_file), "--run", "latest", "--json"])

    lines = [json.loads(line) for line in res.stdout.splitlines()]
    assert {r["event"] for r in lines if r.get("event") == "audit"} == {"audit"}
    assert all("run_id" in r for r in lines)


def test_dry_run_header_says_nothing_was_changed(log_file):
    _write_run(log_file, "ou", dry_run=True)

    res = runner.invoke(app, ["logs", str(log_file), "--run", "latest"])

    assert "DRY RUN" in res.output
    assert "simulated" in res.output


def test_missing_file_and_unknown_run_exit_nonzero(log_file, tmp_path):
    assert runner.invoke(app, ["logs", str(tmp_path / "nope.jsonl")]).exit_code == 1
    _write_run(log_file, "ou")
    res = runner.invoke(app, ["logs", str(log_file), "--run", "zzz"])
    assert res.exit_code == 1
    assert "No run matches" in res.output


def test_no_file_and_no_env_var_is_an_error(monkeypatch):
    monkeypatch.delenv("TARMAC_LOG_FILE", raising=False)
    res = runner.invoke(app, ["logs"])
    assert res.exit_code == 1
    assert "TARMAC_LOG_FILE" in res.output


def test_log_file_defaults_to_environment_variable(log_file, monkeypatch):
    _write_run(log_file, "ou")
    monkeypatch.setenv("TARMAC_LOG_FILE", str(log_file))

    res = runner.invoke(app, ["logs"])

    assert res.exit_code == 0, res.output
    assert "Tarmac Runs" in res.output


def test_reading_a_log_does_not_append_to_it(log_file):
    _write_run(log_file, "ou")
    before = log_file.read_text()

    runner.invoke(app, ["--log-file", str(log_file), "logs", str(log_file)])

    assert log_file.read_text() == before


def test_corrupt_lines_are_skipped_and_reported(log_file):
    _write_run(log_file, "ou")
    with log_file.open("a") as handle:
        handle.write("not json\n[1,2]\n\n")

    records, skipped = read_records(log_file)
    res = runner.invoke(app, ["logs", str(log_file)])

    assert skipped == 2
    assert records
    assert "Skipped 2 lines" in res.output


def test_incomplete_run_is_reported(log_file):
    log_file.write_text(
        json.dumps({"ts": "2026-10-20T10:00:00+00:00", "level": "INFO", "run_id": "r1", "command": "ou"})
        + "\n"
    )
    [run] = group_runs(read_records(log_file)[0])
    assert run.status == "incomplete"


def test_find_run_prefix_ambiguity():
    runs = group_runs(
        [
            {"ts": "2026-10-20T10:00:00+00:00", "run_id": "20261020T1-aaa", "level": "INFO"},
            {"ts": "2026-10-20T11:00:00+00:00", "run_id": "20261020T1-bbb", "level": "INFO"},
        ]
    )
    with pytest.raises(LookupError, match="2 runs"):
        find_run(runs, "20261020")
    assert find_run(runs, "latest").run_id.endswith("bbb")
    assert find_run(runs, "20261020T1-a").run_id.endswith("aaa")


def test_filter_records_combines_filters():
    records = [
        {
            "run_id": "r",
            "event": "audit",
            "level": "INFO",
            "phase": "accounts",
            "data": {"outcome": "failed"},
        },
        {
            "run_id": "r",
            "event": "audit",
            "level": "INFO",
            "phase": "accounts",
            "data": {"outcome": "succeeded"},
        },
        {"run_id": "r", "level": "WARNING", "phase": "identity"},
        {"run_id": "other", "event": "audit", "level": "INFO", "data": {"outcome": "failed"}},
    ]
    assert len(filter_records(records, run_id="r", outcomes={"failed"})) == 1
    assert len(filter_records(records, run_id="r", phase="ACCOUNTS")) == 2
    assert len(filter_records(records, run_id="r", min_level="warning")) == 1
