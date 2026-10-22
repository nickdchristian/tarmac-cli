"""Tests for centralized Rich logging configuration."""

import json
import logging
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest
from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.audit import Outcome, audit
from tarmac.core.logging import bind, current_context, redact, setup_logging, with_current_context


def test_setup_logging_debug_mode():
    setup_logging(debug=True)

    tarmac_logger = logging.getLogger("tarmac")
    assert tarmac_logger.level == logging.DEBUG

    for noisy in ("botocore", "urllib3", "boto3", "s3transfer"):
        assert logging.getLogger(noisy).level == logging.WARNING
    assert logging.getLogger("botocore.credentials").level == logging.ERROR


def test_setup_logging_default_mode():
    setup_logging(debug=False)

    tarmac_logger = logging.getLogger("tarmac")
    assert tarmac_logger.level == logging.WARNING


def test_setup_logging_configures_rich_handler():
    with patch("logging.basicConfig") as mock_basic:
        setup_logging(debug=True)
        assert mock_basic.called
        kwargs = mock_basic.call_args[1]
        assert kwargs["level"] == logging.DEBUG
        assert kwargs["force"] is True
        assert len(kwargs["handlers"]) == 1


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.fixture
def log_file(tmp_path: Path):
    path = tmp_path / "logs" / "run.jsonl"
    setup_logging(log_file=path)
    yield path
    setup_logging()


def test_redact_masks_key_ids_and_secret_values_only():
    text = (
        "key AKIAIOSFODNN7EXAMPLE token=IQoJb3JpZ2luX2VjEXAMPLE "
        '"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG" in arn:aws:iam::123456789012:role/Tarmac'
    )
    out = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "IQoJb3JpZ2luX2VjEXAMPLE" not in out
    assert "wJalrXUtnFEMI" not in out
    assert "arn:aws:iam::123456789012:role/Tarmac" in out


def test_context_is_bound_restored_and_visible_in_threads():
    assert "phase" not in current_context()
    with bind(phase="governance", account_id="111111111111"):
        assert current_context()["phase"] == "governance"

        def read_account(_: int) -> str | None:
            return current_context().get("account_id")

        with ThreadPoolExecutor(max_workers=2) as pool:
            seen = list(pool.map(with_current_context(read_account), range(3)))
        assert seen == ["111111111111"] * 3
    assert "phase" not in current_context()


def test_log_file_records_are_json_with_context_and_redaction(log_file: Path):
    logger = logging.getLogger("tarmac.services.example")
    with bind(run_id="run-1", account_id="111111111111", region="eu-west-1"):
        logger.info("Using key AKIAIOSFODNN7EXAMPLE for %s", "setup")
        logger.debug("below the file level")

    records = _records(log_file)
    assert len(records) == 1
    record = records[0]
    assert record["run_id"] == "run-1"
    assert record["account_id"] == "111111111111"
    assert record["region"] == "eu-west-1"
    assert record["level"] == "INFO"
    assert "AKIA" not in record["message"]
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600


def test_audit_event_has_action_resource_outcome_and_details(log_file: Path):
    audit(
        "attach",
        "scp/FoundationalGuardrails",
        Outcome.SUCCEEDED,
        "Attached SCP FoundationalGuardrails to Root",
        policy_id="p-123",
        session_token="abc123secret",
    )

    (record,) = _records(log_file)
    assert record["event"] == "audit"
    assert record["message"] == "Attached SCP FoundationalGuardrails to Root"
    assert record["data"]["action"] == "attach"
    assert record["data"]["resource"] == "scp/FoundationalGuardrails"
    assert record["data"]["outcome"] == "succeeded"
    assert record["data"]["dry_run"] is False
    assert record["data"]["details"]["session_token"] == "[REDACTED]"
    assert record["data"]["details"]["policy_id"] == "p-123"


def test_audit_dry_run_is_simulated_and_labelled(log_file: Path):
    audit("create", "ou/Security", Outcome.SUCCEEDED, "Created OU Security", dry_run=True)
    (record,) = _records(log_file)
    assert record["data"]["outcome"] == "simulated"
    assert record["message"].startswith("[DRY-RUN] ")


def test_audit_failure_is_logged_as_error(log_file: Path):
    audit("delete", "stack/x", Outcome.FAILED, "Could not delete stack x", error_code="AccessDenied")
    (record,) = _records(log_file)
    assert record["level"] == "ERROR"
    assert record["data"]["outcome"] == "failed"


def test_exception_text_is_included_and_redacted(log_file: Path):
    try:
        raise ValueError("password=hunter2 rejected")
    except ValueError:
        logging.getLogger("tarmac.test").exception("boom")
    (record,) = _records(log_file)
    assert "ValueError" in record["exception"]
    assert "hunter2" not in record["exception"]


def test_verbose_flag_shows_info_on_console(capsys):
    setup_logging(verbose=True)
    assert logging.getLogger("tarmac").level == logging.INFO
    setup_logging()
    assert logging.getLogger("tarmac").level == logging.WARNING


runner = CliRunner()


def test_cli_run_writes_start_and_end_records(tmp_path: Path):
    cfg = make_config(tmp_path, None)
    log = tmp_path / "cli.jsonl"

    res = runner.invoke(app, ["--log-file", str(log), "validate", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    records = _records(log)
    events = [r.get("event") for r in records]
    assert events[0] == "run_start"
    assert events[-1] == "run_end"
    assert records[0]["data"]["version"]
    assert records[-1]["data"]["exit_code"] == 0
    assert {r["run_id"] for r in records} == {records[0]["run_id"]}
    assert records[0]["command"] == "validate"


def test_cli_run_end_records_failure_exit_code(tmp_path: Path):
    log = tmp_path / "cli.jsonl"

    res = runner.invoke(app, ["--log-file", str(log), "validate", "-c", str(tmp_path / "missing")])

    assert res.exit_code == 1
    end = _records(log)[-1]
    assert end["event"] == "run_end"
    assert end["data"]["exit_code"] == 1
    assert end["data"]["status"] == "failed"
    assert end["level"] == "ERROR"


def test_no_log_file_is_created_unless_requested(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("TARMAC_LOG_FILE", raising=False)
    cfg = make_config(tmp_path, None)
    monkeypatch.chdir(tmp_path)

    res = runner.invoke(app, ["validate", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert not list(tmp_path.rglob("*.jsonl"))


def test_log_file_can_come_from_the_environment(tmp_path: Path, monkeypatch):
    cfg = make_config(tmp_path, None)
    log = tmp_path / "env.jsonl"
    monkeypatch.setenv("TARMAC_LOG_FILE", str(log))

    res = runner.invoke(app, ["validate", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert _records(log)[0]["event"] == "run_start"
