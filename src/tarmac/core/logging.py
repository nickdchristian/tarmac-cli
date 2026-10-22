"""Centralized logging for Tarmac: console output, an optional JSON-lines run log, run context and redaction."""

import contextvars
import json
import logging
import os
import platform
import re
import secrets
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from rich.console import Console
from rich.logging import RichHandler

P = ParamSpec("P")
R = TypeVar("R")

_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "tarmac_log_context", default=None
)


def _fields() -> dict[str, Any]:
    return _context.get() or {}


CONTEXT_FIELDS = ("run_id", "command", "phase", "account_id", "account_name", "region")

_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_SECRET_KEY = r"[\w-]*(?:token|password|passwd|authorization|api[_-]?key)|[\w-]*secret[\w-]*"
_SECRET_PAIR = re.compile(
    rf"""(?ix)
    (?P<key>{_SECRET_KEY})
    (?P<sep>["']?\s*[:=]\s*["']?)
    (?P<value>[^\s"',}}]+)
    """
)
_SECRET_NAME = re.compile(rf"(?i)^(?:{_SECRET_KEY})$")
REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Mask AWS access key IDs and values that follow secret-looking keys."""
    text = _KEY_ID.sub(REDACTED, text)
    return _SECRET_PAIR.sub(lambda m: f"{m.group('key')}{m.group('sep')}{REDACTED}", text)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: REDACTED if _SECRET_NAME.match(str(k)) else redact_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(v) for v in value]
    return value


def new_run_id() -> str:
    """Sortable, unique run identifier that is also valid in an STS role session name."""
    return f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def current_context() -> dict[str, Any]:
    return dict(_fields())


@contextmanager
def bind(**fields: Any) -> Iterator[None]:
    """Attach fields (phase, account_id, region, ...) to every log record emitted inside the block."""
    token = _context.set({**_fields(), **{k: v for k, v in fields.items() if v is not None}})
    try:
        yield
    finally:
        _context.reset(token)


def with_current_context(fn: Callable[P, R]) -> Callable[P, R]:
    """Wrap fn so it runs in a copy of the caller's logging context, for use in worker threads."""
    ctx = contextvars.copy_context()

    def runner(*args: P.args, **kwargs: P.kwargs) -> R:
        return ctx.copy().run(fn, *args, **kwargs)

    return runner


class ContextFilter(logging.Filter):
    """Copy the bound run context onto each record and redact secrets from the message."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _fields().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        if not getattr(record, "_redacted", False):
            record.msg = redact(record.getMessage())
            record.args = None
            record.__dict__["_redacted"] = True
        return True


class JsonLineFormatter(logging.Formatter):
    """One JSON object per line; stable keys so the file can be filtered with jq or read by a person."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
        }
        for key in CONTEXT_FIELDS:
            value = getattr(record, key, None)
            if value is not None:
                entry[key] = value
        entry["message"] = redact(record.getMessage())
        event = getattr(record, "event", None)
        if event:
            entry["event"] = event
        data = getattr(record, "data", None)
        if data:
            entry["data"] = redact_value(data)
        if record.exc_info:
            entry["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, default=str, ensure_ascii=False)


def _open_log_file(path: Path) -> logging.FileHandler:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch(mode=0o600)
    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setFormatter(JsonLineFormatter())
    return handler


def setup_logging(
    debug: bool = False,
    console: Console | None = None,
    verbose: bool = False,
    log_file: Path | None = None,
) -> None:
    """Configure console and optional file logging.

    Console: WARNING by default, INFO with verbose (shows every recorded action), DEBUG with debug.
    Log file (when given): JSON lines at INFO, or DEBUG with debug. Third-party libraries stay at WARNING
    so debug output remains focused on Tarmac.
    """
    console_level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    file_level = logging.DEBUG if debug else logging.INFO
    target_console = console if console is not None else Console(stderr=True)

    console_handler = RichHandler(
        console=target_console,
        show_time=True,
        show_path=debug,
        rich_tracebacks=debug,
        markup=True,
    )
    console_handler.setLevel(console_level)
    console_handler.addFilter(ContextFilter())
    handlers: list[logging.Handler] = [console_handler]

    tarmac_level = console_level
    if log_file is not None:
        file_handler = _open_log_file(log_file)
        file_handler.setLevel(file_level)
        file_handler.addFilter(ContextFilter())
        handlers.append(file_handler)
        tarmac_level = min(console_level, file_level)

    logging.basicConfig(
        level=tarmac_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )

    for noisy_pkg in ("botocore", "urllib3", "boto3", "s3transfer"):
        logging.getLogger(noisy_pkg).setLevel(logging.WARNING)
    logging.getLogger("botocore.credentials").setLevel(logging.ERROR)

    logging.getLogger("tarmac").setLevel(tarmac_level)


class RunLog:
    """Records the start and end of one CLI invocation so a log file is self-describing."""

    def __init__(self, command: str, argv: list[str], version: str) -> None:
        self.run_id = new_run_id()
        self.command = command
        self._started = time.monotonic()
        fields: dict[str, Any] = {**_fields(), "run_id": self.run_id, "command": command}
        # Preview runs must not change anything; the AWS call recorder flags any change made while this is set.
        if "--dry-run" in argv:
            fields["dry_run"] = True
        self._token = _context.set(fields)
        logging.getLogger("tarmac.run").info(
            "Run started: tarmac %s (v%s)",
            command,
            version,
            extra={
                "event": "run_start",
                "data": {
                    "version": version,
                    "argv": argv,
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "pid": os.getpid(),
                },
            },
        )

    def finish(self, exc: BaseException | None) -> None:
        exit_code = _exit_code(exc)
        status = "succeeded" if exit_code == 0 else "failed"
        logging.getLogger("tarmac.run").log(
            logging.INFO if exit_code == 0 else logging.ERROR,
            "Run %s (exit code %s) in %.1fs",
            status,
            exit_code,
            time.monotonic() - self._started,
            extra={
                "event": "run_end",
                "data": {
                    "exit_code": exit_code,
                    "status": status,
                    "duration_seconds": round(time.monotonic() - self._started, 3),
                    **({"error": f"{type(exc).__name__}: {exc}"} if exc and exit_code not in (0, 1) else {}),
                },
            },
        )
        for handler in logging.getLogger().handlers:
            handler.flush()
        _context.reset(self._token)


def _exit_code(exc: BaseException | None) -> int:
    if exc is None:
        return 0
    code = getattr(exc, "exit_code", None)
    if isinstance(code, int):
        return code
    if isinstance(exc, SystemExit):
        return exc.code if isinstance(exc.code, int) else 1
    return 1


def start_run(command: str, version: str, argv: list[str] | None = None) -> RunLog:
    return RunLog(command, [redact(a) for a in (argv if argv is not None else sys.argv[1:])], version)
