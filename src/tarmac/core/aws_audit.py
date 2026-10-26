"""Records AWS API calls made through boto3 clients.

State-changing calls are logged at INFO (and so appear in the run log); read-only calls are logged at DEBUG.
Each record carries the service, operation, Region, outcome, duration, request id and a redacted, size-capped
summary of the request parameters, which is enough to match a Tarmac run against CloudTrail.
"""

import contextlib
import contextvars
import logging
import time
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

from .logging import current_context, redact, redact_value

logger = logging.getLogger("tarmac.aws")

READ_ONLY_PREFIXES = (
    "Describe",
    "List",
    "Get",
    "Head",
    "Lookup",
    "Search",
    "Query",
    "Scan",
    "BatchGet",
    "BatchDescribe",
    "Validate",
    "Check",
    "Test",
    "Simulate",
    "Preview",
    "Estimate",
    "Verify",
    "Select",
    "Assume",
)

# Change-type calls that are expected while previewing: sso-oidc.CreateToken is botocore silently refreshing an
# expired IAM Identity Center login token. Entries are either a bare operation name or "service.Operation".
DRY_RUN_ALLOWED = frozenset({"sso-oidc.CreateToken"})

# AWS answers some calls with an error that only means "already done". Tarmac handles these itself and records the
# result as UNCHANGED, so the call recorder keeps them out of the warnings.
_BENIGN_ERROR_CODES = frozenset({"AccountAlreadyRegisteredException"})
_BENIGN_ERROR_TEXT = (
    "No updates are to be performed",
    "already exists",
    "already a delegated administrator",
    "already a member",
)

_BLOB_KEYS = frozenset(
    {"TemplateBody", "PolicyDocument", "Content", "Body", "Document", "ZipFile", "UserData"}
)
_MAX_STRING = 200
_MAX_ITEMS = 10
_MAX_DEPTH = 4
_SESSION_UNIQUE_ID = "tarmac-aws-audit"


def is_read_only(operation: str) -> bool:
    return operation.startswith(READ_ONLY_PREFIXES)


_retrying: contextvars.ContextVar[bool] = contextvars.ContextVar("tarmac_retrying", default=False)


@contextlib.contextmanager
def retrying() -> Iterator[None]:
    """An AWS call tarmac will retry if it fails: the failure is logged quietly, since `retry_notice` says what's
    happening instead. A failure that ends the retries is raised and reported by the caller as usual."""
    token = _retrying.set(True)
    try:
        yield
    finally:
        _retrying.reset(token)


def retry_notice(what: str, why: str, delay: float) -> None:
    """Tell the person running tarmac that it is waiting on AWS and trying again, rather than warning of a failure.
    Callers say it once per wait, not on every attempt."""
    logger.warning("%s: %s; retrying every %.0fs...", what, why, delay)


T = TypeVar("T")

#: What a brand-new account's services answer for its first minutes, until they are activated.
NOT_ACTIVATED = frozenset({"OptInRequired", "SubscriptionRequiredException"})


def while_activating(
    call: Callable[[], T],
    what: str,
    *,
    timeout: float = 600.0,
    poll: float = 20.0,
    sleep: Callable[[float], None] | None = None,
) -> T:
    """``call()``, retried while the account's services are still activating, as they are right after it is
    created. Any other error, or the same one after ``timeout`` seconds, is raised."""
    deadline = time.monotonic() + timeout
    noticed = False
    while True:
        try:
            with retrying():
                return call()
        except Exception as e:
            code = str(getattr(e, "response", {}).get("Error", {}).get("Code", ""))
            if code not in NOT_ACTIVATED or time.monotonic() >= deadline:
                raise
            if not noticed:
                retry_notice(what, "the new account's services are still activating", poll)
                noticed = True
            (sleep or time.sleep)(poll)


def is_benign_error(error: dict[str, Any]) -> bool:
    """True for an error that only reports that the requested state already holds."""
    if not error:
        return False
    if error.get("Code") in _BENIGN_ERROR_CODES:
        return True
    message = str(error.get("Message", ""))
    return any(text in message for text in _BENIGN_ERROR_TEXT)


def summarize_params(value: Any, depth: int = 0) -> Any:
    """Redacted, size-capped copy of request parameters for logging."""
    if depth > _MAX_DEPTH:
        return "..."
    if isinstance(value, dict):
        cleaned = redact_value(
            {
                k: (f"<{len(v)} chars>" if k in _BLOB_KEYS and isinstance(v, str | bytes) else v)
                for k, v in value.items()
            }
        )
        return {k: summarize_params(v, depth + 1) for k, v in cleaned.items()}
    if isinstance(value, list | tuple):
        items = [summarize_params(v, depth + 1) for v in list(value)[:_MAX_ITEMS]]
        if len(value) > _MAX_ITEMS:
            items.append(f"... {len(value) - _MAX_ITEMS} more")
        return items
    if isinstance(value, bytes | bytearray):
        return f"<{len(value)} bytes>"
    if isinstance(value, str):
        text = redact(value)
        return text if len(text) <= _MAX_STRING else f"{text[:_MAX_STRING]}... ({len(text)} chars)"
    return value


def _split(event_name: str) -> tuple[str, str]:
    parts = event_name.split(".")
    return (parts[1], parts[2]) if len(parts) >= 3 else ("unknown", event_name)


def _on_params(params: Any = None, context: Any = None, **_: Any) -> None:
    try:
        if isinstance(context, dict):
            context["tarmac_params"] = summarize_params(params) if params else {}
    except Exception:  # logging must never break an AWS call
        logger.debug("Could not summarize request parameters", exc_info=True)


def _on_before_call(context: Any = None, **_: Any) -> None:
    if isinstance(context, dict):
        context["tarmac_started"] = time.monotonic()


def _log_call(
    event_name: str, context: Any, outcome: str, error: dict[str, Any], meta: dict[str, Any]
) -> None:
    service, operation = _split(event_name)
    ctx: dict[str, Any] = context if isinstance(context, dict) else {}
    read_only = is_read_only(operation)
    started = ctx.get("tarmac_started")
    data: dict[str, Any] = {
        "service": service,
        "operation": operation,
        "region": ctx.get("client_region"),
        "outcome": outcome,
        "read_only": read_only,
        "duration_ms": round((time.monotonic() - started) * 1000) if started else None,
        "request_id": meta.get("RequestId"),
        "http_status": meta.get("HTTPStatusCode"),
        "params": ctx.get("tarmac_params", {}),
    }
    if error:
        data["error_code"] = error.get("Code")
        data["error_message"] = redact(str(error.get("Message", "")))
    allowed = operation in DRY_RUN_ALLOWED or f"{service}.{operation}" in DRY_RUN_ALLOWED
    if current_context().get("dry_run") and not read_only and not allowed:
        logger.error(
            "Dry-run made a state-changing AWS call: %s.%s",
            service,
            operation,
            extra={"event": "dry_run_violation", "data": data},
        )
        return

    where = f" in {data['region']}" if data["region"] else ""
    detail = f": {data['error_code']} {data.get('error_message', '')}".rstrip() if error else ""
    message = f"{service}.{operation} {outcome}{where}{detail}"
    if read_only or (error and (is_benign_error(error) or _retrying.get())):
        level = logging.DEBUG
    else:
        level = logging.WARNING if outcome == "failed" else logging.INFO
    logger.log(level, "%s", message, extra={"event": "aws_call", "data": data})


def _on_after_call(event_name: str = "", context: Any = None, parsed: Any = None, **_: Any) -> None:
    try:
        parsed = parsed if isinstance(parsed, dict) else {}
        error = parsed.get("Error") if isinstance(parsed.get("Error"), dict) else {}
        meta = parsed.get("ResponseMetadata") if isinstance(parsed.get("ResponseMetadata"), dict) else {}
        _log_call(event_name, context, "failed" if error else "succeeded", error, meta)
    except Exception:  # logging must never break an AWS call
        logger.debug("Could not record AWS call", exc_info=True)


def _on_call_error(event_name: str = "", context: Any = None, exception: Any = None, **_: Any) -> None:
    try:
        error = {"Code": type(exception).__name__, "Message": str(exception)}
        _log_call(event_name, context, "failed", error, {})
    except Exception:  # logging must never break an AWS call
        logger.debug("Could not record AWS call error", exc_info=True)


def instrument_session(session: Any) -> None:
    """Attach the call recorder to a boto3 Session; clients created afterwards report their calls."""
    events = session.events
    events.register("provide-client-params.*.*", _on_params, unique_id=f"{_SESSION_UNIQUE_ID}-params")
    events.register("before-call.*.*", _on_before_call, unique_id=f"{_SESSION_UNIQUE_ID}-before")
    events.register("after-call.*.*", _on_after_call, unique_id=f"{_SESSION_UNIQUE_ID}-after")
    events.register("after-call-error.*.*", _on_call_error, unique_id=f"{_SESSION_UNIQUE_ID}-error")
