"""Records AWS API calls made through boto3 clients.

State-changing calls are logged at INFO (and so appear in the run log); read-only calls are logged at DEBUG.
Each record carries the service, operation, Region, outcome, duration, request id and a redacted, size-capped
summary of the request parameters, which is enough to match a Tarmac run against CloudTrail.
"""

import logging
import time
from typing import Any

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

# Change-type calls that are safe, and expected, while previewing: CloudFormation change sets are how a plan is built.
DRY_RUN_ALLOWED = frozenset({"CreateChangeSet", "DeleteChangeSet"})

_BLOB_KEYS = frozenset(
    {"TemplateBody", "PolicyDocument", "Content", "Body", "Document", "ZipFile", "UserData"}
)
_MAX_STRING = 200
_MAX_ITEMS = 10
_MAX_DEPTH = 4
_SESSION_UNIQUE_ID = "tarmac-aws-audit"


def is_read_only(operation: str) -> bool:
    return operation.startswith(READ_ONLY_PREFIXES)


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
    if current_context().get("dry_run") and not read_only and operation not in DRY_RUN_ALLOWED:
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
    level = logging.DEBUG if read_only else logging.WARNING if outcome == "failed" else logging.INFO
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
