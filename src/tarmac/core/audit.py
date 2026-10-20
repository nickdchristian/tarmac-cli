"""Audit events: a record of each change Tarmac makes (or would make), readable by a person and by a script."""

import logging
from enum import StrEnum
from typing import Any

from . import inventory

logger = logging.getLogger("tarmac.audit")


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    SIMULATED = "simulated"
    FAILED = "failed"


def audit(
    action: str,
    resource: str,
    outcome: Outcome,
    message: str,
    *,
    dry_run: bool = False,
    **details: Any,
) -> None:
    """Record one action.

    action is a short verb (create, update, delete, attach, enable, move, tag...), resource names what was
    acted on, and message is a plain sentence a reviewer can read on its own. Extra keyword arguments are
    stored under "details" (for example aws_request_id, policy_id, region).
    """
    if dry_run and outcome is Outcome.SUCCEEDED:
        outcome = Outcome.SIMULATED
    text = f"[DRY-RUN] {message}" if dry_run and not message.startswith("[DRY-RUN]") else message
    logger.log(
        logging.ERROR if outcome is Outcome.FAILED else logging.INFO,
        "%s",
        text,
        extra={
            "event": "audit",
            "data": {
                "action": action,
                "resource": resource,
                "outcome": outcome.value,
                "dry_run": dry_run,
                **({"details": details} if details else {}),
            },
        },
    )

    recorder = inventory.active()
    if recorder is not None:
        try:
            recorder.observe(action, resource, outcome.value, dry_run, details)
        except Exception:
            logger.debug("Could not update the inventory", exc_info=True)
