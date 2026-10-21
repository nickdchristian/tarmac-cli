"""Listing the member accounts of an AWS Organization and reading their state."""

from collections.abc import Iterator
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .exceptions import GovernanceError

# AWS replaced the account `Status` field with `State` and retired `Status` on 9 September 2026.
# `State` is one of PENDING_ACTIVATION, ACTIVE, SUSPENDED, PENDING_CLOSURE or CLOSED.
CLOSED_STATES = frozenset({"SUSPENDED", "PENDING_CLOSURE", "CLOSED"})


def iter_accounts(org_client: Any) -> Iterator[dict[str, Any]]:
    """Yield every account in the organization, across all pages."""
    for page in org_client.get_paginator("list_accounts").paginate():
        for account in page.get("Accounts", []):
            if isinstance(account, dict):
                yield account


def account_state(account: dict[str, Any]) -> str:
    """The account's lifecycle state, read from `State` (or the retired `Status` that older SDKs still parse)."""
    state = account.get("State") or account.get("Status")
    if not state:
        raise GovernanceError(
            f"AWS Organizations did not report the state of account '{account.get('Name', account.get('Id', '?'))}'.",
            details="Upgrade boto3 and botocore: releases before the account State field cannot read it.",
        )
    return str(state)


def is_active(account: dict[str, Any]) -> bool:
    """Whether the account is ACTIVE and so can be assumed into and configured."""
    return account_state(account) == "ACTIVE"


def is_closed(account: dict[str, Any]) -> bool:
    """Whether the account is suspended, closing or closed; its email cannot be reused."""
    return account_state(account) in CLOSED_STATES


def active_account_ids(org_client: Any) -> dict[str, str]:
    """{AccountName: AccountId} for every ACTIVE account. AWS errors propagate."""
    return {str(a["Name"]): str(a["Id"]) for a in iter_accounts(org_client) if is_active(a)}


def get_active_account_id_map(session_mgr: Any) -> dict[str, str]:
    """{AccountName: AccountId} for every ACTIVE account in the organization.

    Raises GovernanceError when the organization cannot be read: an unreadable organization must not look
    like an empty one, or callers skip every account-scoped step and report success.
    """
    try:
        return active_account_ids(session_mgr.get_client("organizations"))
    except (ClientError, BotoCoreError) as exc:
        raise GovernanceError("Could not list the organization's accounts.", details=str(exc)) from exc
