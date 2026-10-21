"""Listing the member accounts of an AWS Organization."""

import logging
from collections.abc import Iterator
from typing import Any

from .exceptions import AWS_ERRORS

logger = logging.getLogger(__name__)


def iter_accounts(org_client: Any) -> Iterator[dict[str, Any]]:
    """Yield every account in the organization, across all pages."""
    for page in org_client.get_paginator("list_accounts").paginate():
        for account in page.get("Accounts", []):
            if isinstance(account, dict):
                yield account


def is_active(account: dict[str, Any]) -> bool:
    """Whether an account is ACTIVE; suspended and pending-closure accounts cannot be assumed into."""
    return account.get("Status", "ACTIVE") == "ACTIVE"


def active_account_ids(org_client: Any) -> dict[str, str]:
    """{AccountName: AccountId} for every ACTIVE account. AWS errors propagate."""
    return {str(a["Name"]): str(a["Id"]) for a in iter_accounts(org_client) if is_active(a)}


def get_active_account_id_map(session_mgr: Any) -> dict[str, str]:
    """{AccountName: AccountId} for every ACTIVE account, or {} when Organizations cannot be read."""
    try:
        return active_account_ids(session_mgr.get_client("organizations"))
    except AWS_ERRORS as exc:
        logger.warning("Could not list organization accounts; account names will not resolve: %s", exc)
        return {}
