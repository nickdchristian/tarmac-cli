from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.exceptions import GovernanceError
from tarmac.core.org_accounts import (
    account_state,
    active_account_ids,
    get_active_account_id_map,
    is_active,
    is_closed,
    iter_accounts,
)


def _org_client(*pages: list[dict]) -> MagicMock:
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"Accounts": accts} for accts in pages]
    return client


def test_iter_accounts_reads_every_page():
    client = _org_client([{"Id": "1", "Name": "a"}], [{"Id": "2", "Name": "b"}])
    assert [a["Id"] for a in iter_accounts(client)] == ["1", "2"]
    client.get_paginator.assert_called_once_with("list_accounts")


def test_state_is_preferred_and_the_retired_status_is_a_fallback():
    assert account_state({"State": "CLOSED", "Status": "SUSPENDED"}) == "CLOSED"
    assert account_state({"Status": "ACTIVE"}) == "ACTIVE"


def test_an_account_without_state_or_status_is_an_error_not_assumed_active():
    with pytest.raises(GovernanceError, match="did not report the state"):
        is_active({"Id": "111111111111", "Name": "prod"})


@pytest.mark.parametrize(
    ("state", "active", "closed"),
    [
        ("ACTIVE", True, False),
        ("PENDING_ACTIVATION", False, False),
        ("SUSPENDED", False, True),
        ("PENDING_CLOSURE", False, True),
        ("CLOSED", False, True),
    ],
)
def test_every_state_is_classified(state, active, closed):
    assert is_active({"State": state}) is active
    assert is_closed({"State": state}) is closed


def test_active_account_ids_skips_closed_and_closing_accounts():
    client = _org_client(
        [
            {"Id": "111111111111", "Name": "prod", "State": "ACTIVE"},
            {"Id": "222222222222", "Name": "old", "State": "CLOSED"},
            {"Id": "333333333333", "Name": "closing", "State": "PENDING_CLOSURE"},
            {"Id": "444444444444", "Name": "legacy", "Status": "SUSPENDED"},
        ]
    )
    assert active_account_ids(client) == {"prod": "111111111111"}


def test_get_active_account_id_map_raises_when_the_organization_cannot_be_read():
    session_mgr = MagicMock()
    session_mgr.get_client.return_value.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListAccounts"
    )
    with pytest.raises(GovernanceError, match="Could not list the organization's accounts"):
        get_active_account_id_map(session_mgr)
