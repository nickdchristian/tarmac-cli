from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from tarmac.core.org_accounts import active_account_ids, get_active_account_id_map, iter_accounts


def _org_client(*pages: list[dict]) -> MagicMock:
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"Accounts": accts} for accts in pages]
    return client


def test_iter_accounts_reads_every_page():
    client = _org_client([{"Id": "1", "Name": "a"}], [{"Id": "2", "Name": "b"}])
    assert [a["Id"] for a in iter_accounts(client)] == ["1", "2"]
    client.get_paginator.assert_called_once_with("list_accounts")


def test_active_account_ids_skips_suspended_and_pending_closure():
    client = _org_client(
        [
            {"Id": "111111111111", "Name": "prod", "Status": "ACTIVE"},
            {"Id": "222222222222", "Name": "old", "Status": "SUSPENDED"},
            {"Id": "333333333333", "Name": "closing", "Status": "PENDING_CLOSURE"},
        ]
    )
    assert active_account_ids(client) == {"prod": "111111111111"}


def test_get_active_account_id_map_returns_empty_on_aws_error():
    session_mgr = MagicMock()
    session_mgr.get_client.return_value.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListAccounts"
    )
    assert get_active_account_id_map(session_mgr) == {}
