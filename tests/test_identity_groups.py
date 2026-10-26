"""Creating Identity Center groups."""

from unittest.mock import MagicMock

import pytest

from tarmac.core.config_schema import GroupDef
from tarmac.services.identity import IdentityService


@pytest.mark.parametrize(("description", "sent"), [("", {}), ("Ops team", {"Description": "Ops team"})])
def test_a_group_description_is_only_sent_when_set(description, sent):
    """Identity Store rejects an empty Description (min length 1), which failed phase 6 for such a group."""
    mock_session_mgr, mock_sso, mock_idstore = MagicMock(), MagicMock(), MagicMock()
    mock_session_mgr.get_client.side_effect = lambda name, **kw: {
        "sso-admin": mock_sso,
        "identitystore": mock_idstore,
    }.get(name, MagicMock())
    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1"}]
    }
    mock_idstore.list_groups.return_value = {"Groups": []}
    mock_idstore.create_group.return_value = {"GroupId": "g-1"}

    IdentityService(mock_session_mgr).get_or_create_group(GroupDef(name="Ops", description=description))

    mock_idstore.create_group.assert_called_once_with(IdentityStoreId="d-1", DisplayName="Ops", **sent)
