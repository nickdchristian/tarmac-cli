"""An external identity provider (Okta, Entra ID...) provisions users and groups over SCIM: tarmac only manages
permission sets and the groups' assignments, and never creates users or groups or changes members."""

from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from tarmac.core.config_schema import IdentityCenterConfig
from tarmac.core.exceptions import IdentityCenterError
from tarmac.services.identity import IdentityService
from tarmac.services.plan import PhasePlan, Planner

ADMIN = {"username": "admin@acme.io", "email": "admin@acme.io", "first_name": "A", "last_name": "Admin"}
BREAKGLASS = {"username": "breakglass", "email": "bg@acme.io", "first_name": "B", "last_name": "Glass"}


def _config(**kw: Any) -> IdentityCenterConfig:
    return IdentityCenterConfig.model_validate({"admin_user": ADMIN, **kw})


def test_the_identity_center_directory_still_needs_a_breakglass_user():
    with pytest.raises(ValidationError, match="breakglass_user is required"):
        _config()
    assert _config(breakglass_user=BREAKGLASS).users[1].username == "breakglass"


@pytest.mark.parametrize(
    ("extra", "problem"),
    [
        ({"breakglass_user": BREAKGLASS}, "root user with MFA"),
        ({"additional_users": [BREAKGLASS]}, "provisions users"),
        ({"groups": [{"name": "Ops", "members": ["admin@acme.io"]}]}, "groups.Ops.members"),
    ],
)
def test_an_external_identity_provider_owns_users_and_members(extra, problem):
    with pytest.raises(ValidationError, match=problem):
        _config(identity_source="external", **extra)


def test_with_an_external_identity_provider_tarmac_creates_no_users():
    cfg = _config(identity_source="external", groups=[{"name": "Ops"}])
    assert cfg.external
    assert cfg.users == []


def _service(groups: dict[str, str], *, external_ids: bool = False) -> tuple[IdentityService, MagicMock]:
    mgr, sso, store = MagicMock(), MagicMock(), MagicMock()
    mgr.get_client.side_effect = lambda name, **kw: {"sso-admin": sso, "identitystore": store}.get(
        name, MagicMock()
    )
    sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-1", "IdentityStoreId": "d-1"}]
    }
    store.list_groups.side_effect = lambda **kw: {
        "Groups": [
            {
                "GroupId": gid,
                "DisplayName": name,
                **({"ExternalIds": [{"Issuer": "okta"}]} if external_ids else {}),
            }
            for name, gid in groups.items()
            if kw.get("Filters", [{}])[0].get("AttributeValue", name) == name
        ]
    }
    store.list_users.return_value = {"Users": []}
    service = IdentityService(mgr)
    service.sync_permission_sets_via_cloudformation = MagicMock(return_value={"Admin": "arn:ps-admin"})  # type: ignore[method-assign]
    service.group_assignments = MagicMock(  # type: ignore[method-assign]
        return_value={("111", "arn:ps-admin"), ("222", "arn:ps-admin")}
    )
    service.group_members = MagicMock(return_value={"someone": "m-1"})  # type: ignore[method-assign]
    service.delete_account_assignment = MagicMock(return_value=True)  # type: ignore[method-assign]
    service._assignment_exists = MagicMock(return_value=True)  # type: ignore[method-assign]
    return service, store


def test_deploy_only_keeps_the_assignments_of_groups_the_idp_provisions():
    service, store = _service({"Ops": "g-ops"})
    cfg = _config(
        identity_source="external",
        groups=[{"name": "Ops", "assignments": [{"permission_set": "Admin", "accounts": ["dev"]}]}],
    )

    report = service.sync_identity(cfg, accounts={"dev": "111", "prod": "222"})

    store.create_user.assert_not_called()
    store.create_group.assert_not_called()
    store.create_group_membership.assert_not_called()
    store.delete_group_membership.assert_not_called()  # "someone" was added in the IdP, so stays
    # The assignment identity.yaml no longer declares is removed, as for any group tarmac manages.
    service.delete_account_assignment.assert_called_once()  # pyright: ignore[reportAttributeAccessIssue]
    assert report.assignments_removed == 1
    assert report.users_synced == []


def test_a_group_the_idp_hasnt_pushed_yet_stops_the_deploy_with_what_to_do():
    service, store = _service({})
    cfg = _config(identity_source="external", groups=[{"name": "Ops"}])

    with pytest.raises(IdentityCenterError, match="not in Identity Center: Ops") as raised:
        service.sync_identity(cfg, accounts={})

    assert "push them from it" in str(raised.value.details)
    store.create_group.assert_not_called()


def test_a_directory_an_idp_provisions_is_not_treated_as_tarmacs_own():
    # Without identity_source: external, tarmac would create users and groups beside the IdP's.
    service, store = _service({"Ops": "g-ops"}, external_ids=True)
    cfg = _config(breakglass_user=BREAKGLASS, groups=[{"name": "Ops"}])

    with pytest.raises(IdentityCenterError, match="identity provider provisions") as raised:
        service.sync_identity(cfg, accounts={})

    assert "identity_source: external" in str(raised.value.details)
    store.create_user.assert_not_called()


def test_the_plan_blocks_a_group_the_idp_hasnt_pushed():
    identity = MagicMock()
    identity.get_group_id_by_name.return_value = None
    phase = PhasePlan(6, "t")

    assert Planner._group(phase, identity, "Ops", external=True) is None
    assert Planner._group(phase, identity, "Local", external=False) is None

    assert [(i.name, i.action) for i in phase.items] == [("Ops", "BLOCKED"), ("Local", "CREATE")]
