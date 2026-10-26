"""Permission sets identity.yaml stopped listing are deleted, with their assignments, and nothing else is.

The permission set stack retains a set it stops declaring, so without this a removed set stayed in Identity Center
with every assignment on it. Only sets the stack declared are candidates: bootstrap's sets carry tarmac's tag too, and
deleting them locks the administrator out.
"""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.services.teardown import TeardownService

LIVE = {
    "Admin": "arn:ps/admin",
    "Old": "arn:ps/old",
    "Adopted": "arn:ps/adopted",
    "TarmacDeployment": "arn:ps/deploy",
    "ManagementAdministrator": "arn:ps/console",
}
UNTAGGED = {"arn:ps/adopted"}


def _bundle(*declared: str) -> Any:
    sets = [SimpleNamespace(name=name) for name in declared]
    return SimpleNamespace(
        org=SimpleNamespace(organization=SimpleNamespace(name="acme")),
        identity=SimpleNamespace(identity_center=SimpleNamespace(permission_sets=sets)),
    )


def _service(
    monkeypatch, *, in_stack: set[str], delete_ok: bool = True
) -> tuple[TeardownService, MagicMock, MagicMock]:
    svc = TeardownService(MagicMock())
    identity = MagicMock()
    identity.list_permission_sets.return_value = dict(LIVE)
    identity.permission_sets_in_stack.return_value = set(in_stack)
    identity.is_tarmac_managed_permission_set.side_effect = lambda inst, arn: arn not in UNTAGGED
    identity.get_assignments_for_permission_set.return_value = [{"AccountId": "1"}, {"AccountId": "2"}]
    identity.delete_permission_set.return_value = delete_ok
    stack = MagicMock(return_value=[])
    monkeypatch.setattr(svc, "_resolve_identity_teardown_context", lambda b, r: (identity, "arn:i", [r]))
    monkeypatch.setattr(svc, "_get_management_account_id", lambda: "111")
    monkeypatch.setattr(svc, "teardown_identity", stack)
    return svc, identity, stack


def test_only_a_set_the_stack_declared_and_identity_yaml_dropped_is_listed(monkeypatch):
    svc, identity, stack = _service(monkeypatch, in_stack={"Admin", "Old", "Adopted"})

    items = svc.teardown_undeclared_permission_sets(_bundle("Admin"), "us-east-1", dry_run=True)

    # Adopted was in the stack but carries no tarmac tag; bootstrap's sets were never in it.
    assert [(i.resource_name, i.action) for i in items] == [("Old", "SIMULATED")]
    assert items[0].message == "not in identity.yaml; also removes its 2 account assignments"
    identity.delete_permission_set.assert_not_called()
    stack.assert_not_called()


def test_bootstrap_sets_survive_even_if_a_stack_once_declared_them(monkeypatch):
    svc, identity, _ = _service(monkeypatch, in_stack={"TarmacDeployment", "ManagementAdministrator"})

    assert svc.teardown_undeclared_permission_sets(_bundle("Admin"), "us-east-1") == []
    identity.delete_permission_set.assert_not_called()


@pytest.mark.parametrize(("ok", "action"), [(True, "DELETED"), (False, "FAILED")])
def test_a_deploy_deletes_what_the_stack_declared_before_it_was_updated(monkeypatch, ok, action):
    svc, identity, _ = _service(monkeypatch, in_stack=set(), delete_ok=ok)

    items = svc.teardown_undeclared_permission_sets(
        _bundle("Admin"), "us-east-1", from_stack={"Admin", "Old"}
    )

    identity.permission_sets_in_stack.assert_not_called()  # the deploy read it before updating the stack
    identity.delete_permission_set.assert_called_once_with("arn:i", "arn:ps/old")
    assert [i.action for i in items] == [action]


def test_with_none_declared_the_stack_goes_and_the_sets_it_retained_follow(monkeypatch):
    svc, _, stack = _service(monkeypatch, in_stack={"Admin", "Old"})

    items = svc.teardown_undeclared_permission_sets(_bundle(), "us-east-1", dry_run=True)

    stack.assert_called_once()
    assert sorted(i.resource_name for i in items) == ["Admin", "Old"]


def test_an_unreadable_stack_deletes_nothing(monkeypatch):
    svc, identity, _ = _service(monkeypatch, in_stack=set())
    assert svc.teardown_undeclared_permission_sets(_bundle("Admin"), "us-east-1") == []
    identity.delete_permission_set.assert_not_called()


def test_permission_sets_in_stack_reads_the_template_names():
    from tarmac.services.identity import IdentityService

    session = MagicMock()
    cfn = session.get_client.return_value
    cfn.get_template.return_value = {
        "TemplateBody": "Resources:\n  PermissionSetAdmin:\n    Type: AWS::SSO::PermissionSet\n"
        "    Properties: {Name: Admin}\n  Other:\n    Type: AWS::IAM::Role\n    Properties: {}\n"
    }
    assert IdentityService(session).permission_sets_in_stack("acme") == {"Admin"}
    cfn.get_template.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "does not exist"}}, "GetTemplate"
    )
    assert IdentityService(session).permission_sets_in_stack("acme") == set()
