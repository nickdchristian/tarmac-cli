"""Full teardown: the inventory of what tarmac created, and removal of only that."""

import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core import inventory as inv_mod
from tarmac.core.audit import Outcome, audit
from tarmac.core.inventory import Inventory
from tarmac.services.teardown import TeardownService


def _err(code: str, op: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


@pytest.fixture
def inv() -> Inventory:
    return Inventory()


def _service(clients: dict[str, Any]) -> TeardownService:
    session = MagicMock()
    fallback = MagicMock()
    session.get_client.side_effect = lambda name, region_name=None: clients.get(name, fallback)
    session.get_caller_identity.return_value = {
        "Account": "111",
        "Arn": "arn:aws:sts::111:assumed-role/Admin/x",
    }
    session.default_region = "us-east-1"
    return TeardownService(session)


# ---------------------------------------------------------------- inventory


def test_only_real_changes_are_recorded(inv: Inventory):
    assert inv.observe("create", "ou:Security", "succeeded", False, {"ou_id": "ou-1"})
    assert not inv.observe("create", "ou:Existing", "unchanged", False, {})  # pre-existing: never ours
    assert not inv.observe("create", "ou:Dry", "simulated", True, {})
    assert not inv.observe("delete", "ou:Security", "succeeded", False, {})  # wrong verb
    assert not inv.observe("create", "stack:x", "succeeded", False, {})  # not a tracked kind
    assert inv.get("ou") == {"Security": {"ou_id": "ou-1"}}


def test_audit_events_feed_the_active_inventory():
    active = inv_mod.activate()
    audit("enable", "trusted-access:cloudtrail.amazonaws.com", Outcome.SUCCEEDED, "x", service="cloudtrail")
    audit("enable", "trusted-access:iam.amazonaws.com", Outcome.UNCHANGED, "x")
    audit("create", "identity-user:bob", Outcome.SUCCEEDED, "x", dry_run=True)
    assert list(active.get("trusted-access")) == ["cloudtrail.amazonaws.com"]
    assert active.get("identity-user") == {}


def test_inventory_rebuilds_from_a_run_log(inv: Inventory, tmp_path: Path):
    def line(action: str, resource: str, outcome: str, **extra: Any) -> str:
        return json.dumps(
            {
                "event": "audit",
                "data": {
                    "action": action,
                    "resource": resource,
                    "outcome": outcome,
                    "dry_run": False,
                    **extra,
                },
            }
        )

    log = tmp_path / "run.jsonl"
    log.write_text(
        "\n".join(
            [
                line("create", "ou:Prod", "succeeded", details={"ou_id": "ou-9"}),
                line("create", "ou:Old", "unchanged"),
                line("create", "identity-group:Admins", "succeeded"),
                "not json",
                json.dumps({"event": "other"}),
            ]
        )
    )
    assert inv.ingest_log(log) == 2
    assert set(inv.get("ou")) == {"Prod"}
    assert set(inv.get("identity-group")) == {"Admins"}


def test_cost_tag_activations_accumulate(inv: Inventory):
    inv.observe("activate", "cost-allocation-tags", "succeeded", False, {"tag_keys": ["a"]})
    inv.observe("activate", "cost-allocation-tags", "succeeded", False, {"tag_keys": ["b"]})
    assert inv.get("cost-allocation-tags")["cost-allocation-tags"]["tag_keys"] == ["a", "b"]


# ---------------------------------------------------------------- OUs


def _org_for_ous(occupied: set[str]) -> MagicMock:
    org = MagicMock()
    parents = {"ou-child": "ou-parent", "ou-parent": "r-1"}
    org.list_parents.side_effect = lambda ChildId: {"Parents": [{"Id": parents[ChildId]}]}

    def paginator(name: str) -> MagicMock:
        pag = MagicMock()
        pag.paginate.side_effect = lambda ParentId=None, ChildType=None, **_: [
            {"Children": [{"Id": "444"}] if (ParentId in occupied and ChildType == "ACCOUNT") else []}
        ]
        return pag

    org.get_paginator.side_effect = paginator
    return org


def test_empty_ous_are_deleted_children_first(inv: Inventory):
    inv.record("ou:Parent", {"ou_id": "ou-parent"})
    inv.record("ou:Child", {"ou_id": "ou-child"})
    org = _org_for_ous(set())
    order: list[str] = []
    org.delete_organizational_unit.side_effect = lambda OrganizationalUnitId: order.append(
        OrganizationalUnitId
    )

    items = _service({"organizations": org}).teardown_ous(inv)

    assert order == ["ou-child", "ou-parent"]
    assert [i.action for i in items] == ["DELETED", "DELETED"]
    assert inv.get("ou") == {}


def test_ou_holding_an_account_is_kept(inv: Inventory):
    inv.record("ou:Parent", {"ou_id": "ou-parent"})
    org = _org_for_ous({"ou-parent"})
    items = _service({"organizations": org}).teardown_ous(inv)
    assert items[0].action == "SKIPPED"
    org.delete_organizational_unit.assert_not_called()
    assert "Parent" in inv.get("ou")


def test_ous_not_in_inventory_are_never_touched(inv: Inventory):
    org = _org_for_ous(set())
    assert _service({"organizations": org}).teardown_ous(inv) == []
    org.delete_organizational_unit.assert_not_called()


def test_ou_dry_run_changes_nothing(inv: Inventory):
    inv.record("ou:Parent", {"ou_id": "ou-parent"})
    org = _org_for_ous(set())
    items = _service({"organizations": org}).teardown_ous(inv, dry_run=True)
    assert items[0].action == "SIMULATED"
    org.delete_organizational_unit.assert_not_called()


# ---------------------------------------------------------------- organization settings


def test_org_settings_are_reverted_but_identity_center_access_is_kept(inv: Inventory):
    inv.record("delegated-admin:iam.amazonaws.com:222")
    inv.record("root-sessions")
    inv.record("root-credentials-management")
    inv.record("trusted-access:cloudtrail.amazonaws.com")
    inv.record("trusted-access:sso.amazonaws.com")
    inv.record("alternate-contact:BILLING")
    org, iam, account = MagicMock(), MagicMock(), MagicMock()
    items = _service({"organizations": org, "iam": iam, "account": account}).teardown_org_settings(inv)

    org.deregister_delegated_administrator.assert_called_once_with(
        AccountId="222", ServicePrincipal="iam.amazonaws.com"
    )
    org.disable_aws_service_access.assert_called_once_with(ServicePrincipal="cloudtrail.amazonaws.com")
    iam.disable_organizations_root_sessions.assert_called_once()
    iam.disable_organizations_root_credentials_management.assert_called_once()
    account.delete_alternate_contact.assert_called_once_with(AlternateContactType="BILLING")
    sso = next(i for i in items if i.resource_name == "sso.amazonaws.com")
    assert sso.action == "SKIPPED"
    assert set(inv.get("trusted-access")) == {"sso.amazonaws.com"}


def test_failed_revert_stays_in_the_inventory(inv: Inventory):
    inv.record("trusted-access:config.amazonaws.com")
    org = MagicMock()
    org.disable_aws_service_access.side_effect = _err("ConstraintViolationException")
    items = _service(
        {"organizations": org, "iam": MagicMock(), "account": MagicMock()}
    ).teardown_org_settings(inv)
    assert items[0].action == "FAILED"
    assert "config.amazonaws.com" in inv.get("trusted-access")


# ---------------------------------------------------------------- Identity Center principals


def test_group_assignments_are_removed_before_the_group(inv: Inventory, monkeypatch: pytest.MonkeyPatch):
    inv.record("identity-group:Admins")
    inv.record("identity-user:alice")
    store, sso = MagicMock(), MagicMock()
    store.get_group_id.return_value = {"GroupId": "g1"}
    store.get_user_id.return_value = {"UserId": "u1"}
    calls: list[str] = []
    store.delete_group.side_effect = lambda **kw: calls.append("delete_group")
    pag = MagicMock()
    pag.paginate.return_value = [{"AccountAssignments": [{"AccountId": "222", "PermissionSetArn": "arn:ps"}]}]
    sso.get_paginator.return_value = pag

    class FakeIdentity:
        sso_client = sso
        identitystore_client = store

        def __init__(self, *a: Any, **k: Any) -> None: ...

        def get_instance_details(self) -> tuple[str, str]:
            return "arn:inst", "d-1"

        def delete_account_assignment(self, *args: Any) -> None:
            calls.append("unassign")

    monkeypatch.setattr("tarmac.services.teardown_everything.IdentityService", FakeIdentity)
    items = _service({}).teardown_identity_principals("us-east-1", inv)

    assert calls == ["unassign", "delete_group"]
    assert {i.action for i in items} == {"DELETED"}
    store.delete_user.assert_called_once_with(IdentityStoreId="d-1", UserId="u1")
    assert inv.get("identity-group") == {}
    assert inv.get("identity-user") == {}


# ---------------------------------------------------------------- deployment permission set


def _teardown_access(arn: str, permission_sets: dict[str, str]) -> tuple[list[Any], MagicMock]:
    service = _service({})
    cast(MagicMock, service.session_mgr).get_caller_identity.return_value = {"Account": "111", "Arn": arn}
    identity = MagicMock()
    identity.return_value.get_instance_details.return_value = ("arn:inst", "d-1")
    identity.return_value.list_permission_sets.return_value = permission_sets
    with patch("tarmac.services.teardown_everything.IdentityService", identity):
        return service.teardown_access(), identity.return_value


def test_the_deployment_permission_set_is_deleted_last():
    items, identity = _teardown_access(
        "arn:aws:sts::111:assumed-role/Admin/x", {"TarmacDeployment": "arn:ps"}
    )
    identity.delete_permission_set.assert_called_once_with("arn:inst", "arn:ps")
    assert [i.action for i in items] == ["DELETED"]


def test_a_run_signed_in_with_one_leaves_that_one():
    arn = "arn:aws:sts::111:assumed-role/AWSReservedSSO_TarmacDeployment_abc123/me"
    items, identity = _teardown_access(
        arn, {"TarmacDeployment": "arn:ps", "ManagementAdministrator": "arn:admin"}
    )
    identity.delete_permission_set.assert_called_once_with("arn:inst", "arn:admin")
    assert [(i.resource_name, i.action) for i in items] == [
        ("TarmacDeployment", "SKIPPED"),
        ("ManagementAdministrator", "DELETED"),
    ]


def test_nothing_to_do_without_the_permission_set():
    items, identity = _teardown_access("arn:aws:sts::111:assumed-role/Admin/x", {})
    identity.delete_permission_set.assert_not_called()
    assert items == []


def test_accounts_are_listed_but_never_closed():
    org = MagicMock()

    def paginator(name: str) -> MagicMock:
        pag = MagicMock()
        if name == "list_accounts":
            pag.paginate.return_value = [
                {
                    "Accounts": [
                        {"Id": "111", "Name": "mgmt", "Status": "ACTIVE"},
                        {"Id": "222", "Name": "Audit", "Status": "ACTIVE"},
                        {"Id": "333", "Name": "Theirs", "Status": "ACTIVE"},
                    ]
                }
            ]
        else:
            pag.paginate.side_effect = lambda ResourceId: [
                {"Tags": [{"Key": "tarmac:managed-by", "Value": "tarmac"}] if ResourceId == "222" else []}
            ]
        return pag

    org.get_paginator.side_effect = paginator
    items = _service({"organizations": org}).report_accounts_kept()
    assert [(i.resource_name, i.action) for i in items] == [("Audit", "SKIPPED")]
    # The hint names the account by ID, which is unambiguous and needs no shell quoting.
    assert "tarmac account suspend 222 --close" in items[0].message
    org.close_account.assert_not_called()


# ---------------------------------------------------------------- CLI


def test_everything_cannot_be_combined_with_a_phase(tmp_path: Path):
    from tarmac.services.scaffold import scaffold_project

    scaffold_project(tmp_path)
    result = CliRunner().invoke(
        app, ["destroy", "--everything", "--phase", "3", "-c", str(tmp_path), "--dry-run"]
    )
    assert result.exit_code == 2
    assert "cannot be combined" in result.output


def test_inventory_command_lists_what_an_earlier_release_recorded_locally(tmp_path: Path):
    from tarmac.services.scaffold import scaffold_project

    scaffold_project(tmp_path)
    local = tmp_path / inv_mod.LOCAL_FILE
    local.parent.mkdir()
    local.write_text(json.dumps({"version": 1, "entries": {"ou": {"Security": {"ou_id": "ou-1"}}}}))
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch("tarmac.core.inventory.find_bucket", return_value=None),
    ):
        result = CliRunner().invoke(app, ["inventory", "-c", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"ou": {"Security": {"ou_id": "ou-1"}}}


def test_dry_run_counts_child_ous_as_already_gone(inv: Inventory):
    inv.record("ou:Parent", {"ou_id": "ou-parent"})
    inv.record("ou:Child", {"ou_id": "ou-child"})
    org = _org_for_ous(set())
    org.get_paginator.side_effect = lambda name: MagicMock(
        paginate=lambda ParentId, ChildType: [
            {
                "Children": [{"Id": "ou-child"}]
                if (ParentId == "ou-parent" and ChildType == "ORGANIZATIONAL_UNIT")
                else []
            }
        ]
    )
    items = _service({"organizations": org}).teardown_ous(inv, dry_run=True)
    assert [i.action for i in items] == ["SIMULATED", "SIMULATED"]
    assert set(inv.get("ou")) == {"Parent", "Child"}  # a dry run forgets nothing


def test_contact_that_replaced_an_existing_one_is_not_removed(inv: Inventory):
    inv.record("alternate-contact:BILLING", {"replaced_existing": True})
    inv.record("alternate-contact:SECURITY", {"replaced_existing": False})
    account = MagicMock()
    items = _service(
        {"organizations": MagicMock(), "iam": MagicMock(), "account": account}
    ).teardown_org_settings(inv)
    account.delete_alternate_contact.assert_called_once_with(AlternateContactType="SECURITY")
    assert {i.resource_name: i.action for i in items} == {"BILLING": "SKIPPED", "SECURITY": "DELETED"}


def test_recording_never_breaks_an_audited_action():
    inv_mod.activate()
    audit("create", "ou:Odd", Outcome.SUCCEEDED, "x", ou_id="ou-1", when=Path("/not/json"))  # must not raise
    assert "Odd" in inv_mod.active().get("ou")  # type: ignore[union-attr]
    bad = MagicMock()
    bad.observe.side_effect = RuntimeError("boom")
    inv_mod._active = bad
    audit("create", "ou:Other", Outcome.SUCCEEDED, "x")  # must not raise


def test_full_teardown_runs_in_order_and_ends_with_the_deployment_permission_set(
    inv: Inventory, tmp_path: Path
):
    from tarmac.core.config_loader import load_all_configs
    from tarmac.services.scaffold import scaffold_project

    scaffold_project(tmp_path / "cfg")
    bundle, errors = load_all_configs(tmp_path / "cfg")
    assert bundle is not None
    assert not errors
    inv.record("ou:Parent", {"ou_id": "ou-parent"})
    svc = _service(
        {
            "organizations": _org_for_ous(set()),
            "iam": MagicMock(),
            "account": MagicMock(),
            "cloudformation": MagicMock(),
        }
    )
    phases: list[str] = []
    svc.on_phase = phases.append
    report = svc.teardown_all(bundle, "us-east-1", dry_run=True, inventory=inv)

    order = [p.split("|")[0].strip() for p in phases]
    assert order.index("Organizational Units created by tarmac") < order.index("Phase 1")
    assert phases[-1] == "Tarmac inventory"
    assert phases[-2] == "Tarmac bootstrap permission sets"
    assert phases[-3] == "Member accounts (kept)"
    assert report.status == "SIMULATED"
    assert "Parent" in inv.get("ou")
