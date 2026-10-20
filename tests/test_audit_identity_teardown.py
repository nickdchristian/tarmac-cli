"""Audit events emitted by the identity and teardown services."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import GroupDef, UserDef
from tarmac.core.exceptions import IdentityCenterError
from tarmac.core.models import TeardownItemReport
from tarmac.services.identity import IdentityService
from tarmac.services.teardown_base import TeardownBase


def _events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [r.data for r in caplog.records if getattr(r, "event", None) == "audit"]  # type: ignore[attr-defined]


def _err(code: str, msg: str = "boom") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")


@pytest.fixture(autouse=True)
def _info(caplog):
    caplog.set_level(logging.INFO, logger="tarmac.audit")


def _identity() -> tuple[IdentityService, MagicMock, MagicMock]:
    mgr = MagicMock()
    sso, store = MagicMock(), MagicMock()
    mgr.get_client.side_effect = lambda svc, **kw: sso if svc == "sso-admin" else store
    sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:inst", "IdentityStoreId": "d-1"}]}
    svc = IdentityService(mgr)
    svc.get_instance_details = MagicMock(return_value=("arn:inst", "d-1"))  # type: ignore[method-assign]
    svc.sso_client = sso
    svc.identitystore_client = store
    return svc, sso, store


def test_user_group_membership_and_assignment_are_audited(caplog):
    svc, sso, store = _identity()
    store.list_users.return_value = {"Users": []}
    store.list_groups.return_value = {"Groups": []}
    store.create_user.return_value = {"UserId": "u-1"}
    store.create_group.return_value = {"GroupId": "g-1"}
    sso.create_account_assignment.return_value = {"AccountAssignmentCreationStatus": {"Status": "SUCCEEDED"}}

    svc.get_or_create_user(UserDef(username="ann", email="a@example.com", first_name="A", last_name="N"))
    svc.get_or_create_group(GroupDef(name="Admins"))
    svc.add_user_to_group("g-1", "u-1", "Admins", "ann")
    svc.assign_group_to_accounts("g-1", "Admins", "arn:ps", ["111122223333"])

    got = [(e["action"], e["resource"]) for e in _events(caplog)]
    assert got == [
        ("create", "identity-user:ann"),
        ("create", "identity-group:Admins"),
        ("add-member", "identity-group:Admins"),
        ("assign", "sso-assignment:111122223333:Admins"),
    ]


def test_identity_dry_run_and_failures(caplog):
    svc, _, store = _identity()
    store.list_groups.return_value = {"Groups": []}
    store.list_users.return_value = {"Users": []}

    svc.get_or_create_group(GroupDef(name="Admins"), dry_run=True)
    svc.add_user_to_group("g-1", "u-1", "Admins", "ann", dry_run=True)
    svc.assign_group_to_accounts("g-1", "Admins", "arn:ps", ["111122223333"], dry_run=True)
    store.create_group.side_effect = _err("AccessDenied")
    with pytest.raises(IdentityCenterError):
        svc.get_or_create_group(GroupDef(name="Ops"))

    assert [e["outcome"] for e in _events(caplog)] == ["simulated", "simulated", "simulated", "failed"]


def test_existing_membership_conflict_is_audited_as_unchanged(caplog):
    svc, _, store = _identity()
    store.create_group_membership.side_effect = _err("ConflictException")

    assert svc.add_user_to_group("g-1", "u-1", "Admins", "ann") is False
    assert [e["outcome"] for e in _events(caplog)] == ["unchanged"]


def test_assignment_and_permission_set_deletion_are_audited(caplog):
    svc, sso, _ = _identity()
    sso.delete_account_assignment.return_value = {"AccountAssignmentDeletionStatus": {"Status": "SUCCEEDED"}}
    svc.get_assignments_for_permission_set = MagicMock(  # type: ignore[method-assign]
        return_value=[{"AccountId": "111122223333", "PrincipalType": "GROUP", "PrincipalId": "g-1"}]
    )

    svc.delete_permission_set("arn:inst", "arn:ps")

    got = [(e["resource"].split(":")[0], e["outcome"]) for e in _events(caplog)]
    assert got == [("sso-assignment", "succeeded"), ("permission-set", "succeeded")]


def test_assignment_deletion_that_does_not_finish_is_reported_failed(caplog):
    svc, sso, _ = _identity()
    sso.delete_account_assignment.return_value = {
        "AccountAssignmentDeletionStatus": {"Status": "IN_PROGRESS", "RequestId": "r-1"}
    }
    svc._poll_assignment_deletion_status = MagicMock(return_value=False)  # type: ignore[method-assign]

    svc.delete_account_assignment("arn:inst", "111122223333", "arn:ps", "GROUP", "g-1")

    [ev] = _events(caplog)
    assert ev["outcome"] == "failed"


@pytest.mark.parametrize(
    ("action", "outcome", "dry_run"),
    [
        ("DELETED", "succeeded", False),
        ("EMPTY", "succeeded", False),
        ("SIMULATED", "simulated", True),
        ("NOT_FOUND", "unchanged", False),
        ("SKIPPED", "skipped", False),
        ("FAILED", "failed", False),
    ],
)
def test_every_teardown_result_is_audited(caplog, action, outcome, dry_run):
    base = TeardownBase(MagicMock())
    base._notify_phase("Phase 4 | Budgets")
    results = base._new_results_list()

    results.append(TeardownItemReport("S3 Bucket", "b1", "Log Archive", "111122223333", action, "why"))

    [ev] = _events(caplog)
    assert ev["outcome"] == outcome
    assert ev["dry_run"] is dry_run
    assert ev["resource"] == "S3 Bucket:b1"
    assert ev["details"]["teardown_phase"] == "Phase 4 | Budgets"
    assert ev["details"]["account_id"] == "111122223333"


def test_teardown_results_still_reach_the_item_callback(caplog):
    seen: list[TeardownItemReport] = []
    base = TeardownBase(MagicMock(), on_item=seen.append)
    item = TeardownItemReport("Stack", "s", "", "", "DELETED")

    base._new_results_list().append(item)

    assert seen == [item]
    assert len(_events(caplog)) == 1


def test_retained_bucket_delete_is_audited(caplog):
    base = TeardownBase(MagicMock())
    s3 = MagicMock()

    assert base._delete_retained_bucket(s3, "bkt", "Log Archive", "111122223333") == []
    [ev] = _events(caplog)
    assert (ev["action"], ev["outcome"]) == ("delete", "succeeded")
