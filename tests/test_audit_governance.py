"""Audit events emitted by the governance services (organization, OU, SCP, accounts)."""

import logging
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import OUDef
from tarmac.core.exceptions import AccountProvisioningError, OUManagementError
from tarmac.services.accounts import AccountService
from tarmac.services.organization import OrganizationService
from tarmac.services.ou import OUService
from tarmac.services.scp import SCPService


def _events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [r.data for r in caplog.records if getattr(r, "event", None) == "audit"]  # type: ignore[attr-defined]


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "Op")


@pytest.fixture
def client() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mgr(client: MagicMock) -> MagicMock:
    m = MagicMock()
    m.get_client.return_value = client
    return m


def test_ou_create_is_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.list_roots.return_value = {"Roots": [{"Id": "r-1"}]}
    client.get_paginator.return_value.paginate.return_value = [{"OrganizationalUnits": []}]
    client.create_organizational_unit.return_value = {"OrganizationalUnit": {"Id": "ou-9", "Name": "Sec"}}

    OUService(mgr).sync_ou_structure([OUDef(name="Sec")])

    [ev] = _events(caplog)
    assert (ev["action"], ev["resource"], ev["outcome"]) == ("create", "ou:Sec", "succeeded")
    assert ev["details"]["ou_id"] == "ou-9"


def test_ou_create_failure_is_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.create_organizational_unit.side_effect = _client_error("AccessDeniedException")

    with pytest.raises(OUManagementError):
        OUService(mgr)._create_ou("r-1", "Sec")

    [ev] = _events(caplog)
    assert ev["outcome"] == "failed"
    assert "Sec" in ev["resource"]


def test_scp_create_update_attach_and_dry_run_are_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.create_policy.return_value = {"Policy": {"PolicySummary": {"Id": "p-1"}}}
    svc = SCPService(mgr)

    svc.sync_policy("Guard", "d", "{}", {}, dry_run=False)
    svc.sync_policy("Guard2", "d", "{}", {}, dry_run=True)
    svc.attach_policy_if_needed("p-1", "r-1", "Root", [], dry_run=False)
    svc.attach_policy_if_needed("p-1", "r-1", "Root", [], dry_run=True)

    got = [(e["action"], e["outcome"], e["dry_run"]) for e in _events(caplog)]
    assert got == [
        ("create", "succeeded", False),
        ("create", "simulated", True),
        ("attach", "succeeded", False),
        ("attach", "simulated", True),
    ]


def test_scp_update_is_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    svc = SCPService(mgr)
    svc.get_policy_content = MagicMock(return_value='{"a": 1}')  # type: ignore[method-assign]
    svc._ensure_ownership_tag = MagicMock()  # type: ignore[method-assign]

    svc.sync_policy("Guard", "d", '{"a": 2}', {"Guard": {"Id": "p-7"}})

    [ev] = _events(caplog)
    assert (ev["action"], ev["resource"]) == ("update", "scp:Guard")
    assert ev["details"]["policy_id"] == "p-7"


def test_unchanged_scp_emits_no_audit_event(caplog, mgr):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    svc = SCPService(mgr)
    svc.get_policy_content = MagicMock(return_value='{"a": 1}')  # type: ignore[method-assign]

    svc.sync_policy("Guard", "d", '{"a": 1}', {"Guard": {"Id": "p-7"}})

    assert _events(caplog) == []


def test_organization_changes_are_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.create_organization.return_value = {"Organization": {"Id": "o-abc"}}
    svc = OrganizationService(mgr)

    svc._create_organization()
    svc.enable_trusted_services(["cloudtrail.amazonaws.com"])
    svc.register_service_delegated_administrators("111122223333", ["guardduty.amazonaws.com"])
    client.register_delegated_administrator.side_effect = _client_error("AccountAlreadyRegisteredException")
    svc.register_service_delegated_administrators("111122223333", ["guardduty.amazonaws.com"])

    got = [(e["action"], e["resource"], e["outcome"]) for e in _events(caplog)]
    assert got == [
        ("create", "organization:o-abc", "succeeded"),
        ("enable", "trusted-access:cloudtrail.amazonaws.com", "succeeded"),
        ("register", "delegated-admin:guardduty.amazonaws.com:111122223333", "succeeded"),
        ("register", "delegated-admin:guardduty.amazonaws.com:111122223333", "unchanged"),
    ]


def test_phase_tagging_and_cost_tags_are_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.get_paginator.return_value.paginate.return_value = [
        {"CostAllocationTags": [{"TagKey": "Owner"}], "Tags": []}
    ]
    svc = OrganizationService(mgr)

    svc.record_phase_completed("111122223333", "ou")
    svc.activate_cost_allocation_tags(["Owner"])

    assert [e["action"] for e in _events(caplog)] == ["tag", "activate"]


def test_account_move_tag_create_close_are_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.list_parents.return_value = {"Parents": [{"Id": "r-1"}]}
    client.get_paginator.return_value.paginate.return_value = [{"Tags": []}]
    client.create_account.return_value = {"CreateAccountStatus": {"Id": "car-1"}}
    svc = AccountService(mgr)

    svc.move_account_if_needed("111122223333", "dev", "ou-2")
    svc.sync_account_tags("111122223333", "dev", {"Env": "dev"})
    svc.sync_account_tags("111122223333", "dev", {"Env": "qa"}, dry_run=True)
    svc.suspend_account("111122223333", "dev", "ou-s", close=True)

    actions = [(e["action"], e["outcome"]) for e in _events(caplog)]
    assert ("move", "succeeded") in actions
    assert ("tag", "succeeded") in actions
    assert ("tag", "simulated") in actions
    assert ("close", "succeeded") in actions


def test_account_close_and_move_failures_are_audited(caplog, mgr, client):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.list_parents.return_value = {"Parents": [{"Id": "r-1"}]}
    client.move_account.side_effect = _client_error("AccessDeniedException")
    svc = AccountService(mgr)

    with pytest.raises(AccountProvisioningError):
        svc.move_account_if_needed("111122223333", "dev", "ou-2")

    [ev] = _events(caplog)
    assert (ev["action"], ev["outcome"]) == ("move", "failed")


def test_account_create_dry_run_and_request_are_audited(caplog, mgr, client):
    from tarmac.core.config_schema import AccountDef

    caplog.set_level(logging.INFO, logger="tarmac.audit")
    client.create_account.return_value = {"CreateAccountStatus": {"Id": "car-1"}}
    client.get_paginator.return_value.paginate.return_value = [{"Accounts": []}]
    svc = AccountService(mgr)
    acct = AccountDef(name="dev", email="dev@acme-corp.io", ou="Workloads")
    svc._poll_pending_creations = MagicMock()  # type: ignore[method-assign]

    svc.provision_accounts([acct], {"Workloads": "ou-1"}, dry_run=True)
    svc.provision_accounts([acct], {"Workloads": "ou-1"}, dry_run=False)

    got = [(e["action"], e["outcome"]) for e in _events(caplog) if e["action"] == "create"]
    assert got == [("create", "simulated"), ("create", "succeeded")]


def test_deploy_binds_the_phase_name_while_a_phase_runs(tmp_path):
    from unittest.mock import patch

    from helpers import make_config
    from typer.testing import CliRunner

    from tarmac.cli.deploy import app
    from tarmac.core.logging import current_context

    seen: list[str | None] = []
    cfg = make_config(tmp_path, None)
    with (
        patch("tarmac.cli.deploy.AwsSessionManager"),
        patch(
            "tarmac.cli.deploy._run_phase_1_org",
            side_effect=lambda *a, **k: seen.append(current_context().get("phase")),
        ),
    ):
        res = CliRunner().invoke(app, ["run", "--yes", "--phase", "1", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    assert seen == ["organization"]
    assert "phase" not in current_context()
