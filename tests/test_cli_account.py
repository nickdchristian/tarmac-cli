"""CLI-level tests for `tarmac account list` and `suspend` (services patched)."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from helpers import make_config
from typer.testing import CliRunner

from tarmac.cli.account import app
from tarmac.core.exceptions import GovernanceError

runner = CliRunner()

ACCOUNTS = [
    {"Id": "111111111111", "Name": "management", "Email": "m@example.com", "Status": "ACTIVE"},
    {"Id": "222222222222", "Name": "Log Archive", "Email": "l@example.com", "Status": "ACTIVE"},
    {"Id": "333333333333", "Name": "old-sandbox", "Email": "o@example.com", "Status": "SUSPENDED"},
]
PARENTS = {"111111111111": "r-root", "222222222222": "ou-sec", "333333333333": "ou-susp"}


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    return make_config(tmp_path, None)


@pytest.fixture
def services():
    with (
        patch("tarmac.cli.account.AwsSessionManager"),
        patch("tarmac.cli.account.OUService") as ou_cls,
        patch("tarmac.cli.account.AccountService") as acct_cls,
    ):
        ou, acct = ou_cls.return_value, acct_cls.return_value
        ou.get_root_id.return_value = "r-root"
        ou.list_all_ous.return_value = {"Security": "ou-sec", "Suspended": "ou-susp"}
        acct.list_all_accounts.return_value = ACCOUNTS
        acct.list_existing_accounts.return_value = {a["Name"]: a for a in ACCOUNTS}
        acct.get_account_parent_id.side_effect = lambda account_id: PARENTS[account_id]
        yield ou, acct


def _names(res) -> list[str]:
    return [r["name"] for r in json.loads(res.stdout)]


def test_list_json_all_accounts_with_parent_names(cfg: Path, services):
    res = runner.invoke(app, ["list", "--json", "-c", str(cfg)])
    assert res.exit_code == 0, res.output
    rows = json.loads(res.stdout)
    assert {r["name"]: r["parent_ou"] for r in rows} == {
        "management": "Root",
        "Log Archive": "Security",
        "old-sandbox": "Suspended",
    }


def test_list_filters(cfg: Path, services):
    assert _names(runner.invoke(app, ["list", "--json", "--suspended", "-c", str(cfg)])) == ["old-sandbox"]
    assert _names(runner.invoke(app, ["list", "--json", "--active", "-c", str(cfg)])) == [
        "management",
        "Log Archive",
    ]


def test_list_table_summarizes_suspended(cfg: Path, services):
    res = runner.invoke(app, ["list", "-c", str(cfg)])
    assert res.exit_code == 0, res.output
    assert "Log Archive" in res.output
    assert "Total accounts: 3 (1 suspended" in res.output


def test_list_governance_error_exits_1(cfg: Path, services):
    services[0].get_root_id.side_effect = GovernanceError("no org")
    res = runner.invoke(app, ["list", "-c", str(cfg)])
    assert res.exit_code == 1
    assert "List Accounts Failed" in res.output


def test_suspend_declined_confirmation_does_nothing(cfg: Path, services):
    _, acct = services
    res = runner.invoke(app, ["suspend", "old-sandbox", "-c", str(cfg)], input="n\n")
    assert res.exit_code == 0
    assert "cancelled" in res.output
    acct.suspend_account.assert_not_called()


@pytest.mark.parametrize("target", ["Log Archive", "log_archive", "222222222222"])
def test_suspend_matches_by_name_normalized_name_or_id(cfg: Path, services, target: str):
    _, acct = services
    acct.suspend_account.return_value = SimpleNamespace(
        status="SUSPENDED", name="Log Archive", account_id="222222222222", message="moved"
    )

    res = runner.invoke(app, ["suspend", target, "--yes", "-c", str(cfg)])

    assert res.exit_code == 0, res.output
    kwargs = acct.suspend_account.call_args.kwargs
    assert kwargs["account_id"] == "222222222222"
    assert kwargs["suspended_ou_id"] == "ou-susp"
    assert kwargs["close"] is False


def test_suspend_unknown_account_exits_1(cfg: Path, services):
    _, acct = services
    res = runner.invoke(app, ["suspend", "ghost", "--yes", "-c", str(cfg)])
    assert res.exit_code == 1
    assert "not found" in res.output
    acct.suspend_account.assert_not_called()


def test_suspend_dry_run_skips_prompt_and_passes_flag(cfg: Path, services):
    _, acct = services
    acct.suspend_account.return_value = SimpleNamespace(
        status="DRY_RUN", name="old-sandbox", account_id="333333333333", message="would move"
    )
    res = runner.invoke(app, ["suspend", "old-sandbox", "--dry-run", "-c", str(cfg)])
    assert res.exit_code == 0, res.output
    assert acct.suspend_account.call_args.kwargs["dry_run"] is True


def test_suspend_close_failure_exits_1(cfg: Path, services):
    _, acct = services
    acct.suspend_account.return_value = SimpleNamespace(
        status="CLOSE_FAILED", name="old-sandbox", account_id="333333333333", message="quota"
    )
    res = runner.invoke(app, ["suspend", "old-sandbox", "--close", "--yes", "-c", str(cfg)])
    assert res.exit_code == 1
    assert acct.suspend_account.call_args.kwargs["close"] is True
