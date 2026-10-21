"""--adopt-existing reaches the services, and is off unless asked for."""

import re
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.adoption import adopt_existing

runner = CliRunner()


@pytest.mark.parametrize("args", [["org", "scp", "plan"], ["org", "scp", "apply", "--dry-run"]])
@pytest.mark.parametrize(("flag", "expected"), [([], False), (["--adopt-existing"], True)])
def test_scp_commands_pass_the_flag(args, flag, expected):
    seen: list[bool] = []

    def fake(*_a, **_k):
        seen.append(adopt_existing())

    with patch("tarmac.cli.org._execute_scp_reconciliation", fake):
        result = runner.invoke(app, [*args, *flag])

    assert result.exit_code == 0, result.output
    assert seen == [expected]


def test_help_describes_the_flag():
    result = runner.invoke(app, ["deploy", "run", "--help"])
    # CI sets GITHUB_ACTIONS, which makes Typer colour the help and split the option name with escape codes.
    assert "--adopt-existing" in re.sub(r"\x1b\[[0-9;]*m", "", result.output)


@pytest.mark.parametrize("args", [["apply", "--dry-run"], ["account", "apply", "--dry-run"]])
def test_account_apply_does_not_adopt_unless_asked(args):
    """`tarmac apply` forwards to `account apply`; it once passed Typer's truthy OptionInfo as the flag."""
    seen: list[object] = []

    def fake(*_a, **_k):
        seen.append(adopt_existing())
        raise typer.Exit(0)

    with patch("tarmac.cli.account.load_configs_or_exit", fake):
        result = runner.invoke(app, args)

    assert result.exit_code == 0, result.output
    assert seen == [False]
