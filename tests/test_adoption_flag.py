"""--adopt-existing reaches the services, and is off unless asked for."""

import re
from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.adoption import adopt_existing

runner = CliRunner()


COMMANDS = [
    (["deploy", "run", "--dry-run"], "tarmac.cli.deploy.load_configs_or_exit"),
    (["account", "baseline", "--dry-run"], "tarmac.cli.account.load_configs_or_exit"),
]


@pytest.mark.parametrize(("args", "loader"), COMMANDS)
@pytest.mark.parametrize(("flag", "expected"), [([], False), (["--adopt-existing"], True)])
def test_commands_pass_the_flag(args, loader, flag, expected):
    """The flag is off unless given; a command that forwards to another must not turn it on by accident."""
    seen: list[object] = []

    def fake(*_a, **_k):
        seen.append(adopt_existing())
        raise typer.Exit(0)

    with patch(loader, fake):
        result = runner.invoke(app, [*args, *flag])

    assert result.exit_code == 0, result.output
    assert seen == [expected]


def test_help_describes_the_flag():
    result = runner.invoke(app, ["deploy", "run", "--help"])
    # CI sets GITHUB_ACTIONS, which makes Typer colour the help and split the option name with escape codes.
    assert "--adopt-existing" in re.sub(r"\x1b\[[0-9;]*m", "", result.output)
