"""The deployment's name and home Region, recorded on the management account, guard against a changed config."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import typer
from botocore.exceptions import ClientError

from tarmac.cli.common import check_deployment_or_exit
from tarmac.core.exceptions import GovernanceError
from tarmac.services import deployment_identity

MGMT = "111122223333"


def _session(
    tags: dict[str, str] | None = None, *, unreadable: bool = False, stacks: tuple[str, ...] = ()
) -> MagicMock:
    session = MagicMock()
    session.get_caller_identity.return_value = {"Account": MGMT}
    org, cfn = MagicMock(), MagicMock()
    session.get_client.side_effect = lambda service, **_kw: org if service == "organizations" else cfn
    cfn.get_paginator.return_value.paginate.return_value = [
        {"StackSummaries": [{"StackName": name} for name in stacks]}
    ]
    if unreadable:
        org.get_paginator.return_value.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListTagsForResource"
        )
    else:
        org.get_paginator.return_value.paginate.return_value = [
            {"Tags": [{"Key": k, "Value": v} for k, v in {"tarmac:status": "ready", **(tags or {})}.items()]}
        ]
    return session


def _bundle(name: str = "acme", region: str = "eu-west-1") -> Any:
    return SimpleNamespace(
        org=SimpleNamespace(organization=SimpleNamespace(name=name, primary_region=region))
    )


DEPLOYED = {"tarmac:name": "acme", "tarmac:home-region": "eu-west-1"}


def test_reads_only_the_two_identity_tags():
    assert deployment_identity.recorded(_session(DEPLOYED)) == DEPLOYED
    assert deployment_identity.recorded(_session()) == {}
    assert deployment_identity.recorded(_session(unreadable=True)) == {}


@pytest.mark.parametrize("tags", [{}, DEPLOYED])
def test_a_matching_or_not_yet_recorded_deployment_passes(tags):
    deployment_identity.check(_session(tags), _bundle())


def test_a_changed_name_or_region_stops_and_names_both():
    with pytest.raises(GovernanceError) as raised:
        deployment_identity.check(_session(DEPLOYED), _bundle("acme-corp", "us-east-1"))
    details = str(raised.value.details)
    assert "organization.name is 'acme-corp', but it was deployed as 'acme'" in details
    assert "organization.primary_region is 'us-east-1', but it was deployed as 'eu-west-1'" in details
    assert "run `tarmac destroy --everything` with the deployed values first" in details
    assert details.count("Set them back") == 1


def test_every_command_that_reaches_aws_runs_the_check():
    from pathlib import Path

    cli = Path(__file__).resolve().parent.parent / "src/tarmac/cli"
    for command, calls in (("deploy.py", 3), ("main.py", 1), ("preflight.py", 1)):
        assert (cli / command).read_text().count("check_deployment_or_exit(session_mgr, bundle)") == calls, (
            command
        )


def test_commands_exit_on_a_mismatch(monkeypatch):
    monkeypatch.setattr(deployment_identity, "_management_tags", lambda _s: dict(DEPLOYED))
    with pytest.raises(typer.Exit):
        check_deployment_or_exit(MagicMock(), _bundle("acme-corp"))


def test_records_once_when_missing():
    session = _session()
    deployment_identity.record(session, _bundle())
    session.get_client("organizations").tag_resource.assert_called_once_with(
        ResourceId=MGMT,
        Tags=[{"Key": "tarmac:name", "Value": "acme"}, {"Key": "tarmac:home-region", "Value": "eu-west-1"}],
    )

    recorded = _session(DEPLOYED)
    deployment_identity.record(recorded, _bundle())
    recorded.get_client("organizations").tag_resource.assert_not_called()


def test_a_failed_record_does_not_stop_the_deploy():
    session = _session()
    session.get_client("organizations").tag_resource.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "TagResource"
    )
    deployment_identity.record(session, _bundle())


def test_before_the_tags_a_name_change_is_caught_from_the_stack_names():
    with pytest.raises(GovernanceError) as raised:
        deployment_identity.check(
            _session(stacks=("acme-organization-scps", "acme-sso-permission-sets", "unrelated")),
            _bundle("acme-corp"),
        )
    assert "organization.name is 'acme-corp', but it was deployed as 'acme'" in str(raised.value.details)


@pytest.mark.parametrize(
    "stacks",
    [
        ("acme-organization-scps", "unrelated"),
        ("acme-organization-scps", "oldname-organization-scps"),  # leftovers next to the real ones
        (),
    ],
)
def test_before_the_tags_stacks_under_organization_name_or_none_pass(stacks):
    deployment_identity.check(_session(stacks=stacks), _bundle())


def test_recorded_tags_win_over_stack_names():
    deployment_identity.check(_session(DEPLOYED, stacks=("oldname-organization-scps",)), _bundle())


DEPLOYED_BEFORE_TAGS = {"tarmac:completed-phases": "ou+cloudtrail"}


def test_before_the_tags_a_deployment_with_no_stacks_in_primary_region_stops():
    """An upgrade that set primary_region to a Region it never deployed to must not start over there."""
    with pytest.raises(GovernanceError) as raised:
        deployment_identity.check(_session(DEPLOYED_BEFORE_TAGS), _bundle(region="us-east-1"))
    details = str(raised.value.details)
    assert "none of its stacks are in organization.primary_region 'us-east-1'" in details
    assert "defaulted to eu-west-1" in details
    assert "Set them back" not in details  # one fix, not two


def test_before_the_tags_the_inventory_stack_alone_proves_the_region():
    deployment_identity.check(_session(DEPLOYED_BEFORE_TAGS, stacks=("acme-tarmac-inventory",)), _bundle())


def test_a_fresh_organization_with_no_stacks_passes():
    deployment_identity.check(_session(), _bundle(region="us-east-1"))


def test_before_the_tags_an_inventory_stack_under_another_name_is_a_name_change():
    with pytest.raises(GovernanceError, match=r"organization\.yaml doesn't match"):
        deployment_identity.check(_session(stacks=("oldname-tarmac-inventory",)), _bundle())
