"""The organization trail's stack runs from the audit account, CloudTrail's delegated administrator."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tarmac.cli import deploy_phases
from tarmac.core.config_loader import load_all_configs
from tarmac.services.cloudformation import cloudtrail_stack_home

MGMT, LOG_ARCHIVE, AUDIT = "111111111111", "222222222222", "333333333333"


@pytest.fixture
def bundle(sample_config_dir: Path):
    b, errors = load_all_configs(sample_config_dir)
    assert b is not None, errors
    return b


def _session(stack_in_management: bool) -> MagicMock:
    mgr = MagicMock()
    mgr.get_caller_identity.return_value = {"Account": MGMT}
    mgmt_cfn = MagicMock()
    if stack_in_management:
        mgmt_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}
    else:
        mgmt_cfn.describe_stacks.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack with id x does not exist"}},
            "DescribeStacks",
        )
    clients = {"cloudformation": mgmt_cfn, "organizations": MagicMock(), "cloudtrail": MagicMock()}
    clients["organizations"].describe_organization.return_value = {"Organization": {"Id": "o-abc1234567"}}
    mgr.get_client.side_effect = lambda service, **_: clients[service]
    mgr.clients = clients
    return mgr


def test_a_new_trail_stack_goes_to_the_audit_account(bundle):
    mgr = _session(stack_in_management=False)

    client, account_id = cloudtrail_stack_home(mgr, bundle, "us-east-1", {"audit": AUDIT})

    assert account_id == AUDIT
    assert client is mgr.get_member_client.return_value
    mgr.get_member_client.assert_called_once_with(AUDIT, "cloudformation", region_name="us-east-1")


def test_a_trail_stack_already_in_the_management_account_stays_there(bundle):
    mgr = _session(stack_in_management=True)

    client, account_id = cloudtrail_stack_home(mgr, bundle, "us-east-1", {"audit": AUDIT})

    assert (client, account_id) == (mgr.clients["cloudformation"], MGMT)
    mgr.get_member_client.assert_not_called()


def test_without_an_audit_account_the_management_account_keeps_the_trail(bundle):
    mgr = _session(stack_in_management=False)

    assert cloudtrail_stack_home(mgr, bundle, "us-east-1", {})[1] == MGMT


def test_phase_3_delegates_cloudtrail_to_audit_and_deploys_the_trail_there(bundle, tmp_path):
    mgr = _session(stack_in_management=False)
    accounts = {"log-archive": LOG_ARCHIVE, "audit": AUDIT}

    with (
        patch("tarmac.cli.deploy_phases.get_active_account_id_map", return_value=accounts),
        patch("tarmac.cli.deploy_phases._deploy_log_archive_hardening_stack"),
        patch("tarmac.cli.deploy_phases.CloudFormationService") as cfn,
        patch("tarmac.cli.deploy_phases.OrganizationService") as org,
    ):
        deploy_phases._run_phase_3_cloudtrail(mgr, bundle, "us-east-1", tmp_path)

    org.return_value.register_cloudtrail_delegated_administrator.assert_called_once_with(AUDIT)
    deployed_with = cfn.return_value.deploy_stack.call_args.args[0]
    assert deployed_with is mgr.get_member_client.return_value


def test_registering_an_already_registered_audit_account_is_not_an_error():
    from tarmac.services.organization import OrganizationService

    mgr = MagicMock()
    mgr.get_client.return_value.register_organization_delegated_admin.side_effect = ClientError(
        {"Error": {"Code": "AccountRegisteredException", "Message": "already"}},
        "RegisterOrganizationDelegatedAdmin",
    )

    OrganizationService(mgr).register_cloudtrail_delegated_administrator(AUDIT)
