"""The audit account runs the organization trail as CloudTrail's delegated administrator."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tarmac.cli import deploy_phases
from tarmac.core.config_loader import load_all_configs
from tarmac.core.exceptions import GovernanceError
from tarmac.services.organization import OrganizationService

LOG_ARCHIVE, AUDIT = "222222222222", "333333333333"


@pytest.fixture
def bundle(sample_config_dir: Path):
    b, errors = load_all_configs(sample_config_dir)
    assert b is not None, errors
    return b


def _run_phase_3(bundle, tmp_path: Path, accounts: dict[str, str]) -> tuple[MagicMock, MagicMock, MagicMock]:
    mgr = MagicMock()
    mgr.get_client.return_value.describe_organization.return_value = {"Organization": {"Id": "o-abc1234567"}}
    with (
        patch("tarmac.cli.deploy_phases.get_active_account_id_map", return_value=accounts),
        patch("tarmac.cli.deploy_phases._deploy_log_archive_hardening_stack"),
        patch("tarmac.cli.deploy_phases.CloudFormationService") as cfn,
        patch("tarmac.cli.deploy_phases.OrganizationService") as org,
    ):
        deploy_phases._run_phase_3_cloudtrail(mgr, bundle, "us-east-1", tmp_path)
    return mgr, cfn, org


def test_phase_3_delegates_cloudtrail_to_audit_and_deploys_the_trail_there(bundle, tmp_path):
    mgr, cfn, org = _run_phase_3(bundle, tmp_path, {"log-archive": LOG_ARCHIVE, "audit": AUDIT})

    org.return_value.register_cloudtrail_delegated_administrator.assert_called_once_with(AUDIT)
    mgr.get_member_client.assert_called_with(AUDIT, "cloudformation", region_name="us-east-1")
    assert cfn.return_value.deploy_stack.call_args.args[0] is mgr.get_member_client.return_value


def test_phase_3_needs_an_audit_account(bundle, tmp_path):
    bundle.accounts.accounts = [a for a in bundle.accounts.accounts if a.name != "audit"]

    with pytest.raises(GovernanceError, match="Audit account 'audit'"):
        _run_phase_3(bundle, tmp_path, {"log-archive": LOG_ARCHIVE})


def test_registering_an_already_registered_audit_account_is_not_an_error():
    mgr = MagicMock()
    mgr.get_client.return_value.register_organization_delegated_admin.side_effect = ClientError(
        {"Error": {"Code": "AccountRegisteredException", "Message": "already"}},
        "RegisterOrganizationDelegatedAdmin",
    )

    OrganizationService(mgr).register_cloudtrail_delegated_administrator(AUDIT)
