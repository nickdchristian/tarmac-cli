"""Adopting an existing organization: sample values, existing trails, renamed stacks and quarantine."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.config_schema import AccountDef, AccountsCatalog
from tarmac.core.models import PreflightCheckStatus
from tarmac.core.placeholders import find_placeholder_values, is_placeholder_email
from tarmac.services.accounts import AccountService
from tarmac.services.preflight import PreflightService
from tarmac.services.scaffold import scaffold_project


@pytest.fixture
def bundle(sample_config_dir: Path) -> ConfigBundle:
    loaded, errors = load_all_configs(sample_config_dir)
    assert loaded is not None
    assert not errors
    return loaded


def test_sample_email_domains_are_recognised():
    assert is_placeholder_email("ops@myorg.example.com")
    assert is_placeholder_email("a@example.com")
    assert is_placeholder_email("A@Example.ORG")
    assert not is_placeholder_email("me+prod@gmail.com")
    assert not is_placeholder_email("a@notexample.com")


def test_fresh_scaffold_reports_every_sample_value(tmp_path: Path):
    scaffold_project(tmp_path)
    scaffolded, errors = load_all_configs(tmp_path)
    assert scaffolded is not None
    assert not errors

    problems = find_placeholder_values(scaffolded)

    assert any("phone" in p for p in problems)
    assert any("accounts.yaml" in p for p in problems)
    assert any("identity.yaml" in p for p in problems)


def test_sample_values_check_passes_for_a_real_configuration(bundle: ConfigBundle, monkeypatch):
    monkeypatch.setattr("tarmac.services.preflight.find_placeholder_values", lambda _b: [])
    result = PreflightService(MagicMock(), bundle).check_sample_values()
    assert result.status is PreflightCheckStatus.PASS


def test_sample_values_check_warns_and_names_the_problem(bundle: ConfigBundle, monkeypatch):
    monkeypatch.setattr(
        "tarmac.services.preflight.find_placeholder_values", lambda _b: ["accounts.yaml: sample email"]
    )
    result = PreflightService(MagicMock(), bundle).check_sample_values()
    assert result.status is PreflightCheckStatus.WARN
    assert "sample email" in (result.action_required or "")


def _session(client: MagicMock) -> MagicMock:
    mgr = MagicMock()
    mgr.get_client.return_value = client
    return mgr


def test_existing_organization_trail_is_flagged(bundle: ConfigBundle):
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = {
        "trailList": [
            {"Name": "old-org-trail", "IsOrganizationTrail": True},
            {"Name": bundle.org.cloudtrail.trail_name, "IsOrganizationTrail": True},
            {"Name": "member-trail", "IsOrganizationTrail": False},
        ]
    }

    result = PreflightService(_session(cloudtrail), bundle).check_existing_organization_trail("us-east-1")

    assert result.status is PreflightCheckStatus.WARN
    assert result.live_value == "old-org-trail"
    assert "second copy" in (result.action_required or "")
    cloudtrail.describe_trails.assert_called_once_with(includeShadowTrails=True)


def test_no_other_organization_trail_passes(bundle: ConfigBundle):
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = {"trailList": []}
    result = PreflightService(_session(cloudtrail), bundle).check_existing_organization_trail("us-east-1")
    assert result.status is PreflightCheckStatus.PASS


def test_trail_check_degrades_to_info_when_unreadable(bundle: ConfigBundle):
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "x"}}, "D"
    )
    result = PreflightService(_session(cloudtrail), bundle).check_existing_organization_trail("us-east-1")
    assert result.status is PreflightCheckStatus.INFO


def _stacks(*names: str) -> MagicMock:
    cfn = MagicMock()
    cfn.get_paginator.return_value.paginate.return_value = [
        {"StackSummaries": [{"StackName": n} for n in names]}
    ]
    return cfn


def test_stacks_named_for_a_different_organization_name_are_flagged(bundle: ConfigBundle):
    cfn = _stacks("oldname-organization-scps", "oldname-sso-permission-sets", "unrelated-stack")

    result = PreflightService(_session(cfn), bundle).check_stack_name_prefix("us-east-1")

    assert result.status is PreflightCheckStatus.WARN
    assert "oldname" in result.live_value
    assert "Set organization.name back to 'oldname'" in (result.action_required or "")


def test_stacks_matching_the_organization_name_pass(bundle: ConfigBundle):
    name = bundle.org.organization.name
    cfn = _stacks(f"{name}-organization-scps", f"{name}-terraform-backend", "unrelated-stack")
    result = PreflightService(_session(cfn), bundle).check_stack_name_prefix("us-east-1")
    assert result.status is PreflightCheckStatus.PASS


def _factory_with_unlisted_managed_account() -> AccountService:
    mgr = MagicMock()
    org = MagicMock()
    mgr.get_client.return_value = org
    mgr.get_caller_identity.return_value = {"Account": "999999999999"}
    tags = MagicMock()
    tags.paginate.return_value = [{"Tags": [{"Key": "tarmac:managed-by", "Value": "tarmac"}]}]
    org.get_paginator.side_effect = lambda op: tags if op == "list_tags_for_resource" else MagicMock()
    org.list_parents.return_value = {"Parents": [{"Id": "ou-workloads"}]}
    return AccountService(mgr)


_EXISTING = {
    "OldWorkload": {
        "Id": "333333333333",
        "Name": "OldWorkload",
        "Status": "ACTIVE",
        "Email": "o@acme-corp.io",
    }
}


def test_removed_managed_account_is_quarantined_by_default():
    catalog = AccountsCatalog(accounts=[AccountDef(name="Deployment", email="d@acme-corp.io", ou="Infra")])
    items = _factory_with_unlisted_managed_account()._detect_removed_accounts(  # type: ignore[reportPrivateUsage]
        catalog, {"Suspended": "ou-suspended"}, _EXISTING
    )
    assert [i.action for i in items] == ["SUSPEND"]


def test_quarantine_can_be_turned_off():
    catalog = AccountsCatalog(
        accounts=[AccountDef(name="Deployment", email="d@acme-corp.io", ou="Infra")],
        quarantine_removed_accounts=False,
    )
    items = _factory_with_unlisted_managed_account()._detect_removed_accounts(  # type: ignore[reportPrivateUsage]
        catalog, {"Suspended": "ou-suspended"}, _EXISTING
    )
    assert items == []


def test_account_with_sample_email_is_never_created():
    mgr = MagicMock()
    org = MagicMock()
    mgr.get_client.return_value = org
    service = AccountService(mgr)
    service.list_existing_accounts = MagicMock(return_value={})  # type: ignore[method-assign]
    accounts = [AccountDef(name="Prod", email="prod@myorg.example.com", ou="Production")]

    with pytest.raises(Exception, match="sample email"):
        service.provision_accounts(accounts, {"Production": "ou-prod"}, dry_run=False)

    org.create_account.assert_not_called()
