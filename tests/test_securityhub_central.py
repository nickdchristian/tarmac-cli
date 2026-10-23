"""Security Hub central configuration, run against botocore Stubber clients so every request is checked against the
real service model (a misspelled parameter fails here, not in a live account)."""

from typing import Any, cast
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from tarmac.core import adoption
from tarmac.core.config_schema import SecurityHubConfig
from tarmac.core.exceptions import GovernanceError
from tarmac.services.security import SecurityServicesService
from tarmac.services.security_central import POLICY_NAME, SecurityHubCentralConfiguration

STD = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
CIS = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
STANDARDS = {"Standards": [{"StandardsArn": STD, "Name": "AWS Foundational Security Best Practices v1.0.0"}]}
ROOT = "r-abcd"
CONTROLS = {"DisabledSecurityControlIdentifiers": []}
POLICY = {
    "SecurityHub": {
        "ServiceEnabled": True,
        "EnabledStandardIdentifiers": [STD],
        "SecurityControlsConfiguration": CONTROLS,
    }
}


def _sh() -> Any:
    return boto3.client(
        "securityhub", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y"
    )


def _central(sh: Any, standards: list[str] | None = None) -> SecurityHubCentralConfiguration:
    return SecurityHubCentralConfiguration(
        sh,
        policy_name=POLICY_NAME,
        standards=standards or ["aws-foundational-security-best-practices"],
        root_id=ROOT,
        sleep=lambda _s: None,
        timeout_seconds=10,
    )


def _org_config(kind: str, status: str = "ENABLED") -> dict[str, Any]:
    return {
        "AutoEnable": False,
        "AutoEnableStandards": "NONE",
        "OrganizationConfiguration": {"ConfigurationType": kind, "Status": status},
    }


_ASSOC_KEYS = {"ConfigurationPolicyId": "pol-1", "TargetId": ROOT, "TargetType": "ROOT"}


def test_first_run_switches_to_central_creates_the_policy_and_applies_it_to_the_root():
    sh = _sh()
    with Stubber(sh) as stub:
        stub.add_response("describe_organization_configuration", _org_config("LOCAL"))
        stub.add_response("list_members", {"Members": []}, {"OnlyAssociated": True, "MaxResults": 1})
        stub.add_response(
            "update_organization_configuration",
            {},
            {"AutoEnable": False, "OrganizationConfiguration": {"ConfigurationType": "CENTRAL"}},
        )
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL", "PENDING"))
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_standards", STANDARDS)
        stub.add_response("list_configuration_policies", {"ConfigurationPolicySummaries": []})
        stub.add_response(
            "create_configuration_policy",
            {"Id": "pol-1"},
            {
                "Name": POLICY_NAME,
                "Description": "Security Hub baseline managed by tarmac",
                "ConfigurationPolicy": POLICY,
            },
        )
        stub.add_client_error("get_configuration_policy_association", "ResourceNotFoundException")
        stub.add_response(
            "start_configuration_policy_association",
            {**_ASSOC_KEYS, "AssociationStatus": "PENDING"},
            {"ConfigurationPolicyIdentifier": "pol-1", "Target": {"RootId": ROOT}},
        )
        _central(sh).apply()
        stub.assert_no_pending_responses()


def test_second_run_changes_nothing():
    sh = _sh()
    with Stubber(sh) as stub:
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_standards", STANDARDS)
        stub.add_response(
            "list_configuration_policies",
            {"ConfigurationPolicySummaries": [{"Id": "pol-1", "Name": POLICY_NAME}]},
        )
        stub.add_response(
            "get_configuration_policy",
            {"Id": "pol-1", "ConfigurationPolicy": POLICY},
            {"Identifier": "pol-1"},
        )
        stub.add_response(
            "get_configuration_policy_association",
            {**_ASSOC_KEYS, "AssociationStatus": "SUCCESS"},
            {"Target": {"RootId": ROOT}},
        )
        _central(sh).apply()
        stub.assert_no_pending_responses()


def test_changed_standards_update_the_existing_policy():
    sh = _sh()
    other = {
        "SecurityHub": {
            "ServiceEnabled": True,
            "EnabledStandardIdentifiers": [CIS],
            "SecurityControlsConfiguration": CONTROLS,
        }
    }
    with Stubber(sh) as stub:
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_standards", STANDARDS)
        stub.add_response(
            "list_configuration_policies",
            {"ConfigurationPolicySummaries": [{"Id": "pol-1", "Name": POLICY_NAME}]},
        )
        stub.add_response(
            "get_configuration_policy", {"Id": "pol-1", "ConfigurationPolicy": other}, {"Identifier": "pol-1"}
        )
        stub.add_response(
            "update_configuration_policy",
            {},
            {
                "Identifier": "pol-1",
                "ConfigurationPolicy": POLICY,
                "UpdatedReason": "Synced from tarmac configuration",
            },
        )
        stub.add_response(
            "get_configuration_policy_association",
            {**_ASSOC_KEYS, "AssociationStatus": "SUCCESS"},
            {"Target": {"RootId": ROOT}},
        )
        _central(sh).apply()
        stub.assert_no_pending_responses()


def test_a_failed_association_is_an_error():
    sh = _sh()
    with Stubber(sh) as stub:
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_standards", STANDARDS)
        stub.add_response(
            "list_configuration_policies",
            {"ConfigurationPolicySummaries": [{"Id": "pol-1", "Name": POLICY_NAME}]},
        )
        stub.add_response(
            "get_configuration_policy",
            {"Id": "pol-1", "ConfigurationPolicy": POLICY},
            {"Identifier": "pol-1"},
        )
        stub.add_client_error("get_configuration_policy_association", "ResourceNotFoundException")
        stub.add_response(
            "start_configuration_policy_association",
            {**_ASSOC_KEYS, "AssociationStatus": "FAILED", "AssociationStatusMessage": "no admin"},
            {"ConfigurationPolicyIdentifier": "pol-1", "Target": {"RootId": ROOT}},
        )
        with pytest.raises(GovernanceError, match="could not apply"):
            _central(sh).apply()


def test_a_central_configuration_that_stays_pending_times_out():
    sh = MagicMock()
    sh.describe_organization_configuration.return_value = _org_config("CENTRAL", "PENDING")
    with pytest.raises(GovernanceError, match="still PENDING"):
        _central(sh).apply()


def test_an_unknown_standard_is_reported():
    sh = _sh()
    with Stubber(sh) as stub:
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        stub.add_response("describe_standards", STANDARDS)
        with pytest.raises(GovernanceError, match="Unknown Security Hub standard"):
            _central(sh, ["nonsense"]).apply()


def _service(sh: Any) -> SecurityServicesService:
    mgr = MagicMock()
    org = MagicMock()
    org.list_roots.return_value = {"Roots": [{"Id": ROOT}]}
    mgmt = MagicMock()
    mgmt.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    mgr.get_client.side_effect = lambda svc, **_k: org if svc == "organizations" else mgmt
    mgr.get_member_client.return_value = sh
    return SecurityServicesService(mgr)


def test_service_uses_central_configuration_by_default_and_skips_per_region_calls():
    sh = MagicMock()
    sh.describe_organization_configuration.return_value = _org_config("CENTRAL")
    sh.describe_standards.return_value = STANDARDS
    sh.list_configuration_policies.return_value = {"ConfigurationPolicySummaries": []}
    sh.get_paginator.return_value.paginate.return_value = [{"ConfigurationPolicySummaries": []}]
    sh.create_configuration_policy.return_value = {"Id": "pol-1"}
    sh.get_configuration_policy_association.return_value = {}
    sh.start_configuration_policy_association.return_value = {"AssociationStatus": "PENDING"}
    sh.list_finding_aggregators.return_value = {
        "FindingAggregators": [
            {"FindingAggregatorArn": "arn:aws:securityhub:us-east-1:111122223333:finding-aggregator/abc"}
        ]
    }
    sh.get_finding_aggregator.return_value = {
        "RegionLinkingMode": "SPECIFIED_REGIONS",
        "Regions": ["eu-west-1"],
    }

    report = _service(sh).configure_securityhub(
        "111122223333", "us-east-1", ["us-east-1", "eu-west-1"], SecurityHubConfig(enabled=True)
    )

    assert report.status == "ENABLED"
    sh.create_configuration_policy.assert_called_once()
    sh.start_configuration_policy_association.assert_called_once()
    # Local-mode calls would fail under central configuration.
    sh.batch_enable_standards.assert_not_called()
    sh.update_organization_configuration.assert_not_called()


def test_service_keeps_local_configuration_when_central_is_off():
    sh = MagicMock()
    sh.describe_standards.return_value = STANDARDS
    sh.get_enabled_standards.return_value = {"StandardsSubscriptions": [{"StandardsArn": STD}]}
    sh.list_finding_aggregators.return_value = {"FindingAggregators": [{}]}

    report = _service(sh).configure_securityhub(
        "111122223333",
        "us-east-1",
        ["us-east-1"],
        SecurityHubConfig(enabled=True, central_configuration=False),
    )

    assert report.status == "ENABLED"
    sh.update_organization_configuration.assert_called_once_with(AutoEnable=True, AutoEnableStandards="NONE")
    sh.create_configuration_policy.assert_not_called()


def test_service_reports_a_central_configuration_failure():
    sh = MagicMock()
    sh.list_finding_aggregators.return_value = {
        "FindingAggregators": [
            {"FindingAggregatorArn": "arn:aws:securityhub:us-east-1:111122223333:finding-aggregator/abc"}
        ]
    }
    sh.get_finding_aggregator.return_value = {"RegionLinkingMode": "NO_REGIONS", "Regions": []}
    sh.describe_organization_configuration.return_value = _org_config("CENTRAL", "FAILED")

    report = _service(sh).configure_securityhub(
        "111122223333", "us-east-1", ["us-east-1"], SecurityHubConfig(enabled=True)
    )

    assert report.status == "FAILED"
    assert "Central configuration failed" in report.message


def test_central_configuration_designates_the_administrator_in_the_home_region_only():
    """Linked Regions inherit the central policy, so the delegation is made once, from the home Region."""
    sh = MagicMock()
    sh.describe_organization_configuration.return_value = _org_config("CENTRAL")
    sh.describe_standards.return_value = STANDARDS
    sh.get_paginator.return_value.paginate.return_value = [{"ConfigurationPolicySummaries": []}]
    sh.create_configuration_policy.return_value = {"Id": "pol-1"}
    sh.get_configuration_policy_association.return_value = {}
    sh.start_configuration_policy_association.return_value = {"AssociationStatus": "PENDING"}
    sh.list_finding_aggregators.return_value = {"FindingAggregators": [{"FindingAggregatorArn": AGG_ARN}]}
    sh.get_finding_aggregator.return_value = {
        "RegionLinkingMode": "SPECIFIED_REGIONS",
        "Regions": ["eu-west-1"],
    }

    mgr = MagicMock()
    org = MagicMock()
    org.list_roots.return_value = {"Roots": [{"Id": ROOT}]}
    mgmt_by_region: dict[str, MagicMock] = {}

    def client(svc: str, **kwargs: Any) -> MagicMock:
        if svc == "organizations":
            return org
        m = mgmt_by_region.setdefault(kwargs.get("region_name", ""), MagicMock())
        m.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
        return m

    mgr.get_client.side_effect = client
    mgr.get_member_client.return_value = sh

    SecurityServicesService(mgr).configure_securityhub(
        "111122223333", "us-east-1", ["us-east-1", "eu-west-1"], SecurityHubConfig(enabled=True)
    )

    assert set(mgmt_by_region) == {"us-east-1"}
    mgmt_by_region["us-east-1"].enable_organization_admin_account.assert_called_once_with(
        AdminAccountId="111122223333"
    )


def _regions_service(sh: Any, status: str | None) -> SecurityServicesService:
    service = _service(sh)
    ec2 = MagicMock()
    ec2.describe_regions.return_value = {"Regions": [{"RegionName": "af-south-1", "OptInStatus": status}]}
    get_client = cast(MagicMock, service.session_mgr.get_client)
    original = get_client.side_effect
    get_client.side_effect = lambda svc, **k: ec2 if svc == "ec2" else original(svc, **k)
    return service


@pytest.mark.parametrize("status", ["opted-in", "not-opted-in"])
def test_an_opt_in_home_region_is_refused_before_anything_is_changed(status: str):
    sh = MagicMock()
    report = _regions_service(sh, status).configure_securityhub(
        "111122223333", "af-south-1", ["af-south-1"], SecurityHubConfig(enabled=True)
    )

    assert report.status == "FAILED"
    assert "opt-in Region" in report.message
    sh.create_configuration_policy.assert_not_called()
    sh.enable_security_hub.assert_not_called()


def test_a_default_home_region_is_accepted():
    sh = MagicMock()
    sh.describe_organization_configuration.return_value = _org_config("CENTRAL")
    sh.describe_standards.return_value = STANDARDS
    sh.get_paginator.return_value.paginate.return_value = [{"ConfigurationPolicySummaries": []}]
    sh.create_configuration_policy.return_value = {"Id": "pol-1"}
    sh.get_configuration_policy_association.return_value = {}
    sh.start_configuration_policy_association.return_value = {"AssociationStatus": "PENDING"}
    sh.list_finding_aggregators.return_value = {"FindingAggregators": [{"FindingAggregatorArn": AGG_ARN}]}
    sh.get_finding_aggregator.return_value = {"RegionLinkingMode": "NO_REGIONS", "Regions": []}

    report = _regions_service(sh, "opt-in-not-required").configure_securityhub(
        "111122223333", "af-south-1", ["af-south-1"], SecurityHubConfig(enabled=True)
    )

    assert report.status == "ENABLED"


# -- finding aggregator scope ---------------------------------------------------------------------------------

AGG_ARN = "arn:aws:securityhub:us-east-1:111122223333:finding-aggregator/abc"


def _aggregator_service(existing: dict[str, Any] | None) -> tuple[SecurityServicesService, MagicMock]:
    sh = MagicMock()
    sh.list_finding_aggregators.return_value = {
        "FindingAggregators": [{"FindingAggregatorArn": AGG_ARN}] if existing is not None else []
    }
    if existing is not None:
        sh.get_finding_aggregator.return_value = existing
    return _service(sh), sh


def test_the_aggregator_links_exactly_the_declared_regions_under_central_configuration():
    service, sh = _aggregator_service(None)
    service._ensure_finding_aggregator(sh, ["eu-west-1", "ap-southeast-2"])
    sh.create_finding_aggregator.assert_called_once_with(
        RegionLinkingMode="SPECIFIED_REGIONS", Regions=["ap-southeast-2", "eu-west-1"]
    )


def test_a_single_region_deployment_links_no_other_regions():
    service, sh = _aggregator_service(None)
    service._ensure_finding_aggregator(sh, [])
    sh.create_finding_aggregator.assert_called_once_with(RegionLinkingMode="NO_REGIONS")


def test_local_configuration_still_aggregates_every_region():
    service, sh = _aggregator_service(None)
    service._ensure_finding_aggregator(sh)
    sh.create_finding_aggregator.assert_called_once_with(RegionLinkingMode="ALL_REGIONS")


def test_an_aggregator_that_links_other_regions_is_narrowed_to_the_declared_ones():
    service, sh = _aggregator_service({"RegionLinkingMode": "ALL_REGIONS", "Regions": []})
    service._ensure_finding_aggregator(sh, ["eu-west-1"])
    sh.update_finding_aggregator.assert_called_once_with(
        FindingAggregatorArn=AGG_ARN, RegionLinkingMode="SPECIFIED_REGIONS", Regions=["eu-west-1"]
    )
    sh.create_finding_aggregator.assert_not_called()


def test_an_aggregator_that_already_matches_is_left_alone():
    service, sh = _aggregator_service({"RegionLinkingMode": "SPECIFIED_REGIONS", "Regions": ["eu-west-1"]})
    service._ensure_finding_aggregator(sh, ["eu-west-1"])
    sh.update_finding_aggregator.assert_not_called()
    sh.create_finding_aggregator.assert_not_called()


def test_local_configuration_does_not_rewrite_an_existing_aggregator():
    service, sh = _aggregator_service({"RegionLinkingMode": "SPECIFIED_REGIONS", "Regions": ["eu-west-1"]})
    service._ensure_finding_aggregator(sh)
    sh.update_finding_aggregator.assert_not_called()


# -- brownfield guards ----------------------------------------------------------------------------------------


def _local_org_with_members(sh: Any) -> None:
    stub = Stubber(sh)
    stub.add_response("describe_organization_configuration", _org_config("LOCAL"))
    stub.add_response(
        "list_members",
        {"Members": [{"AccountId": "444455556666"}]},
        {"OnlyAssociated": True, "MaxResults": 1},
    )
    stub.activate()


def test_switching_to_central_stops_when_members_are_already_configured_one_by_one():
    sh = _sh()
    _local_org_with_members(sh)
    with pytest.raises(GovernanceError, match="configured one by one") as exc:
        _central(sh).apply()
    assert "--adopt-existing" in str(exc.value.details)
    assert "central_configuration: false" in str(exc.value.details)


def test_adopt_existing_lets_the_switch_proceed_without_looking_at_members():
    sh = MagicMock()
    sh.describe_organization_configuration.return_value = _org_config("LOCAL")
    sh.describe_standards.return_value = STANDARDS
    sh.get_paginator.return_value.paginate.return_value = [{"ConfigurationPolicySummaries": []}]
    sh.create_configuration_policy.return_value = {"Id": "pol-1"}
    sh.get_configuration_policy_association.return_value = {}
    sh.start_configuration_policy_association.return_value = {"AssociationStatus": "PENDING"}
    adoption.set_adopt_existing(True)
    try:
        _central(sh).apply()
    finally:
        adoption.set_adopt_existing(False)
    sh.list_members.assert_not_called()
    sh.update_organization_configuration.assert_called_once()


def _root_with_policy(sh: Any, existing: str) -> Stubber:
    stub = Stubber(sh)
    stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
    stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
    stub.add_response("describe_standards", STANDARDS)
    stub.add_response(
        "list_configuration_policies",
        {"ConfigurationPolicySummaries": [{"Id": "pol-1", "Name": POLICY_NAME}]},
    )
    stub.add_response(
        "get_configuration_policy", {"Id": "pol-1", "ConfigurationPolicy": POLICY}, {"Identifier": "pol-1"}
    )
    stub.add_response(
        "get_configuration_policy_association",
        {**_ASSOC_KEYS, "ConfigurationPolicyId": existing, "AssociationStatus": "SUCCESS"},
        {"Target": {"RootId": ROOT}},
    )
    return stub


def test_a_root_that_already_uses_someone_elses_policy_is_not_replaced():
    sh = _sh()
    _root_with_policy(sh, "their-policy").activate()
    with pytest.raises(GovernanceError, match="did not create") as exc:
        _central(sh).apply()
    assert "--adopt-existing" in str(exc.value.details)


def test_a_root_without_a_policy_is_taken_over_without_adoption():
    sh = _sh()
    stub = _root_with_policy(sh, "SELF_MANAGED_SECURITY_HUB")
    stub.add_response(
        "start_configuration_policy_association",
        {**_ASSOC_KEYS, "AssociationStatus": "PENDING"},
        {"ConfigurationPolicyIdentifier": "pol-1", "Target": {"RootId": ROOT}},
    )
    stub.activate()
    _central(sh).apply()
    stub.assert_no_pending_responses()


def test_switching_waits_while_security_hub_syncs_a_new_organization():
    sh = _sh()
    switch = {"AutoEnable": False, "OrganizationConfiguration": {"ConfigurationType": "CENTRAL"}}
    with Stubber(sh) as stub:
        stub.add_response("describe_organization_configuration", _org_config("LOCAL"))
        stub.add_response("list_members", {"Members": []}, {"OnlyAssociated": True, "MaxResults": 1})
        stub.add_client_error(
            "update_organization_configuration",
            "ResourceNotFoundException",
            "Central configuration couldn't be enabled because data from organization o-1 is still syncing.",
            expected_params=switch,
        )
        stub.add_response("update_organization_configuration", {}, switch)
        stub.add_response("describe_organization_configuration", _org_config("CENTRAL"))
        _central(sh)._enable_central_mode()
        stub.assert_no_pending_responses()
