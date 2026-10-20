"""Security Hub central configuration, run against botocore Stubber clients so every request is checked against the
real service model (a misspelled parameter fails here, not in a live account)."""

from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from tarmac.core.config_schema import SecurityHubConfig
from tarmac.core.exceptions import GovernanceError
from tarmac.services.security import SecurityServicesService
from tarmac.services.security_central import POLICY_NAME, SecurityHubCentralConfiguration

STD = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
CIS = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
STANDARDS = {"Standards": [{"StandardsArn": STD, "Name": "AWS Foundational Security Best Practices v1.0.0"}]}
ROOT = "r-abcd"
POLICY = {"SecurityHub": {"ServiceEnabled": True, "EnabledStandardIdentifiers": [STD]}}


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
    other = {"SecurityHub": {"ServiceEnabled": True, "EnabledStandardIdentifiers": [CIS]}}
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
    sh.list_finding_aggregators.return_value = {"FindingAggregators": [{}]}

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
    sh.list_finding_aggregators.return_value = {"FindingAggregators": [{}]}
    sh.describe_organization_configuration.return_value = _org_config("CENTRAL", "FAILED")

    report = _service(sh).configure_securityhub(
        "111122223333", "us-east-1", ["us-east-1"], SecurityHubConfig(enabled=True)
    )

    assert report.status == "FAILED"
    assert "Central configuration failed" in report.message
