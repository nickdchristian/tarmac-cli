"""Audit events emitted by the CloudFormation, baseline and security services."""

import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import GuardDutyConfig, SecurityHubConfig
from tarmac.core.exceptions import DeploymentError
from tarmac.core.logging import ContextFilter, current_context
from tarmac.services.baseline import BaselineService
from tarmac.services.cloudformation import CloudFormationService
from tarmac.services.security import SecurityServicesService


def _events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [r.data for r in caplog.records if getattr(r, "event", None) == "audit"]  # type: ignore[attr-defined]


def _err(code: str, msg: str = "boom") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")


@pytest.fixture(autouse=True)
def _info(caplog):
    caplog.set_level(logging.INFO, logger="tarmac.audit")


def _template(tmp_path: Path) -> Path:
    t = tmp_path / "t.yaml"
    t.write_text("Resources: {}\n")
    return t


def test_stack_create_update_unchanged_and_dry_run(caplog, tmp_path):
    svc = CloudFormationService(MagicMock())
    tpl = _template(tmp_path)
    cfn = MagicMock()
    cfn.describe_stacks.side_effect = [
        _err("ValidationError", "Stack does not exist"),
        {"Stacks": [{}]},
        {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]},
        {"Stacks": [{}]},
        {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]},
        {"Stacks": [{}]},
    ]
    svc.deploy_stack(cfn, "s", tpl, {})
    svc.deploy_stack(cfn, "s", tpl, {})
    cfn.update_stack.side_effect = _err("ValidationError", "No updates are to be performed")
    svc.deploy_stack(cfn, "s", tpl, {})
    svc.deploy_stack(cfn, "s", tpl, {}, dry_run=True)

    got = [(e["action"], e["outcome"]) for e in _events(caplog)]
    assert got == [
        ("create", "succeeded"),
        ("update", "succeeded"),
        ("update", "unchanged"),
        ("deploy", "simulated"),
    ]


def test_stack_failure_is_audited(caplog, tmp_path):
    svc = CloudFormationService(MagicMock())
    cfn = MagicMock()
    cfn.describe_stacks.side_effect = _err("ValidationError", "Stack does not exist")
    cfn.create_stack.side_effect = _err("AccessDenied", "nope")

    with pytest.raises(DeploymentError):
        svc.deploy_stack(cfn, "s", _template(tmp_path), {})

    [ev] = _events(caplog)
    assert (ev["action"], ev["outcome"], ev["resource"]) == ("create", "failed", "stack:s")


def test_stack_delete_is_audited(caplog):
    svc = CloudFormationService(MagicMock())
    cfn = MagicMock()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}

    assert svc.delete_stack(cfn, "s") is True
    [ev] = _events(caplog)
    assert (ev["action"], ev["outcome"]) == ("delete", "succeeded")


def test_default_vpc_delete_is_audited_and_tagged_with_account_and_region(caplog):
    caplog.handler.addFilter(ContextFilter())
    mgr = MagicMock()
    mgr.default_region = "eu-west-1"
    ec2 = MagicMock()
    mgr.get_member_client.return_value = ec2
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
    ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    ec2.describe_internet_gateways.return_value = {"InternetGateways": [{"InternetGatewayId": "igw-1"}]}
    ec2.describe_subnets.return_value = {"Subnets": [{"SubnetId": "subnet-1"}]}

    BaselineService(mgr).cleanup_default_vpcs("123456789012", "Dev", regions=["eu-west-1"])

    [ev] = _events(caplog)
    assert (ev["action"], ev["outcome"]) == ("delete", "succeeded")
    assert ev["details"]["subnets"] == ["subnet-1"]
    record = next(r for r in caplog.records if getattr(r, "event", None) == "audit")
    assert (record.account_id, record.account_name, record.region) == ("123456789012", "Dev", "eu-west-1")  # type: ignore[attr-defined]
    assert "region" not in current_context()


def test_default_vpc_dry_run_in_use_and_error(caplog):
    mgr = MagicMock()
    ec2 = MagicMock()
    mgr.get_member_client.return_value = ec2
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
    ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    svc = BaselineService(mgr)

    svc.cleanup_default_vpcs("123456789012", "Dev", regions=["r1"], dry_run=True)
    ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]}
    svc.cleanup_default_vpcs("123456789012", "Dev", regions=["r1"])
    ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    ec2.describe_internet_gateways.return_value = {"InternetGateways": []}
    ec2.describe_subnets.return_value = {"Subnets": []}
    ec2.delete_vpc.side_effect = _err("DependencyViolation")
    svc.cleanup_default_vpcs("123456789012", "Dev", regions=["r1"])

    assert [e["outcome"] for e in _events(caplog)] == ["simulated", "skipped", "failed"]


def test_account_marked_baselined_is_audited(caplog):
    mgr = MagicMock()
    BaselineService(mgr).mark_account_baselined("123456789012")
    [ev] = _events(caplog)
    assert (ev["action"], ev["resource"]) == ("tag", "account:123456789012")


def test_member_anomaly_monitor_creation_is_audited(caplog):
    mgr = MagicMock()
    ce = MagicMock()
    mgr.get_member_client.return_value = ce
    ce.get_anomaly_monitors.return_value = {"AnomalyMonitors": []}
    ce.create_anomaly_monitor.return_value = {"MonitorArn": "arn:m"}
    ce.get_anomaly_subscriptions.return_value = {"AnomalySubscriptions": []}
    cfg = MagicMock(threshold_usd=10, notification_emails=["a@example.com"])

    BaselineService(mgr)._setup_member_anomaly_monitor("123456789012", "Dev", cfg)

    [ev] = _events(caplog)
    assert (ev["action"], ev["resource"]) == ("create", "anomaly-monitor:Dev-services-monitor")


def test_guardduty_and_securityhub_changes_are_audited(caplog):
    mgr = MagicMock()
    mgmt, member = MagicMock(), MagicMock()
    mgr.get_client.return_value = mgmt
    mgr.get_member_client.return_value = member
    mgmt.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    member.list_detectors.return_value = {"DetectorIds": []}
    member.create_detector.return_value = {"DetectorId": "det-1"}
    member.describe_hub.side_effect = _err("ResourceNotFoundException")
    member.describe_standards.return_value = {
        "Standards": [
            {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
            }
        ]
    }
    member.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
    member.list_finding_aggregators.return_value = {"FindingAggregators": []}
    svc = SecurityServicesService(mgr)

    svc.configure_guardduty("111122223333", "eu-west-1", ["eu-west-1"], GuardDutyConfig(enabled=True))
    svc.configure_securityhub(
        "111122223333",
        "eu-west-1",
        ["eu-west-1"],
        SecurityHubConfig(enabled=True, standards=["aws-foundational-security-best-practices"]),
    )

    resources = [e["resource"] for e in _events(caplog)]
    assert "guardduty:111122223333" in resources
    assert "guardduty-detector:111122223333:eu-west-1" in resources
    assert "securityhub:111122223333:eu-west-1" in resources
    assert any(r.startswith("securityhub-standard:") for r in resources)
    assert "securityhub-finding-aggregator" in resources


def test_security_region_failure_is_audited_with_region_context(caplog):
    mgr = MagicMock()
    mgmt, member = MagicMock(), MagicMock()
    mgr.get_client.return_value = mgmt
    mgr.get_member_client.return_value = member
    mgmt.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminAccountId": "111122223333", "AdminStatus": "ENABLED"}]
    }
    member.list_detectors.side_effect = _err("AccessDenied")

    report = SecurityServicesService(mgr).configure_guardduty(
        "111122223333", "eu-west-1", ["eu-west-1"], GuardDutyConfig(enabled=True)
    )

    assert report.status == "FAILED"
    [ev] = _events(caplog)
    assert (ev["action"], ev["outcome"]) == ("configure", "failed")
    assert ev["details"]["region"] == "eu-west-1"
