"""Tests for SecurityServicesService (GuardDuty & Security Hub delegation)."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from tarmac.core.config_schema import (
    GuardDutyConfig,
    SecurityHubConfig,
    SecurityServicesConfig,
)
from tarmac.services.security import SecurityServicesService


def test_security_services_dry_run():
    mock_session_mgr = MagicMock()
    service = SecurityServicesService(mock_session_mgr)
    cfg = SecurityServicesConfig(
        delegated_account="audit",
        guardduty=GuardDutyConfig(enabled=True),
        securityhub=SecurityHubConfig(enabled=True),
    )

    reports = service.configure_security_services(
        config=cfg,
        primary_region="eu-west-1",
        all_regions=["eu-west-1", "us-east-1"],
        account_id_map={"audit": "111122223333"},
        dry_run=True,
    )

    assert len(reports) == 2
    assert all(r.status == "SIMULATED" for r in reports)
    mock_session_mgr.get_client.assert_not_called()
    mock_session_mgr.get_member_client.assert_not_called()


def test_security_services_unresolved_audit_account():
    mock_session_mgr = MagicMock()
    service = SecurityServicesService(mock_session_mgr)
    cfg = SecurityServicesConfig(
        delegated_account="audit",
        guardduty=GuardDutyConfig(enabled=True),
        securityhub=SecurityHubConfig(enabled=True),
    )

    reports = service.configure_security_services(
        config=cfg,
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        account_id_map={"workload": "999999999999"},
        dry_run=False,
    )

    assert len(reports) == 2
    assert all(r.status == "FAILED" for r in reports)
    assert "could not be resolved" in reports[0].message


def test_guardduty_delegation_and_member_configuration():
    mock_session_mgr = MagicMock()
    mock_gd_mgmt = MagicMock()
    mock_gd_audit = MagicMock()

    mock_session_mgr.get_client.return_value = mock_gd_mgmt
    mock_session_mgr.get_member_client.return_value = mock_gd_audit

    mock_gd_mgmt.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    mock_gd_audit.list_detectors.return_value = {"DetectorIds": []}
    mock_gd_audit.create_detector.return_value = {"DetectorId": "det-new123"}

    service = SecurityServicesService(mock_session_mgr)
    cfg = GuardDutyConfig(enabled=True, auto_enable_members=True)

    report = service.configure_guardduty(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=cfg,
        dry_run=False,
    )

    assert report.status == "ENABLED"
    assert report.service_name == "GuardDuty"
    assert "eu-west-1" in report.regions
    mock_gd_mgmt.enable_organization_admin_account.assert_called_once_with(AdminAccountId="111122223333")
    mock_gd_audit.create_detector.assert_called_once()
    mock_gd_audit.update_organization_configuration.assert_called_once()


def test_guardduty_idempotent_when_already_registered():
    mock_session_mgr = MagicMock()
    mock_gd_mgmt = MagicMock()
    mock_gd_audit = MagicMock()

    mock_session_mgr.get_client.return_value = mock_gd_mgmt
    mock_session_mgr.get_member_client.return_value = mock_gd_audit

    mock_gd_mgmt.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminAccountId": "111122223333", "AdminStatus": "ENABLED"}]
    }
    mock_gd_audit.list_detectors.return_value = {"DetectorIds": ["det-existing456"]}

    service = SecurityServicesService(mock_session_mgr)
    cfg = GuardDutyConfig(enabled=True, auto_enable_members=True)

    report = service.configure_guardduty(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=cfg,
        dry_run=False,
    )

    assert report.status == "ENABLED"
    mock_gd_mgmt.enable_organization_admin_account.assert_not_called()
    mock_gd_audit.create_detector.assert_not_called()
    mock_gd_audit.update_organization_configuration.assert_called_once_with(
        DetectorId="det-existing456", AutoEnableOrganizationMembers="ALL"
    )


def test_securityhub_delegation_and_member_configuration():
    mock_session_mgr = MagicMock()
    mock_sh_mgmt = MagicMock()
    mock_sh_audit = MagicMock()

    mock_session_mgr.get_client.return_value = mock_sh_mgmt
    mock_session_mgr.get_member_client.return_value = mock_sh_audit

    mock_sh_mgmt.list_organization_admin_accounts.return_value = {"AdminAccounts": []}

    mock_sh_audit.describe_hub.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Hub not found"}},
        "DescribeHub",
    )
    mock_sh_audit.describe_standards.return_value = {
        "Standards": [
            {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "Name": "AWS Foundational Security Best Practices v1.0.0",
            }
        ]
    }
    mock_sh_audit.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
    mock_sh_audit.list_finding_aggregators.return_value = {"FindingAggregators": []}

    service = SecurityServicesService(mock_session_mgr)
    cfg = SecurityHubConfig(
        enabled=True,
        auto_enable_members=True,
        standards=["aws-foundational-security-best-practices"],
    )

    report = service.configure_securityhub(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=cfg,
        dry_run=False,
    )

    assert report.status == "ENABLED"
    assert report.service_name == "SecurityHub"
    mock_sh_mgmt.enable_organization_admin_account.assert_called_once_with(AdminAccountId="111122223333")
    mock_sh_audit.enable_security_hub.assert_called_once_with(EnableDefaultStandards=False)
    mock_sh_audit.batch_enable_standards.assert_called_once()
    mock_sh_audit.update_organization_configuration.assert_called_once_with(
        AutoEnable=True, AutoEnableStandards="NONE"
    )
    mock_sh_audit.create_finding_aggregator.assert_called_once_with(RegionLinkingMode="ALL_REGIONS")


def test_securityhub_idempotent_when_already_enabled():
    mock_session_mgr = MagicMock()
    mock_sh_mgmt = MagicMock()
    mock_sh_audit = MagicMock()

    mock_session_mgr.get_client.return_value = mock_sh_mgmt
    mock_session_mgr.get_member_client.return_value = mock_sh_audit

    mock_sh_mgmt.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AccountId": "111122223333", "Status": "ENABLED"}]
    }

    mock_sh_audit.describe_hub.return_value = {
        "HubArn": "arn:aws:securityhub:eu-west-1:111122223333:hub/default"
    }
    std_arn = "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
    mock_sh_audit.describe_standards.return_value = {"Standards": [{"StandardsArn": std_arn, "Name": "FSBP"}]}
    mock_sh_audit.get_enabled_standards.return_value = {"StandardsSubscriptions": [{"StandardsArn": std_arn}]}
    mock_sh_audit.list_finding_aggregators.return_value = {
        "FindingAggregators": [
            {"FindingAggregatorArn": "arn:aws:securityhub:eu-west-1:111122223333:aggregator/123"}
        ]
    }

    service = SecurityServicesService(mock_session_mgr)
    cfg = SecurityHubConfig(
        enabled=True,
        auto_enable_members=True,
        standards=["aws-foundational-security-best-practices"],
    )

    report = service.configure_securityhub(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=cfg,
        dry_run=False,
    )

    assert report.status == "ENABLED"
    mock_sh_mgmt.enable_organization_admin_account.assert_not_called()
    mock_sh_audit.enable_security_hub.assert_not_called()
    mock_sh_audit.batch_enable_standards.assert_not_called()
    mock_sh_audit.create_finding_aggregator.assert_not_called()


def test_guardduty_handles_client_error_on_admin_registration():
    mock_session_mgr = MagicMock()
    mock_gd_mgmt = MagicMock()
    mock_session_mgr.get_client.return_value = mock_gd_mgmt

    mock_gd_mgmt.list_organization_admin_accounts.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
        "ListOrganizationAdminAccounts",
    )

    service = SecurityServicesService(mock_session_mgr)
    cfg = GuardDutyConfig(enabled=True)

    report = service.configure_guardduty(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=cfg,
        dry_run=False,
    )

    assert report.status == "FAILED"
    assert "Access denied" in report.message
