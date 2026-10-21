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
    call = mock_gd_audit.update_organization_configuration.call_args
    assert call.kwargs["DetectorId"] == "det-existing456"
    assert call.kwargs["AutoEnableOrganizationMembers"] == "ALL"


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


def test_guardduty_and_securityhub_report_failed_when_all_regions_fail():
    """Verify configure_guardduty and configure_securityhub report FAILED when all regions fail."""
    mock_session_mgr = MagicMock()
    mock_mgmt = MagicMock()
    mock_audit = MagicMock()
    mock_session_mgr.get_client.return_value = mock_mgmt
    mock_session_mgr.get_member_client.return_value = mock_audit

    mock_mgmt.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    regional_err = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Region blocked by SCP"}},
        "RegionalCall",
    )
    mock_audit.list_detectors.side_effect = regional_err
    mock_audit.describe_hub.side_effect = regional_err

    service = SecurityServicesService(mock_session_mgr)
    gd_report = service.configure_guardduty(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=GuardDutyConfig(enabled=True),
        dry_run=False,
    )
    assert gd_report.status == "FAILED"
    assert gd_report.regions == []

    sh_report = service.configure_securityhub(
        audit_id="111122223333",
        primary_region="eu-west-1",
        all_regions=["eu-west-1"],
        config=SecurityHubConfig(enabled=True),
        dry_run=False,
    )
    assert sh_report.status == "FAILED"
    assert sh_report.regions == []


# per-region failures must be visible, never averaged into success


def _ce(code: str, msg: str = "boom") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")


def _gd_service(fail_regions: dict[str, ClientError]) -> SecurityServicesService:
    mgr = MagicMock()
    mgr.get_client.return_value.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminAccountId": "111122223333", "AdminStatus": "ENABLED"}]
    }

    def member_client(acct: str, svc: str, region_name: str | None = None, **kw):
        gd = MagicMock()
        if region_name in fail_regions:
            gd.list_detectors.side_effect = fail_regions[region_name]
        else:
            gd.list_detectors.return_value = {"DetectorIds": ["d1"]}
        return gd

    mgr.get_member_client.side_effect = member_client
    return SecurityServicesService(mgr)


def test_guardduty_all_regions_ok_is_enabled():
    report = _gd_service({}).configure_guardduty(
        "111122223333", "us-east-1", ["us-east-1", "eu-west-1"], GuardDutyConfig(enabled=True)
    )
    assert report.status == "ENABLED"
    assert report.regions == ["us-east-1", "eu-west-1"]


def test_guardduty_partial_region_failure_is_reported_as_failed():
    service = _gd_service({"eu-west-1": _ce("AccessDeniedException", "no perms in eu-west-1")})

    report = service.configure_guardduty(
        "111122223333", "us-east-1", ["us-east-1", "eu-west-1"], GuardDutyConfig(enabled=True)
    )

    assert report.status == "FAILED"
    assert report.regions == ["us-east-1"]
    assert "eu-west-1" in report.message
    assert "no perms in eu-west-1" in report.message


def _sh_service(
    *,
    fail_update: bool = False,
    standards: list[dict] | None = None,
    aggregator_error: ClientError | None = None,
) -> SecurityServicesService:
    mgr = MagicMock()
    mgr.get_client.return_value.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AccountId": "111122223333", "Status": "ENABLED"}]
    }
    sh = MagicMock()
    sh.describe_hub.return_value = {}
    sh.describe_standards.return_value = {
        "Standards": standards
        or [
            {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "Name": "AWS Foundational Security Best Practices v1.0.0",
            }
        ]
    }
    sh.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
    if fail_update:
        sh.update_organization_configuration.side_effect = _ce(
            "AccessDeniedException", "cannot set auto-enable"
        )
    if aggregator_error:
        sh.list_finding_aggregators.side_effect = aggregator_error
    else:
        sh.list_finding_aggregators.return_value = {"FindingAggregators": [{"x": 1}]}
    mgr.get_member_client.return_value = sh
    return SecurityServicesService(mgr)


def test_securityhub_success_is_enabled():
    report = _sh_service().configure_securityhub(
        "111122223333", "us-east-1", ["us-east-1"], SecurityHubConfig(enabled=True)
    )
    assert report.status == "ENABLED"


def test_securityhub_auto_enable_failure_fails_the_region():
    report = _sh_service(fail_update=True).configure_securityhub(
        "111122223333", "us-east-1", ["us-east-1"], SecurityHubConfig(enabled=True)
    )
    assert report.status == "FAILED"
    assert "cannot set auto-enable" in report.message


def test_securityhub_unknown_standard_is_a_failure_not_a_silent_noop():
    report = _sh_service().configure_securityhub(
        "111122223333",
        "us-east-1",
        ["us-east-1"],
        SecurityHubConfig(enabled=True, standards=["cis-typo-benchmark"]),
    )
    assert report.status == "FAILED"
    assert "Unknown Security Hub standard 'cis-typo-benchmark'" in report.message


def test_securityhub_finding_aggregator_failure_is_reported():
    report = _sh_service(
        aggregator_error=_ce("AccessDeniedException", "no aggregator perms")
    ).configure_securityhub("111122223333", "us-east-1", ["us-east-1"], SecurityHubConfig(enabled=True))
    assert report.status == "FAILED"
    assert "finding aggregator" in report.message
    assert "no aggregator perms" in report.message


# -- the delegated administrator is Regional ------------------------------------------------------------------


def _regional_session() -> MagicMock:
    """A session whose management-account client is a distinct mock per (service, Region)."""
    clients: dict[tuple[str, str], MagicMock] = {}

    def get_client(service: str, region_name: str | None = None, **_kw):
        key = (service, region_name or "")
        if key not in clients:
            client = MagicMock()
            client.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
            clients[key] = client
        return clients[key]

    mgr = MagicMock()
    mgr.get_client.side_effect = get_client
    audit_client = MagicMock()
    audit_client.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    audit_client.describe_hub.return_value = {}
    audit_client.describe_standards.return_value = {
        "Standards": [
            {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "Name": "AWS Foundational Security Best Practices v1.0.0",
            }
        ]
    }
    audit_client.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
    audit_client.list_finding_aggregators.return_value = {"FindingAggregators": [{}]}
    mgr.get_member_client.return_value = audit_client
    return mgr


def test_guardduty_admin_is_registered_in_every_region_not_only_the_primary():
    mgr = _regional_session()
    service = SecurityServicesService(mgr)

    report = service.configure_guardduty(
        "111122223333",
        "eu-west-1",
        ["eu-west-1", "us-east-1", "ap-southeast-2"],
        GuardDutyConfig(enabled=True),
    )

    assert report.status == "ENABLED"
    registered = {
        region
        for call in mgr.get_client.call_args_list
        for region in [call.kwargs.get("region_name")]
        if call.args[0] == "guardduty"
    }
    assert registered == {"eu-west-1", "us-east-1", "ap-southeast-2"}
    for region in ("eu-west-1", "us-east-1", "ap-southeast-2"):
        client = mgr.get_client("guardduty", region_name=region)
        client.enable_organization_admin_account.assert_called_once_with(AdminAccountId="111122223333")


def test_guardduty_admin_failure_in_a_secondary_region_fails_that_region_only():
    mgr = _regional_session()
    mgr.get_client(
        "guardduty", region_name="us-east-1"
    ).enable_organization_admin_account.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not allowed in us-east-1"}},
        "EnableOrganizationAdminAccount",
    )

    report = SecurityServicesService(mgr).configure_guardduty(
        "111122223333", "eu-west-1", ["eu-west-1", "us-east-1"], GuardDutyConfig(enabled=True)
    )

    assert report.status == "FAILED"
    assert report.regions == ["eu-west-1"]
    assert "us-east-1" in report.message


def test_securityhub_local_mode_registers_the_admin_in_every_region():
    mgr = _regional_session()

    report = SecurityServicesService(mgr).configure_securityhub(
        "111122223333",
        "eu-west-1",
        ["eu-west-1", "us-east-1"],
        SecurityHubConfig(enabled=True, central_configuration=False),
    )

    assert report.status == "ENABLED"
    for region in ("eu-west-1", "us-east-1"):
        mgr.get_client(
            "securityhub", region_name=region
        ).enable_organization_admin_account.assert_called_once_with(AdminAccountId="111122223333")


# -- optional GuardDuty features stay off unless asked for ---------------------------------------------------

OPTIONAL = {
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
}


def _gd_pair(existing_detector: str | None = None, current: list[dict] | None = None):
    mgr = MagicMock()
    mgmt = MagicMock()
    audit_client = MagicMock()
    mgmt.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminAccountId": "111122223333", "AdminStatus": "ENABLED"}]
    }
    audit_client.list_detectors.return_value = {
        "DetectorIds": [existing_detector] if existing_detector else []
    }
    audit_client.create_detector.return_value = {"DetectorId": "det-new"}
    audit_client.get_detector.return_value = {"Features": current or []}
    mgr.get_client.return_value = mgmt
    mgr.get_member_client.return_value = audit_client
    return SecurityServicesService(mgr), audit_client


def _statuses(features: list[dict]) -> dict[str, str]:
    return {f["Name"]: f["Status"] for f in features}


def test_a_new_detector_is_created_with_every_optional_feature_disabled():
    service, gd = _gd_pair()

    service.configure_guardduty("111122223333", "eu-west-1", ["eu-west-1"], GuardDutyConfig(enabled=True))

    features = gd.create_detector.call_args.kwargs["Features"]
    assert _statuses(features) == {name: "DISABLED" for name in OPTIONAL}


def test_a_requested_feature_is_enabled_and_the_rest_stay_disabled():
    from tarmac.core.config_schema import GuardDutyFeaturesConfig

    service, gd = _gd_pair()
    cfg = GuardDutyConfig(enabled=True, features=GuardDutyFeaturesConfig(s3_data_events=True))

    service.configure_guardduty("111122223333", "eu-west-1", ["eu-west-1"], cfg)

    statuses = _statuses(gd.create_detector.call_args.kwargs["Features"])
    assert statuses["S3_DATA_EVENTS"] == "ENABLED"
    assert {k: v for k, v in statuses.items() if k != "S3_DATA_EVENTS"} == {
        name: "DISABLED" for name in OPTIONAL - {"S3_DATA_EVENTS"}
    }


def test_new_member_accounts_inherit_the_same_feature_choice():
    service, gd = _gd_pair()

    service.configure_guardduty("111122223333", "eu-west-1", ["eu-west-1"], GuardDutyConfig(enabled=True))

    org_features = gd.update_organization_configuration.call_args.kwargs["Features"]
    assert {f["Name"]: f["AutoEnable"] for f in org_features} == {name: "NONE" for name in OPTIONAL}


def test_an_existing_detector_keeps_features_it_already_has():
    service, gd = _gd_pair(
        existing_detector="det-old", current=[{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}]
    )

    service.configure_guardduty("111122223333", "eu-west-1", ["eu-west-1"], GuardDutyConfig(enabled=True))

    gd.update_detector.assert_not_called()
    gd.create_detector.assert_not_called()


def test_an_existing_detector_gets_a_requested_feature_turned_on():
    from tarmac.core.config_schema import GuardDutyFeaturesConfig

    service, gd = _gd_pair(existing_detector="det-old", current=[])
    cfg = GuardDutyConfig(enabled=True, features=GuardDutyFeaturesConfig(malware_protection=True))

    service.configure_guardduty("111122223333", "eu-west-1", ["eu-west-1"], cfg)

    gd.update_detector.assert_called_once_with(
        DetectorId="det-old", Features=[{"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"}]
    )
