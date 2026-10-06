"""Tests for AccountBaseliner module."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from tarmac.core.config_schema import (
    AccountBaselineConfig,
    AccountDef,
    BudgetConfig,
)
from tarmac.services.baseline import BaselineService


def test_cleanup_default_vpcs_skips_when_no_default_vpc():
    mock_session_mgr = MagicMock()
    mock_ec2 = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_ec2
    mock_session_mgr.default_region = "eu-west-1"

    mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

    baseliner = BaselineService(mock_session_mgr)
    reports = baseliner.cleanup_default_vpcs("123456789012", "TestAccount", regions=["eu-west-1"])

    assert len(reports) == 1
    assert reports[0].skipped is True
    assert reports[0].region == "eu-west-1"
    assert "No default VPC found" in reports[0].message


def test_cleanup_default_vpcs_deletes_components():
    mock_session_mgr = MagicMock()
    mock_ec2 = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_ec2
    mock_session_mgr.default_region = "eu-west-1"

    mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-default123"}]}
    mock_ec2.describe_internet_gateways.return_value = {
        "InternetGateways": [{"InternetGatewayId": "igw-111"}]
    }
    mock_ec2.describe_subnets.return_value = {"Subnets": [{"SubnetId": "subnet-222"}]}

    baseliner = BaselineService(mock_session_mgr)
    reports = baseliner.cleanup_default_vpcs("123456789012", "TestAccount", regions=["eu-west-1"])

    assert len(reports) == 1
    assert reports[0].deleted_vpc is True
    assert reports[0].vpc_id == "vpc-default123"
    assert "igw-111" in reports[0].detached_igws
    assert "subnet-222" in reports[0].deleted_subnets
    mock_ec2.delete_vpc.assert_called_once_with(VpcId="vpc-default123")


def test_setup_account_budget_creates_stack():
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_cfn
    mock_session_mgr.default_region = "eu-west-1"

    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": [{"OutputKey": "BudgetName", "OutputValue": "ProdAccount-monthly-budget"}]}]},
    ]

    baseliner = BaselineService(mock_session_mgr)
    budget_cfg = BudgetConfig(
        monthly_limit_usd=100.0,
        alert_threshold_percent=80.0,
        notification_emails=["test@example.com"],
    )

    report = baseliner.setup_account_budget("123456789012", "ProdAccount", budget_cfg, dry_run=False)

    assert report.status == "CREATED"
    assert report.limit_usd == 100.0
    mock_cfn.create_stack.assert_called_once()
    call_kwargs = mock_cfn.create_stack.call_args[1]
    assert call_kwargs["StackName"] == "ProdAccount-monthly-budget"
    param_dict = {p["ParameterKey"]: p["ParameterValue"] for p in call_kwargs["Parameters"]}
    assert param_dict["MonthlyLimitUSD"] == "100.0"
    assert param_dict["NotificationEmail"] == "test@example.com"


def test_setup_account_budget_maps_multiple_emails_to_parameters():
    """Verify that multiple emails configure the primary email on NotificationEmail for the SNS topic."""
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_cfn
    mock_session_mgr.default_region = "eu-west-1"

    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": [{"OutputKey": "BudgetName", "OutputValue": "CoreApp-monthly-budget"}]}]},
    ]

    baseliner = BaselineService(mock_session_mgr)
    emails = ["team@example.com", "ops@example.com", "finops@example.com", "oncall@example.com"]
    budget_cfg = BudgetConfig(
        monthly_limit_usd=500.0,
        alert_threshold_percent=90.0,
        notification_emails=emails,  # pyright: ignore[reportArgumentType]
    )

    report = baseliner.setup_account_budget("123456789012", "CoreApp", budget_cfg, dry_run=False)
    assert report.status == "CREATED"
    call_kwargs = mock_cfn.create_stack.call_args[1]
    param_dict = {p["ParameterKey"]: p["ParameterValue"] for p in call_kwargs["Parameters"]}
    assert param_dict["NotificationEmail"] == "team@example.com"


def test_setup_account_budget_updates_stack():
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_cfn
    mock_session_mgr.default_region = "eu-west-1"

    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "ProdAccount-monthly-budget", "StackStatus": "UPDATE_COMPLETE"}]
    }

    baseliner = BaselineService(mock_session_mgr)
    budget_cfg = BudgetConfig(
        monthly_limit_usd=250.0,
        alert_threshold_percent=85.0,
        notification_emails=["alert@example.com"],
    )

    report = baseliner.setup_account_budget("123456789012", "ProdAccount", budget_cfg, dry_run=False)

    assert report.status == "UPDATED"
    mock_cfn.update_stack.assert_called_once()


def test_setup_account_budget_cleans_up_orphan_unmanaged_budget():
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    mock_budgets = MagicMock()

    def member_client_side_effect(acct_id, service_name, **kwargs):
        if service_name == "cloudformation":
            return mock_cfn
        if service_name == "budgets":
            return mock_budgets
        return MagicMock()

    mock_session_mgr.get_member_client.side_effect = member_client_side_effect
    mock_session_mgr.default_region = "eu-west-1"

    # Stack does not exist
    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": [{"OutputKey": "BudgetName", "OutputValue": "ProdAccount-monthly-budget"}]}]},
    ]
    # Orphan budget exists in AWS Budgets API
    mock_budgets.describe_budget.return_value = {"Budget": {"BudgetName": "ProdAccount-monthly-budget"}}

    baseliner = BaselineService(mock_session_mgr)
    budget_cfg = BudgetConfig(
        monthly_limit_usd=100.0,
        alert_threshold_percent=80.0,
        notification_emails=["test@example.com"],
    )

    report = baseliner.setup_account_budget("123456789012", "ProdAccount", budget_cfg, dry_run=False)

    assert report.status == "CREATED"
    mock_budgets.delete_budget.assert_called_once_with(
        AccountId="123456789012", BudgetName="ProdAccount-monthly-budget"
    )
    mock_cfn.create_stack.assert_called_once()


def test_setup_account_budget_dry_run():
    mock_session_mgr = MagicMock()
    baseliner = BaselineService(mock_session_mgr)
    budget_cfg = BudgetConfig(
        monthly_limit_usd=100.0,
        alert_threshold_percent=80.0,
        notification_emails=["test@example.com"],
    )

    report = baseliner.setup_account_budget("123456789012", "ProdAccount", budget_cfg, dry_run=True)

    assert report.status == "SIMULATED"
    mock_session_mgr.get_member_client.assert_not_called()


def test_setup_account_budget_with_webhook_only():
    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_cfn
    mock_session_mgr.default_region = "eu-west-1"

    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": [{"OutputKey": "BudgetName", "OutputValue": "OpsAccount-monthly-budget"}]}]},
    ]

    baseliner = BaselineService(mock_session_mgr)
    budget_cfg = BudgetConfig(
        monthly_limit_usd=300.0,
        incident_response_webhook_url="https://events.pagerduty.com/integration/test",
    )

    report = baseliner.setup_account_budget("123456789012", "OpsAccount", budget_cfg, dry_run=False)
    assert report.status == "CREATED"
    call_kwargs = mock_cfn.create_stack.call_args[1]
    param_dict = {p["ParameterKey"]: p["ParameterValue"] for p in call_kwargs["Parameters"]}
    assert param_dict["IncidentResponseWebhookUrl"] == "https://events.pagerduty.com/integration/test"
    assert param_dict["NotificationEmail"] == ""


def test_setup_account_budget_skipped_when_no_subscribers():
    mock_session_mgr = MagicMock()
    baseliner = BaselineService(mock_session_mgr)
    budget_cfg = BudgetConfig(
        monthly_limit_usd=100.0,
    )

    report = baseliner.setup_account_budget("123456789012", "EmptyAccount", budget_cfg, dry_run=False)
    assert report.status == "SKIPPED"
    assert report.message == "No notification emails or incident response webhook specified."
    mock_session_mgr.get_member_client.assert_not_called()


def test_setup_cost_anomaly_monitor():
    from tarmac.core.config_schema import AnomalyDetectionConfig

    mock_session_mgr = MagicMock()
    mock_ce = MagicMock()
    mock_session_mgr.get_client.return_value = mock_ce

    mock_ce.get_anomaly_monitors.return_value = {"AnomalyMonitors": []}
    mock_ce.create_anomaly_monitor.return_value = {"MonitorArn": "arn:aws:ce::123:anomalymonitor/test-mon"}
    mock_ce.get_anomaly_subscriptions.return_value = {"AnomalySubscriptions": []}
    mock_ce.create_anomaly_subscription.return_value = {
        "SubscriptionArn": "arn:aws:ce::123:anomalysub/test-sub"
    }

    baseliner = BaselineService(mock_session_mgr)
    anomaly_cfg = AnomalyDetectionConfig(
        enabled=True,
        threshold_usd=100.0,
        notification_emails=["test@example.com"],
    )

    report = baseliner.setup_cost_anomaly_monitor("123456789012", "ProdAccount", anomaly_cfg)

    assert report.status == "CREATED"
    assert report.monitor_name == "ProdAccount-cost-anomaly-monitor"
    mock_ce.create_anomaly_monitor.assert_called_once()
    call_args = mock_ce.create_anomaly_monitor.call_args[1]
    monitor_spec = call_args["AnomalyMonitor"]["MonitorSpecification"]
    assert isinstance(monitor_spec, dict)
    assert monitor_spec["Dimensions"]["Key"] == "LINKED_ACCOUNT"
    assert monitor_spec["Dimensions"]["Values"] == ["123456789012"]
    mock_ce.create_anomaly_subscription.assert_called_once()


def test_get_anomaly_overview():
    mock_session_mgr = MagicMock()
    mock_ce = MagicMock()
    mock_session_mgr.get_client.return_value = mock_ce

    mock_ce.get_anomaly_monitors.return_value = {
        "AnomalyMonitors": [{"MonitorName": "test-mon", "MonitorType": "CUSTOM"}]
    }
    mock_ce.get_anomaly_subscriptions.return_value = {
        "AnomalySubscriptions": [{"SubscriptionName": "test-sub", "Threshold": 100.0}]
    }

    baseliner = BaselineService(mock_session_mgr)
    monitors, subs = baseliner.get_anomaly_overview()

    assert len(monitors) == 1
    assert monitors[0]["MonitorName"] == "test-mon"
    assert len(subs) == 1
    assert subs[0]["SubscriptionName"] == "test-sub"


def test_cleanup_default_vpcs_dynamic_region_discovery():
    mock_session_mgr = MagicMock()
    mock_ec2 = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_ec2
    mock_session_mgr.default_region = "eu-west-1"

    mock_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "us-east-1"}]
    }
    mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

    baseliner = BaselineService(mock_session_mgr)
    reports = baseliner.cleanup_default_vpcs("123456789012", "TestAccount", regions=None)

    assert len(reports) == 2
    assert {r.region for r in reports} == {"eu-west-1", "us-east-1"}
    mock_ec2.describe_regions.assert_called_once_with(AllRegions=False)


def test_cleanup_default_vpcs_handles_dependency_violation():
    from botocore.exceptions import ClientError

    mock_session_mgr = MagicMock()
    mock_ec2 = MagicMock()
    mock_session_mgr.get_member_client.return_value = mock_ec2
    mock_session_mgr.default_region = "eu-west-1"

    mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-dep123"}]}
    mock_ec2.describe_internet_gateways.return_value = {"InternetGateways": []}
    mock_ec2.describe_subnets.return_value = {"Subnets": []}

    mock_ec2.delete_vpc.side_effect = ClientError(
        {"Error": {"Code": "DependencyViolation", "Message": "There are active network interfaces"}},
        "DeleteVpc",
    )

    baseliner = BaselineService(mock_session_mgr)
    reports = baseliner.cleanup_default_vpcs("123456789012", "TestAccount", regions=["eu-west-1"])

    assert len(reports) == 1
    assert reports[0].skipped is True
    assert "DependencyViolation" in reports[0].message
    assert "active network interfaces" in reports[0].message


def test_is_account_baselined():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": [{"Key": "tarmac:baseline", "Value": "completed"}]}]
    mock_org.get_paginator.return_value = tag_paginator

    baseliner = BaselineService(mock_session_mgr)
    assert baseliner.is_account_baselined("123456789012") is True

    tag_paginator.paginate.return_value = [{"Tags": []}]
    assert baseliner.is_account_baselined("123456789012") is False

    mock_org.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListTagsForResource"
    )
    assert baseliner.is_account_baselined("123456789012") is False


def test_mark_account_baselined():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org

    baseliner = BaselineService(mock_session_mgr)
    baseliner.mark_account_baselined("123456789012")

    mock_org.tag_resource.assert_called_once()
    call_kwargs = mock_org.tag_resource.call_args[1]
    assert call_kwargs["ResourceId"] == "123456789012"
    tag_map = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert tag_map["tarmac:baseline"] == "completed"
    assert tag_map["tarmac:managed-by"] == "tarmac"


def test_baseline_account_fast_forwards_when_already_baselined():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": [{"Key": "tarmac:baseline", "Value": "completed"}]}]
    mock_org.get_paginator.return_value = tag_paginator

    baseliner = BaselineService(mock_session_mgr)
    acct_def = AccountDef(
        name="AlreadyBaselinedAccount",
        email="test@example.com",
        ou="Workloads",
        baseline=AccountBaselineConfig(delete_default_vpc=True),
    )

    report = baseliner.baseline_account(acct_def, "123456789012", regions=["eu-west-1"])

    mock_session_mgr.get_member_client.assert_not_called()
    assert len(report.vpc_reports) == 1
    assert report.vpc_reports[0].skipped is True
    assert "Already baselined" in report.vpc_reports[0].message
    mock_org.tag_resource.assert_not_called()


def test_baseline_account_runs_and_tags_when_not_baselined():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_ec2 = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    mock_session_mgr.get_member_client.return_value = mock_ec2
    mock_session_mgr.default_region = "eu-west-1"

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": []}]
    mock_org.get_paginator.return_value = tag_paginator
    mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

    baseliner = BaselineService(mock_session_mgr)
    acct_def = AccountDef(
        name="NewAccount",
        email="new@example.com",
        ou="Workloads",
        baseline=AccountBaselineConfig(delete_default_vpc=True),
    )

    baseliner.baseline_account(acct_def, "123456789012", regions=["eu-west-1"])

    mock_session_mgr.get_member_client.assert_called_once_with("123456789012", "ec2", region_name="eu-west-1")
    mock_org.tag_resource.assert_called_once()


def test_baseline_account_purges_all_enabled_regions_by_default():
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_ec2 = MagicMock()
    mock_session_mgr.get_client.return_value = mock_org
    mock_session_mgr.get_member_client.return_value = mock_ec2
    mock_session_mgr.default_region = "eu-west-1"

    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [{"Tags": []}]
    mock_org.get_paginator.return_value = tag_paginator
    mock_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "us-east-1"}]
    }
    mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

    baseliner = BaselineService(mock_session_mgr)
    acct_def = AccountDef(
        name="NewAccount",
        email="new@example.com",
        ou="Workloads",
        baseline=AccountBaselineConfig(delete_default_vpc=True),
    )

    report = baseliner.baseline_account(acct_def, "123456789012", regions=None)

    assert len(report.vpc_reports) == 2
    assert {r.region for r in report.vpc_reports} == {"eu-west-1", "us-east-1"}
    mock_ec2.describe_regions.assert_called_once_with(AllRegions=False)
