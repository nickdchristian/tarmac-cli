"""Unit tests for PreflightService."""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.models import PreflightCheckStatus
from tarmac.services.preflight import PreflightService


@pytest.fixture
def mock_session():
    return MagicMock()


@pytest.fixture
def test_bundle(sample_config_dir) -> ConfigBundle:
    bundle, errors = load_all_configs(sample_config_dir)
    assert bundle is not None
    assert not errors
    return bundle


def test_check_root_mfa_pass(mock_session, test_bundle):
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    mock_session.get_client.return_value = mock_iam

    service = PreflightService(mock_session, test_bundle)
    res = service.check_root_mfa()

    assert res.status == PreflightCheckStatus.PASS
    assert "Enabled" in res.live_value
    assert res.action_required is None


def test_check_root_mfa_fail(mock_session, test_bundle):
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    mock_session.get_client.return_value = mock_iam

    service = PreflightService(mock_session, test_bundle)
    res = service.check_root_mfa()

    assert res.status == PreflightCheckStatus.FAIL
    assert "Disabled" in res.live_value
    assert res.action_required is not None


def test_check_root_mfa_error(mock_session, test_bundle):
    mock_iam = MagicMock()
    mock_iam.get_account_summary.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}}, "GetAccountSummary"
    )
    mock_session.get_client.return_value = mock_iam

    service = PreflightService(mock_session, test_bundle)
    res = service.check_root_mfa()

    assert res.status == PreflightCheckStatus.INFO
    assert res.live_value == "Unavailable"
    assert "Check IAM permissions" in str(res.action_required)


def test_check_alternate_contacts_pass(mock_session, test_bundle):
    mock_account = MagicMock()
    mock_account.get_alternate_contact.return_value = {
        "AlternateContact": {"EmailAddress": "ops@example.com"}
    }
    mock_session.get_client.return_value = mock_account

    service = PreflightService(mock_session, test_bundle)
    results = service.check_alternate_contacts()

    assert len(results) == 3
    assert all(r.status == PreflightCheckStatus.PASS for r in results)


def test_check_alternate_contacts_warn(mock_session, test_bundle):
    mock_account = MagicMock()
    mock_account.get_alternate_contact.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}}, "GetAlternateContact"
    )
    mock_session.get_client.return_value = mock_account

    service = PreflightService(mock_session, test_bundle)
    results = service.check_alternate_contacts()

    assert len(results) == 3
    assert all(r.status == PreflightCheckStatus.WARN for r in results)


def test_check_identity_center_pass(mock_session, test_bundle):
    mock_sso = MagicMock()
    mock_sso.list_instances.return_value = {"Instances": [{"InstanceArn": "arn:aws:sso:::instance/sso-test"}]}
    mock_session.get_client.return_value = mock_sso

    service = PreflightService(mock_session, test_bundle)
    res = service.check_identity_center("eu-west-1")

    assert res.status == PreflightCheckStatus.PASS
    assert "Active" in res.live_value


def test_check_identity_center_warn(mock_session, test_bundle):
    mock_sso = MagicMock()
    mock_sso.list_instances.return_value = {"Instances": []}
    mock_session.get_client.return_value = mock_sso

    service = PreflightService(mock_session, test_bundle)
    res = service.check_identity_center("eu-west-1")

    assert res.status == PreflightCheckStatus.WARN
    assert "Not Initialized" in res.live_value


def test_check_cost_explorer_pass(mock_session, test_bundle):
    mock_ce = MagicMock()
    mock_ce.get_dimension_values.return_value = {"DimensionValues": []}
    mock_session.get_client.return_value = mock_ce

    service = PreflightService(mock_session, test_bundle)
    res = service.check_cost_explorer()

    assert res.status == PreflightCheckStatus.PASS
    assert "Active" in res.live_value


def test_check_cost_explorer_warn_unavailable(mock_session, test_bundle):
    mock_ce = MagicMock()
    mock_ce.get_dimension_values.side_effect = ClientError(
        {"Error": {"Code": "DataUnavailableException", "Message": "Not ready"}}, "GetDimensionValues"
    )
    mock_session.get_client.return_value = mock_ce

    service = PreflightService(mock_session, test_bundle)
    res = service.check_cost_explorer()

    assert res.status == PreflightCheckStatus.WARN
    assert "Not Activated" in res.live_value


def test_check_cost_allocation_tags_pass(mock_session, test_bundle):
    mock_ce = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {
            "CostAllocationTags": [
                {"TagKey": k, "Status": "Active"} for k in test_bundle.get_cost_allocation_tags()
            ]
        }
    ]
    mock_ce.get_paginator.return_value = mock_paginator
    mock_session.get_client.return_value = mock_ce

    service = PreflightService(mock_session, test_bundle)
    res = service.check_cost_allocation_tags()

    assert res.status == PreflightCheckStatus.PASS
    assert "Active" in res.live_value


def test_check_cost_allocation_tags_warn_inactive(mock_session, test_bundle):
    mock_ce = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"CostAllocationTags": []}]
    mock_ce.get_paginator.return_value = mock_paginator
    mock_session.get_client.return_value = mock_ce

    service = PreflightService(mock_session, test_bundle)
    res = service.check_cost_allocation_tags()

    assert res.status == PreflightCheckStatus.WARN
    assert "missing:" in res.live_value
    assert "Environment" in res.live_value


def test_check_cost_allocation_tags_disabled(mock_session, test_bundle):
    test_bundle.org.cost_allocation_tags.enabled = False
    service = PreflightService(mock_session, test_bundle)
    res = service.check_cost_allocation_tags()

    assert res.status == PreflightCheckStatus.PASS
    assert "Disabled" in res.live_value


def test_check_cost_allocation_tags_warn_none_defined(mock_session, test_bundle):
    test_bundle.org.cost_allocation_tags.tags = []
    service = PreflightService(mock_session, test_bundle)
    res = service.check_cost_allocation_tags()

    assert res.status == PreflightCheckStatus.WARN
    assert "None defined" in res.live_value
    assert "Define cost_allocation_tags" in (res.action_required or "")


def test_check_sns_subscriptions_pass(mock_session, test_bundle):
    mock_sns = MagicMock()
    mock_sns.list_topics.return_value = {"Topics": [{"TopicArn": "arn:aws:sns:eu-west-1:123:alerts"}]}
    mock_sns.list_subscriptions_by_topic.return_value = {
        "Subscriptions": [{"SubscriptionArn": "arn:aws:sns:123:sub1", "Endpoint": "test@example.com"}]
    }
    mock_session.get_client.return_value = mock_sns

    service = PreflightService(mock_session, test_bundle)
    res = service.check_sns_subscriptions("eu-west-1")

    assert res.status == PreflightCheckStatus.PASS
    assert "Confirmed" in res.live_value


def test_check_sns_subscriptions_warn_pending(mock_session, test_bundle):
    mock_sns = MagicMock()
    mock_sns.list_topics.return_value = {"Topics": [{"TopicArn": "arn:aws:sns:eu-west-1:123:alerts"}]}
    mock_sns.list_subscriptions_by_topic.return_value = {
        "Subscriptions": [{"SubscriptionArn": "PendingConfirmation", "Endpoint": "test@example.com"}]
    }
    mock_session.get_client.return_value = mock_sns

    service = PreflightService(mock_session, test_bundle)
    res = service.check_sns_subscriptions("eu-west-1")

    assert res.status == PreflightCheckStatus.WARN
    assert "1 Pending Confirmation" in res.live_value


def test_check_support_tier_business(mock_session, test_bundle):
    mock_support = MagicMock()
    mock_support.describe_severity_levels.return_value = {"severityLevels": [{"code": "low"}]}
    mock_session.get_client.return_value = mock_support

    service = PreflightService(mock_session, test_bundle)
    res = service.check_support_tier()

    assert res.status == PreflightCheckStatus.PASS
    assert "Business / Enterprise" in res.live_value


def test_check_support_tier_basic(mock_session, test_bundle):
    mock_support = MagicMock()
    mock_support.describe_severity_levels.side_effect = ClientError(
        {"Error": {"Code": "SubscriptionRequiredException", "Message": "Basic tier"}},
        "DescribeSeverityLevels",
    )
    mock_session.get_client.return_value = mock_support

    service = PreflightService(mock_session, test_bundle)
    res = service.check_support_tier()

    assert res.status == PreflightCheckStatus.INFO
    assert "Basic" in res.live_value


def test_check_organization_status_pass(mock_session, test_bundle):
    mock_session.get_caller_identity.return_value = {"Account": "111111111111"}
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "111111111111", "FeatureSet": "ALL"}
    }
    mock_session.get_client.return_value = mock_org

    service = PreflightService(mock_session, test_bundle)
    res = service.check_organization_status()

    assert res.status == PreflightCheckStatus.PASS
    assert "All Features" in res.live_value


def test_check_organization_status_not_master_fail(mock_session, test_bundle):
    mock_session.get_caller_identity.return_value = {"Account": "222222222222"}
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "111111111111", "FeatureSet": "ALL"}
    }
    mock_session.get_client.return_value = mock_org

    service = PreflightService(mock_session, test_bundle)
    res = service.check_organization_status()

    assert res.status == PreflightCheckStatus.FAIL
    assert "Member Account" in res.live_value


def test_check_organization_status_consolidated_warn(mock_session, test_bundle):
    mock_session.get_caller_identity.return_value = {"Account": "111111111111"}
    mock_org = MagicMock()
    mock_org.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "111111111111", "FeatureSet": "CONSOLIDATED_BILLING"}
    }
    mock_session.get_client.return_value = mock_org

    service = PreflightService(mock_session, test_bundle)
    res = service.check_organization_status()

    assert res.status == PreflightCheckStatus.WARN
    assert "Consolidated Billing" in res.live_value


def test_check_iam_user_hygiene_clean(mock_session, test_bundle):
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"Users": 0}}
    mock_session.get_client.return_value = mock_iam

    service = PreflightService(mock_session, test_bundle)
    res = service.check_iam_user_hygiene()

    assert res.status == PreflightCheckStatus.PASS
    assert "0 Local IAM Users" in res.live_value


def test_check_iam_user_hygiene_warn(mock_session, test_bundle):
    mock_iam = MagicMock()
    mock_iam.get_account_summary.return_value = {"SummaryMap": {"Users": 3}}
    mock_session.get_client.return_value = mock_iam

    service = PreflightService(mock_session, test_bundle)
    res = service.check_iam_user_hygiene()

    assert res.status == PreflightCheckStatus.WARN
    assert "3 Local IAM User(s)" in res.live_value


def test_run_all_checks_compilation(mock_session, test_bundle):
    mock_session.get_caller_identity.return_value = {"Account": "111111111111"}
    mock_client = MagicMock()
    mock_client.describe_organization.return_value = {
        "Organization": {"MasterAccountId": "111111111111", "FeatureSet": "ALL"}
    }
    mock_client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1, "Users": 0}}
    mock_client.get_alternate_contact.return_value = {
        "AlternateContact": {"EmailAddress": "test@example.com"}
    }
    mock_client.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/sso-123"}]
    }
    mock_client.get_dimension_values.return_value = {"DimensionValues": []}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {
            "CostAllocationTags": [
                {"TagKey": k, "Status": "Active"} for k in test_bundle.get_cost_allocation_tags()
            ]
        }
    ]
    mock_client.get_paginator.return_value = mock_paginator
    mock_client.list_topics.return_value = {"Topics": []}
    mock_client.list_subscriptions_by_topic.return_value = {"Subscriptions": []}
    mock_client.describe_severity_levels.return_value = {"severityLevels": []}
    mock_client.list_roots.return_value = {"Roots": [{"Id": "r-123"}]}
    mock_client.get_service_quota.return_value = {"Quota": {"Value": 100.0}}
    mock_client.head_bucket.return_value = {}

    mock_session.get_client.return_value = mock_client

    service = PreflightService(mock_session, test_bundle)
    report = service.run_all_checks()

    assert report.can_proceed is True
    assert report.failures == 0
    assert report.passed > 0
    assert len(report.checks) == 17


def test_check_account_quota_pass(mock_session, test_bundle):
    mock_org = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}]
    mock_org.get_paginator.return_value = mock_paginator

    mock_sq = MagicMock()
    mock_sq.get_service_quota.return_value = {"Quota": {"Value": 50.0}}

    def mock_get_client(service, region_name=None):
        if service == "service-quotas":
            return mock_sq
        return mock_org

    mock_session.get_client.side_effect = mock_get_client

    service = PreflightService(mock_session, test_bundle)
    res = service.check_account_quota()
    assert res.status == PreflightCheckStatus.PASS
    assert "remaining" in res.live_value


def test_check_account_quota_exceeded(mock_session, test_bundle):
    mock_org = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"Accounts": [{"Id": f"11111111111{i}", "Status": "ACTIVE"}]} for i in range(5)
    ]
    mock_org.get_paginator.return_value = mock_paginator

    mock_sq = MagicMock()
    # Total capacity 8, but 5 active + 7 declared = 12 > 8
    mock_sq.get_service_quota.return_value = {"Quota": {"Value": 8.0}}

    def mock_get_client(service, region_name=None):
        if service == "service-quotas":
            return mock_sq
        return mock_org

    mock_session.get_client.side_effect = mock_get_client

    service = PreflightService(mock_session, test_bundle)
    res = service.check_account_quota()
    assert res.status == PreflightCheckStatus.FAIL
    assert "max quota" in res.live_value
    assert res.action_required is not None


def test_check_scp_quota_pass(mock_session, test_bundle):
    mock_org = MagicMock()
    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-1234"}]}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Policies": [{"Id": "p-1"}, {"Id": "p-2"}]}]
    mock_org.get_paginator.return_value = mock_paginator
    mock_session.get_client.return_value = mock_org

    service = PreflightService(mock_session, test_bundle)
    res = service.check_scp_quota()
    assert res.status == PreflightCheckStatus.PASS
    assert "2 of 5 SCPs" in res.live_value


def test_check_scp_quota_warn_limit(mock_session, test_bundle):
    mock_org = MagicMock()
    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-1234"}]}
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Policies": [{"Id": f"p-{i}"} for i in range(5)]}]
    mock_org.get_paginator.return_value = mock_paginator
    mock_session.get_client.return_value = mock_org

    service = PreflightService(mock_session, test_bundle)
    res = service.check_scp_quota()
    assert res.status == PreflightCheckStatus.WARN
    assert "5 of 5 SCPs attached" in res.live_value
    assert res.action_required is not None
