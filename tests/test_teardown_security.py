"""Opt-in security-service teardown and log-archive KMS key retirement."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from typer.testing import CliRunner

from tarmac.cli.deploy import app
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_loader import load_all_configs
from tarmac.services.scaffold import scaffold_project
from tarmac.services.teardown import TeardownService

AUDIT = "444455556666"
MGMT = "111122223333"


@pytest.fixture
def bundle(tmp_path: Path):
    scaffold_project(tmp_path)
    b, errors = load_all_configs(tmp_path)
    assert b is not None, errors
    b.org.security_services.guardduty.enabled = True
    b.org.security_services.securityhub.enabled = True
    b.org.root_access_management.enabled = False
    b.org.organization.additional_regions = []
    return b


def _real(service: str) -> Any:
    name: Any = service
    return boto3.client(name, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")


def _security_service(clients: dict[str, Any]) -> TeardownService:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.default_region = "us-east-1"
    mgr.get_client.side_effect = lambda svc, **kw: clients[svc]
    mgr.get_member_client.side_effect = lambda acct, svc, **kw: clients[svc]
    mgr.get_caller_identity.return_value = {"Account": MGMT}
    return TeardownService(mgr)


def _audit_name(bundle) -> str:
    return bundle.org.security_services.delegated_account


def test_security_teardown_issues_valid_calls_in_a_safe_order(bundle):
    """Stubber validates every request against the real service models and fixes the call order."""
    gd, sh, org = _real("guardduty"), _real("securityhub"), _real("organizations")
    accounts = {_audit_name(bundle): AUDIT}
    svc = _security_service({"guardduty": gd, "securityhub": sh, "organizations": org})

    with Stubber(gd) as gds, Stubber(sh) as shs, Stubber(org) as orgs:
        # Security Hub: stop auto-enable, drop aggregator, deregister admin, disable the hub.
        shs.add_response(
            "update_organization_configuration", {}, {"AutoEnable": False, "AutoEnableStandards": "NONE"}
        )
        shs.add_response(
            "list_finding_aggregators",
            {"FindingAggregators": [{"FindingAggregatorArn": "arn:aws:securityhub:us-east-1:1:agg/a"}]},
        )
        shs.add_response(
            "delete_finding_aggregator", {}, {"FindingAggregatorArn": "arn:aws:securityhub:us-east-1:1:agg/a"}
        )
        shs.add_response("list_organization_admin_accounts", {"AdminAccounts": [{"AccountId": AUDIT}]})
        shs.add_response("disable_organization_admin_account", {}, {"AdminAccountId": AUDIT})
        # The hub is disabled in the management account and in the audit account (shared stub client).
        shs.add_response("disable_security_hub", {})
        shs.add_response("disable_security_hub", {})
        # GuardDuty: stop auto-enable, deregister admin, THEN delete the detector.
        gds.add_response("list_detectors", {"DetectorIds": ["d1"]})
        gds.add_response(
            "update_organization_configuration",
            {},
            {"DetectorId": "d1", "AutoEnableOrganizationMembers": "NONE"},
        )
        gds.add_response("list_organization_admin_accounts", {"AdminAccounts": [{"AdminAccountId": AUDIT}]})
        gds.add_response("disable_organization_admin_account", {}, {"AdminAccountId": AUDIT})
        for _ in range(2):  # management account and audit account
            gds.add_response("list_detectors", {"DetectorIds": ["d1"]})
            gds.add_response("delete_detector", {}, {"DetectorId": "d1"})
        # Config delegated admin registrations.
        for principal in ("config-multiaccountsetup.amazonaws.com", "config.amazonaws.com"):
            orgs.add_response(
                "list_delegated_administrators",
                {"DelegatedAdministrators": [{"Id": AUDIT}]},
                {"ServicePrincipal": principal},
            )
            orgs.add_response(
                "deregister_delegated_administrator", {}, {"AccountId": AUDIT, "ServicePrincipal": principal}
            )

        reports = svc.teardown_security_services(bundle, "us-east-1", accounts)

        gds.assert_no_pending_responses()
        shs.assert_no_pending_responses()
        orgs.assert_no_pending_responses()

    assert not [r for r in reports if r.action == "FAILED"]
    assert [r.action for r in reports].count("DELETED") == len(reports)


def test_security_teardown_dry_run_makes_no_changes(bundle):
    gd, sh, org = MagicMock(), MagicMock(), MagicMock()
    svc = _security_service({"guardduty": gd, "securityhub": sh, "organizations": org})

    reports = svc.teardown_security_services(bundle, "us-east-1", {_audit_name(bundle): AUDIT}, dry_run=True)

    assert reports
    assert {r.action for r in reports} == {"SIMULATED"}
    for client in (gd, sh, org):
        for name in (
            "disable_organization_admin_account",
            "delete_detector",
            "disable_security_hub",
            "deregister_delegated_administrator",
            "update_organization_configuration",
        ):
            assert not getattr(client, name).called


def test_security_teardown_only_touches_services_enabled_in_config(bundle):
    bundle.org.security_services.guardduty.enabled = False
    gd, sh, org = MagicMock(), MagicMock(), MagicMock()
    # GuardDuty really is active in the account; tarmac must still leave it alone because config disables it.
    gd.list_detectors.return_value = {"DetectorIds": ["d1"]}
    gd.list_organization_admin_accounts.return_value = {"AdminAccounts": [{"AdminAccountId": AUDIT}]}
    sh.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    org.list_delegated_administrators.return_value = {"DelegatedAdministrators": []}
    svc = _security_service({"guardduty": gd, "securityhub": sh, "organizations": org})

    svc.teardown_security_services(bundle, "us-east-1", {_audit_name(bundle): AUDIT})

    gd.delete_detector.assert_not_called()
    gd.disable_organization_admin_account.assert_not_called()
    gd.update_organization_configuration.assert_not_called()


def test_security_teardown_skips_when_audit_account_unresolved(bundle):
    clients = {"guardduty": MagicMock(), "securityhub": MagicMock(), "organizations": MagicMock()}
    svc = _security_service(clients)

    reports = svc.teardown_security_services(bundle, "us-east-1", {"unrelated": "999999999999"})

    assert [r.action for r in reports] == ["SKIPPED"]
    clients["guardduty"].delete_detector.assert_not_called()


def test_security_teardown_reports_failures_and_keeps_going(bundle):
    gd, sh, org = MagicMock(), MagicMock(), MagicMock()
    sh.update_organization_configuration.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "UpdateOrganizationConfiguration"
    )
    sh.list_finding_aggregators.return_value = {"FindingAggregators": []}
    sh.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    gd.list_detectors.return_value = {"DetectorIds": []}
    gd.list_organization_admin_accounts.return_value = {"AdminAccounts": []}
    org.list_delegated_administrators.return_value = {"DelegatedAdministrators": []}
    svc = _security_service({"guardduty": gd, "securityhub": sh, "organizations": org})

    reports = svc.teardown_security_services(bundle, "us-east-1", {_audit_name(bundle): AUDIT})

    assert any(r.action == "FAILED" and "Security Hub auto-enable" in r.resource_type for r in reports)
    assert any(r.resource_type.startswith("GuardDuty") for r in reports)  # later steps still ran


def test_deregistration_happens_before_detector_deletion(bundle):
    order: list[str] = []
    gd, sh, org = MagicMock(), MagicMock(), MagicMock()
    bundle.org.security_services.securityhub.enabled = False
    gd.list_detectors.return_value = {"DetectorIds": ["d1"]}
    gd.list_organization_admin_accounts.return_value = {"AdminAccounts": [{"AdminAccountId": AUDIT}]}
    gd.disable_organization_admin_account.side_effect = lambda **k: order.append("deregister")
    gd.delete_detector.side_effect = lambda **k: order.append("delete_detector")
    org.list_delegated_administrators.return_value = {"DelegatedAdministrators": []}
    svc = _security_service({"guardduty": gd, "securityhub": sh, "organizations": org})

    svc.teardown_security_services(bundle, "us-east-1", {_audit_name(bundle): AUDIT})

    assert order[0] == "deregister"
    assert order[1:]
    assert set(order[1:]) == {"delete_detector"}


# phase wiring and CLI flag


def test_teardown_all_runs_security_teardown_only_when_requested(bundle):
    svc = _security_service({})
    svc.teardown_security_services = MagicMock(return_value=[])  # type: ignore[method-assign]
    for name in ("teardown_backend", "teardown_audit", "teardown_root_alert"):
        setattr(svc, name, MagicMock(return_value=[]))
    svc._get_active_accounts = MagicMock(return_value={})  # type: ignore[method-assign]

    svc.teardown_all(bundle, phases=[5], dry_run=True)
    svc.teardown_security_services.assert_not_called()

    svc.teardown_all(bundle, phases=[5], dry_run=True, disable_security_services=True)
    svc.teardown_security_services.assert_called_once()


def test_cli_passes_disable_security_flag_and_adjusts_notice(tmp_path):
    from unittest.mock import patch

    from tarmac.core.models import TeardownItemReport
    from tarmac.services.teardown import TeardownReport

    scaffold_project(tmp_path)
    report = TeardownReport(items=[TeardownItemReport("Stack", "s", "m", "1", "DELETED")], status="COMPLETED")
    with patch("tarmac.services.teardown.TeardownService.teardown_all", return_value=report) as td:
        plain = CliRunner().invoke(app, ["destroy", "-c", str(tmp_path), "-y"])
        flagged = CliRunner().invoke(
            app, ["destroy", "-c", str(tmp_path), "-y", "--disable-security-services"]
        )

    assert plain.exit_code == 0
    assert flagged.exit_code == 0
    assert td.call_args_list[0].kwargs["disable_security_services"] is False
    assert td.call_args_list[1].kwargs["disable_security_services"] is True
    assert "GuardDuty" in plain.stdout
    assert "GuardDuty" not in flagged.stdout


# log-archive KMS key retirement


def _log_archive_service(bundle, kms: MagicMock, bucket_delete_error: Exception | None = None):
    cfn, s3 = MagicMock(), MagicMock()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Outputs": []}]}
    cfn.describe_stack_resource.return_value = {"StackResourceDetail": {"PhysicalResourceId": "key-123"}}
    s3.head_bucket.side_effect = ClientError({"Error": {"Code": "404", "Message": "nf"}}, "HeadBucket")
    if bucket_delete_error:
        s3.head_bucket.side_effect = None
        s3.get_paginator.return_value.paginate.return_value = []
        s3.delete_bucket.side_effect = bucket_delete_error
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.default_region = "us-east-1"
    mgr.get_member_client.side_effect = lambda acct, svc, **kw: {
        "cloudformation": cfn,
        "s3": s3,
        "kms": kms,
    }[svc]
    mgr.get_caller_identity.return_value = {"Account": MGMT}
    return TeardownService(mgr)


def _la_accounts(bundle) -> dict[str, str]:
    return {bundle.get_log_archive_account_name() or "log-archive": "555566667777"}


def test_log_key_is_scheduled_for_deletion_after_clean_log_archive_teardown(bundle):
    kms = MagicMock()
    kms.describe_key.return_value = {"KeyMetadata": {"KeyState": "Enabled"}}
    svc = _log_archive_service(bundle, kms)

    reports = svc.teardown_log_archive(bundle, "us-east-1", account_id_map=_la_accounts(bundle))

    kms.schedule_key_deletion.assert_called_once_with(KeyId="key-123", PendingWindowInDays=30)
    assert any(r.resource_type == "KMS Key" and r.action == "DELETED" for r in reports)


def test_log_key_is_kept_when_bucket_cleanup_failed(bundle):
    kms = MagicMock()
    err = ClientError({"Error": {"Code": "BucketNotEmpty", "Message": "full"}}, "DeleteBucket")
    svc = _log_archive_service(bundle, kms, bucket_delete_error=err)

    reports = svc.teardown_log_archive(bundle, "us-east-1", account_id_map=_la_accounts(bundle))

    kms.schedule_key_deletion.assert_not_called()
    assert any(r.resource_type == "KMS Key" and r.action == "SKIPPED" for r in reports)


def test_log_key_dry_run_and_already_pending_are_noops(bundle):
    kms = MagicMock()
    svc = _log_archive_service(bundle, kms)
    dry = svc.teardown_log_archive(bundle, "us-east-1", dry_run=True, account_id_map=_la_accounts(bundle))
    assert any(r.resource_type == "KMS Key" and r.action == "SIMULATED" for r in dry)
    kms.schedule_key_deletion.assert_not_called()

    kms.describe_key.return_value = {"KeyMetadata": {"KeyState": "PendingDeletion"}}
    svc.teardown_log_archive(bundle, "us-east-1", account_id_map=_la_accounts(bundle))
    kms.schedule_key_deletion.assert_not_called()


def test_kms_schedule_key_deletion_request_is_valid_for_the_real_service_model():
    kms = _real("kms")
    svc = _security_service({})
    svc.session_mgr.get_member_client.side_effect = lambda *a, **k: kms  # type: ignore[attr-defined]
    with Stubber(kms) as stub:
        stub.add_response(
            "describe_key", {"KeyMetadata": {"KeyId": "k", "KeyState": "Enabled"}}, {"KeyId": "k"}
        )
        stub.add_response(
            "schedule_key_deletion",
            {"KeyId": "k", "KeyState": "PendingDeletion"},
            {"KeyId": "k", "PendingWindowInDays": 30},
        )
        out = svc._schedule_log_key_deletion(
            "1", "log-archive", "k", "us-east-1", dry_run=False, any_failed=False
        )
    assert [r.action for r in out] == ["DELETED"]
