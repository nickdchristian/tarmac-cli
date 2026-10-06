"""Unit tests for domain models, DTOs, and reporting data structures."""

import dataclasses

import pytest

from tarmac.core.config_schema import AccountBaselineConfig
from tarmac.core.models import (
    BASELINE_COMPLETED,
    STATUS_IN_PROGRESS,
    STATUS_READY,
    STATUS_SUSPENDED,
    TAG_BASELINE,
    TAG_COMPLETED_PHASES,
    TAG_MANAGED_BY,
    TAG_STATUS,
    TAG_VERSION,
    AccountPlanItem,
    AccountProvisionResult,
    OUSyncReport,
    PreflightCheckResult,
    PreflightCheckStatus,
    PreflightReport,
    SCPReconciliationResult,
    StackDeployReport,
    VpcCleanupReport,
)


def test_tag_constants():
    """Verify system governance tag keys and values."""
    assert TAG_MANAGED_BY == "tarmac:managed-by"
    assert TAG_STATUS == "tarmac:status"
    assert TAG_VERSION == "tarmac:version"
    assert TAG_COMPLETED_PHASES == "tarmac:completed-phases"
    assert TAG_BASELINE == "tarmac:baseline"

    assert STATUS_READY == "ready"
    assert STATUS_IN_PROGRESS == "in-progress"
    assert STATUS_SUSPENDED == "suspended"
    assert BASELINE_COMPLETED == "completed"


def test_frozen_dataclass_immutability():
    """Verify that execution result DTOs are frozen and prevent accidental mutation."""
    item = AccountPlanItem(
        name="Security",
        email="sec@example.com",
        ou="SecurityOU",
        action="CREATE",
        account_id=None,
        reason="New account",
        baseline=AccountBaselineConfig(),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        item.name = "MutatedName"  # pyright: ignore[reportAttributeAccessIssue]

    prov_res = AccountProvisionResult(
        name="Security",
        email="sec@example.com",
        account_id="111111111111",
        ou_name="SecurityOU",
        ou_id="ou-1234",
        action_taken="CREATED",
        status="SUCCEEDED",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        prov_res.account_id = "222222222222"  # pyright: ignore[reportAttributeAccessIssue]

    vpc_rep = VpcCleanupReport(region="us-east-1", deleted_vpc=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        vpc_rep.region = "eu-west-1"  # pyright: ignore[reportAttributeAccessIssue]


def test_preflight_report_immutability_and_structure():
    """Verify PreflightReport fields and immutability."""
    check = PreflightCheckResult(
        name="MFA Check",
        target="Management",
        status=PreflightCheckStatus.PASS,
        live_value="MFA enabled",
    )
    report = PreflightReport(
        checks=[check],
        passed=1,
        warnings=0,
        failures=0,
        info=0,
        can_proceed=True,
    )
    assert report.passed == 1
    assert report.can_proceed is True
    assert len(report.checks) == 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.passed = 2  # pyright: ignore[reportAttributeAccessIssue]


def test_ou_sync_report():
    """Verify OUSyncReport tracking of created vs existing OUs."""
    rep = OUSyncReport(
        synced_ous={"Security": "ou-1", "Infrastructure": "ou-2"},
        created_ous=["Infrastructure"],
        existing_ous=["Security"],
    )
    assert len(rep.synced_ous) == 2
    assert "Infrastructure" in rep.created_ous
    assert "Security" in rep.existing_ous


def test_scp_reconciliation_result():
    """Verify SCPReconciliationResult fields and defaults."""
    res = SCPReconciliationResult(
        name="FoundationalGuardrails",
        policy_id="p-12345",
        action_taken="ATTACHED",
        attached_targets=["r-root"],
        newly_attached_targets=["r-root"],
    )
    assert res.name == "FoundationalGuardrails"
    assert res.action_taken == "ATTACHED"
    assert res.status == "SUCCEEDED"
    assert res.attached_targets == ["r-root"]


def test_stack_deploy_report():
    """Verify StackDeployReport outputs and actions."""
    rep = StackDeployReport(
        stack_name="myorg-cloudtrail",
        action="UPDATED",
        outputs={"BucketArn": "arn:aws:s3:::myorg-logs"},
        status="SUCCEEDED",
    )
    assert rep.stack_name == "myorg-cloudtrail"
    assert rep.action == "UPDATED"
    assert rep.outputs["BucketArn"] == "arn:aws:s3:::myorg-logs"
    assert rep.status == "SUCCEEDED"
