"""Optional S3 Object Lock on the CloudTrail log bucket."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from tarmac.cli.common import log_archive_parameters
from tarmac.core.config_schema import CloudTrailConfig

ROOT = Path(__file__).resolve().parent.parent


class CfnLoader(yaml.SafeLoader):
    """Reads CloudFormation templates, treating ``!Ref``-style tags as plain values."""


CfnLoader.add_multi_constructor(
    "!",
    lambda loader, _suffix, node: (
        loader.construct_scalar(node)
        if isinstance(node, yaml.ScalarNode)
        else loader.construct_sequence(node, deep=True)
        if isinstance(node, yaml.SequenceNode)
        else loader.construct_mapping(node, deep=True)
    ),
)


def _bundle(**cloudtrail) -> SimpleNamespace:
    return SimpleNamespace(
        org=SimpleNamespace(
            organization=SimpleNamespace(name="acme"), cloudtrail=CloudTrailConfig(**cloudtrail)
        )
    )


def test_object_lock_is_governance_for_a_year_by_default():
    lock = CloudTrailConfig().object_lock
    assert lock is not None
    assert (lock.mode, lock.retention_days) == ("GOVERNANCE", 365)
    params = log_archive_parameters(_bundle(), "o-abc1234567")  # type: ignore[arg-type]
    assert params["ObjectLockMode"] == "GOVERNANCE"
    assert params["ObjectLockRetentionDays"] == "365"


def test_object_lock_can_be_turned_off_and_then_adds_no_parameters():
    assert CloudTrailConfig(object_lock=None).object_lock is None
    params = log_archive_parameters(_bundle(object_lock=None), "o-abc1234567")  # type: ignore[arg-type]
    assert "ObjectLockMode" not in params
    assert "ObjectLockRetentionDays" not in params


def test_object_lock_parameters_are_passed_when_configured():
    bundle = _bundle(object_lock={"mode": "COMPLIANCE", "retention_days": 30})
    params = log_archive_parameters(bundle, "o-abc1234567")  # type: ignore[arg-type]
    assert params["ObjectLockMode"] == "COMPLIANCE"
    assert params["ObjectLockRetentionDays"] == "30"


def test_default_lock_shrinks_to_a_shorter_log_retention():
    """Lifecycle cannot delete a locked version, so the default must not outlast retention_days."""
    assert CloudTrailConfig(retention_days=90).object_lock.retention_days == 90  # type: ignore[union-attr]
    assert CloudTrailConfig(retention_days=730).object_lock.retention_days == 365  # type: ignore[union-attr]


def test_explicit_lock_longer_than_log_retention_is_rejected():
    with pytest.raises(ValidationError, match="longer than"):
        CloudTrailConfig(retention_days=90, object_lock={"mode": "GOVERNANCE", "retention_days": 365})


@pytest.mark.parametrize(
    "lock",
    [
        {"mode": "WORM", "retention_days": 30},
        {"mode": "COMPLIANCE", "retention_days": 0},
        {"mode": "COMPLIANCE"},
    ],
)
def test_invalid_object_lock_is_rejected(lock):
    with pytest.raises(ValidationError):
        CloudTrailConfig(object_lock=lock)


def test_template_locks_the_bucket_only_when_asked():
    template = yaml.load(
        (ROOT / "cloudformation" / "log-archive-hardening.yaml").read_text(encoding="utf-8"), Loader=CfnLoader
    )
    assert template["Parameters"]["ObjectLockMode"]["Default"] == ""
    assert template["Parameters"]["ObjectLockMode"]["AllowedValues"] == ["", "GOVERNANCE", "COMPLIANCE"]
    assert "HasObjectLock" in template["Conditions"]
    props = template["Resources"]["OrganizationCloudTrailBucket"]["Properties"]
    assert props["ObjectLockEnabled"][0] == "HasObjectLock"
    assert props["ObjectLockConfiguration"][0] == "HasObjectLock"
    # The access-logs bucket is not locked: it only receives S3 server access logs.
    assert "ObjectLockEnabled" not in template["Resources"]["AccessLogsBucket"]["Properties"]
