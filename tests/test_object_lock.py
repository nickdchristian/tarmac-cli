"""Optional S3 Object Lock on the CloudTrail log bucket."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from tarmac.core.config_schema import CloudTrailConfig, SecurityServicesConfig
from tarmac.services.stack_parameters import log_archive_parameters, object_lock_advice

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
            organization=SimpleNamespace(name="acme"),
            security_services=SecurityServicesConfig(),
            cloudtrail=CloudTrailConfig(**cloudtrail),
        )
    )


def test_object_lock_is_off_by_default_and_adds_no_parameters():
    """It cannot be undone, so tarmac never enables it unasked."""
    assert CloudTrailConfig().object_lock is None
    params = log_archive_parameters(_bundle(), "o-abc1234567")  # type: ignore[arg-type]
    assert "ObjectLockMode" not in params
    assert "ObjectLockRetentionDays" not in params


def test_object_lock_parameters_are_passed_when_configured():
    bundle = _bundle(object_lock={"mode": "COMPLIANCE", "retention_days": 30})
    params = log_archive_parameters(bundle, "o-abc1234567")  # type: ignore[arg-type]
    assert params["ObjectLockMode"] == "COMPLIANCE"
    assert params["ObjectLockRetentionDays"] == "30"


def test_explicit_lock_longer_than_log_retention_is_rejected():
    with pytest.raises(ValidationError, match="longer than"):
        CloudTrailConfig.model_validate(
            {"retention_days": 90, "object_lock": {"mode": "GOVERNANCE", "retention_days": 365}}
        )


def test_lock_equal_to_log_retention_is_accepted():
    config = CloudTrailConfig.model_validate(
        {"retention_days": 90, "object_lock": {"mode": "GOVERNANCE", "retention_days": 90}}
    )
    assert config.object_lock is not None


@pytest.mark.parametrize(
    ("config", "warns"),
    [
        ({}, True),
        ({"object_lock": None}, True),  # null is the same as leaving it out
        ({"object_lock": {"mode": "GOVERNANCE", "retention_days": 365}}, False),
    ],
)
def test_recommends_object_lock_while_it_is_off(config, warns):
    advice = object_lock_advice(_bundle(**config))  # type: ignore[arg-type]

    assert bool(advice) is warns
    if advice:
        assert "GOVERNANCE" in advice


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
        (ROOT / "src/tarmac/templates/cloudformation" / "log-archive-hardening.yaml").read_text(
            encoding="utf-8"
        ),
        Loader=CfnLoader,
    )
    assert template["Parameters"]["ObjectLockMode"]["Default"] == ""
    assert template["Parameters"]["ObjectLockMode"]["AllowedValues"] == ["", "GOVERNANCE", "COMPLIANCE"]
    assert "HasObjectLock" in template["Conditions"]
    props = template["Resources"]["OrganizationCloudTrailBucket"]["Properties"]
    assert props["ObjectLockEnabled"][0] == "HasObjectLock"
    assert props["ObjectLockConfiguration"][0] == "HasObjectLock"
    # The access-logs bucket is not locked: it only receives S3 server access logs.
    assert "ObjectLockEnabled" not in template["Resources"]["AccessLogsBucket"]["Properties"]
