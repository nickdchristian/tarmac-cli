"""`cloudtrail.retention_days` bounds how long CloudTrail logs are kept."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.config_schema import CloudTrailConfig
from tarmac.core.models import StackDeployReport

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ["src/tarmac/templates/cloudformation"]


class _Loader(yaml.SafeLoader):
    pass


def _value(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


_Loader.add_multi_constructor("!", lambda loader, suffix, node: {suffix: _value(loader, node)})


def test_retention_defaults_to_keeping_logs_forever():
    assert CloudTrailConfig().retention_days is None


@pytest.mark.parametrize("days", [1, 90, 365, 36500])
def test_retention_accepts_positive_days(days):
    assert CloudTrailConfig(retention_days=days).retention_days == days


@pytest.mark.parametrize("days", [0, -1, 36501])
def test_retention_rejects_values_that_would_mean_nothing_or_delete_immediately(days):
    with pytest.raises(ValidationError):
        CloudTrailConfig(retention_days=days)


@pytest.mark.parametrize("base", TEMPLATES)
def test_template_expires_logs_only_when_retention_is_set(base: str):
    doc = yaml.load((ROOT / base / "log-archive-hardening.yaml").read_text(), Loader=_Loader)

    param = doc["Parameters"]["LogRetentionDays"]
    assert param["Default"] == "0"
    assert doc["Conditions"]["HasLogRetention"] == {"Not": [{"Equals": [{"Ref": "LogRetentionDays"}, "0"]}]}

    rules = doc["Resources"]["OrganizationCloudTrailBucket"]["Properties"]["LifecycleConfiguration"]["Rules"]
    always = [r for r in rules if "Id" in r]
    conditional = [r["If"] for r in rules if "If" in r]

    assert [r["Id"] for r in always] == ["TransitionOldVersionsToGlacier"]
    assert [c[0] for c in conditional] == ["HasLogRetention", "HasLogRetention"]
    assert all(c[2] == {"Ref": "AWS::NoValue"} for c in conditional)

    expire, markers = (c[1] for c in conditional)
    assert expire["ExpirationInDays"] == {"Ref": "LogRetentionDays"}
    assert expire["NoncurrentVersionExpirationInDays"] == 7
    assert markers["ExpiredObjectDeleteMarker"] is True
    assert "ExpirationInDays" not in markers  # S3 rejects delete-marker cleanup combined with an expiry


@pytest.mark.parametrize(("retention", "expected"), [(None, "0"), (90, "90")])
def test_deploy_passes_retention_to_the_log_archive_stack(
    writable_config_dir, monkeypatch, retention, expected
):
    org_file = writable_config_dir / "organization.yaml"
    data = yaml.safe_load(org_file.read_text())
    cloudtrail = data.setdefault("cloudtrail", {})
    if retention is None:
        cloudtrail.pop("retention_days", None)
    else:
        cloudtrail["retention_days"] = retention
    org_file.write_text(yaml.safe_dump(data))

    session_mgr = MagicMock()
    session_mgr.get_caller_identity.return_value = {"Account": "111111111111"}
    org = MagicMock()
    org.describe_organization.return_value = {"Organization": {"Id": "o-test12345"}}
    org.get_paginator.return_value.paginate.return_value = [
        {"Accounts": [{"Id": "888888888888", "Name": "Log-Archive", "Status": "ACTIVE"}]}
    ]
    session_mgr.get_client.return_value = org
    session_mgr.get_member_client.return_value = MagicMock()

    captured: dict[str, dict[str, str]] = {}

    def deploy_stack(cfn_client, stack_name, template, params, *args, **kwargs):
        captured[stack_name] = params
        return StackDeployReport(stack_name=stack_name, action="CREATED", outputs={})

    service = MagicMock()
    service.deploy_stack.side_effect = deploy_stack
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy_phases.CloudFormationService", lambda sm: service)
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: MagicMock())
    monkeypatch.setattr("tarmac.cli.deploy_phases.OrganizationService", lambda sm: MagicMock())

    res = runner.invoke(app, ["deploy", "--config-dir", str(writable_config_dir), "--phase", "3", "--yes"])

    assert res.exit_code == 0, res.output
    archive = next(p for name, p in captured.items() if name.endswith("log-archive-hardening"))
    assert archive["LogRetentionDays"] == expected
