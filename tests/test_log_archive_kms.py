"""`cloudtrail.enable_kms` controls the log archive key as well as the trail."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from typer.testing import CliRunner

from tarmac.cli.deploy import app
from tarmac.core.models import StackDeployReport

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ["cloudformation", "src/tarmac/templates/cloudformation"]


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_multi_constructor("!", lambda loader, suffix, node: {suffix: _node_value(loader, node)})


def _node_value(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


def _load(base: str) -> dict:
    return yaml.load((ROOT / base / "log-archive-hardening.yaml").read_text(), Loader=_Loader)


@pytest.mark.parametrize("base", TEMPLATES)
def test_template_can_skip_the_kms_key_and_use_sse_s3(base: str):
    doc = _load(base)
    res = doc["Resources"]

    param = doc["Parameters"]["EnableKmsEncryption"]
    assert param["Default"] == "true"
    assert param["AllowedValues"] == ["true", "false"]
    assert "UseKmsEncryption" in doc["Conditions"]

    assert res["LogArchiveKmsKey"]["Condition"] == "UseKmsEncryption"
    assert res["LogArchiveKmsAlias"]["Condition"] == "UseKmsEncryption"

    enc = res["OrganizationCloudTrailBucket"]["Properties"]["BucketEncryption"][
        "ServerSideEncryptionConfiguration"
    ][0]["ServerSideEncryptionByDefault"]
    assert enc["SSEAlgorithm"]["If"] == ["UseKmsEncryption", "aws:kms", "AES256"]
    assert enc["KMSMasterKeyID"]["If"][0] == "UseKmsEncryption"
    assert enc["KMSMasterKeyID"]["If"][2] == {"Ref": "AWS::NoValue"}

    for name in ("KmsKeyArn", "KmsKeyId"):
        assert doc["Outputs"][name]["Condition"] == "UseKmsEncryption"


def test_bundled_and_repository_templates_match():
    assert (ROOT / TEMPLATES[0] / "log-archive-hardening.yaml").read_text() == (
        ROOT / TEMPLATES[1] / "log-archive-hardening.yaml"
    ).read_text()


@pytest.mark.parametrize(("enable_kms", "expected"), [(True, "true"), (False, "false")])
def test_deploy_passes_the_setting_to_the_log_archive_stack(
    writable_config_dir, monkeypatch, enable_kms, expected
):
    org_file = writable_config_dir / "organization.yaml"
    data = yaml.safe_load(org_file.read_text())
    data.setdefault("cloudtrail", {})["enable_kms"] = enable_kms
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

    params_by_stack: dict[str, dict[str, str]] = {}

    def deploy_stack(cfn_client, stack_name, template, params, *args, **kwargs):
        params_by_stack[stack_name] = params
        return StackDeployReport(stack_name=stack_name, action="CREATED", outputs={})

    service = MagicMock()
    service.deploy_stack.side_effect = deploy_stack
    monkeypatch.setattr("tarmac.cli.deploy.AwsSessionManager", lambda **kw: session_mgr)
    monkeypatch.setattr("tarmac.cli.deploy.CloudFormationService", lambda sm: service)
    monkeypatch.setattr("tarmac.cli.deploy.OrganizationService", lambda sm: MagicMock())

    res = runner.invoke(app, ["run", "--config-dir", str(writable_config_dir), "--phase", "3", "--yes"])

    assert res.exit_code == 0, res.output
    archive = next(p for name, p in params_by_stack.items() if name.endswith("log-archive-hardening"))
    trail = next(p for name, p in params_by_stack.items() if name.endswith("organization-cloudtrail"))
    assert archive["EnableKmsEncryption"] == expected
    assert trail["EnableKmsEncryption"] == expected


@pytest.mark.parametrize(("enable_kms", "expected"), [(True, "true"), (False, "false")])
def test_baseline_command_passes_the_setting_to_the_log_archive_stack(enable_kms, expected):
    from types import SimpleNamespace

    from tarmac.cli.baseline import _deploy_log_archive_stack

    bundle = SimpleNamespace(
        org=SimpleNamespace(
            organization=SimpleNamespace(name="acme"),
            cloudtrail=SimpleNamespace(
                enable_kms=enable_kms, retention_days=None, object_lock=None, model_fields_set={"object_lock"}
            ),
        ),
        config_dir=ROOT / "examples" / "config",
        get_log_archive_account_name=lambda: "log-archive",
        get_organization_tags=lambda: {},
        get_account_tags=lambda name: {},
    )
    service = MagicMock()
    service.deploy_stack.return_value = StackDeployReport(stack_name="s", action="CREATED", outputs={})

    _deploy_log_archive_stack(service, MagicMock(), bundle, "eu-west-1", "888888888888", "o-test12345", True)

    params = service.deploy_stack.call_args.args[3]
    assert params["EnableKmsEncryption"] == expected
