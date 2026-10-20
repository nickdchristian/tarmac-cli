"""Bootstrap access: root detection, preflight, deploy guard, and the `tarmac access` commands."""

from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from tarmac.cli.deploy import _refuse_root_identity
from tarmac.cli.main import app
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.models import PreflightCheckStatus
from tarmac.services.preflight import PreflightService

runner = CliRunner()
ROOT = {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:root"}
ROLE = {"Account": "111111111111", "Arn": "arn:aws:sts::111111111111:assumed-role/TarmacDeploymentRole/s"}


def _mgr(identity: dict[str, str]) -> AwsSessionManager:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.get_caller_identity.return_value = identity
    mgr.is_root_identity.side_effect = lambda: AwsSessionManager.is_root_identity(mgr)
    return mgr


def test_is_root_identity_detects_root_only() -> None:
    assert _mgr(ROOT).is_root_identity() is True
    assert _mgr(ROLE).is_root_identity() is False
    user = {"Account": "1", "Arn": "arn:aws:iam::1:user/root"}
    assert _mgr(user).is_root_identity() is False


def test_preflight_fails_for_root_and_passes_for_role() -> None:
    root = PreflightService(_mgr(ROOT), MagicMock()).check_not_root_identity()
    assert root.status == PreflightCheckStatus.FAIL
    assert "tarmac access template" in (root.action_required or "")
    role = PreflightService(_mgr(ROLE), MagicMock()).check_not_root_identity()
    assert role.status == PreflightCheckStatus.PASS


def test_preflight_unknown_identity_is_info() -> None:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.is_root_identity.side_effect = RuntimeError("boom")
    assert PreflightService(mgr, MagicMock()).check_not_root_identity().status == PreflightCheckStatus.INFO


def test_run_all_checks_includes_root_check() -> None:
    svc = PreflightService(_mgr(ROOT), MagicMock())
    svc.bundle.org.organization.primary_region = "us-east-1"
    sentinel = PreflightService(_mgr(ROOT), MagicMock()).check_not_root_identity()
    for name in dir(svc):
        if name.startswith("check_") and name != "check_not_root_identity":
            multi = name in {"check_alternate_contacts", "check_s3_bucket_collision"}
            setattr(svc, name, MagicMock(return_value=[] if multi else sentinel))
    report = svc.run_all_checks()
    assert report.failures >= 1
    assert any(c.name == "Caller Identity" for c in report.checks)


def test_deploy_refuses_root_but_allows_roles() -> None:
    import typer

    with pytest.raises(typer.Exit):
        _refuse_root_identity(_mgr(ROOT))
    _refuse_root_identity(_mgr(ROLE))
    unauth = MagicMock(spec=AwsSessionManager)
    unauth.is_root_identity.side_effect = RuntimeError("no creds")
    _refuse_root_identity(unauth)  # must not raise: phases report auth problems themselves


def test_access_template_prints_and_writes(tmp_path: Path) -> None:
    result = runner.invoke(app, ["access", "template"])
    assert result.exit_code == 0
    assert "TarmacDeploymentRole" in result.output
    out = tmp_path / "sub" / "access.yaml"
    result = runner.invoke(app, ["access", "template", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "TarmacRole" in out.read_text(encoding="utf-8")


def test_access_check_reports_root_and_role() -> None:
    with patch("tarmac.cli.access.AwsSessionManager", return_value=_mgr(ROOT)):
        assert runner.invoke(app, ["access", "check"]).exit_code == 1
    ok = _mgr(ROLE)
    with patch("tarmac.cli.access.AwsSessionManager", return_value=ok):
        assert runner.invoke(app, ["access", "check"]).exit_code == 0
    cast(MagicMock, ok.get_client).return_value.describe_organization.side_effect = RuntimeError("denied")
    with patch("tarmac.cli.access.AwsSessionManager", return_value=ok):
        assert runner.invoke(app, ["access", "check"]).exit_code == 1


def test_access_template_is_least_surprising() -> None:
    """MFA required by default, long sessions, and the bootstrap user may only assume the role."""

    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    path = Path(__file__).resolve().parent.parent / "cloudformation" / "tarmac-access.yaml"
    t = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)
    assert t["Parameters"]["RequireMfa"]["Default"] == "true"
    assert t["Parameters"]["MaxSessionDurationSeconds"]["Default"] >= 14400
    user_policies = {p["PolicyName"] for p in t["Resources"]["BootstrapUser"]["Properties"]["Policies"]}
    assert user_policies == {"AssumeTarmacRole", "ManageOwnMfaAndAccessKey"}


def test_template_defaults_and_mfa_condition() -> None:
    text = (Path(__file__).resolve().parent.parent / "cloudformation" / "tarmac-access.yaml").read_text(
        encoding="utf-8"
    )
    assert "BoolIfExists" in text  # SSO sessions carry no MFA flag
    assert "CreateBootstrapUser:\n    Type: String\n    Default: 'false'" in text


def test_write_role_profile_is_idempotent(tmp_path: Path) -> None:
    from tarmac.cli.access import _write_role_profile

    cfg = tmp_path / ".aws" / "config"
    assert _write_role_profile(cfg, "tarmac", "arn:role", "tarmac-bootstrap", "arn:mfa", "us-east-1") is True
    assert _write_role_profile(cfg, "tarmac", "arn:other", "x", "y", "z") is False
    text = cfg.read_text(encoding="utf-8")
    assert "[profile tarmac]" in text
    assert "role_arn = arn:role" in text
    assert "source_profile = tarmac-bootstrap" in text
    assert "arn:other" not in text


def _bootstrap_mgr() -> MagicMock:
    mgr = _mgr(ROOT)
    cast(MagicMock, mgr.get_caller_identity).return_value = ROOT
    return cast(MagicMock, mgr)


def test_bootstrap_deploys_and_writes_profile_for_user(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    report = MagicMock(
        action="CREATED", outputs={"TarmacRoleArn": "arn:aws:iam::111111111111:role/TarmacDeploymentRole"}
    )
    with (
        patch("tarmac.cli.access.AwsSessionManager", return_value=_bootstrap_mgr()),
        patch("tarmac.cli.access.CloudFormationService") as svc,
    ):
        svc.return_value.deploy_stack.return_value = report
        result = runner.invoke(
            app, ["access", "bootstrap", "--with-bootstrap-user", "--aws-config", str(cfg)]
        )
    assert result.exit_code == 0
    params = svc.return_value.deploy_stack.call_args.args[3]
    assert params["CreateBootstrapUser"] == "true"
    assert "role_arn = arn:aws:iam::111111111111:role/TarmacDeploymentRole" in cfg.read_text(encoding="utf-8")


def test_bootstrap_without_user_writes_nothing(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    report = MagicMock(action="CREATED", outputs={})
    with (
        patch("tarmac.cli.access.AwsSessionManager", return_value=_bootstrap_mgr()),
        patch("tarmac.cli.access.CloudFormationService") as svc,
    ):
        svc.return_value.deploy_stack.return_value = report
        result = runner.invoke(app, ["access", "bootstrap", "--aws-config", str(cfg)])
    assert result.exit_code == 0
    assert svc.return_value.deploy_stack.call_args.args[3]["CreateBootstrapUser"] == "false"
    assert not cfg.exists()
    assert "Identity Center" in result.output


def test_bootstrap_dry_run_and_failure() -> None:
    from tarmac.core.exceptions import DeploymentError

    with (
        patch("tarmac.cli.access.AwsSessionManager", return_value=_bootstrap_mgr()),
        patch("tarmac.cli.access.CloudFormationService") as svc,
    ):
        svc.return_value.deploy_stack.return_value = MagicMock(action="SIMULATED", outputs={})
        assert runner.invoke(app, ["access", "bootstrap", "--dry-run"]).exit_code == 0
        svc.return_value.deploy_stack.side_effect = DeploymentError("boom")
        assert runner.invoke(app, ["access", "bootstrap"]).exit_code == 1


# --- least-privilege policy ------------------------------------------------------------------------------------


class _CfnLoader(yaml.SafeLoader):
    pass


def _construct(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]


_CfnLoader.add_multi_constructor("!", _construct)

# IAM prefix -> botocore service name (where they differ), plus actions whose IAM name is not an API operation.
_PREFIX_TO_SERVICE = {"sso": "sso-admin", "servicequotas": "service-quotas"}
_NON_OPERATION_ACTIONS = {"s3:ListBucket", "sso-directory:DescribeDirectory", "sso-directory:SearchUsers"}
_NON_OPERATION_ACTIONS |= {"sso-directory:SearchGroups"}


def _policy_statements() -> list[dict[str, object]]:
    path = Path(__file__).resolve().parent.parent / "cloudformation" / "tarmac-access.yaml"
    template = yaml.load(path.read_text(encoding="utf-8"), Loader=_CfnLoader)
    return template["Resources"]["TarmacPolicy"]["Properties"]["PolicyDocument"]["Statement"]


def _allowed_actions() -> list[str]:
    actions: list[str] = []
    for stmt in _policy_statements():
        if stmt["Effect"] != "Allow":
            continue
        raw = stmt["Action"]
        actions.extend([raw] if isinstance(raw, str) else list(raw))  # type: ignore[arg-type]
    return actions


def _is_allowed(action: str) -> bool:
    from fnmatch import fnmatchcase

    return any(fnmatchcase(action.lower(), pattern.lower()) for pattern in _allowed_actions())


def test_policy_has_no_admin_grants() -> None:
    actions = _allowed_actions()
    assert "*" not in actions
    assert not any(
        a.endswith(":*") and a.split(":")[0] in {"iam", "sts", "kms", "s3", "ec2"} for a in actions
    )
    assert "iam:PassRole" not in actions
    assert "iam:CreateRole" not in actions
    assert "iam:AttachRolePolicy" not in actions
    assume = [s for s in _policy_statements() if s["Effect"] == "Allow" and s["Action"] == "sts:AssumeRole"]
    assert len(assume) == 1
    assert str(assume[0]["Resource"]).endswith(":role/OrganizationAccountAccessRole")


def test_policy_denies_self_modification() -> None:
    deny = [s for s in _policy_statements() if s["Effect"] == "Deny"]
    assert len(deny) == 1
    assert deny[0]["Action"] == ["iam:*"]


def test_policy_actions_exist_in_aws_service_models() -> None:
    from botocore import xform_name  # noqa: F401  (ensures botocore is available)
    from botocore.session import get_session

    session = get_session()
    for action in _allowed_actions():
        prefix, name = action.split(":")
        if "*" in name or action in _NON_OPERATION_ACTIONS:
            continue
        model = session.get_service_model(_PREFIX_TO_SERVICE.get(prefix, prefix))
        assert name in cast(list[str], model.operation_names), f"{action} is not a real API operation"


def test_policy_covers_every_management_account_api_call() -> None:
    """Every organizations/cloudformation/cloudtrail/sso/identitystore/guardduty/securityhub call in the source is allowed."""
    import re

    from botocore import xform_name
    from botocore.session import get_session

    src_dir = Path(__file__).resolve().parent.parent / "src" / "tarmac"
    source = "\n".join(p.read_text(encoding="utf-8") for p in src_dir.rglob("*.py"))
    used = set(re.findall(r"\.([a-z_]+)\(", source)) | set(
        re.findall(r'get_paginator\(\s*"([a-z_]+)"', source)
    )
    session = get_session()
    missing: list[str] = []
    for service, prefix in {
        "organizations": "organizations",
        "cloudformation": "cloudformation",
        "cloudtrail": "cloudtrail",
        "sso-admin": "sso",
        "identitystore": "identitystore",
        "guardduty": "guardduty",
        "securityhub": "securityhub",
    }.items():
        for op in cast(list[str], session.get_service_model(service).operation_names):
            if xform_name(op) in used and not _is_allowed(f"{prefix}:{op}"):
                missing.append(f"{prefix}:{op}")
    assert not missing, f"Policy does not allow API calls tarmac makes: {sorted(missing)}"
