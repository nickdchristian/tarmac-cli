"""Bootstrap access: root detection, preflight, deploy guard, and the `tarmac access` commands."""

import ast
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
import yaml
from botocore.exceptions import ClientError
from helpers import CfnLoader
from typer.testing import CliRunner

from tarmac.cli.deploy import _refuse_root_identity
from tarmac.cli.main import app
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.exceptions import AWSAuthenticationError
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
    mgr.is_root_identity.side_effect = AWSAuthenticationError("boom")
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
    cast(MagicMock, ok.get_client).return_value.describe_organization.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DescribeOrganization"
    )
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


def test_write_role_profile_preserves_existing_config(tmp_path: Path) -> None:
    from tarmac.cli.access import _write_role_profile

    cfg = tmp_path / "config"
    original = "# my settings\n[default]\nregion = eu-west-1   # home\n\n[sso-session corp]\nsso_start_url = https://x\n"
    cfg.write_text(original, encoding="utf-8")
    assert _write_role_profile(cfg, "tarmac", "arn:role", "src", "arn:mfa", "us-east-1") is True
    text = cfg.read_text(encoding="utf-8")
    assert text.startswith(original)  # comments, spacing and other sections untouched
    assert text.count("[profile tarmac]") == 1


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


# least-privilege policy


# IAM prefix -> botocore service name (where they differ), plus actions whose IAM name is not an API operation.
_PREFIX_TO_SERVICE = {"sso": "sso-admin", "servicequotas": "service-quotas"}
_PREFIX_TO_SERVICE_INVERSE = {v: k for k, v in _PREFIX_TO_SERVICE.items()}
_NON_OPERATION_ACTIONS = {"s3:ListBucket", "sso-directory:DescribeDirectory", "sso-directory:SearchUsers"}
_NON_OPERATION_ACTIONS |= {"sso-directory:SearchGroups"}


def _policy_statements() -> list[dict[str, object]]:
    path = Path(__file__).resolve().parent.parent / "cloudformation" / "tarmac-access.yaml"
    template = yaml.load(path.read_text(encoding="utf-8"), Loader=CfnLoader)
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


# IAM action names that differ from the API operation name.
_IAM_ACTION_FOR_OPERATION = {
    "s3:HeadBucket": "s3:ListBucket",
    "s3:ListObjectVersions": "s3:ListBucketVersions",
    "s3:DeleteObjects": "s3:DeleteObject",
}

# Services whose member-account client resolves to the management account's own session when the target is the
# management account (``get_member_client``), so the role needs the permission too. Default-VPC cleanup runs
# against the management account.
_MEMBER_CLIENT_SERVICES_ON_MANAGEMENT = {"ec2"}

# Calls tarmac makes that the role is deliberately NOT granted, with the reason.
_DELIBERATELY_NOT_GRANTED = {
    # Removing the bootstrap IAM user is an administrator action; teardown reports AccessDenied as SKIPPED.
    "iam:GetUser",
    "iam:ListUserTags",
    "iam:ListAccessKeys",
    "iam:DeleteAccessKey",
    "iam:ListMFADevices",
    "iam:DeactivateMFADevice",
    "iam:DeleteVirtualMFADevice",
    "iam:ListUserPolicies",
    "iam:DeleteUserPolicy",
    "iam:ListAttachedUserPolicies",
    "iam:DetachUserPolicy",
    "iam:DeleteUser",
}


def _client_of(call: ast.Call) -> tuple[str, str] | None:
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    if name == "get_client" and call.args and isinstance(call.args[0], ast.Constant):
        return "mgmt", str(call.args[0].value)
    if name == "get_member_client" and len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
        return "member", str(call.args[1].value)
    return None


def _name_of(node: ast.expr) -> str | None:
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def _client_variables(tree: ast.AST) -> dict[str, set[tuple[str, str]]]:
    """Map each variable or attribute assigned a session-manager client to the clients it may hold."""
    variables: dict[str, set[tuple[str, str]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign | ast.AnnAssign) and isinstance(node.value, ast.Call):
            client = _client_of(node.value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if client and (name := _name_of(target)):
                    variables.setdefault(name, set()).add(client)
    return variables


def _client_calls() -> dict[tuple[str, str, str], set[str]]:
    """Statically find ``(kind, service, operation)`` calls made on clients obtained from the session manager.

    ``kind`` is ``mgmt`` for ``get_client("svc")`` and ``member`` for ``get_member_client(acct, "svc")``. A call
    is attributed to a client by the variable or attribute it was assigned to, so operations that merely share a
    name with another service's (``get_user``, ``delete_bucket``) are not confused.
    """
    from botocore import xform_name
    from botocore.session import get_session

    session = get_session()
    models: dict[str, dict[str, str]] = {}
    calls: dict[tuple[str, str, str], set[str]] = {}
    src_dir = Path(__file__).resolve().parent.parent / "src" / "tarmac"
    for path in src_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        variables = _client_variables(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            receiver = node.func.value
            inline = _client_of(receiver) if isinstance(receiver, ast.Call) else None
            owners = {inline} if inline else variables.get(_name_of(receiver) or "", set())
            op = node.func.attr
            if op == "get_paginator" and node.args and isinstance(node.args[0], ast.Constant):
                op = str(node.args[0].value)
            for kind, service in owners:
                if service not in models:
                    names = cast(list[str], session.get_service_model(service).operation_names)
                    models[service] = {xform_name(o): o for o in names}
                if op in models[service]:
                    calls.setdefault((kind, service, models[service][op]), set()).add(path.name)
    return calls


def test_policy_covers_every_management_account_api_call() -> None:
    """Every API call made with a management-account client is allowed by the role's policy."""
    missing: list[str] = []
    for (kind, service, operation), files in _client_calls().items():
        if kind == "member" and service not in _MEMBER_CLIENT_SERVICES_ON_MANAGEMENT:
            continue
        action = f"{_PREFIX_TO_SERVICE_INVERSE.get(service, service)}:{operation}"
        action = _IAM_ACTION_FOR_OPERATION.get(action, action)
        if action not in _DELIBERATELY_NOT_GRANTED and not _is_allowed(action):
            missing.append(f"{action} ({', '.join(sorted(files))})")
    assert not missing, f"The role's policy does not allow API calls tarmac makes: {sorted(missing)}"


def test_deliberately_not_granted_calls_are_still_made() -> None:
    """Keep the exclusion list honest: drop an entry once the code stops making that call."""
    made = {f"iam:{op}" for kind, service, op in _client_calls() if service == "iam" and kind == "mgmt"}
    assert not (_DELIBERATELY_NOT_GRANTED - made), _DELIBERATELY_NOT_GRANTED - made
    assert not any(_is_allowed(a) for a in _DELIBERATELY_NOT_GRANTED), "granted after all: drop the exclusion"


def test_aws_error_helpers_tolerate_missing_fields() -> None:
    from tarmac.core.exceptions import aws_error_code, aws_error_message

    full = ClientError({"Error": {"Code": "Throttling", "Message": "slow down"}}, "Op")
    assert aws_error_code(full) == "Throttling"
    assert aws_error_message(full) == "slow down"
    bare = ClientError({}, "Op")  # type: ignore[arg-type]
    assert aws_error_code(bare) == ""
    assert "Op" in aws_error_message(bare)


def test_caller_identity_keeps_only_known_string_fields() -> None:
    with patch("boto3.Session") as session_cls:
        sts = session_cls.return_value.client.return_value
        sts.get_caller_identity.return_value = {
            "Account": "1",
            "Arn": "arn:aws:iam::1:root",
            "UserId": "U",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }
        identity = AwsSessionManager(region_name="us-east-1").get_caller_identity()
    assert identity == {"Account": "1", "Arn": "arn:aws:iam::1:root", "UserId": "U"}
