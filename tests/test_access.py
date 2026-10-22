"""Bootstrap access: root detection, preflight, deploy guard, `tarmac bootstrap` and the deployment policy."""

import ast
import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from tarmac.cli.deploy import _refuse_root_identity
from tarmac.cli.main import app
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.exceptions import AWSAuthenticationError
from tarmac.core.models import PreflightCheckStatus
from tarmac.services.identity import deployment_policy
from tarmac.services.preflight import PreflightService

runner = CliRunner()
ROOT = {"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:root"}
ROLE = {
    "Account": "111111111111",
    "Arn": "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_TarmacDeployment_abc/me",
}


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
    assert "tarmac bootstrap" in (root.action_required or "")
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
            multi = name == "check_alternate_contacts"
            setattr(svc, name, MagicMock(return_value=[] if multi else sentinel))
    report = svc.run_all_checks()
    assert report.failures >= 1
    assert any(c.name == "Caller Identity" for c in report.checks)


def test_deploy_refuses_root_but_allows_roles() -> None:
    import typer

    with pytest.raises(typer.Exit):
        _refuse_root_identity(_mgr(ROOT))
    _refuse_root_identity(_mgr(ROLE))


def test_info_strict_reports_root_and_role() -> None:
    """`tarmac info --strict` exits 1 unless the credentials are non-root and can read the organization."""

    def info_mgr(identity: dict[str, str]) -> AwsSessionManager:
        mgr = _mgr(identity)
        mgr.default_region = "us-east-1"
        return mgr

    with patch("tarmac.cli.main.AwsSessionManager", return_value=info_mgr(ROOT)):
        root = runner.invoke(app, ["info", "--strict"])
    assert root.exit_code == 1
    assert "Root credentials" in root.output

    ok = info_mgr(ROLE)
    with patch("tarmac.cli.main.AwsSessionManager", return_value=ok):
        assert runner.invoke(app, ["info", "--strict"]).exit_code == 0

    cast(MagicMock, ok.get_client).return_value.describe_organization.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DescribeOrganization"
    )
    with patch("tarmac.cli.main.AwsSessionManager", return_value=ok):
        assert runner.invoke(app, ["info", "--strict"]).exit_code == 1
        assert runner.invoke(app, ["info"]).exit_code == 0


def test_append_section_is_idempotent(tmp_path: Path) -> None:
    from tarmac.cli.bootstrap import _append_section

    cfg = tmp_path / ".aws" / "config"
    assert _append_section(
        cfg, "profile tarmac", {"role_arn": "arn:role", "source_profile": "tarmac-bootstrap"}
    )
    assert _append_section(cfg, "profile tarmac", {"role_arn": "arn:other"}) is False
    text = cfg.read_text(encoding="utf-8")
    assert "[profile tarmac]" in text
    assert "role_arn = arn:role" in text
    assert "source_profile = tarmac-bootstrap" in text
    assert "arn:other" not in text


def test_append_section_preserves_existing_config(tmp_path: Path) -> None:
    from tarmac.cli.bootstrap import _append_section

    cfg = tmp_path / "config"
    original = "# my settings\n[default]\nregion = eu-west-1   # home\n\n[sso-session corp]\nsso_start_url = https://x\n"
    cfg.write_text(original, encoding="utf-8")
    assert _append_section(cfg, "profile tarmac", {"role_arn": "arn:role"}) is True
    text = cfg.read_text(encoding="utf-8")
    assert text.startswith(original)  # comments, spacing and other sections untouched
    assert text.count("[profile tarmac]") == 1


def _bootstrap_mgr() -> MagicMock:
    mgr = _mgr(ROOT)
    cast(MagicMock, mgr.get_caller_identity).return_value = ROOT
    return cast(MagicMock, mgr)


def _identity(existing_sets: dict[str, str], assigned: bool = False) -> MagicMock:
    identity = MagicMock()
    identity.discover_instance.return_value = ("arn:inst", "d-123", "us-east-1")
    identity.return_value.get_or_create_user.return_value = "u-1"
    identity.return_value.list_permission_sets.return_value = existing_sets
    sso = identity.return_value.sso_client
    sso.create_permission_set.return_value = {"PermissionSet": {"PermissionSetArn": "arn:ps-new"}}
    sso.list_account_assignments.return_value = {
        "AccountAssignments": [{"PrincipalId": "u-1"}] if assigned else []
    }
    sso.describe_account_assignment_creation_status.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "SUCCEEDED"}
    }
    sso.describe_permission_set_provisioning_status.return_value = {
        "PermissionSetProvisioningStatus": {"Status": "SUCCEEDED"}
    }
    return identity


def _bootstrap(identity: MagicMock, config_dir: Path, home: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("HOME", str(home))
    with (
        patch("tarmac.cli.bootstrap.AwsSessionManager", return_value=_bootstrap_mgr()),
        patch("tarmac.cli.bootstrap.IdentityService", identity),
    ):
        return runner.invoke(app, ["bootstrap", "-c", str(config_dir)])


def test_bootstrap_creates_the_login_and_writes_the_profile(
    writable_config_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity({})
    result = _bootstrap(identity, writable_config_dir, tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    sso = identity.return_value.sso_client
    assert [c.kwargs["Name"] for c in sso.create_permission_set.call_args_list] == [
        "TarmacDeployment",
        "ManagementAdministrator",
    ]
    sso.attach_managed_policy_to_permission_set.assert_called_once_with(
        InstanceArn="arn:inst",
        PermissionSetArn="arn:ps-new",
        ManagedPolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )
    policy = sso.put_inline_policy_to_permission_set.call_args.kwargs
    assert (policy["PermissionSetArn"], json.loads(policy["InlinePolicy"])) == (
        "arn:ps-new",
        json.loads(deployment_policy()),
    )
    assert sso.create_account_assignment.call_count == 2
    assert sso.create_account_assignment.call_args.kwargs == {
        "InstanceArn": "arn:inst",
        "TargetId": "111111111111",
        "TargetType": "AWS_ACCOUNT",
        "PermissionSetArn": "arn:ps-new",
        "PrincipalType": "USER",
        "PrincipalId": "u-1",
    }
    text = (tmp_path / ".aws" / "config").read_text(encoding="utf-8")
    assert (
        "[sso-session tarmac]\nsso_start_url = https://d-123.awsapps.com/start\nsso_region = us-east-1\n"
        in text
    )
    assert "[profile tarmac]\nsso_session = tarmac\nsso_account_id = 111111111111\n" in text
    assert "sso_role_name = TarmacDeployment\nregion = us-east-2\n" in text


def test_bootstrap_rerun_refreshes_the_policy(
    writable_config_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity(
        {"TarmacDeployment": "arn:ps-old", "ManagementAdministrator": "arn:admin"}, assigned=True
    )
    result = _bootstrap(identity, writable_config_dir, tmp_path, monkeypatch)
    assert result.exit_code == 0, result.output
    sso = identity.return_value.sso_client
    sso.create_permission_set.assert_not_called()
    sso.create_account_assignment.assert_not_called()
    sso.put_inline_policy_to_permission_set.assert_called_once()
    sso.provision_permission_set.assert_called_once_with(
        InstanceArn="arn:inst", PermissionSetArn="arn:ps-old", TargetType="ALL_PROVISIONED_ACCOUNTS"
    )


def test_bootstrap_fails_with_aws_reason_when_an_assignment_fails(
    writable_config_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity({})
    identity.return_value.sso_client.describe_account_assignment_creation_status.return_value = {
        "AccountAssignmentCreationStatus": {"Status": "FAILED", "FailureReason": "Policy is invalid"}
    }
    result = _bootstrap(identity, writable_config_dir, tmp_path, monkeypatch)
    assert result.exit_code == 1
    assert "Assigning TarmacDeployment failed: Policy is invalid" in result.output
    assert not (tmp_path / ".aws").exists()


def test_bootstrap_without_identity_center_says_what_to_enable(
    writable_config_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tarmac.core.exceptions import IdentityCenterError

    identity = _identity({})
    identity.discover_instance.side_effect = IdentityCenterError("No IAM Identity Center instance found.")
    result = _bootstrap(identity, writable_config_dir, tmp_path, monkeypatch)
    assert result.exit_code == 1
    assert not (tmp_path / ".aws").exists()


# least-privilege policy


# IAM prefix -> botocore service name (where they differ), plus actions whose IAM name is not an API operation.
_PREFIX_TO_SERVICE = {"sso": "sso-admin", "servicequotas": "service-quotas"}
_PREFIX_TO_SERVICE_INVERSE = {v: k for k, v in _PREFIX_TO_SERVICE.items()}
_NON_OPERATION_ACTIONS = {"s3:ListBucket", "sso-directory:DescribeDirectory", "sso-directory:SearchUsers"}
_NON_OPERATION_ACTIONS |= {"sso-directory:SearchGroups"}


def _policy_statements() -> list[dict[str, object]]:
    return json.loads(deployment_policy())["Statement"]


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
        if not _is_allowed(action):
            missing.append(f"{action} ({', '.join(sorted(files))})")
    assert not missing, f"The role's policy does not allow API calls tarmac makes: {sorted(missing)}"


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
