"""AWS call recording: change vs read classification, redaction, dry-run guard and CloudTrail correlation."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.stub import Stubber

from tarmac.core.aws_audit import instrument_session, is_read_only, summarize_params
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.logging import bind, current_context, setup_logging, start_run

POLICY = {"Policy": {"PolicySummary": {"Id": "p-1", "Name": "Guard"}}}


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _client(service: str) -> Any:
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name="eu-west-1"
    )
    instrument_session(session)
    name: Any = service
    return session.client(name)


@pytest.fixture
def info_log(tmp_path: Path):
    path = tmp_path / "info.jsonl"
    setup_logging(log_file=path)
    yield path
    setup_logging()


@pytest.fixture
def debug_log(tmp_path: Path):
    path = tmp_path / "debug.jsonl"
    setup_logging(debug=True, log_file=path)
    yield path
    setup_logging()


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("DescribeOrganization", True),
        ("ListAccounts", True),
        ("GetCallerIdentity", True),
        ("AssumeRole", True),
        ("BatchGetResourceConfig", True),
        ("CreatePolicy", False),
        ("PutAlternateContact", False),
        ("EnableAWSServiceAccess", False),
        ("CloseAccount", False),
        ("DeleteStack", False),
    ],
)
def test_operation_classification(operation: str, expected: bool):
    assert is_read_only(operation) is expected


def test_change_call_is_recorded_with_redacted_summarized_params(info_log: Path):
    client = _client("organizations")
    content = '{"Version":"2012-10-17","Statement":[]}'
    with Stubber(client) as stub:
        stub.add_response("create_policy", POLICY)
        client.create_policy(
            Name="Guard",
            Description="d",
            Type="SERVICE_CONTROL_POLICY",
            Content=content,
            Tags=[{"Key": "tarmac:managed-by", "Value": "tarmac"}],
        )

    (record,) = _records(info_log)
    assert record["event"] == "aws_call"
    assert record["level"] == "INFO"
    assert record["message"] == "organizations.CreatePolicy succeeded in aws-global"
    data = record["data"]
    assert data["service"] == "organizations"
    assert data["operation"] == "CreatePolicy"
    assert data["read_only"] is False
    assert data["outcome"] == "succeeded"
    assert data["params"]["Name"] == "Guard"
    assert data["params"]["Content"] == f"<{len(content)} chars>"
    assert data["duration_ms"] is not None


def test_read_call_is_only_in_the_debug_log(info_log: Path, tmp_path: Path):
    client = _client("organizations")
    with Stubber(client) as stub:
        stub.add_response(
            "describe_organization",
            {"Organization": {"Id": "o-abc123def4", "FeatureSet": "ALL", "MasterAccountId": "111111111111"}},
        )
        client.describe_organization()
    assert not info_log.read_text()


def test_read_call_is_recorded_in_debug_mode(debug_log: Path):
    client = _client("organizations")
    with Stubber(client) as stub:
        stub.add_response(
            "describe_organization",
            {"Organization": {"Id": "o-abc123def4", "FeatureSet": "ALL", "MasterAccountId": "111111111111"}},
        )
        client.describe_organization()

    (record,) = [r for r in _records(debug_log) if r.get("event") == "aws_call"]
    assert record["level"] == "DEBUG"
    assert record["data"]["read_only"] is True


def test_failed_change_is_a_warning_with_the_error_code(info_log: Path):
    client = _client("organizations")
    with Stubber(client) as stub:
        stub.add_client_error(
            "attach_policy",
            service_error_code="DuplicatePolicyAttachmentException",
            service_message="already",
        )
        with pytest.raises(client.exceptions.DuplicatePolicyAttachmentException):
            client.attach_policy(PolicyId="p-1", TargetId="r-root")

    (record,) = _records(info_log)
    assert record["level"] == "WARNING"
    assert record["data"]["outcome"] == "failed"
    assert record["data"]["error_code"] == "DuplicatePolicyAttachmentException"
    assert "failed" in record["message"]


def test_secrets_in_parameters_are_redacted(info_log: Path):
    client = _client("iam")
    with Stubber(client) as stub:
        stub.add_response(
            "create_login_profile", {"LoginProfile": {"UserName": "u", "CreateDate": "2026-01-01"}}
        )
        client.create_login_profile(UserName="u", Password="Sup3rSecret!")

    (record,) = _records(info_log)
    assert record["data"]["params"]["Password"] == "[REDACTED]"
    assert "Sup3rSecret" not in json.dumps(record)


def test_dry_run_flags_state_changing_calls_but_not_reads_or_change_sets(info_log: Path):
    orgs = _client("organizations")
    cfn = _client("cloudformation")
    with Stubber(orgs) as org_stub, Stubber(cfn) as cfn_stub, bind(dry_run=True):
        org_stub.add_response("list_roots", {"Roots": []})
        org_stub.add_response("create_policy", POLICY)
        cfn_stub.add_response("create_change_set", {"Id": "cs", "StackId": "stack"})
        orgs.list_roots()
        orgs.create_policy(Name="Guard", Description="d", Type="SERVICE_CONTROL_POLICY", Content="{}")
        cfn.create_change_set(StackName="s", ChangeSetName="c", TemplateBody="x")

    records = _records(info_log)
    violations = [r for r in records if r["event"] == "dry_run_violation"]
    assert len(violations) == 1
    assert violations[0]["level"] == "ERROR"
    assert violations[0]["data"]["operation"] == "CreatePolicy"
    assert [r["data"]["operation"] for r in records if r["event"] == "aws_call"] == ["CreateChangeSet"]


def test_summarize_params_caps_size_and_redacts_nested_secrets():
    summary = summarize_params(
        {
            "Items": list(range(25)),
            "Long": "x" * 500,
            "Nested": {"SecretAccessKey": "abc", "Name": "ok"},
            "TemplateBody": "y" * 4000,
            "Raw": b"1234",
        }
    )
    assert summary["Items"][-1] == "... 15 more"
    assert summary["Long"].endswith("(500 chars)")
    assert summary["Nested"] == {"SecretAccessKey": "[REDACTED]", "Name": "ok"}
    assert summary["TemplateBody"] == "<4000 chars>"
    assert summary["Raw"] == "<4 bytes>"


def test_hook_failures_never_break_the_aws_call(info_log: Path):
    client = _client("organizations")
    with Stubber(client) as stub, patch("tarmac.core.aws_audit._log_call", side_effect=RuntimeError("boom")):
        stub.add_response("create_policy", POLICY)
        assert client.create_policy(
            Name="Guard", Description="d", Type="SERVICE_CONTROL_POLICY", Content="{}"
        )


def test_plan_and_dry_run_arguments_enable_the_guard():
    for argv in (["run", "--dry-run"], ["org", "scp", "plan"]):
        run = start_run("x", "0", argv)
        assert current_context().get("dry_run") is True
        run.finish(None)
    run = start_run("x", "0", ["run", "--yes"])
    assert "dry_run" not in current_context()
    run.finish(None)


def test_run_id_is_in_the_user_agent_appid_and_role_session_name():
    with bind(run_id="20261020T000000Z-abc123"):
        mgr = AwsSessionManager(region_name="eu-west-1")
    appid: Any = mgr.boto_config
    assert appid.user_agent_appid == "tarmac-20261020T000000Z-abc123"

    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "a",
            "SecretAccessKey": "b",
            "SessionToken": "c",
            "Expiration": datetime(2099, 1, 1, tzinfo=UTC),
        }
    }
    mgr._sts_client = sts
    mgr.get_assumed_session("222222222222")
    assert sts.assume_role.call_args.kwargs["RoleSessionName"] == "tarmac-20261020T000000Z-abc123"


def _manager() -> AwsSessionManager:
    with patch.dict("os.environ", {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing"}):
        return AwsSessionManager(region_name="eu-west-1")


def test_clients_from_the_session_manager_report_their_calls(info_log: Path):
    client = _manager().get_client("organizations")
    with Stubber(client) as stub:
        stub.add_response("create_policy", POLICY)
        client.create_policy(Name="Guard", Description="d", Type="SERVICE_CONTROL_POLICY", Content="{}")

    assert [r["data"]["operation"] for r in _records(info_log)] == ["CreatePolicy"]


def test_clients_from_assumed_role_sessions_report_their_calls(info_log: Path):
    mgr = _manager()
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "a",
            "SecretAccessKey": "b",
            "SessionToken": "c",
            "Expiration": datetime(2099, 1, 1, tzinfo=UTC),
        }
    }
    mgr._sts_client = sts

    client: Any = mgr.get_assumed_session("222222222222").client("organizations")
    with Stubber(client) as stub:
        stub.add_response("create_policy", POLICY)
        client.create_policy(Name="Guard", Description="d", Type="SERVICE_CONTROL_POLICY", Content="{}")

    assert [r["data"]["operation"] for r in _records(info_log)] == ["CreatePolicy"]
