"""The access role's managed policy: it must fit IAM's size limit, and preflight must notice a stale deployment."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import yaml
from botocore.exceptions import ClientError

from tarmac.core.models import PreflightCheckStatus
from tarmac.services.preflight import ACCESS_TEMPLATE, PreflightService

TEMPLATE = Path(__file__).resolve().parent.parent / ACCESS_TEMPLATE
# IAM rejects a managed policy over 6,144 characters (whitespace excluded); CloudFormation only finds out at deploy
# time. Keep headroom so the next feature does not discover the limit in a customer's account.
IAM_LIMIT = 6144
HEADROOM = 400


class _Loader(yaml.SafeLoader):
    pass


def _tag(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return {suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {suffix: loader.construct_sequence(node)}
    return {suffix: loader.construct_mapping(node)}  # type: ignore[arg-type]


_Loader.add_multi_constructor("!", _tag)


def test_the_managed_policy_stays_well_under_the_iam_size_limit() -> None:
    template = yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)
    document = template["Resources"]["TarmacPolicy"]["Properties"]["PolicyDocument"]
    size = len(json.dumps(document, separators=(",", ":")).replace(" ", ""))
    assert size <= IAM_LIMIT - HEADROOM, (
        f"TarmacPolicy is {size} characters; IAM allows {IAM_LIMIT}. Split the policy or trim actions before adding more."
    )


# -- preflight: is the deployed role from this release? -----------------------------------------------------------


def _service(get_template: Any) -> PreflightService:
    cfn = MagicMock()
    cfn.get_template = get_template
    mgr = MagicMock()
    mgr.get_client.return_value = cfn
    return PreflightService(mgr, MagicMock())


def _error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetTemplate")


def test_a_deployed_role_matching_this_release_passes() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    result = _service(MagicMock(return_value={"TemplateBody": text})).check_access_policy_current("eu-west-1")
    assert result.status is PreflightCheckStatus.PASS


def test_trailing_whitespace_and_line_endings_do_not_count_as_a_difference() -> None:
    text = TEMPLATE.read_text(encoding="utf-8").replace("\n", "  \r\n")
    result = _service(MagicMock(return_value={"TemplateBody": text})).check_access_policy_current("eu-west-1")
    assert result.status is PreflightCheckStatus.PASS


def test_a_deployed_role_from_another_release_warns_to_rebootstrap() -> None:
    result = _service(MagicMock(return_value={"TemplateBody": "Resources: {}"})).check_access_policy_current(
        "eu-west-1"
    )
    assert result.status is PreflightCheckStatus.WARN
    assert "tarmac access bootstrap" in (result.action_required or "")
    assert "us-east-1" in (result.live_value or "")


def test_the_home_region_is_checked_when_the_default_region_has_no_stack() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    calls: list[str] = []

    def get_template(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs["StackName"])
        if len(calls) == 1:
            raise _error("ValidationError")
        return {"TemplateBody": text}

    result = _service(get_template).check_access_policy_current("eu-west-1")
    assert result.status is PreflightCheckStatus.PASS
    assert "eu-west-1" in (result.live_value or "")
    assert len(calls) == 2


def test_no_access_stack_is_informational_not_a_warning() -> None:
    result = _service(MagicMock(side_effect=_error("ValidationError"))).check_access_policy_current(
        "us-east-1"
    )
    assert result.status is PreflightCheckStatus.INFO


def test_missing_permission_to_read_the_stack_is_informational() -> None:
    result = _service(MagicMock(side_effect=_error("AccessDenied"))).check_access_policy_current("us-east-1")
    assert result.status is PreflightCheckStatus.INFO
