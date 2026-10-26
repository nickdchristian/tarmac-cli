"""baseline_stacks: user templates deployed to OUs through service-managed StackSets (Stubber clients)."""

from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import ANY, Stubber
from pydantic import ValidationError

from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_schema import BaselineStackDef
from tarmac.core.models import TAG_MANAGED_BY
from tarmac.services.baseline_stacks import BaselineStacksService
from tarmac.services.stackset import StackSetService
from tarmac.services.teardown import TeardownService

NAME = "acme-baseline-password-policy"
OWNED = [{"Key": TAG_MANAGED_BY, "Value": "tarmac"}]
DONE = {"StackSetOperation": {"Status": "SUCCEEDED"}}
PREFS = {
    "RegionConcurrencyType": "PARALLEL",
    "MaxConcurrentPercentage": 100,
    "FailureTolerancePercentage": 100,
}


def _cf() -> Any:
    return boto3.client(
        "cloudformation", region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x"
    )


def _session(cf: Any) -> MagicMock:
    mgr = MagicMock(spec=AwsSessionManager)
    org = MagicMock()  # no closed accounts
    mgr.get_client.side_effect = lambda service, **_kw: org if service == "organizations" else cf
    mgr.get_caller_identity.return_value = {"Account": "111111111111"}
    return mgr


def _instances(*pairs: tuple[str, str]) -> dict[str, Any]:
    return {
        "Summaries": [
            {
                "StackSetId": "id",
                "Region": region,
                "Account": "333333333333",
                "Status": "CURRENT",
                "OrganizationalUnitId": ou,
            }
            for region, ou in pairs
        ]
    }


def _described(ous: list[str]) -> dict[str, Any]:
    return {
        "StackSet": {"StackSetName": NAME, "Tags": OWNED, "Status": "ACTIVE", "OrganizationalUnitIds": ous}
    }


def _listed(*names: str) -> dict[str, Any]:
    return {
        "Summaries": [
            {
                "StackSetName": n,
                "StackSetId": f"{n}:1",
                "Status": "ACTIVE",
                "PermissionModel": "SERVICE_MANAGED",
            }
            for n in names
        ]
    }


@pytest.mark.parametrize(
    "change",
    [{"name": "bad_name"}, {"target_ous": []}, {"regions": []}],
)
def test_baseline_stack_definitions_are_validated(change):
    valid = {"name": "ok", "template_file": "t.yaml", "target_ous": ["Workloads"], "regions": ["us-east-1"]}
    BaselineStackDef.model_validate(valid)
    with pytest.raises(ValidationError):
        BaselineStackDef.model_validate({**valid, **change})


def test_targets_may_not_include_an_ou_another_target_already_covers(writable_config_dir):
    from tarmac.core.config_loader import load_all_configs

    bundle, errors = load_all_configs(writable_config_dir)
    assert bundle is not None, errors
    (writable_config_dir.parent / "baseline.yaml").write_text("Resources: {}\n")
    parent = next(ou for ou in bundle.org.ou_structure if ou.children)
    child = parent.children[0].name

    def problems(targets: list[str]) -> list[str]:
        bundle.org.baseline_stacks = [
            BaselineStackDef(
                name="a", template_file="baseline.yaml", target_ous=targets, regions=["us-east-1"]
            )
        ]
        return bundle._check_baseline_stacks()

    assert problems([parent.name]) == []
    assert len(problems([parent.name, child])) == 1
    assert len(problems(["root", parent.name])) == 1


def test_cross_references_catch_unknown_ous_missing_templates_and_duplicates(writable_config_dir):
    from tarmac.core.config_loader import load_all_configs

    bundle, errors = load_all_configs(writable_config_dir)
    assert bundle is not None, errors
    (writable_config_dir.parent / "baseline.yaml").write_text("Resources: {}\n")
    bundle.org.baseline_stacks = [
        BaselineStackDef(name="a", template_file="baseline.yaml", target_ous=["root"], regions=["us-east-1"]),
        BaselineStackDef(name="A", template_file="missing.yaml", target_ous=["Nope"], regions=["us-east-1"]),
    ]

    problems = bundle._check_baseline_stacks()

    assert len(problems) == 3
    assert "more than once" in problems[0]
    assert "missing.yaml" in problems[1]
    assert "Nope" in problems[2]


def _operation(s: Stubber, call: str, op: str, ou: str, regions: list[str]) -> None:
    params: dict[str, Any] = {
        "StackSetName": NAME,
        "DeploymentTargets": {"OrganizationalUnitIds": [ou]},
        "Regions": regions,
        "OperationPreferences": PREFS,
    }
    if call == "delete_stack_instances":
        params["RetainStacks"] = False
    s.add_response(call, {"OperationId": op}, params)
    s.add_response("describe_stack_set_operation", DONE, {"StackSetName": NAME, "OperationId": op})


def test_sync_targets_gives_each_ou_exactly_the_regions_and_drops_ous_no_longer_targeted():
    cf = _cf()
    current = _instances(("us-east-1", "ou-a"), ("eu-west-1", "ou-a"), ("us-east-1", "ou-b"))
    with Stubber(cf) as s:
        s.add_response("list_stack_instances", current, {"StackSetName": NAME})
        _operation(s, "delete_stack_instances", "op-1", "ou-b", ["us-east-1"])
        _operation(s, "delete_stack_instances", "op-2", "ou-a", ["eu-west-1"])
        _operation(s, "create_stack_instances", "op-3", "ou-c", ["us-east-1"])
        s.add_response("list_stack_instances", _instances(("us-east-1", "ou-a")), {"StackSetName": NAME})

        failures = StackSetService().sync_targets(cf, NAME, ["ou-a", "ou-c"], ["us-east-1"])
        s.assert_no_pending_responses()

    assert failures == []


def test_deploy_creates_declared_stack_sets_and_deletes_undeclared_ones(tmp_path):
    (tmp_path / "policy.yaml").write_text("Resources: {}\n")
    stack = BaselineStackDef(
        name="password-policy",
        template_file="policy.yaml",
        target_ous=["root"],
        regions=["us-east-1"],
        parameters={"MinimumLength": "14"},
    )
    old = "acme-baseline-old"
    cf = _cf()
    with Stubber(cf) as s:
        s.add_response("activate_organizations_access", {}, {})
        s.add_client_error(
            "describe_stack_set", "StackSetNotFoundException", expected_params={"StackSetName": NAME}
        )
        s.add_response(
            "create_stack_set",
            {"StackSetId": "id"},
            {
                "StackSetName": NAME,
                "Description": "Baseline stack 'password-policy' managed by tarmac",
                "TemplateBody": "Resources: {}\n",
                "Parameters": [{"ParameterKey": "MinimumLength", "ParameterValue": "14"}],
                "Capabilities": ["CAPABILITY_NAMED_IAM"],
                "Tags": ANY,
                "PermissionModel": "SERVICE_MANAGED",
                "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False},
            },
        )
        s.add_response("list_stack_instances", {"Summaries": []}, {"StackSetName": NAME})
        _operation(s, "create_stack_instances", "op-1", "r-ab12", ["us-east-1"])
        s.add_response("list_stack_instances", _instances(("us-east-1", "r-ab12")), {"StackSetName": NAME})
        s.add_response("list_stack_sets", _listed(NAME, old, "acme-config-recorder"), {"Status": "ACTIVE"})
        s.add_response("describe_stack_set", {"StackSet": {"StackSetName": old, "Tags": OWNED}}, None)
        s.add_response("list_stack_instances", {"Summaries": []}, None)
        s.add_response("delete_stack_set", {}, {"StackSetName": old})

        failures = BaselineStacksService(_session(cf), "eu-west-1").deploy(
            "acme", [stack], tmp_path, {"root": "r-ab12"}, {TAG_MANAGED_BY: "tarmac"}
        )
        s.assert_no_pending_responses()

    assert failures == []


def test_teardown_removes_every_baseline_stack_set_of_the_organization():
    cf = _cf()
    bundle = MagicMock()
    bundle.org.organization.name = "acme"
    with Stubber(cf) as s:
        s.add_response("list_stack_sets", _listed(NAME, "other-baseline-x"), {"Status": "ACTIVE"})
        s.add_response("describe_stack_set", _described(["r-ab12"]), {"StackSetName": NAME})
        items = TeardownService(_session(cf)).teardown_baseline_stacks(bundle, "eu-west-1", dry_run=True)
        s.assert_no_pending_responses()

    assert [(i.resource_name, i.action) for i in items] == [(NAME, "SIMULATED")]
