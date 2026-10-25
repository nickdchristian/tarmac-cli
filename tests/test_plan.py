"""The dry-run plan: read-only comparisons per phase, and what each item says a live run would do."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.models import AccountPlanItem
from tarmac.core.tagging import merge_tags
from tarmac.services.cloudformation import CloudFormationService
from tarmac.services.plan import Planner


@pytest.fixture
def bundle(sample_config_dir: Path) -> ConfigBundle:
    loaded, errors = load_all_configs(sample_config_dir)
    assert loaded is not None, errors
    return loaded


def _planner(bundle: ConfigBundle, **kwargs: Any) -> Planner:
    session = MagicMock()
    session.default_region = "eu-west-1"
    session.get_caller_identity.return_value = {"Account": "111111111111", "Arn": "arn:aws:iam::1:role/x"}
    session.get_client.return_value.describe_organization.return_value = {
        "Organization": {"Id": "o-abc1234567"}
    }
    return Planner(session, bundle, "eu-west-1", bundle.config_dir.parent, **kwargs)


def _items(plan: Any, phase: int) -> dict[str, tuple[str, str]]:
    (found,) = [p for p in plan.phases if p.phase == phase]
    return {item.name: (item.action, item.detail) for item in found.items}


def test_phase_2_creates_only_the_missing_ous_and_previews_the_scp_stack(bundle):
    planner = _planner(bundle)
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.SCPService") as scps,
        patch.object(CloudFormationService, "preview_stack", return_value=("NO CHANGE", "")) as preview,
    ):
        ous.return_value.get_root_id.return_value = "r-root"
        ous.return_value.list_all_ous.return_value = {"Security": "ou-1", "Infrastructure": "ou-2"}
        scps.return_value.synthesize_template.return_value = {"Resources": {}}
        items = _items(planner.build([2]), 2)

    assert items["Security"] == ("NO CHANGE", "")
    assert items["Sandbox"] == ("CREATE", "under Root")
    stack = next(name for name in items if name.endswith("organization-scps"))
    assert items[stack][0] == "NO CHANGE"
    assert preview.call_args.kwargs["template_body"] == "Resources: {}\n"


def test_a_missing_scp_stack_that_would_take_over_existing_policies_is_an_import(bundle):
    planner = _planner(bundle)
    declared = bundle.org.service_control_policies.policies[0].name  # type: ignore[union-attr]
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.SCPService") as scps,
        patch.object(CloudFormationService, "preview_stack", return_value=("CREATE", "")),
    ):
        ous.return_value.list_all_ous.return_value = {}
        scps.return_value.synthesize_template.return_value = {}
        scps.return_value.list_existing_scps.return_value = {declared: {"Id": "p-1"}}
        items = _items(planner.build([2]), 2)

    action, detail = next(v for k, v in items.items() if k.endswith("organization-scps"))
    assert action == "IMPORT"
    assert declared in detail


@pytest.mark.parametrize(("in_stack", "expected"), [({"PolicyX"}, "NO CHANGE"), ({"Other"}, "IMPORT")])
def test_an_existing_policy_the_scp_stack_does_not_manage_yet_is_an_import(bundle, in_stack, expected):
    planner = _planner(bundle)
    declared = bundle.org.service_control_policies.policies[0].name  # type: ignore[union-attr]
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.SCPService") as scps,
        patch.object(CloudFormationService, "preview_stack", return_value=("NO CHANGE", "")),
        patch.object(CloudFormationService, "resource_ids", return_value=in_stack),
    ):
        ous.return_value.list_all_ous.return_value = {}
        scps.return_value.synthesize_template.return_value = {}
        scps.return_value.list_existing_scps.return_value = {declared: {"Id": "p-1"}}
        scps.return_value._logical_ids_for_policies.return_value = {declared: "PolicyX"}
        items = _items(planner.build([2]), 2)

    action, _ = next(v for k, v in items.items() if k.endswith("organization-scps"))
    assert action == expected


def test_phase_4_compares_accounts_tags_and_budgets(bundle):
    planner = _planner(bundle)
    names = [a.name for a in bundle.accounts.accounts]
    existing = {
        name: AccountPlanItem(name, "e", "Security", "NOOP", f"{i:012d}", "ok", a.baseline)
        for i, (name, a) in enumerate(zip(names, bundle.accounts.accounts, strict=True), start=1)
        if name != "dev-app"
    }
    existing["audit"] = AccountPlanItem(
        "audit", "e", "Security", "MOVE", "000000000004", "wrong OU", MagicMock()
    )
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.AccountService") as accounts,
        patch.object(CloudFormationService, "preview_stack", return_value=("NO CHANGE", "")),
    ):
        ous.return_value.list_all_ous.return_value = {a.ou: "ou-x" for a in bundle.accounts.accounts}
        accounts.return_value.plan.return_value = list(existing.values())
        accounts.return_value.get_account_tags.side_effect = lambda account_id: (
            {}
            if account_id == "000000000001"
            else {**bundle.get_organization_tags(), **bundle.accounts.accounts[1].tags}
        )
        items = _items(planner.build([4]), 4)

    assert items["dev-app"][0] == "CREATE"
    assert items["dev-app-monthly-budget"] == ("CREATE", "once account 'dev-app' exists")
    assert items["audit"] == ("MOVE", "wrong OU")
    assert items[names[0]][0] == "UPDATE"
    assert items[names[0]][1].startswith("tags ")
    assert items[names[1]][0] == "NO CHANGE"


def test_phase_4_account_filter_limits_the_plan_and_skips_quarantine(bundle):
    planner = _planner(bundle, only_accounts=["Dev-App"])
    removed = AccountPlanItem(
        "legacy", "e", "Suspended", "SUSPEND", "999999999999", "not declared", MagicMock()
    )
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.AccountService") as accounts,
        patch.object(CloudFormationService, "preview_stack", return_value=("NO CHANGE", "")),
    ):
        ous.return_value.list_all_ous.return_value = {a.ou: "ou-x" for a in bundle.accounts.accounts}
        accounts.return_value.plan.return_value = [removed]
        plan = planner.build([4])

    names = set(_items(plan, 4))
    assert names == {"dev-app", "dev-app-monthly-budget"}
    assert any("not quarantined" in note for note in plan.phases[0].notes)


def test_a_failed_read_is_unknown_and_does_not_stop_the_plan(bundle):
    planner = _planner(bundle)
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "DescribeStacks")
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.SCPService") as scps,
        patch.object(CloudFormationService, "preview_stack", side_effect=denied),
    ):
        ous.return_value.list_all_ous.return_value = {}
        scps.return_value.synthesize_template.return_value = {}
        items = _items(planner.build([2]), 2)

    action, detail = next(v for k, v in items.items() if k.endswith("organization-scps"))
    assert action == "UNKNOWN"
    assert "denied" in detail
    assert items["Security"] == ("CREATE", "under Root")


def test_every_item_is_recorded_as_a_simulated_action(bundle):
    planner = _planner(bundle)
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.SCPService") as scps,
        patch.object(CloudFormationService, "preview_stack", return_value=("CREATE", "")),
        patch("tarmac.services.plan.audit") as audit,
    ):
        ous.return_value.list_all_ous.return_value = {}
        scps.return_value.synthesize_template.return_value = {}
        scps.return_value.list_existing_scps.return_value = {}
        plan = planner.build([2])

    assert audit.call_count == len(plan.phases[0].items)
    assert all(call.kwargs["dry_run"] is True for call in audit.call_args_list)


def test_counts_summarize_every_phase(bundle):
    planner = _planner(bundle)
    with (
        patch("tarmac.services.plan.OUService") as ous,
        patch("tarmac.services.plan.SCPService") as scps,
        patch.object(CloudFormationService, "preview_stack", return_value=("UPDATE", "template")),
    ):
        ous.return_value.list_all_ous.return_value = {"Security": "ou-1"}
        scps.return_value.synthesize_template.return_value = {}
        plan = planner.build([2])

    declared = ConfigBundle.count_declared_ous(bundle.org.ou_structure)
    assert plan.counts() == {"NO CHANGE": 1, "CREATE": declared - 1, "UPDATE": 1}
    assert plan.to_dict()["summary"] == plan.counts()


# preview_stack: the read-only comparison every stack item uses


def _cfn(status: str | None, parameters: dict[str, str], body: str, tags: dict[str, str]) -> MagicMock:
    cfn = MagicMock()
    stack = {
        "StackStatus": status,
        "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
    }
    cfn.describe_stacks.return_value = {"Stacks": [stack] if status else []}
    cfn.get_template.return_value = {"TemplateBody": body}
    return cfn


def test_preview_reports_create_for_a_missing_stack():
    service = CloudFormationService(MagicMock())
    assert service.preview_stack(_cfn(None, {}, "", {}), "s", template_body="x") == ("CREATE", "")


def test_preview_reports_replace_for_an_unusable_stack():
    service = CloudFormationService(MagicMock())
    action, _ = service.preview_stack(_cfn("ROLLBACK_COMPLETE", {}, "", {}), "s", template_body="x")
    assert action == "REPLACE"


def test_preview_reports_no_change_when_template_parameters_and_tags_match():
    service = CloudFormationService(MagicMock())
    cfn = _cfn("UPDATE_COMPLETE", {"A": "1", "Extra": "kept"}, "body\n", merge_tags({"Env": "prod"}))
    result = service.preview_stack(
        cfn, "s", template_body="body", parameters={"A": "1"}, org_tags={"Env": "prod"}
    )
    assert result == ("NO CHANGE", "")
    cfn.get_template.assert_called_once_with(StackName="s", TemplateStage="Original")


def test_preview_compares_non_ascii_text_as_cloudformation_stores_it():
    service = CloudFormationService(MagicMock())
    cfn = _cfn("UPDATE_COMPLETE", {}, "Description: a ? b\n", merge_tags())
    assert service.preview_stack(cfn, "s", template_body="Description: a — b") == ("NO CHANGE", "")


def test_preview_names_what_would_change():
    service = CloudFormationService(MagicMock())
    cfn = _cfn("CREATE_COMPLETE", {"A": "1"}, "old", merge_tags())
    action, detail = service.preview_stack(
        cfn, "s", template_body="new", parameters={"A": "2", "B": "x"}, tags={"Team": "a"}
    )
    assert action == "UPDATE"
    assert detail == "A: 1 -> 2; B: (unset) -> x; template; tags"


def test_preview_ignores_key_order_but_not_content():
    service = CloudFormationService(MagicMock())
    live = "Resources:\n  B:\n    Type: X\n    Properties: {Name: !Ref A, Size: 1}\n"
    local = "Resources:\n  B:\n    Properties:\n      Size: 1\n      Name: !Ref A\n    Type: X\n"
    assert service.preview_stack(
        _cfn("UPDATE_COMPLETE", {}, live, merge_tags()), "s", template_body=local
    ) == (
        "NO CHANGE",
        "",
    )
    changed = local.replace("!Ref A", "!Ref C")
    action, detail = service.preview_stack(
        _cfn("UPDATE_COMPLETE", {}, live, merge_tags()), "s", template_body=changed
    )
    assert (action, detail) == ("UPDATE", "template")


@pytest.mark.parametrize(
    ("counts", "line"),
    [
        ({"NO CHANGE": 39, "CREATE": 7, "APPLY": 4}, "7 to create, 4 to apply, 39 unchanged"),
        ({"NO CHANGE": 3}, "no changes (3 unchanged)"),
        ({"BLOCKED": 1, "DELETE": 2}, "2 to delete, 1 blocked"),
    ],
)
def test_the_plan_summary_reads_like_a_sentence(counts, line):
    from tarmac.cli.plan_view import summarize

    assert summarize(counts) == line


def test_a_baseline_stack_shows_the_ous_and_regions_whose_stack_instances_change(bundle):
    from tarmac.core.config_schema import BaselineStackDef

    planner = _planner(bundle)
    planner.__dict__.update(
        ou_map={"Workloads": "ou-w", "Security": "ou-s", "Sandbox": "ou-x", "Infrastructure": "ou-i"},
        root_id="r-root",
    )
    stack = BaselineStackDef(
        name="p",
        template_file="t.yaml",
        target_ous=["Workloads", "Security", "Sandbox"],
        regions=["eu-west-1", "us-east-1"],
    )
    instances = [
        {"OrganizationalUnitId": "ou-w", "Region": "eu-west-1"},
        {"OrganizationalUnitId": "ou-w", "Region": "eu-west-2"},
        {"OrganizationalUnitId": "ou-i", "Region": "eu-west-1"},
    ]
    with (
        patch.object(Planner, "_stack_set", return_value=("NO CHANGE", "")),
        patch("tarmac.services.plan.StackSetService") as stack_sets,
    ):
        stack_sets.return_value.list_instances.return_value = instances
        action, detail = planner._baseline_stack("acme-baseline-p", stack)

    # Workloads has accounts through its child OUs; Sandbox has none, so deploying to it changes nothing.
    assert action == "UPDATE"
    assert detail == (
        "remove Infrastructure; add us-east-1 in Workloads; remove eu-west-2 in Workloads; "
        "add eu-west-1, us-east-1 in Security"
    )


def test_a_baseline_stack_whose_instances_match_is_unchanged(bundle):
    from tarmac.core.config_schema import BaselineStackDef

    planner = _planner(bundle)
    planner.__dict__.update(ou_map={"Security": "ou-s"}, root_id="r-root")
    stack = BaselineStackDef(name="p", template_file="t.yaml", target_ous=["Security"], regions=["eu-west-1"])
    with (
        patch.object(Planner, "_stack_set", return_value=("NO CHANGE", "")),
        patch("tarmac.services.plan.StackSetService") as stack_sets,
    ):
        stack_sets.return_value.list_instances.return_value = [
            {"OrganizationalUnitId": "ou-s", "Region": "eu-west-1"}
        ]
        assert planner._baseline_stack("acme-baseline-p", stack) == ("NO CHANGE", "in eu-west-1")


def test_preview_shows_an_empty_value_as_quotes():
    service = CloudFormationService(MagicMock())
    cfn = _cfn("CREATE_COMPLETE", {"A": "1", "B": ""}, "old", merge_tags())
    _, detail = service.preview_stack(cfn, "s", template_body="old", parameters={"A": "", "B": "x"})
    assert detail == "A: 1 -> ''; B: '' -> x"
