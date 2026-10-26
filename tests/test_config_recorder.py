"""AWS Config recorders: opt-in, deployed as a service-managed StackSet plus a management account stack.

AWS calls go through botocore Stubber clients, so every request is validated against the real service model.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
import yaml
from botocore.stub import ANY, Stubber

from tarmac.cli.deploy_config_recorder import deploy_config_recorder
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_schema import ConfigRecorderConfig, SecurityServicesConfig
from tarmac.core.exceptions import GovernanceError
from tarmac.core.models import TAG_MANAGED_BY, StackDeployReport
from tarmac.core.stack_names import Stack
from tarmac.services.config_recorder import ConfigRecorderService
from tarmac.services.stack_parameters import (
    config_recorder_advice,
    config_recorder_regions,
    log_archive_parameters,
)
from tarmac.services.teardown import TeardownService

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "src/tarmac/templates/cloudformation" / "config-recorder.yaml"
MGMT = "111111111111"
SLR = {
    "Role": {
        "Path": "/aws-service-role/config.amazonaws.com/",
        "RoleName": "AWSServiceRoleForConfig",
        "RoleId": "AROAEXAMPLE1234567890",
        "Arn": f"arn:aws:iam::{MGMT}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        "CreateDate": "2026-10-20T00:00:00Z",
    }
}
_GET_SLR = {"RoleName": "AWSServiceRoleForConfig"}
NAME = Stack.CONFIG_RECORDER.for_org("acme")
PARAMS = {
    "DeliveryBucketName": "acme-org-cloudtrail-logs-222222222222",
    "DeliveryKmsKeyArn": "",
    "GlobalResourcesRegion": "eu-west-1",
    "IncludeGlobalResources": "true",
}
OWNED_TAGS = [{"Key": TAG_MANAGED_BY, "Value": "tarmac"}, {"Key": "ManagedBy", "Value": "tarmac"}]


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


def _bundle(*, config: dict[str, Any] | None = None, cloudtrail_kms: bool = False) -> MagicMock:
    bundle = MagicMock()
    bundle.org.organization.name = "acme"
    bundle.org.organization.additional_regions = []
    bundle.org.cloudtrail.enable_kms = cloudtrail_kms
    bundle.org.security_services = SecurityServicesConfig.model_validate({"config_recorder": config or {}})
    bundle.get_log_archive_account_name.return_value = "log-archive"
    bundle.resolve_account_id.return_value = "222222222222"
    bundle.get_organization_tags.return_value = {}
    return bundle


def _client(service: str) -> Any:
    name: Any = service
    return boto3.client(name, region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")


def _session(**clients: Any) -> MagicMock:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.default_region = "eu-west-1"
    mgr.get_client.side_effect = lambda svc, **kw: clients[svc]
    mgr.get_member_client.return_value = MagicMock()
    mgr.get_caller_identity.return_value = {
        "Account": MGMT,
        "Arn": f"arn:aws:iam::{MGMT}:role/TarmacDeploymentRole",
    }
    return mgr


def _service(mgr: MagicMock, cfn_service: Any = None) -> ConfigRecorderService:
    cfn = cfn_service or MagicMock()
    if cfn_service is None:
        cfn.deploy_stack.side_effect = lambda *a, **k: StackDeployReport(action="CREATED", outputs={})
    return ConfigRecorderService(mgr, cfn, sleep=lambda _s: None, poll_seconds=0, timeout_seconds=5)


def _organization(org: Any, stub: Stubber, accounts: list[dict[str, str]] | None = None) -> None:
    stub.add_response("list_roots", {"Roots": [{"Id": "r-ab12"}]}, {})
    stub.add_response(
        "list_accounts",
        {
            "Accounts": accounts
            or [
                {"Id": MGMT, "Status": "ACTIVE"},
                {"Id": "333333333333", "Status": "ACTIVE"},
                {"Id": "444444444444", "Status": "SUSPENDED"},
            ]
        },
        {},
    )


def _closed_then_root(stub: Stubber) -> None:
    """Removal reads the closed accounts first, then the root it removes the instances through."""
    stub.add_response(
        "list_accounts",
        {"Accounts": [{"Id": MGMT, "Status": "ACTIVE"}, {"Id": "333333333333", "Status": "ACTIVE"}]},
        {},
    )
    stub.add_response("list_roots", {"Roots": [{"Id": "r-ab12"}]}, {})


TARGETS = {
    "OrganizationalUnitIds": ["r-ab12"],
    "AccountFilterType": "DIFFERENCE",
    "Accounts": [MGMT, "444444444444"],
}
PREFS = {
    "RegionConcurrencyType": "PARALLEL",
    "MaxConcurrentPercentage": 100,
    "FailureTolerancePercentage": 100,
}


def _instances(*regions: str, status: str = "CURRENT", reason: str = "") -> dict[str, Any]:
    return {
        "Summaries": [
            {
                "StackSetId": "id",
                "Region": r,
                "Account": "333333333333",
                "Status": status,
                "StatusReason": reason,
            }
            for r in regions
        ]
    }


def _existing(template: str, tags: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "StackSet": {
            "StackSetName": NAME,
            "TemplateBody": template,
            # As AWS returns it: every template parameter, including RecorderRoleArn left at its default.
            "Parameters": [
                {"ParameterKey": k, "ParameterValue": v} for k, v in {**PARAMS, "RecorderRoleArn": ""}.items()
            ],
            "Tags": OWNED_TAGS if tags is None else tags,
            "Status": "ACTIVE",
        }
    }


def _deploy(svc: ConfigRecorderService, regions: list[str], **kw: Any) -> Any:
    return svc.deploy(
        org_name="acme",
        template_file=TEMPLATE,
        parameters=PARAMS,
        regions=regions,
        primary_region="eu-west-1",
        management_account_id=MGMT,
        **kw,
    )


def _setup() -> tuple[Any, Any, Any, Any]:
    cf, org, iam = _client("cloudformation"), _client("organizations"), _client("iam")
    return cf, org, iam, _session(cloudformation=cf, organizations=org, iam=iam)


# --------------------------------------------------------------------------- deploy


def test_first_run_creates_the_stack_set_its_instances_and_the_management_stacks():
    cf, org, iam, mgr = _setup()
    cfn_service = MagicMock()
    cfn_service.deploy_stack.side_effect = lambda *a, **k: StackDeployReport(action="CREATED", outputs={})
    with Stubber(cf) as cfs, Stubber(org) as orgs, Stubber(iam) as iams:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_client_error(
            "describe_stack_set", "StackSetNotFoundException", expected_params={"StackSetName": NAME}
        )
        cfs.add_response(
            "create_stack_set",
            {"StackSetId": "id"},
            {
                "StackSetName": NAME,
                "Description": ANY,
                "TemplateBody": ANY,
                "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in PARAMS.items()],
                "Capabilities": ["CAPABILITY_NAMED_IAM"],
                "Tags": ANY,
                "PermissionModel": "SERVICE_MANAGED",
                "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False},
            },
        )
        cfs.add_response("list_stack_instances", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response("list_stack_set_auto_deployment_targets", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response(
            "create_stack_instances",
            {"OperationId": "op-1"},
            {
                "StackSetName": NAME,
                "DeploymentTargets": TARGETS,
                "Regions": ["eu-west-1", "us-east-1"],
                "OperationPreferences": PREFS,
            },
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "RUNNING"}},
            {"StackSetName": NAME, "OperationId": "op-1"},
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "SUCCEEDED"}},
            {"StackSetName": NAME, "OperationId": "op-1"},
        )
        cfs.add_response("list_stack_instances", _instances("eu-west-1", "us-east-1"), {"StackSetName": NAME})
        iams.add_client_error("get_role", "NoSuchEntity", "not found", expected_params=_GET_SLR)
        iams.add_response(
            "create_service_linked_role",
            {
                "Role": {
                    "Path": "/aws-service-role/config.amazonaws.com/",
                    "RoleName": "AWSServiceRoleForConfig",
                    "RoleId": "AROAEXAMPLE1234567890",
                    "Arn": "arn:aws:iam::111111111111:role/aws-service-role/config.amazonaws.com/X",
                    "CreateDate": "2026-10-20T00:00:00Z",
                }
            },
            {"AWSServiceName": "config.amazonaws.com"},
        )

        report = _deploy(_service(mgr, cfn_service), ["eu-west-1", "us-east-1"])

        cfs.assert_no_pending_responses()
        iams.assert_no_pending_responses()

    assert report.stack_set_action == "CREATED"
    assert report.failures == []
    assert len(report.management_stacks) == 2
    for call in cfn_service.deploy_stack.call_args_list:
        # Region by Region, the management account records with its service-linked role.
        assert call.args[3]["RecorderRoleArn"].endswith("/X")
        assert call.args[3]["DeliveryBucketName"] == PARAMS["DeliveryBucketName"]


def test_unchanged_stack_set_with_all_regions_current_changes_nothing():
    cf, org, iam, mgr = _setup()
    template = TEMPLATE.read_text(encoding="utf-8")
    with Stubber(cf) as cfs, Stubber(org) as orgs, Stubber(iam) as iams:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_response("describe_stack_set", _existing(template), {"StackSetName": NAME})
        # tags merge to the defaults plus the ownership tag
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        cfs.add_response("list_stack_set_auto_deployment_targets", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        iams.add_response("get_role", SLR, _GET_SLR)

        report = _deploy(_service(mgr), ["eu-west-1"])

        cfs.assert_no_pending_responses()

    assert report.stack_set_action == "UNCHANGED"
    assert report.failures == []


def test_changed_template_updates_the_stack_set_and_waits_for_the_operation():
    cf, org, iam, mgr = _setup()
    with Stubber(cf) as cfs, Stubber(org) as orgs, Stubber(iam) as iams:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_response("describe_stack_set", _existing("# older template"), {"StackSetName": NAME})
        cfs.add_response(
            "update_stack_set",
            {"OperationId": "op-2"},
            {
                "StackSetName": NAME,
                "OperationPreferences": PREFS,
                "TemplateBody": ANY,
                "Parameters": ANY,
                "Capabilities": ["CAPABILITY_NAMED_IAM"],
                "Tags": ANY,
                "PermissionModel": "SERVICE_MANAGED",
                "AutoDeployment": {"Enabled": True, "RetainStacksOnAccountRemoval": False},
            },
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "SUCCEEDED"}},
            {"StackSetName": NAME, "OperationId": "op-2"},
        )
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        cfs.add_response("list_stack_set_auto_deployment_targets", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        iams.add_response("get_role", SLR, _GET_SLR)

        report = _deploy(_service(mgr), ["eu-west-1"])

        cfs.assert_no_pending_responses()

    assert report.stack_set_action == "UPDATED"


def test_a_failed_stack_set_update_is_recorded_as_failed(monkeypatch: pytest.MonkeyPatch):
    from tarmac.core.audit import Outcome
    from tarmac.services.stackset import StackSetService

    recorded: list[tuple[str, Any]] = []
    monkeypatch.setattr(
        "tarmac.services.stackset.audit",
        lambda action, resource, outcome, message, **_: recorded.append((message, outcome)),
    )
    cf = _client("cloudformation")
    with Stubber(cf) as cfs:
        cfs.add_response("describe_stack_set", _existing("# older template"), {"StackSetName": NAME})
        cfs.add_response("update_stack_set", {"OperationId": "op-3"}, None)
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "FAILED"}},
            {"StackSetName": NAME, "OperationId": "op-3"},
        )
        action = StackSetService(sleep=lambda _s: None).ensure(cf, NAME, "d", "# new", {}, {})
    assert action == "FAILED"
    assert recorded == [(f"StackSet operation op-3 on '{NAME}' ended FAILED", Outcome.FAILED)]


def test_a_stack_set_tarmac_did_not_create_is_never_touched():
    cf, org, _iam, mgr = _setup()
    with Stubber(cf) as cfs, Stubber(org) as orgs:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_response("describe_stack_set", _existing("# theirs", tags=[]), {"StackSetName": NAME})

        with pytest.raises(GovernanceError, match="not created by tarmac"):
            _deploy(_service(mgr), ["eu-west-1"])

        cfs.assert_no_pending_responses()


def test_regions_no_longer_configured_are_removed_and_failed_instances_are_reported():
    cf, org, iam, mgr = _setup()
    template = TEMPLATE.read_text(encoding="utf-8")
    with Stubber(cf) as cfs, Stubber(org) as orgs, Stubber(iam) as iams:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_response("describe_stack_set", _existing(template), {"StackSetName": NAME})
        cfs.add_response("list_stack_instances", _instances("eu-west-1", "us-west-2"), {"StackSetName": NAME})
        cfs.add_response("list_stack_set_auto_deployment_targets", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response(
            "delete_stack_instances",
            {"OperationId": "op-3"},
            {
                "StackSetName": NAME,
                # Without the account filter, so the Region also leaves the auto-deployment targets.
                "DeploymentTargets": {"OrganizationalUnitIds": ["r-ab12"]},
                "Regions": ["us-west-2"],
                "RetainStacks": False,
                "OperationPreferences": PREFS,
            },
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "SUCCEEDED"}},
            {"StackSetName": NAME, "OperationId": "op-3"},
        )
        cfs.add_response(
            "list_stack_instances",
            _instances("eu-west-1", status="OUTDATED", reason="AWS Config recorder limit reached"),
            {"StackSetName": NAME},
        )
        iams.add_response("get_role", SLR, _GET_SLR)

        report = _deploy(_service(mgr), ["eu-west-1"])

        cfs.assert_no_pending_responses()

    assert len(report.failures) == 1
    assert "333333333333 eu-west-1: OUTDATED AWS Config recorder limit reached" in report.failures[0]


def _account_instance(account: str, region: str) -> dict[str, Any]:
    return {
        "StackSetId": "id",
        "Region": region,
        "Account": account,
        "Status": "OUTDATED" if account == "444444444444" else "CURRENT",
        "OrganizationalUnitId": "r-ab12",
    }


def test_instances_in_closed_accounts_are_released_through_their_ou_keeping_their_stacks():
    # A closed account's instances stay OUTDATED for good and fail every deploy and destroy after it.
    cf, org, iam, mgr = _setup()
    template = TEMPLATE.read_text(encoding="utf-8")
    with Stubber(cf) as cfs, Stubber(org) as orgs, Stubber(iam) as iams:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_response("describe_stack_set", _existing(template), {"StackSetName": NAME})
        cfs.add_response(
            "list_stack_instances",
            {
                "Summaries": [
                    _account_instance("333333333333", "eu-west-1"),
                    _account_instance("444444444444", "eu-west-1"),
                    _account_instance("444444444444", "us-west-2"),
                ]
            },
            {"StackSetName": NAME},
        )
        cfs.add_response(
            "delete_stack_instances",
            {"OperationId": "op-6"},
            {
                "StackSetName": NAME,
                "DeploymentTargets": {
                    "OrganizationalUnitIds": ["r-ab12"],
                    "Accounts": ["444444444444"],
                    "AccountFilterType": "INTERSECTION",
                },
                "Regions": ["eu-west-1", "us-west-2"],
                "RetainStacks": True,
                "OperationPreferences": PREFS,
            },
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "SUCCEEDED"}},
            {"StackSetName": NAME, "OperationId": "op-6"},
        )
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        cfs.add_response("list_stack_set_auto_deployment_targets", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        iams.add_response("get_role", SLR, _GET_SLR)

        report = _deploy(_service(mgr), ["eu-west-1"])

        cfs.assert_no_pending_responses()

    assert report.failures == []


def test_a_region_left_in_the_auto_deployment_targets_is_removed():
    # New accounts would otherwise still get the Region, as an account created after it was dropped did.
    cf, org, iam, mgr = _setup()
    template = TEMPLATE.read_text(encoding="utf-8")
    with Stubber(cf) as cfs, Stubber(org) as orgs, Stubber(iam) as iams:
        cfs.add_response("activate_organizations_access", {}, {})
        _organization(org, orgs)
        cfs.add_response("describe_stack_set", _existing(template), {"StackSetName": NAME})
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        cfs.add_response(
            "list_stack_set_auto_deployment_targets",
            {"Summaries": [{"OrganizationalUnitId": "r-ab12", "Regions": ["eu-west-1", "us-west-2"]}]},
            {"StackSetName": NAME},
        )
        cfs.add_response(
            "delete_stack_instances",
            {"OperationId": "op-7"},
            {
                "StackSetName": NAME,
                "DeploymentTargets": {"OrganizationalUnitIds": ["r-ab12"]},
                "Regions": ["us-west-2"],
                "RetainStacks": False,
                "OperationPreferences": PREFS,
            },
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "SUCCEEDED"}},
            {"StackSetName": NAME, "OperationId": "op-7"},
        )
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        iams.add_response("get_role", SLR, _GET_SLR)

        report = _deploy(_service(mgr), ["eu-west-1"])

        cfs.assert_no_pending_responses()

    assert report.failures == []


def test_a_dropped_region_loses_its_management_stack_only_where_one_was_recorded(monkeypatch):
    from tarmac.core import inventory

    service = MagicMock()
    service.return_value.deploy.return_value = MagicMock(
        failures=[], management_stacks=[], stack_set_action="UNCHANGED"
    )
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    teardown = MagicMock()
    teardown.return_value.teardown_config_recorder.return_value = []
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.TeardownService", teardown)
    recorded = inventory.activate()
    recorded.entries = {"config-recorder": {"eu-west-1": {}, "us-west-2": {}}}
    cfn_service = MagicMock()
    cfn_service._fetch_stack_outputs.return_value = {"ConfigBucketName": "acme-org-config-logs-222222222222"}
    bundle = _bundle(config={"enabled": True})

    deploy_config_recorder(
        _session(), cfn_service, bundle, "eu-west-1", ROOT, {"log-archive": "222222222222"}
    )

    teardown.return_value.teardown_config_recorder.assert_called_once_with(
        bundle, "eu-west-1", regions=["us-west-2"]
    )
    assert set(recorded.get("config-recorder")) == {"eu-west-1", "us-west-2"}


def test_teardown_reaches_every_region_a_management_stack_was_recorded_in(monkeypatch):
    from tarmac.core.inventory import Inventory

    remove = MagicMock(return_value=[])
    monkeypatch.setattr("tarmac.services.teardown_config.ConfigRecorderService.remove", remove)
    bundle = MagicMock()
    bundle.org.organization.name = "acme"
    bundle.org.organization.additional_regions = []
    recorded = Inventory()
    recorded.entries = {"config-recorder": {"us-west-2": {}}}

    TeardownService(_session()).teardown_config_recorder(bundle, "eu-west-1", recorded=recorded)
    TeardownService(_session()).teardown_config_recorder(bundle, "eu-west-1", regions=["us-west-2"])

    full, dropped = (c.kwargs for c in remove.call_args_list)
    assert (full["regions"], full["stack_set"]) == (["eu-west-1", "us-west-2"], True)
    # A dropped Region keeps the StackSet, which serves the Regions still declared.
    assert (dropped["regions"], dropped["stack_set"]) == (["us-west-2"], False)


def test_an_operation_that_never_finishes_times_out_with_guidance():
    cf, _org, _iam, mgr = _setup()
    service = ConfigRecorderService(
        mgr, MagicMock(), sleep=lambda _s: None, poll_seconds=0, timeout_seconds=0
    )
    with Stubber(cf) as cfs:
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "RUNNING"}},
            {"StackSetName": NAME, "OperationId": "op-9"},
        )
        with pytest.raises(GovernanceError, match="keeps running in AWS"):
            service.stack_sets.wait(cf, NAME, "op-9")


def test_an_existing_service_linked_role_is_used_without_trying_to_create_it():
    iam = _client("iam")
    mgr = _session(iam=iam)
    with Stubber(iam) as iams:
        iams.add_response("get_role", SLR, _GET_SLR)
        arn = _service(mgr)._ensure_service_linked_role(MGMT)
        iams.assert_no_pending_responses()
    assert arn == f"arn:aws:iam::{MGMT}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"


def test_other_service_linked_role_errors_are_not_swallowed():
    iam = _client("iam")
    mgr = _session(iam=iam)
    with Stubber(iam) as iams:
        iams.add_client_error("get_role", "NoSuchEntity", "not found", expected_params=_GET_SLR)
        iams.add_client_error("create_service_linked_role", "AccessDenied", "no")
        with pytest.raises(GovernanceError, match="service-linked role"):
            _service(mgr)._ensure_service_linked_role(MGMT)


# --------------------------------------------------------------------------- remove


def test_remove_deletes_instances_then_the_stack_set_then_the_management_stacks():
    cf, org, _iam, mgr = _setup()
    cfn_service = MagicMock()
    cfn_service._get_stack_status.return_value = "CREATE_COMPLETE"
    with Stubber(cf) as cfs, Stubber(org) as orgs:
        cfs.add_response("describe_stack_set", _existing("# t"), {"StackSetName": NAME})
        _closed_then_root(orgs)
        cfs.add_response("list_stack_instances", _instances("eu-west-1", "us-east-1"), {"StackSetName": NAME})
        cfs.add_response(
            "delete_stack_instances",
            {"OperationId": "op-4"},
            {
                "StackSetName": NAME,
                "DeploymentTargets": {"OrganizationalUnitIds": ["r-ab12"]},
                "Regions": ["eu-west-1", "us-east-1"],
                "RetainStacks": False,
                "OperationPreferences": PREFS,
            },
        )
        cfs.add_response(
            "describe_stack_set_operation",
            {"StackSetOperation": {"Status": "SUCCEEDED"}},
            {"StackSetName": NAME, "OperationId": "op-4"},
        )
        cfs.add_response("list_stack_instances", {"Summaries": []}, {"StackSetName": NAME})
        cfs.add_response("delete_stack_set", {}, {"StackSetName": NAME})

        rows = _service(mgr, cfn_service).remove(
            org_name="acme",
            regions=["eu-west-1", "us-east-1"],
            primary_region="eu-west-1",
            management_account_id=MGMT,
        )
        cfs.assert_no_pending_responses()

    assert [r[1] for r in rows] == ["DELETED", "DELETED", "DELETED"]
    assert cfn_service.delete_stack.call_count == 2


def test_remove_skips_a_stack_set_it_does_not_own_and_reports_missing_ones_quietly():
    cf, _org, _iam, mgr = _setup()
    cfn_service = MagicMock()
    cfn_service._get_stack_status.return_value = None
    with Stubber(cf) as cfs:
        cfs.add_response("describe_stack_set", _existing("# t", tags=[]), {"StackSetName": NAME})
        rows = _service(mgr, cfn_service).remove(
            org_name="acme", regions=["eu-west-1"], primary_region="eu-west-1", management_account_id=MGMT
        )
    assert [r[1] for r in rows] == ["SKIPPED", "NOT_FOUND"]
    cfn_service.delete_stack.assert_not_called()


def test_remove_reports_instances_that_could_not_be_deleted():
    cf, org, _iam, mgr = _setup()
    cfn_service = MagicMock()
    cfn_service._get_stack_status.return_value = None
    with Stubber(cf) as cfs, Stubber(org) as orgs:
        cfs.add_response("describe_stack_set", _existing("# t"), {"StackSetName": NAME})
        _closed_then_root(orgs)
        cfs.add_response("list_stack_instances", _instances("eu-west-1"), {"StackSetName": NAME})
        cfs.add_response("delete_stack_instances", {"OperationId": "op-5"}, None)
        cfs.add_response("describe_stack_set_operation", {"StackSetOperation": {"Status": "FAILED"}}, None)
        cfs.add_response("list_stack_instances", _instances("eu-west-1", status="INOPERABLE"), None)
        rows = _service(mgr, cfn_service).remove(
            org_name="acme", regions=["eu-west-1"], primary_region="eu-west-1", management_account_id=MGMT
        )
    assert rows[0][1] == "FAILED"
    assert "could not be deleted" in rows[0][2]


def test_teardown_lists_only_what_was_found(monkeypatch):
    svc = TeardownService(_session())
    bundle = MagicMock()
    bundle.org.organization.name = "acme"
    bundle.org.organization.additional_regions = []
    monkeypatch.setattr(
        "tarmac.services.teardown_config.ConfigRecorderService.remove",
        MagicMock(
            return_value=[
                ("StackSet acme-config-recorder", "NOT_FOUND", "StackSet does not exist"),
                ("Stack acme-config-recorder (eu-west-1)", "DELETED", "Deleted"),
            ]
        ),
    )

    items = svc.teardown_config_recorder(bundle, "eu-west-1")

    assert [(i.resource_type, i.action) for i in items] == [("Config recorder Stack", "DELETED")]


# --------------------------------------------------------------------------- configuration and phase glue


def test_config_recorder_is_off_by_default():
    assert ConfigRecorderConfig().enabled is False
    assert ConfigRecorderConfig().include_global_resources is True
    assert SecurityServicesConfig().config_recorder.enabled is False


def test_regions_are_primary_first_without_repeats():
    bundle = MagicMock()
    bundle.org.organization.additional_regions = ["us-east-1", "eu-west-1", "us-east-1"]
    assert config_recorder_regions(bundle, "eu-west-1") == ["eu-west-1", "us-east-1"]


@pytest.mark.parametrize(
    ("security", "warns"),
    [
        ({"securityhub": {"enabled": True}}, True),  # standards on, Config off: recommend it
        ({"securityhub": {"enabled": True}, "config_recorder": {"enabled": False}}, True),
        ({"securityhub": {"enabled": True}, "config_recorder": {"enabled": True}}, False),
        ({"securityhub": {"enabled": False}}, False),  # nothing needs it
    ],
)
def test_recommends_a_recorder_while_security_hub_runs_without_one(security, warns):
    bundle = MagicMock()
    bundle.org.security_services = SecurityServicesConfig(**security)

    assert bool(config_recorder_advice(bundle)) is warns


def test_nothing_is_deployed_while_the_feature_is_off(monkeypatch):
    service = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    bundle = MagicMock()
    bundle.org.security_services = SecurityServicesConfig()

    deploy_config_recorder(MagicMock(), MagicMock(), bundle, "eu-west-1", ROOT, {})

    service.assert_not_called()


def test_deploy_passes_the_config_bucket_key_regions_and_frequency_to_the_service(monkeypatch):
    service = MagicMock()
    service.return_value.deploy.return_value = MagicMock(
        failures=[], management_stacks=[], stack_set_action="CREATED"
    )
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    cfn_service = MagicMock()
    cfn_service._fetch_stack_outputs.return_value = {
        "KmsKeyArn": "arn:aws:kms:eu-west-1:2:key/k",
        "ConfigBucketName": "acme-org-config-logs-222222222222",
    }
    bundle = _bundle(
        cloudtrail_kms=True,
        config={"enabled": True, "include_global_resources": False, "recording_frequency": "DAILY"},
    )
    bundle.org.organization.additional_regions = ["us-east-1"]

    deploy_config_recorder(
        _session(), cfn_service, bundle, "eu-west-1", ROOT, {"log-archive": "222222222222"}
    )

    kwargs = service.return_value.deploy.call_args.kwargs
    assert kwargs["regions"] == ["eu-west-1", "us-east-1"]
    assert kwargs["management_account_id"] == MGMT
    assert kwargs["parameters"] == {
        "DeliveryBucketName": "acme-org-config-logs-222222222222",
        "DeliveryKmsKeyArn": "arn:aws:kms:eu-west-1:2:key/k",
        "GlobalResourcesRegion": "eu-west-1",
        "IncludeGlobalResources": "false",
        "RecordResourceCompliance": "false",
        "RecordingFrequency": "DAILY",
    }


def test_deploy_stops_with_guidance_when_the_log_archive_has_no_config_bucket_yet(monkeypatch):
    service = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    cfn_service = MagicMock()
    cfn_service._fetch_stack_outputs.return_value = {"KmsKeyArn": "arn"}
    bundle = _bundle(config={"enabled": True})

    with pytest.raises(GovernanceError, match="no AWS Config bucket") as raised:
        deploy_config_recorder(
            _session(), cfn_service, bundle, "eu-west-1", ROOT, {"log-archive": "222222222222"}
        )

    assert "--phase 3" in str(raised.value.details)
    service.assert_not_called()


def test_recording_frequency_is_continuous_unless_daily_is_asked_for():
    assert ConfigRecorderConfig().recording_frequency == "CONTINUOUS"
    assert ConfigRecorderConfig(recording_frequency="DAILY").recording_frequency == "DAILY"
    with pytest.raises(ValueError):
        ConfigRecorderConfig(recording_frequency="HOURLY")  # type: ignore[arg-type]


def test_failed_instances_fail_the_phase(monkeypatch):
    service = MagicMock()
    service.return_value.deploy.return_value = MagicMock(failures=["333 eu-west-1: OUTDATED x"])
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    cfn_service = MagicMock()
    cfn_service._fetch_stack_outputs.return_value = {"ConfigBucketName": "acme-org-config-logs-222222222222"}

    with pytest.raises(GovernanceError, match="not current"):
        deploy_config_recorder(
            _session(), cfn_service, _bundle(config={"enabled": True}), "eu-west-1", ROOT, {}
        )


def test_missing_log_archive_account_skips_with_a_warning(monkeypatch):
    messages: list[str] = []
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.print_warning", messages.append)
    service = MagicMock()
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    bundle = MagicMock()
    bundle.org.security_services = SecurityServicesConfig.model_validate(
        {"config_recorder": {"enabled": True}}
    )
    bundle.get_log_archive_account_name.return_value = "log-archive"
    bundle.resolve_account_id.return_value = None

    deploy_config_recorder(MagicMock(), MagicMock(), bundle, "eu-west-1", ROOT, {})

    service.assert_not_called()
    assert any("log-archive" in m for m in messages)


# --------------------------------------------------------------------------- templates


def _load(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=CfnLoader)


def test_recorder_template_records_everything_and_global_types_in_one_region_only():
    doc = _load(TEMPLATE)
    recorder = doc["Resources"]["ConfigRecorder"]["Properties"]
    condition, all_supported, _exclusion = recorder["RecordingGroup"]
    assert condition == "RecordCompliance"
    assert all_supported["AllSupported"] is True
    assert all_supported["IncludeGlobalResourceTypes"][0] == "RecordGlobalResources"
    # both must hold: global resources requested, and this is the designated Region
    assert doc["Conditions"]["RecordGlobalResources"] == [
        ["IncludeGlobalResources", "true"],
        ["AWS::Region", "GlobalResourcesRegion"],
    ]
    # CloudFormation starts the recorder once the channel exists, so ordering the two never finishes
    assert "DependsOn" not in doc["Resources"]["DeliveryChannel"]
    assert "DependsOn" not in doc["Resources"]["ConfigRecorder"]
    assert doc["Resources"]["DeliveryChannel"]["Properties"]["S3BucketName"] == "DeliveryBucketName"


def test_recorder_role_is_per_region_and_only_created_when_no_role_is_passed():
    doc = _load(TEMPLATE)
    role = doc["Resources"]["RecorderRole"]
    assert role["Condition"] == "CreateRecorderRole"
    assert "${AWS::Region}" in role["Properties"]["RoleName"]
    assert doc["Parameters"]["RecorderRoleArn"]["Default"] == ""


def test_recorder_template_sets_the_kms_key_and_recording_frequency():
    doc = _load(TEMPLATE)
    channel = doc["Resources"]["DeliveryChannel"]["Properties"]
    assert channel["S3KmsKeyArn"][0] == "HasKmsKey"  # otherwise Config falls back to SSE-S3
    assert doc["Parameters"]["RecordingFrequency"]["AllowedValues"] == ["CONTINUOUS", "DAILY"]
    assert doc["Resources"]["ConfigRecorder"]["Properties"]["RecordingMode"]["RecordingFrequency"] == (
        "RecordingFrequency"
    )


LOG_ARCHIVE = ROOT / "src/tarmac/templates/cloudformation" / "log-archive-hardening.yaml"


def test_config_gets_its_own_unlocked_bucket_and_cloudtrails_bucket_has_no_config_access():
    """AWS Config cannot deliver to a bucket with Object Lock default retention, so the buckets are separate."""
    doc = _load(LOG_ARCHIVE)
    resources = doc["Resources"]

    bucket = resources["ConfigLogsBucket"]
    assert bucket["Condition"] == "CreateConfigBucket"
    assert bucket["DeletionPolicy"] == "Retain"
    assert "ObjectLockEnabled" not in bucket["Properties"]
    assert "ObjectLockConfiguration" not in bucket["Properties"]

    trail_sids = {
        s["Sid"]
        for s in resources["OrganizationCloudTrailBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    }
    assert not {sid for sid in trail_sids if "Config" in sid}

    statements = resources["ConfigLogsBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    by_sid = {s["Sid"]: s for s in statements}
    assert {
        "AWSConfigAclCheck",
        "AWSConfigWrite",
        "AWSConfigRecorderRoleAclCheck",
        "AWSConfigRecorderRoleWrite",
    } <= set(by_sid)
    # The service principal (used by the management account's service-linked role) is limited by the documented
    # aws:SourceAccount condition, not by an organization key AWS Config does not document.
    for sid in ("AWSConfigAclCheck", "AWSConfigWrite"):
        assert by_sid[sid]["Condition"]["StringEquals"]["aws:SourceAccount"] == "ManagementAccountId"
        assert "aws:SourceOrgID" not in by_sid[sid]["Condition"]["StringEquals"]
    assert by_sid["AWSConfigWrite"]["Resource"].endswith("/AWSLogs/${ManagementAccountId}/Config/*")
    # Member account recorder roles are limited to this organization and their role name.
    assert (
        by_sid["AWSConfigRecorderRoleWrite"]["Condition"]["StringEquals"]["aws:PrincipalOrgID"]
        == "OrganizationId"
    )
    assert by_sid["AWSConfigRecorderRoleWrite"]["Resource"].endswith("/AWSLogs/*/Config/*")


def test_config_bucket_is_only_created_when_enabled_and_needs_the_management_account():
    doc = _load(LOG_ARCHIVE)
    assert doc["Parameters"]["EnableConfigDelivery"]["Default"] == "false"
    assert doc["Parameters"]["ManagementAccountId"]["Default"] == ""
    assert doc["Resources"]["ConfigLogsBucketPolicy"]["Condition"] == "CreateConfigBucket"
    assert "ConfigDeliveryNeedsManagementAccount" in doc["Rules"]
    assert doc["Outputs"]["ConfigBucketName"]["Condition"] == "CreateConfigBucket"
    key_statements = doc["Resources"]["LogArchiveKmsKey"]["Properties"]["KeyPolicy"]["Statement"]
    conditional = [s for s in key_statements if isinstance(s, list) and s[0] == "CreateConfigBucket"]
    assert len(conditional) == 2  # recorder roles + the management account's service principal


@pytest.mark.parametrize(("enabled", "expected"), [(False, ("false", "")), (True, ("true", MGMT))])
def test_log_archive_stack_parameters_turn_on_config_delivery_only_when_enabled(enabled, expected):
    params = log_archive_parameters(_bundle(config={"enabled": enabled}), "o-abc1234567", MGMT)  # type: ignore[arg-type]

    assert (params["EnableConfigDelivery"], params["ManagementAccountId"]) == expected


def test_destroy_empties_and_deletes_the_config_bucket_with_the_other_log_buckets():
    mgr = _session()
    svc = TeardownService(mgr)
    bundle = MagicMock()
    bundle.org.organization.name = "acme"
    bundle.get_log_archive_account_name.return_value = "log-archive"
    bundle.resolve_account_id.return_value = "222222222222"
    svc.cfn_service = MagicMock()
    svc.cfn_service._get_stack_status.return_value = "CREATE_COMPLETE"
    svc.cfn_service._fetch_stack_outputs.return_value = {
        "AccessLogsBucketName": "acme-access-logs-ec042910",
        "CloudTrailBucketName": "acme-cloudtrail-logs-ec042910",
        "ConfigBucketName": "acme-config-logs-ec042910",
    }

    items = svc.teardown_log_archive(
        bundle, "eu-west-1", dry_run=True, account_id_map={"log-archive": "222222222222"}
    )

    assert {i.resource_name for i in items if i.resource_type == "S3 Bucket"} == {
        "acme-access-logs-ec042910",
        "acme-cloudtrail-logs-ec042910",
        "acme-config-logs-ec042910",
    }


# -- ResourceCompliance is left out unless asked for ---------------------------------------------------------

IAM_TYPES = ["AWS::IAM::Group", "AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User"]


def _recording_groups() -> tuple[dict[str, Any], dict[str, Any]]:
    doc = _load(TEMPLATE)
    _condition, all_supported, exclusion = doc["Resources"]["ConfigRecorder"]["Properties"]["RecordingGroup"]
    return all_supported, exclusion


def test_resource_compliance_is_off_by_default_in_the_template_and_the_config():
    assert _load(TEMPLATE)["Parameters"]["RecordResourceCompliance"]["Default"] == "false"
    assert ConfigRecorderConfig().record_resource_compliance is False


def test_without_resource_compliance_the_exclusion_strategy_is_used_as_the_docs_show():
    _all, exclusion = _recording_groups()
    # the combination the CloudFormation reference documents for EXCLUSION_BY_RESOURCE_TYPES
    assert exclusion["AllSupported"] is False
    assert exclusion["IncludeGlobalResourceTypes"] is False
    assert exclusion["RecordingStrategy"] == {"UseOnly": "EXCLUSION_BY_RESOURCE_TYPES"}


def test_the_global_region_excludes_only_resource_compliance():
    _all, exclusion = _recording_groups()
    condition, in_global_region, elsewhere = exclusion["ExclusionByResourceTypes"]["ResourceTypes"]
    assert condition == "RecordGlobalResources"
    assert in_global_region == ["AWS::Config::ResourceCompliance"]
    # the exclusion strategy does not drop IAM types by itself, so every other Region must list them
    assert elsewhere == ["AWS::Config::ResourceCompliance", *IAM_TYPES]


def test_the_deploy_passes_the_resource_compliance_choice_through(monkeypatch):
    service = MagicMock()
    service.return_value.deploy.return_value = MagicMock(
        failures=[], management_stacks=[], stack_set_action="CREATED"
    )
    monkeypatch.setattr("tarmac.cli.deploy_config_recorder.ConfigRecorderService", service)
    cfn_service = MagicMock()
    cfn_service._fetch_stack_outputs.return_value = {"ConfigBucketName": "b"}
    bundle = _bundle(config={"enabled": True, "record_resource_compliance": True})

    deploy_config_recorder(
        _session(), cfn_service, bundle, "eu-west-1", ROOT, {"log-archive": "222222222222"}
    )

    assert service.return_value.deploy.call_args.kwargs["parameters"]["RecordResourceCompliance"] == "true"
