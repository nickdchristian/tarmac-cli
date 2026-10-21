"""Management account root activity alert: on by default, cheap, and removed again by teardown."""

from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
import yaml

from tarmac.cli.deploy_root_alert import (
    deploy_management_root_alert,
    root_alert_regions,
)
from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.config_loader import ConfigBundle, load_all_configs
from tarmac.core.config_schema import RootAlertConfig
from tarmac.core.stack_names import Stack
from tarmac.services.teardown import TeardownService

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def test_bundle(sample_config_dir) -> ConfigBundle:
    bundle, errors = load_all_configs(sample_config_dir)
    assert bundle is not None
    assert not errors
    return bundle


def _template() -> dict[str, Any]:
    class Loader(yaml.SafeLoader):
        pass

    Loader.add_multi_constructor("!", lambda loader, suffix, node: None)
    return cast(
        dict[str, Any],
        yaml.load(
            (ROOT / "src/tarmac/templates/cloudformation" / "management-root-alert.yaml").read_text(), Loader
        ),
    )


def _bundle(test_bundle, *, email: str | None = "sec@example.com", **root_alert: Any):
    test_bundle.org.contacts.security.email = email
    test_bundle.org.security_services.incident_response_webhook_url = None
    test_bundle.org.security_services.root_alert = RootAlertConfig(**root_alert)
    test_bundle.org.organization.primary_region = "eu-west-1"
    test_bundle.org.organization.additional_regions = ["eu-central-1"]
    return test_bundle


def _deploy(bundle) -> MagicMock:
    mgr = MagicMock(spec=AwsSessionManager)
    cfn_service = MagicMock()
    deploy_management_root_alert(mgr, cfn_service, bundle, "eu-west-1", ROOT, dry_run=False)
    return cfn_service


def test_the_alert_is_on_by_default_and_watches_two_regions():
    cfg = RootAlertConfig()
    assert cfg.enabled is True
    assert cfg.all_regions is False


def test_the_regions_are_us_east_1_and_the_primary_region(test_bundle):
    assert root_alert_regions(_bundle(test_bundle), "eu-west-1") == ["us-east-1", "eu-west-1"]


def test_all_regions_adds_the_declared_regions(test_bundle):
    regions = root_alert_regions(_bundle(test_bundle, all_regions=True), "eu-west-1")
    assert regions == ["us-east-1", "eu-west-1", "eu-central-1"]


def test_a_primary_region_of_us_east_1_is_not_deployed_twice(test_bundle):
    assert root_alert_regions(_bundle(test_bundle), "us-east-1") == ["us-east-1"]


def test_it_deploys_one_stack_per_region(test_bundle):
    bundle = _bundle(test_bundle)

    cfn_service = _deploy(bundle)

    assert cfn_service.deploy_stack.call_count == 2
    names = {call.args[1] for call in cfn_service.deploy_stack.call_args_list}
    assert names == {Stack.ROOT_ALERT.for_org(bundle.org.organization.name)}
    params = cfn_service.deploy_stack.call_args_list[0].args[3]
    assert params["AlertEmail"] == "sec@example.com"


def test_it_is_skipped_when_nobody_would_receive_it(test_bundle):
    cfn_service = _deploy(_bundle(test_bundle, email=None))

    cfn_service.deploy_stack.assert_not_called()


def test_it_can_be_turned_off(test_bundle):
    cfn_service = _deploy(_bundle(test_bundle, enabled=False))

    cfn_service.deploy_stack.assert_not_called()


def test_the_template_matches_only_root_activity():
    rule = _template()["Resources"]["RootActivityRule"]["Properties"]["EventPattern"]

    assert rule["detail"]["userIdentity"]["type"] == ["Root"]
    assert set(rule["detail-type"]) == {"AWS Console Sign In via CloudTrail", "AWS API Call via CloudTrail"}


def test_the_template_needs_no_iam_role():
    kinds = {r["Type"] for r in _template()["Resources"].values()}

    assert not any(k.startswith("AWS::IAM::") for k in kinds)


def _teardown(cfn: MagicMock) -> TeardownService:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.default_region = "us-east-1"
    mgr.get_client.return_value = cfn
    mgr.get_caller_identity.return_value = {"Account": "111122223333"}
    return TeardownService(mgr)


def test_teardown_deletes_the_alert_stack_where_it_exists(test_bundle):
    cfn = MagicMock()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}
    bundle = _bundle(test_bundle)

    items = _teardown(cfn).teardown_root_alert(bundle, "eu-west-1")

    assert {i.action for i in items} == {"DELETED"}
    assert len(items) == 3  # us-east-1, the primary Region and the one additional Region


def test_teardown_dry_run_deletes_nothing(test_bundle):
    cfn = MagicMock()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}

    items = _teardown(cfn).teardown_root_alert(_bundle(test_bundle), "eu-west-1", dry_run=True)

    assert {i.action for i in items} == {"SIMULATED"}
    cfn.delete_stack.assert_not_called()
