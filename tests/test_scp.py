"""Tests for Service Control Policies (SCP) engine and CLI commands."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tarmac.core.adoption import set_adopt_existing
from tarmac.core.config_schema import SCPDef, ServiceControlPoliciesConfig
from tarmac.core.exceptions import GovernanceError
from tarmac.services.scp import SCPService


def test_ensure_scp_enabled_already_enabled():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    mock_client.list_roots.return_value = {
        "Roots": [
            {
                "Id": "r-test123",
                "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}],
            }
        ]
    }

    service = SCPService(mock_session)
    service.ensure_scp_enabled("r-test123")

    mock_client.enable_policy_type.assert_not_called()


def test_ensure_scp_enabled_needs_enabling():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    mock_client.list_roots.side_effect = [
        {"Roots": [{"Id": "r-test123", "PolicyTypes": []}]},
        {
            "Roots": [
                {
                    "Id": "r-test123",
                    "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}],
                }
            ]
        },
    ]

    service = SCPService(mock_session)
    service.ensure_scp_enabled("r-test123")

    mock_client.enable_policy_type.assert_called_once_with(
        RootId="r-test123", PolicyType="SERVICE_CONTROL_POLICY"
    )


def test_list_existing_scps():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Policies": [
                {"Id": "p-FullAWSAccess", "Name": "FullAWSAccess", "Type": "SERVICE_CONTROL_POLICY"},
                {"Id": "p-12345", "Name": "DenyMemberRootActivity", "Type": "SERVICE_CONTROL_POLICY"},
            ]
        }
    ]
    mock_client.get_paginator.return_value = paginator

    service = SCPService(mock_session)
    scps = service.list_existing_scps()

    assert "FullAWSAccess" in scps
    assert scps["DenyMemberRootActivity"]["Id"] == "p-12345"


def test_scp_synthesize_template(tmp_path: Path):
    policy_file = tmp_path / "policies" / "scp" / "deny-root.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")

    mock_session = MagicMock()
    service = SCPService(mock_session)
    config = ServiceControlPoliciesConfig(
        enabled=True,
        policies=[
            SCPDef(
                name="DenyMemberRootActivity",
                description="Deny member root",
                policy_file="policies/scp/deny-root.json",
                targets=["root", "Security"],
            )
        ],
    )
    tmpl = service.synthesize_template(config, "r-root1", {"Security": "ou-sec-1"}, tmp_path)
    assert tmpl["AWSTemplateFormatVersion"] == "2010-09-09"
    assert "ScpDenyMemberRootActivity" in tmpl["Resources"]
    props = tmpl["Resources"]["ScpDenyMemberRootActivity"]["Properties"]
    assert props["Name"] == "DenyMemberRootActivity"
    assert props["TargetIds"] == ["r-root1", "ou-sec-1"]
    assert tmpl["Resources"]["ScpDenyMemberRootActivity"]["DeletionPolicy"] == "Retain"


def test_scp_reconcile_via_cloudformation(tmp_path: Path):
    from botocore.exceptions import ClientError

    policy_file = tmp_path / "policies" / "scp" / "deny-root.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")

    mock_session = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()

    def get_client_side_effect(service_name: str, **kwargs):
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session.get_client.side_effect = get_client_side_effect
    mock_org.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }

    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": []}]},
    ]

    config = ServiceControlPoliciesConfig(
        enabled=True,
        policies=[
            SCPDef(
                name="DenyMemberRootActivity",
                description="Deny member root",
                policy_file="policies/scp/deny-root.json",
                targets=["root"],
            )
        ],
    )
    service = SCPService(mock_session)
    results = service.reconcile_via_cloudformation(
        config=config,
        root_id="r-root1",
        ou_map={},
        project_root=tmp_path,
        org_name="myorg",
        dry_run=False,
    )

    assert len(results) == 1
    assert results[0].name == "DenyMemberRootActivity"
    assert results[0].action_taken == "CREATED"
    mock_cfn.create_stack.assert_called_once()
    assert (tmp_path / "outputs" / "managed-scps.yaml").exists()


def test_scp_reconcile_via_cfn_fallback_when_preexisting_and_broken_stack(tmp_path: Path):
    policy_file = tmp_path / "policies" / "scp" / "deny-root.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")

    mock_session = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()

    def get_client_side_effect(service_name: str, **kwargs):
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session.get_client.side_effect = get_client_side_effect
    mock_org.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }

    # Policy already exists in AWS Organizations
    mock_org.get_paginator.return_value.paginate.return_value = [
        {"Policies": [{"Id": "p-existing", "Name": "DenyMemberRootActivity"}]}
    ]
    mock_org.describe_policy.return_value = {"Policy": {"Content": '{"Version":"2012-10-17","Statement":[]}'}}
    mock_org.list_targets_for_policy.return_value = {"Targets": [{"TargetId": "r-root1"}]}

    # Stack is in ROLLBACK_COMPLETE state
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "myorg-organization-scps", "StackStatus": "ROLLBACK_COMPLETE"}]
    }

    config = ServiceControlPoliciesConfig(
        enabled=True,
        policies=[
            SCPDef(
                name="DenyMemberRootActivity",
                description="Deny member root",
                policy_file="policies/scp/deny-root.json",
                targets=["root"],
            )
        ],
    )
    service = SCPService(mock_session)
    results = service.reconcile_via_cloudformation(
        config=config,
        root_id="r-root1",
        ou_map={},
        project_root=tmp_path,
        org_name="myorg",
        dry_run=False,
    )

    mock_cfn.delete_stack.assert_any_call(StackName="myorg-organization-scps")
    mock_cfn.create_change_set.assert_called_once()
    call_kwargs = mock_cfn.create_change_set.call_args.kwargs
    assert call_kwargs["ChangeSetType"] == "IMPORT"
    # IMPORT cannot change tags, so the import template is untagged; the ownership tag is applied by
    # the normal stack deployment that follows.
    assert "tarmac:managed-by" not in call_kwargs["TemplateBody"]
    final_body = (mock_cfn.create_stack.call_args or mock_cfn.update_stack.call_args).kwargs["TemplateBody"]
    assert "tarmac:managed-by" in final_body
    assert call_kwargs["ResourcesToImport"][0]["ResourceType"] == "AWS::Organizations::Policy"
    assert call_kwargs["ResourcesToImport"][0]["ResourceIdentifier"] == {"Id": "p-existing"}
    mock_cfn.execute_change_set.assert_called_once()
    assert len(results) == 1
    assert results[0].name == "DenyMemberRootActivity"
    assert results[0].policy_id == "p-existing"
    assert results[0].status == "SUCCEEDED"


def test_scp_reconcile_via_cfn_raises_on_deployment_error(tmp_path: Path):
    from tarmac.core.exceptions import DeploymentError

    policy_file = tmp_path / "policies" / "scp" / "deny-root.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")

    mock_session = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()

    def get_client_side_effect(service_name: str, **kwargs):
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session.get_client.side_effect = get_client_side_effect
    mock_org.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }
    mock_org.get_paginator.return_value.paginate.return_value = []

    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "ROLLBACK_COMPLETE"}]}
    mock_cfn.create_stack.side_effect = DeploymentError(
        "Waiter timed out",
        details="HandlerErrorCode: AlreadyExists; Policy already exists for policy name [DenyMemberRootActivity]",
    )

    config = ServiceControlPoliciesConfig(
        enabled=True,
        policies=[
            SCPDef(
                name="DenyMemberRootActivity",
                description="Deny member root",
                policy_file="policies/scp/deny-root.json",
                targets=["root"],
            )
        ],
    )
    service = SCPService(mock_session)
    with pytest.raises(DeploymentError) as exc_info:
        service.reconcile_via_cloudformation(
            config=config,
            root_id="r-root1",
            ou_map={},
            project_root=tmp_path,
            org_name="myorg",
            dry_run=False,
        )

    assert "Waiter timed out" in str(exc_info.value)


def test_normalize_json_falls_back_for_invalid_json():
    service = SCPService(MagicMock())
    assert service._normalize_json("  {not json  ") == "{not json"
    assert service._normalize_json("") == ""


def _unowned_service(live: str) -> SCPService:
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client
    mock_client.describe_policy.return_value = {"Policy": {"Content": live}}
    mock_client.get_paginator.return_value.paginate.return_value = [{"Tags": []}]
    return SCPService(mock_session)


_EXISTING = {"Guard": {"Id": "p-theirs", "Name": "Guard"}}
_THEIRS = '{"Version":"2012-10-17","Statement":[{"Sid":"TheirRule","Effect":"Deny","Action":"s3:*","Resource":"*"}]}'
_OURS = (
    '{"Version":"2012-10-17","Statement":[{"Sid":"OurRule","Effect":"Deny","Action":"ec2:*","Resource":"*"}]}'
)


def _declared_policy(tmp_path: Path, content: str):
    from types import SimpleNamespace

    (tmp_path / "ours.json").write_text(content)
    return SimpleNamespace(policies=[SimpleNamespace(name="Guard", policy_file=str(tmp_path / "ours.json"))])


def test_import_refuses_to_take_over_a_policy_tarmac_did_not_create(tmp_path: Path):
    service = _unowned_service(_THEIRS)

    with pytest.raises(GovernanceError) as exc:
        service._require_declared_policies_adoptable(_declared_policy(tmp_path, _OURS), _EXISTING, tmp_path)  # type: ignore[arg-type]

    assert "was not created by tarmac" in str(exc.value)
    assert "TheirRule" in str(exc.value)
    assert "--adopt-existing" in str(exc.value)


def test_import_adopts_an_unowned_policy_with_the_flag(tmp_path: Path):
    service = _unowned_service(_THEIRS)
    set_adopt_existing(True)

    service._require_declared_policies_adoptable(_declared_policy(tmp_path, _OURS), _EXISTING, tmp_path)  # type: ignore[arg-type]


def test_import_takes_over_an_unowned_policy_that_already_matches(tmp_path: Path):
    service = _unowned_service(_OURS)

    service._require_declared_policies_adoptable(_declared_policy(tmp_path, _OURS), _EXISTING, tmp_path)  # type: ignore[arg-type]


def test_scp_synthesize_template_disambiguates_colliding_logical_ids(tmp_path: Path):
    """Colliding sanitized SCP names and symbol-only names receive distinct alphanumeric logical IDs."""
    policy_file = tmp_path / "policies" / "scp" / "deny.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")

    config = ServiceControlPoliciesConfig(
        enabled=True,
        policies=[
            SCPDef(name="Deny-Root", policy_file="policies/scp/deny.json", targets=["root"]),
            SCPDef(name="Deny_Root", policy_file="policies/scp/deny.json", targets=["root"]),
            SCPDef(name="---", policy_file="policies/scp/deny.json", targets=["root"]),
        ],
    )
    service = SCPService(MagicMock())
    tmpl = service.synthesize_template(config, "r-root1", {}, tmp_path)
    resources = tmpl["Resources"]
    assert len(resources) == 3
    for logical_id in resources:
        assert logical_id.isalnum()
        assert logical_id != "Scp"


def test_scp_reconcile_via_cfn_imports_only_preexisting_when_mixed_with_new(tmp_path: Path):
    """When only a subset of declared SCPs exist in AWS, the IMPORT change set only includes those SCPs."""
    import yaml

    policy_file = tmp_path / "policies" / "scp" / "deny.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17","Statement":[]}', encoding="utf-8")

    mock_session = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()
    mock_session.get_client.side_effect = lambda s, **_: mock_org if s == "organizations" else mock_cfn
    mock_org.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }
    mock_org.get_paginator.return_value.paginate.return_value = [
        {"Policies": [{"Id": "p-existing", "Name": "ExistingGuard"}]}
    ]
    mock_org.describe_policy.return_value = {"Policy": {"Content": '{"Version":"2012-10-17","Statement":[]}'}}
    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "myorg-organization-scps", "StackStatus": "ROLLBACK_COMPLETE"}]
    }

    config = ServiceControlPoliciesConfig(
        enabled=True,
        policies=[
            SCPDef(name="ExistingGuard", policy_file="policies/scp/deny.json", targets=["root"]),
            SCPDef(name="BrandNewGuard", policy_file="policies/scp/deny.json", targets=["root"]),
        ],
    )
    service = SCPService(mock_session)
    service.reconcile_via_cloudformation(
        config=config,
        root_id="r-root1",
        ou_map={},
        project_root=tmp_path,
        org_name="myorg",
        dry_run=False,
    )

    import_kwargs = mock_cfn.create_change_set.call_args.kwargs
    import_doc = yaml.safe_load(import_kwargs["TemplateBody"])
    assert list(import_doc["Resources"].keys()) == ["ScpExistingGuard"]
    assert [r["LogicalResourceId"] for r in import_kwargs["ResourcesToImport"]] == ["ScpExistingGuard"]

    final_kwargs = (mock_cfn.create_stack.call_args or mock_cfn.update_stack.call_args).kwargs
    final_doc = yaml.safe_load(final_kwargs["TemplateBody"])
    assert set(final_doc["Resources"].keys()) == {"ScpExistingGuard", "ScpBrandNewGuard"}
