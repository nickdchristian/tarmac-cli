"""Tests for Service Control Policies (SCP) engine and CLI commands."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tarmac.core.config_schema import SCPDef, ServiceControlPoliciesConfig
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


def test_sync_policy_creates_new():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    mock_client.create_policy.return_value = {
        "Policy": {"PolicySummary": {"Id": "p-new123", "Name": "DenyMemberRootActivity"}}
    }

    service = SCPService(mock_session)
    policy_id, action = service.sync_policy(
        name="DenyMemberRootActivity",
        description="Guardrail",
        content='{"Version":"2012-10-17","Statement":[]}',
        existing_scps={},
        dry_run=False,
    )

    assert policy_id == "p-new123"
    assert action == "CREATED"
    mock_client.create_policy.assert_called_once()


def test_sync_policy_updates_drifted():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    mock_client.describe_policy.return_value = {
        "Policy": {"Content": '{"Version":"2012-10-17","Statement":[{"Sid":"Old"}]}'}
    }

    service = SCPService(mock_session)
    existing_scps = {
        "DenyMemberRootActivity": {
            "Id": "p-existing1",
            "Name": "DenyMemberRootActivity",
            "Description": "Guardrail",
        }
    }

    new_content = '{"Version":"2012-10-17","Statement":[{"Sid":"New"}]}'
    policy_id, action = service.sync_policy(
        name="DenyMemberRootActivity",
        description="Guardrail",
        content=new_content,
        existing_scps=existing_scps,
        dry_run=False,
    )

    assert policy_id == "p-existing1"
    assert action == "UPDATED"
    mock_client.update_policy.assert_called_once_with(
        PolicyId="p-existing1",
        Name="DenyMemberRootActivity",
        Description="Guardrail",
        Content=new_content,
    )


def test_sync_policy_unchanged():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    raw_json = json.dumps({"Version": "2012-10-17", "Statement": []})
    mock_client.describe_policy.return_value = {"Policy": {"Content": raw_json}}

    service = SCPService(mock_session)
    existing_scps = {
        "DenyMemberRootActivity": {
            "Id": "p-existing1",
            "Name": "DenyMemberRootActivity",
            "Description": "Guardrail",
        }
    }

    policy_id, action = service.sync_policy(
        name="DenyMemberRootActivity",
        description="Guardrail",
        content=raw_json,
        existing_scps=existing_scps,
        dry_run=False,
    )

    assert policy_id == "p-existing1"
    assert action == "NOOP"
    mock_client.update_policy.assert_not_called()


def test_sync_policy_dry_run():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    service = SCPService(mock_session)
    policy_id, action = service.sync_policy(
        name="DenyMemberRootActivity",
        description="Guardrail",
        content="{}",
        existing_scps={},
        dry_run=True,
    )

    assert policy_id == "DRY-RUN-POLICY-ID"
    assert action == "SIMULATED_CREATE"
    mock_client.create_policy.assert_not_called()


def test_attach_policy_if_needed():
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    service = SCPService(mock_session)

    res = service.attach_policy_if_needed(
        policy_id="p-123",
        target_id="r-root1",
        target_name="Root",
        attached_targets=["r-root1"],
        dry_run=False,
    )
    assert res is False
    mock_client.attach_policy.assert_not_called()

    res2 = service.attach_policy_if_needed(
        policy_id="p-123",
        target_id="r-root1",
        target_name="Root",
        attached_targets=[],
        dry_run=False,
    )
    assert res2 is True
    mock_client.attach_policy.assert_called_once_with(PolicyId="p-123", TargetId="r-root1")

    mock_client.reset_mock()
    res3 = service.attach_policy_if_needed(
        policy_id="p-123",
        target_id="ou-sec",
        target_name="Security",
        attached_targets=[],
        dry_run=True,
    )
    assert res3 is True
    mock_client.attach_policy.assert_not_called()

    mock_client.reset_mock()
    from botocore.exceptions import ClientError

    not_enabled_err = ClientError(
        {"Error": {"Code": "PolicyTypeNotEnabledException", "Message": "Not enabled"}},
        "AttachPolicy",
    )
    mock_client.attach_policy.side_effect = [not_enabled_err, {}]
    res4 = service.attach_policy_if_needed(
        policy_id="p-123",
        target_id="ou-sec",
        target_name="Security",
        attached_targets=[],
        dry_run=False,
        delay=0.01,
    )
    assert res4 is True
    assert mock_client.attach_policy.call_count == 2


def test_reconcile_all(tmp_path: Path):
    policy_file = tmp_path / "policies" / "scp" / "deny-root.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17"}', encoding="utf-8")

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    mock_client.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Policies": []}]
    mock_client.get_paginator.return_value = paginator

    mock_client.create_policy.return_value = {
        "Policy": {"PolicySummary": {"Id": "p-new", "Name": "DenyMemberRootActivity"}}
    }
    mock_client.list_targets_for_policy.return_value = {"Targets": []}

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

    service = SCPService(mock_session)
    results = service.reconcile_all(
        config=config,
        root_id="r-root1",
        ou_map={"Security": "ou-sec-1"},
        project_root=tmp_path,
        dry_run=False,
    )

    assert len(results) == 1
    assert results[0].name == "DenyMemberRootActivity"
    assert results[0].policy_id == "p-new"
    assert results[0].action_taken == "CREATED"
    assert "Root (r-root1)" in results[0].attached_targets
    assert "Security (ou-sec-1)" in results[0].attached_targets


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


def test_attach_policy_handles_duplicate_attachment_gracefully():
    """Verify DuplicatePolicyAttachmentException from eventual consistency is treated as a graceful no-op."""
    from botocore.exceptions import ClientError

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    dupe_err = ClientError(
        {"Error": {"Code": "DuplicatePolicyAttachmentException", "Message": "Policy already attached"}},
        "AttachPolicy",
    )
    mock_client.attach_policy.side_effect = dupe_err

    service = SCPService(mock_session)
    attached = service.attach_policy_if_needed(
        policy_id="p-123",
        target_id="ou-sec",
        target_name="Security",
        attached_targets=[],  # not known locally, but already attached in AWS
        dry_run=False,
    )

    assert attached is False
    mock_client.attach_policy.assert_called_once_with(PolicyId="p-123", TargetId="ou-sec")


def test_sync_policy_constraint_violation_wrapped():
    """Verify AWS 5120-byte ConstraintViolationException is wrapped into GovernanceError."""
    import pytest
    from botocore.exceptions import ClientError

    from tarmac.core.exceptions import GovernanceError

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    quota_err = ClientError(
        {
            "Error": {
                "Code": "ConstraintViolationException",
                "Message": "The maximum size of the policy document is 5120 characters",
            }
        },
        "CreatePolicy",
    )
    mock_client.create_policy.side_effect = quota_err

    service = SCPService(mock_session)
    with pytest.raises(GovernanceError) as exc_info:
        service.sync_policy(
            name="OversizedPolicy",
            description="Too large",
            content='{"Version":"2012-10-17","Statement":[]}',
            existing_scps={},
            dry_run=False,
        )

    assert "Failed to create SCP 'OversizedPolicy'" in str(exc_info.value)
    assert "5120 characters" in (exc_info.value.details or "")


def test_reconcile_scp_unresolved_target_skipped_without_crashing(tmp_path: Path):
    """Verify that an invalid or unresolvable target in SCP configuration is logged and skipped."""
    policy_file = tmp_path / "policies" / "scp" / "deny-root.json"
    policy_file.parent.mkdir(parents=True, exist_ok=True)
    policy_file.write_text('{"Version":"2012-10-17"}', encoding="utf-8")

    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.get_client.return_value = mock_client

    mock_client.list_roots.return_value = {
        "Roots": [{"Id": "r-root1", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
    }
    mock_client.create_policy.return_value = {
        "Policy": {"PolicySummary": {"Id": "p-new", "Name": "DenyMemberRootActivity"}}
    }
    mock_client.list_targets_for_policy.return_value = {"Targets": []}

    service = SCPService(mock_session)
    scp_def = SCPDef(
        name="DenyMemberRootActivity",
        description="Deny member root",
        policy_file="policies/scp/deny-root.json",
        targets=["root", "NonExistentOU"],  # NonExistentOU cannot be resolved
    )

    result = service.reconcile_scp(
        scp_def=scp_def,
        existing_scps={},
        root_id="r-root1",
        ou_map={"Security": "ou-sec-1"},
        project_root=tmp_path,
        dry_run=False,
    )

    assert result.name == "DenyMemberRootActivity"
    assert result.policy_id == "p-new"
    # Root attached, NonExistentOU safely skipped
    assert "Root (r-root1)" in result.attached_targets
    assert not any("NonExistentOU" in t for t in result.attached_targets)


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

    mock_cfn.delete_stack.assert_called_once_with(StackName="myorg-organization-scps")
    mock_cfn.create_change_set.assert_called_once()
    call_kwargs = mock_cfn.create_change_set.call_args.kwargs
    assert call_kwargs["ChangeSetType"] == "IMPORT"
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
