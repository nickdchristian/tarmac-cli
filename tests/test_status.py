"""StatusService and DriftService tests."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock


def test_status_service_inspect_end_to_end(sample_config_dir: Path):
    """Verify StatusService.inspect end-to-end against live AWS resource state."""
    from tarmac.core.config_loader import load_all_configs
    from tarmac.services.status import StatusService

    bundle, errors = load_all_configs(sample_config_dir)
    assert bundle is not None
    assert not errors

    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_cfn_mgmt = MagicMock()
    mock_cfn_dep = MagicMock()
    mock_sso = MagicMock()

    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-live123", "FeatureSet": "ALL"}}
    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-root-live"}]}

    # Paginator for list_accounts
    accts_paginator = MagicMock()
    accts_paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111111111111", "Name": "Deployment", "Status": "ACTIVE"},
                {"Id": "222222222222", "Name": "Production", "Status": "ACTIVE"},
                {"Id": "333333333333", "Name": "ClosedOld", "Status": "SUSPENDED"},
            ]
        }
    ]
    ous_paginator = MagicMock()
    ous_paginator.paginate.side_effect = lambda ParentId: (
        [{"OrganizationalUnits": [{"Id": "ou-infra", "Name": "Infrastructure"}]}]
        if ParentId == "r-root-live"
        else [{"OrganizationalUnits": []}]
    )

    def org_paginator_side_effect(op: str) -> MagicMock:
        return accts_paginator if op == "list_accounts" else ous_paginator

    mock_org.get_paginator.side_effect = org_paginator_side_effect

    # CFN Stacks: CloudTrail on mgmt, Backend on deployment
    mock_cfn_mgmt.describe_stacks.return_value = {
        "Stacks": [{"StackName": "flumen-organization-cloudtrail", "StackStatus": "CREATE_COMPLETE"}]
    }
    mock_cfn_dep.describe_stacks.return_value = {
        "Stacks": [{"StackName": "flumen-terraform-backend", "StackStatus": "CREATE_COMPLETE"}]
    }

    mock_sso.list_instances.return_value = {
        "Instances": [{"InstanceArn": "arn:aws:sso:::instance/sso-test", "IdentityStoreId": "d-123"}]
    }

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn_mgmt
        if service_name == "sso-admin":
            return mock_sso
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_session_mgr.get_member_client.return_value = mock_cfn_dep

    status_service = StatusService(mock_session_mgr)
    status = status_service.inspect(bundle, target_region="eu-west-1")

    assert status.org_id == "o-live123"
    assert status.feature_set == "ALL"
    assert status.accounts_live == 2  # 2 active
    assert status.accounts_suspended == 1  # 1 suspended
    assert status.cloudtrail_status == "CREATE_COMPLETE"
    assert status.backend_status == "CREATE_COMPLETE"
    assert status.sso_configured is True


def test_drift_service_inspect_in_sync(sample_config_dir):
    from tarmac.core.config_loader import load_all_configs
    from tarmac.services.drift import DriftService

    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None
    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()

    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-root123"}]}

    def get_paginator(operation_name: str) -> MagicMock:
        p = MagicMock()
        if operation_name in ["list_organizational_units_for_parent", "list_children"]:
            p.paginate.return_value = [
                {
                    "OrganizationalUnits": [
                        {"Id": f"ou-{ou.name.lower()}", "Name": ou.name} for ou in bundle.org.ou_structure
                    ]
                }
            ]
        elif operation_name == "list_accounts":
            p.paginate.return_value = [
                {
                    "Accounts": [
                        {"Id": f"11111111111{i}", "Name": a.name, "Status": "ACTIVE"}
                        for i, a in enumerate(bundle.accounts.accounts)
                    ]
                }
            ]
        elif operation_name == "list_policies":
            p.paginate.return_value = [
                {
                    "Policies": [
                        {"Id": f"p-{p.name}", "Name": p.name}
                        for p in bundle.org.service_control_policies.policies
                    ]
                }
            ]
        elif operation_name == "list_targets_for_policy":
            p.paginate.return_value = [{"Targets": [{"TargetId": "r-root123"}]}]
        else:
            p.paginate.return_value = [{"Tags": []}]
        return p

    mock_org.get_paginator.side_effect = get_paginator
    mock_org.describe_policy.return_value = {
        "Policy": {"Content": '{"Version": "2012-10-17", "Statement": []}'}
    }

    mock_cfn.describe_stacks.return_value = {
        "Stacks": [{"StackName": "test-stack", "StackStatus": "CREATE_COMPLETE"}]
    }

    def client_side_effect(service_name: str, **kwargs: Any) -> MagicMock:
        if service_name == "organizations":
            return mock_org
        if service_name == "cloudformation":
            return mock_cfn
        return MagicMock()

    mock_session_mgr.get_client.side_effect = client_side_effect
    mock_session_mgr.get_member_client.return_value = mock_cfn

    drift_service = DriftService(mock_session_mgr)
    report = drift_service.inspect_drift(bundle, target_region="eu-west-1", project_root=sample_config_dir)

    assert report.in_sync_count > 0
    assert isinstance(report.has_drift, bool)


def test_status_service_handles_member_role_assumption_failure(sample_config_dir):
    """Verify StatusService.inspect sets backend_status='ACCESS_ERROR' when member role assumption fails."""
    from tarmac.core.config_loader import load_all_configs
    from tarmac.core.exceptions import AWSAuthenticationError
    from tarmac.services.status import StatusService

    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None

    mock_session_mgr = MagicMock()
    mock_org = MagicMock()
    mock_cfn = MagicMock()

    mock_org.describe_organization.return_value = {"Organization": {"Id": "o-test123", "FeatureSet": "ALL"}}
    mock_org.list_roots.return_value = {"Roots": [{"Id": "r-root"}]}
    paginator = MagicMock()
    paginator.paginate.side_effect = lambda **kw: (
        [{"OrganizationalUnits": []}]
        if "ParentId" in kw
        else [{"Accounts": [{"Id": "222233334444", "Name": "deployment", "Status": "ACTIVE"}]}]
    )
    mock_org.get_paginator.return_value = paginator
    mock_cfn.describe_stacks.return_value = {"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}

    mock_session_mgr.get_client.side_effect = lambda s, **kw: mock_org if s == "organizations" else mock_cfn
    mock_session_mgr.get_member_client.side_effect = AWSAuthenticationError(
        "Failed to assume role into account 222233334444"
    )

    status = StatusService(mock_session_mgr).inspect(bundle, "eu-west-1")
    assert status.backend_status == "ACCESS_ERROR"
