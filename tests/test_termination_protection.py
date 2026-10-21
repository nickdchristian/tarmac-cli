"""Stacks that hold the log bucket, keys, state and access role are protected until a teardown is asked to remove them."""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.exceptions import DeploymentError
from tarmac.services.cloudformation import CloudFormationService

STACK = "acme-log-archive-hardening"


def _cfn(protected: bool, status: str = "CREATE_COMPLETE") -> MagicMock:
    cfn = MagicMock()
    cfn.describe_stacks.return_value = {
        "Stacks": [{"StackStatus": status, "EnableTerminationProtection": protected}]
    }
    return cfn


def _service() -> CloudFormationService:
    return CloudFormationService(MagicMock())


def test_protect_turns_protection_on():
    cfn = _cfn(protected=False)

    _service().protect_stack(cfn, STACK)

    cfn.update_termination_protection.assert_called_once_with(
        StackName=STACK, EnableTerminationProtection=True
    )


def test_protect_leaves_an_already_protected_stack_alone():
    cfn = _cfn(protected=True)

    _service().protect_stack(cfn, STACK)

    cfn.update_termination_protection.assert_not_called()


def test_missing_permission_to_protect_is_reported_not_raised():
    cfn = _cfn(protected=False)
    cfn.update_termination_protection.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "UpdateTerminationProtection"
    )

    _service().protect_stack(cfn, STACK)  # must not raise: the deployment itself succeeded


def test_a_protected_stack_is_not_deleted_by_default():
    cfn = _cfn(protected=True)

    with pytest.raises(DeploymentError, match="termination protection"):
        _service().delete_stack(cfn, STACK)

    cfn.delete_stack.assert_not_called()


def test_teardown_releases_protection_and_says_so():
    cfn = _cfn(protected=True)
    progress: list[str] = []

    deleted = _service().delete_stack(
        cfn, STACK, wait=False, on_progress=progress.append, release_protection=True
    )

    assert deleted is True
    cfn.update_termination_protection.assert_called_once_with(
        StackName=STACK, EnableTerminationProtection=False
    )
    cfn.delete_stack.assert_called_once_with(StackName=STACK)
    assert any("termination protection" in m for m in progress)


def test_an_unprotected_stack_deletes_without_touching_protection():
    cfn = _cfn(protected=False)

    _service().delete_stack(cfn, STACK, wait=False, release_protection=True)

    cfn.update_termination_protection.assert_not_called()
    cfn.delete_stack.assert_called_once_with(StackName=STACK)


def test_deploy_protects_the_stack_when_asked(monkeypatch):
    service = _service()
    monkeypatch.setattr(service, "_get_stack_status", lambda *_a: None)
    monkeypatch.setattr(service, "_execute_deployment", lambda *_a, **_k: "CREATED")
    monkeypatch.setattr(service, "_fetch_stack_outputs", lambda *_a: {})
    cfn = _cfn(protected=False)

    service.deploy_stack(cfn, STACK, template_body="Resources: {}", termination_protection=True)

    cfn.update_termination_protection.assert_called_once_with(
        StackName=STACK, EnableTerminationProtection=True
    )


def test_deploy_does_not_protect_by_default(monkeypatch):
    service = _service()
    monkeypatch.setattr(service, "_get_stack_status", lambda *_a: None)
    monkeypatch.setattr(service, "_execute_deployment", lambda *_a, **_k: "CREATED")
    monkeypatch.setattr(service, "_fetch_stack_outputs", lambda *_a: {})
    cfn = _cfn(protected=False)

    service.deploy_stack(cfn, STACK, template_body="Resources: {}")

    cfn.update_termination_protection.assert_not_called()
