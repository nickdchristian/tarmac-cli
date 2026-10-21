"""`cloudtrail.enable_kms` unset: SSE-S3 for a new deployment, an existing KMS key is kept."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import CloudTrailConfig
from tarmac.core.exceptions import DeploymentError
from tarmac.services.log_encryption import existing_kms_choice, resolve_log_encryption


def _client_error(message: str) -> ClientError:
    return ClientError({"Error": {"Code": "ValidationError", "Message": message}}, "DescribeStacks")


def _cfn(parameter_value: str | None = None, *, missing: bool = False, error: str | None = None) -> MagicMock:
    cfn = MagicMock()
    if missing:
        cfn.describe_stacks.side_effect = _client_error("Stack with id x does not exist")
    elif error:
        cfn.describe_stacks.side_effect = _client_error(error)
    else:
        params = (
            []
            if parameter_value is None
            else [{"ParameterKey": "EnableKmsEncryption", "ParameterValue": parameter_value}]
        )
        cfn.describe_stacks.return_value = {"Stacks": [{"Parameters": params}]}
    return cfn


def _bundle(enable_kms: bool | None) -> Any:
    trail = CloudTrailConfig()
    if enable_kms is not None:
        trail.enable_kms = enable_kms
    org = SimpleNamespace(cloudtrail=trail, organization=SimpleNamespace(name="acme"))
    return SimpleNamespace(org=org)


def _session(cfn: MagicMock) -> MagicMock:
    session = MagicMock()
    session.get_member_client.return_value = cfn
    return session


def test_the_default_is_unset():
    assert CloudTrailConfig().enable_kms is None


def test_a_new_deployment_gets_sse_s3():
    bundle = _bundle(None)
    assert resolve_log_encryption(_session(_cfn(missing=True)), bundle, "us-east-1", "111122223333") is False
    assert bundle.org.cloudtrail.enable_kms is False


def test_an_existing_deployment_with_the_key_keeps_it():
    bundle = _bundle(None)
    assert resolve_log_encryption(_session(_cfn("true")), bundle, "us-east-1", "111122223333") is True
    assert bundle.org.cloudtrail.enable_kms is True


def test_an_existing_deployment_without_the_key_stays_without_it():
    bundle = _bundle(None)
    assert resolve_log_encryption(_session(_cfn("false")), bundle, "us-east-1", "111122223333") is False


@pytest.mark.parametrize("explicit", [True, False])
def test_an_explicit_setting_wins_and_nothing_is_read(explicit):
    cfn = _cfn("true")
    bundle = _bundle(explicit)
    assert resolve_log_encryption(_session(cfn), bundle, "us-east-1", "111122223333") is explicit
    cfn.describe_stacks.assert_not_called()


def test_without_a_log_archive_account_the_answer_is_sse_s3():
    session = MagicMock()
    assert resolve_log_encryption(session, _bundle(None), "us-east-1", "") is False
    session.get_member_client.assert_not_called()


def test_a_read_failure_stops_instead_of_guessing():
    """Guessing 'false' here could silently drop the key from a deployment that has it."""
    with pytest.raises(DeploymentError):
        resolve_log_encryption(
            _session(_cfn(error="Access denied")), _bundle(None), "us-east-1", "111122223333"
        )


def test_a_stack_without_the_parameter_reads_as_unknown():
    assert existing_kms_choice(_cfn(None), "acme-log-archive-hardening") is None
