"""Terraform state locking: S3-only unless enable_dynamodb is on, with a warning when a table would be dropped."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from tarmac.core.config_schema import TerraformBackendConfig
from tarmac.services.cloudformation import lock_table_wanted

STACK = "acme-terraform-backend"


def _cfn(enable_dynamodb: str | None) -> MagicMock:
    cfn = MagicMock()
    if enable_dynamodb is None:
        cfn.describe_stacks.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": f"Stack with id {STACK} does not exist"}},
            "DescribeStacks",
        )
    else:
        cfn.describe_stacks.return_value = {
            "Stacks": [
                {"Parameters": [{"ParameterKey": "EnableDynamoDB", "ParameterValue": enable_dynamodb}]}
            ]
        }
    return cfn


def test_the_default_is_s3_only():
    assert TerraformBackendConfig().enable_dynamodb is False


def test_a_new_backend_is_s3_only_by_default():
    assert lock_table_wanted(_cfn(None), STACK, False) == (False, None)


def test_an_existing_s3_only_backend_stays_s3_only():
    assert lock_table_wanted(_cfn("false"), STACK, False) == (False, None)


def test_asking_for_the_table_creates_or_keeps_it():
    assert lock_table_wanted(_cfn(None), STACK, True) == (True, None)
    assert lock_table_wanted(_cfn("true"), STACK, True) == (True, None)


def test_removing_an_existing_table_is_allowed_but_warned_about():
    wanted, warning = lock_table_wanted(_cfn("true"), STACK, False)

    assert wanted is False
    assert warning is not None
    assert "use_lockfile" in warning
    assert "enable_dynamodb: true" in warning


def test_an_unreadable_stack_counts_as_new():
    cfn = MagicMock()
    cfn.describe_stacks.return_value = MagicMock()
    assert lock_table_wanted(cfn, STACK, False) == (False, None)
