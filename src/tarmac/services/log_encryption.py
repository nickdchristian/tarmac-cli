"""Decide whether the CloudTrail log archive uses a customer managed KMS key.

CloudTrail encrypts delivered logs with SSE-S3 by default, and AWS describes SSE-KMS as "an added layer of security"
(Security Hub control CloudTrail.2). The default here is the cheaper option, SSE-S3. A deployment that already has the
key keeps it unless `cloudtrail.enable_kms: false` is written down, so upgrading never lowers its encryption.
"""

from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import DeploymentError, aws_error_message
from ..core.stack_names import Stack

PARAMETER = "EnableKmsEncryption"


def existing_kms_choice(cfn_client: Any, stack_name: str) -> str | None:
    """'true' or 'false' when the stack exists with the parameter, None when it does not. Other errors raise."""
    try:
        stacks = cfn_client.describe_stacks(StackName=stack_name).get("Stacks", [])
    except ClientError as e:
        if "does not exist" in aws_error_message(e):
            return None
        raise DeploymentError(
            f"Could not read stack {stack_name} to decide on KMS encryption", details=str(e)
        ) from e
    if not isinstance(stacks, list) or not stacks:
        return None
    for param in stacks[0].get("Parameters", []) or []:
        if isinstance(param, dict) and param.get("ParameterKey") == PARAMETER:
            return str(param.get("ParameterValue"))
    return None


def resolve_log_encryption(
    session_mgr: AwsSessionManager, bundle: ConfigBundle, region: str, log_archive_id: str
) -> bool:
    """Settle `cloudtrail.enable_kms` when it is unset, record the answer on the bundle, and return it."""
    trail = bundle.org.cloudtrail
    if trail.enable_kms is not None:
        return trail.enable_kms
    keep_key = False
    if log_archive_id:
        cfn = session_mgr.get_member_client(log_archive_id, "cloudformation", region_name=region)
        keep_key = existing_kms_choice(cfn, Stack.LOG_ARCHIVE.for_org(bundle.org.organization.name)) == "true"
    trail.enable_kms = keep_key
    return keep_key
