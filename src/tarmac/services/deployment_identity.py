"""Which tarmac deployment an organization holds, recorded once on the management account.

Stacks, buckets and the inventory are found by ``organization.name``, and the inventory by ``primary_region`` too.
CloudFormation can't rename stacks, so both are fixed once deployed. They are recorded as tags on the management
account in AWS Organizations (global, so readable from any Region), and every command that reaches AWS stops when the
config no longer matches them, instead of quietly looking for a deployment that isn't there.
"""

import logging

from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import GovernanceError
from ..core.models import TAG_COMPLETED_PHASES, TAG_HOME_REGION, TAG_NAME
from ..core.stack_names import LIVE_STACK_STATUSES, TARMAC_STACK_SUFFIXES, Stack

logger = logging.getLogger(__name__)


def _management_id(session_mgr: AwsSessionManager) -> str:
    return str(session_mgr.get_caller_identity().get("Account", ""))


def _management_tags(session_mgr: AwsSessionManager) -> dict[str, str]:
    try:
        org = session_mgr.get_client("organizations")
        return {
            str(tag["Key"]): str(tag["Value"])
            for page in org.get_paginator("list_tags_for_resource").paginate(
                ResourceId=_management_id(session_mgr)
            )
            for tag in page.get("Tags", [])
        }
    except (ClientError, BotoCoreError) as e:
        logger.debug("Could not read the management account's tags: %s", e)
        return {}


def recorded(session_mgr: AwsSessionManager) -> dict[str, str]:
    """The recorded name and home Region, by tag key; empty before the first deploy records them."""
    tags = _management_tags(session_mgr)
    return {key: tags[key] for key in (TAG_NAME, TAG_HOME_REGION) if key in tags}


# Stacks in the management account's home Region; the inventory stack is the one every deployment has.
_HOME_STACK_SUFFIXES = (*TARMAC_STACK_SUFFIXES, Stack.INVENTORY)


def _stack_prefixes(session_mgr: AwsSessionManager, region: str) -> set[str] | None:
    """The organization names tarmac's stacks in ``region`` are named after; None when they can't be listed."""
    try:
        cfn = session_mgr.get_client("cloudformation", region_name=region)
        names = [
            str(summary.get("StackName", ""))
            for page in cfn.get_paginator("list_stacks").paginate(StackStatusFilter=LIVE_STACK_STATUSES)
            for summary in page.get("StackSummaries", [])
        ]
    except (ClientError, BotoCoreError) as e:
        logger.debug("Could not list stacks to find the deployment: %s", e)
        return None
    return {
        name[: -len(suffix) - 1]
        for name in names
        for suffix in _HOME_STACK_SUFFIXES
        if name.endswith(f"-{suffix}")
    }


def _mismatch(differences: list[str], fix: str = "Set them back to the deployed values.") -> GovernanceError:
    return GovernanceError(
        "organization.yaml doesn't match the tarmac deployment in this organization.",
        details="; ".join(differences)
        + f". {fix} Tarmac finds its stacks, buckets and inventory by name and Region, and CloudFormation can't "
        "rename stacks. To deploy under a different name or Region instead, run `tarmac destroy --everything` "
        "with the deployed values first, then deploy with the new ones.",
    )


def check(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> None:
    """Stop when organization.name or primary_region differ from what this organization was deployed with.

    Deployments from before the tags are checked against their stacks in primary_region instead: stacks under
    another name mean the name changed, and none at all, while the management account records completed phases,
    mean the Region changed. Stacks left over under another name, next to ones under organization.name, are fine.
    """
    tags = _management_tags(session_mgr)
    org = bundle.org.organization
    if TAG_NAME not in tags:
        prefixes = _stack_prefixes(session_mgr, org.primary_region)
        if prefixes and org.name not in prefixes:
            tags[TAG_NAME] = ", ".join(sorted(prefixes))
        elif prefixes == set() and TAG_COMPLETED_PHASES in tags:
            raise _mismatch(
                [
                    "tarmac has deployed in this organization, but none of its stacks are in "
                    f"organization.primary_region '{org.primary_region}'"
                ],
                fix="Set it to the Region you deployed from (before 0.7 it defaulted to eu-west-1).",
            )
    differences = [
        f"{field} is '{configured}', but it was deployed as '{tags[key]}'"
        for field, key, configured in (
            ("organization.name", TAG_NAME, org.name),
            ("organization.primary_region", TAG_HOME_REGION, org.primary_region),
        )
        if key in tags and tags[key] != configured
    ]
    if differences:
        raise _mismatch(differences)


def record(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> None:
    """Record the name and home Region, once the inventory bucket has been found under them."""
    if recorded(session_mgr):
        return
    org = bundle.org.organization
    try:
        session_mgr.get_client("organizations").tag_resource(
            ResourceId=_management_id(session_mgr),
            Tags=[
                {"Key": TAG_NAME, "Value": org.name},
                {"Key": TAG_HOME_REGION, "Value": org.primary_region},
            ],
        )
    except (ClientError, BotoCoreError) as e:
        logger.warning(
            "Could not record the deployment's name and home Region on the management account: %s", e
        )
