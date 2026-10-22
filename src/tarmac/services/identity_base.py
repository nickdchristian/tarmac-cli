"""IAM Identity Center instance discovery, shared by the IdentityService mixins."""

import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import IdentityCenterError

logger = logging.getLogger(__name__)

SUPPORTED_SSO_REGIONS: list[str] = [
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "eu-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "sa-east-1",
    "ap-south-1",
]


def _build_candidate_regions(session_mgr: AwsSessionManager, preferred_region: str | None) -> list[str]:
    """Build unique ordered list of candidate regions to probe for Identity Center."""
    candidates: list[str] = []
    if preferred_region:
        candidates.append(preferred_region)
    if session_mgr.default_region and session_mgr.default_region not in candidates:
        candidates.append(session_mgr.default_region)
    for r in SUPPORTED_SSO_REGIONS:
        if r not in candidates:
            candidates.append(r)
    return candidates


def _probe_region_for_instance(session_mgr: AwsSessionManager, region: str) -> tuple[str, str] | None:
    """Probe a single region for an IAM Identity Center instance."""
    try:
        client = session_mgr.get_client("sso-admin", region_name=region)
        instances = client.list_instances().get("Instances", [])
        if instances:
            arn = instances[0].get("InstanceArn")
            store_id = instances[0].get("IdentityStoreId")
            if arn and store_id:
                return str(arn), str(store_id)
    except (ClientError, BotoCoreError) as e:
        logger.debug("Could not probe sso-admin in region %s: %s", region, e)
    return None


class IdentityBase:
    """Finds the Identity Center instance and holds the clients for it."""

    def __init__(self, session_mgr: AwsSessionManager, preferred_region: str | None = None):
        self.session_mgr: AwsSessionManager = session_mgr
        self.preferred_region: str | None = preferred_region
        self._discovered_region: str = preferred_region or session_mgr.default_region
        self.sso_client: Any = session_mgr.get_client("sso-admin", region_name=self._discovered_region)
        self.identitystore_client: Any = session_mgr.get_client(
            "identitystore", region_name=self._discovered_region
        )
        self._instance_arn: str | None = None
        self._identity_store_id: str | None = None

    @classmethod
    def discover_instance(
        cls,
        session_mgr: AwsSessionManager,
        preferred_region: str | None = None,
    ) -> tuple[str, str, str]:
        """Discover the active IAM Identity Center instance across candidate AWS regions.

        Returns:
            tuple[str, str, str]: (instance_arn, identity_store_id, region)
        """
        candidates = _build_candidate_regions(session_mgr, preferred_region)
        for region in candidates:
            found = _probe_region_for_instance(session_mgr, region)
            if found:
                arn, store_id = found
                logger.debug("Discovered active IAM Identity Center in '%s' (ARN: %s)", region, arn)
                return arn, store_id, region

        raise IdentityCenterError(
            "No IAM Identity Center instance found across AWS regions.",
            details="Ensure IAM Identity Center is enabled in the AWS Console (in any supported region).",
        )

    @property
    def region(self) -> str:
        """Return the active region of the IAM Identity Center instance."""
        if not self._instance_arn:
            self.get_instance_details()
        return self._discovered_region

    def get_instance_details(self) -> tuple[str, str]:
        """Fetch the SSO Instance ARN and Identity Store ID, auto-discovering region if needed."""
        if self._instance_arn and self._identity_store_id:
            return self._instance_arn, self._identity_store_id

        arn, store_id, discovered_region = self.discover_instance(
            self.session_mgr, preferred_region=self.preferred_region
        )
        self._instance_arn = arn
        self._identity_store_id = store_id
        if discovered_region != self._discovered_region:
            self._discovered_region = discovered_region
            self.sso_client = self.session_mgr.get_client("sso-admin", region_name=discovered_region)
            self.identitystore_client = self.session_mgr.get_client(
                "identitystore", region_name=discovered_region
            )

        return self._instance_arn, self._identity_store_id
