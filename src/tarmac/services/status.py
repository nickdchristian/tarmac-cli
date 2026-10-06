"""Landing zone status and reconciliation inspector."""

import logging
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import IdentityCenterError
from .accounts import AccountService
from .identity import IdentityService
from .ou import OUService

logger = logging.getLogger(__name__)


@dataclass
class LandingZoneStatus:
    """Consolidated state comparison between declared config and live AWS environment."""

    org_id: str
    feature_set: str
    ous_declared: int
    ous_live: int
    accounts_declared: int
    accounts_live: int
    cloudtrail_status: str
    backend_status: str
    sso_configured: bool
    accounts_suspended: int = 0


class StatusService:
    """Inspects live AWS resources and compares them against declared config."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr = session_mgr

    def get_stack_status(self, client: Any, stack_name: str) -> str:
        """Fetch status of a CloudFormation stack or return NOT_FOUND."""
        try:
            resp = client.describe_stacks(StackName=stack_name)
            stacks = resp.get("Stacks", [])
            return str(stacks[0]["StackStatus"]) if stacks else "NOT_FOUND"
        except ClientError:
            return "NOT_FOUND"

    def inspect(self, bundle: ConfigBundle, target_region: str) -> LandingZoneStatus:
        """Inspect AWS Organization, OUs, accounts, stacks, and SSO state."""
        org_client = self.session_mgr.get_client("organizations")
        org_desc = org_client.describe_organization()["Organization"]
        org_id = str(org_desc.get("Id", "Unknown"))
        feature_set = str(org_desc.get("FeatureSet", "Unknown"))

        roots = org_client.list_roots().get("Roots", [])
        root_id = str(roots[0]["Id"]) if roots else ""

        ou_service = OUService(self.session_mgr)
        live_ous_map = ou_service.list_all_ous(root_id) if root_id else {}
        live_accts = AccountService(self.session_mgr).list_all_accounts()
        active_accts = [a for a in live_accts if a.get("Status") == "ACTIVE"]
        suspended_accts = [a for a in live_accts if a.get("Status") == "SUSPENDED"]

        cfn_client = self.session_mgr.get_client("cloudformation", region_name=target_region)
        ct_stack = f"{bundle.org.organization.name}-organization-cloudtrail"
        ct_status = self.get_stack_status(cfn_client, ct_stack)

        acct_map = {str(a["Name"]): str(a["Id"]) for a in active_accts}
        backend_name = bundle.get_backend_account_name() or "deployment"
        deployment_id = bundle.resolve_account_id(backend_name, acct_map)
        backend_stack = f"{bundle.org.organization.name}-terraform-backend"

        if deployment_id:
            dep_cfn = self.session_mgr.get_member_client(
                deployment_id, "cloudformation", region_name=target_region
            )
            backend_status = self.get_stack_status(dep_cfn, backend_stack)
        else:
            backend_status = self.get_stack_status(cfn_client, backend_stack)

        try:
            IdentityService.discover_instance(
                self.session_mgr, preferred_region=bundle.identity.identity_center.region
            )
            sso_configured = True
        except (IdentityCenterError, ClientError):
            sso_configured = False

        return LandingZoneStatus(
            org_id=org_id,
            feature_set=feature_set,
            ous_declared=ConfigBundle.count_declared_ous(bundle.org.ou_structure),
            ous_live=len(live_ous_map),
            accounts_declared=len(bundle.accounts.accounts),
            accounts_live=len(active_accts),
            cloudtrail_status=ct_status,
            backend_status=backend_status,
            sso_configured=sso_configured,
            accounts_suspended=len(suspended_accts),
        )
