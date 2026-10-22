"""Landing zone status and reconciliation inspector."""

import logging
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS, IdentityCenterError
from ..core.org_accounts import is_active, is_closed
from ..core.stack_names import Stack
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


def stack_status(client: Any, stack_name: str) -> str:
    """Status of a CloudFormation stack, or NOT_FOUND when it cannot be described."""
    try:
        stacks = client.describe_stacks(StackName=stack_name).get("Stacks", [])
        return str(stacks[0]["StackStatus"]) if stacks else "NOT_FOUND"
    except ClientError:
        return "NOT_FOUND"


class StatusService:
    """Inspects live AWS resources and compares them against declared config."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr = session_mgr

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
        active_accts = [a for a in live_accts if is_active(a)]
        suspended_accts = [a for a in live_accts if is_closed(a)]

        cfn_client = self.session_mgr.get_client("cloudformation", region_name=target_region)
        acct_map = {str(a["Name"]): str(a["Id"]) for a in active_accts}
        audit_id = bundle.resolve_account_id(bundle.get_audit_account_name() or "audit", acct_map)
        ct_status = "NOT_FOUND"
        if audit_id:
            try:
                audit_cfn = self.session_mgr.get_member_client(
                    audit_id, "cloudformation", region_name=target_region
                )
                ct_status = stack_status(audit_cfn, Stack.CLOUDTRAIL.for_org(bundle.org.organization.name))
            except AWS_ERRORS as e:
                logger.debug("Could not inspect CloudTrail stack in account %s: %s", audit_id, e)
                ct_status = "ACCESS_ERROR"

        backend_name = bundle.get_backend_account_name() or "deployment"
        deployment_id = bundle.resolve_account_id(backend_name, acct_map)
        backend_stack = Stack.TERRAFORM_BACKEND.for_org(bundle.org.organization.name)

        if deployment_id:
            try:
                dep_cfn = self.session_mgr.get_member_client(
                    deployment_id, "cloudformation", region_name=target_region
                )
                backend_status = stack_status(dep_cfn, backend_stack)
            except AWS_ERRORS as e:
                logger.debug("Could not inspect backend stack in account %s: %s", deployment_id, e)
                backend_status = "ACCESS_ERROR"
        else:
            backend_status = stack_status(cfn_client, backend_stack)

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
