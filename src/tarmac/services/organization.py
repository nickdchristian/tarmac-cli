"""AWS Organizations and Management Account Governance Service."""

import logging
import re
from typing import Any

from botocore.exceptions import ClientError

from .. import __version__
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import ContactsConfig, RootAccessConfig
from ..core.exceptions import GovernanceError
from ..core.models import (
    STATUS_IN_PROGRESS,
    STATUS_READY,
    TAG_COMPLETED_PHASES,
    TAG_MANAGED_BY,
    TAG_STATUS,
    TAG_VERSION,
)

logger = logging.getLogger(__name__)

DEFAULT_TRUSTED_SERVICES = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "member.org.stacksets.cloudformation.amazonaws.com",
]


class OrganizationService:
    """Manages AWS Organizations creation, trusted services, contacts, and root access."""

    def __init__(self, session_mgr: AwsSessionManager):
        self.session_mgr: AwsSessionManager = session_mgr
        self.org_client: Any = session_mgr.get_client("organizations")
        self.account_client: Any = session_mgr.get_client("account")
        self.iam_client: Any = session_mgr.get_client("iam")
        self.last_error: dict[str, str] = {}

    def ensure_organization(self) -> str:
        """Ensure AWS Organizations is enabled with ALL features. Returns Org ID."""
        try:
            resp = self.org_client.describe_organization()
            org_id = resp["Organization"]["Id"]
            logger.info("AWS Organization already active: %s", org_id)
            return org_id
        except self.org_client.exceptions.AWSOrganizationsNotInUseException:
            logger.info("Creating new AWS Organization with FeatureSet='ALL'...")
            try:
                resp = self.org_client.create_organization(FeatureSet="ALL")
                org_id = resp["Organization"]["Id"]
                logger.info("Created AWS Organization: %s", org_id)
                return org_id
            except ClientError as e:
                raise GovernanceError("Failed to create AWS Organization", details=str(e)) from e
        except ClientError as e:
            if e.response["Error"]["Code"] == "AlreadyInOrganizationException":
                resp = self.org_client.describe_organization()
                return resp["Organization"]["Id"]
            raise GovernanceError("Failed to describe AWS Organization", details=str(e)) from e

    def set_account_contacts(self, contacts: ContactsConfig) -> list[str]:
        """Configure alternate contacts (Billing, Operations, Security) on the management account.

        Returns a list of successfully updated contact types.
        """
        contact_map = {
            "BILLING": contacts.billing,
            "OPERATIONS": contacts.operations,
            "SECURITY": contacts.security,
        }
        updated = []

        for contact_type, contact_data in contact_map.items():
            try:
                self.account_client.put_alternate_contact(
                    AlternateContactType=contact_type,
                    Name=contact_data.name,
                    Title=contact_data.title,
                    EmailAddress=contact_data.email,
                    PhoneNumber=contact_data.phone,
                )
                logger.info("Set alternate contact for %s (%s)", contact_type, contact_data.email)
                updated.append(contact_type)
            except ClientError as e:
                logger.error("Failed to set %s contact: %s", contact_type, e)
                raise GovernanceError(
                    f"Failed to set {contact_type} contact",
                    details=e.response["Error"].get("Message", str(e)),
                ) from e

        return updated

    def enable_trusted_services(self, services: list[str] | None = None) -> list[str]:
        """Enable trusted service access for foundational AWS services in Organizations."""
        target_services = services or DEFAULT_TRUSTED_SERVICES
        enabled = []

        for service in target_services:
            try:
                self.org_client.enable_aws_service_access(ServicePrincipal=service)
                logger.info("Enabled trusted service access for %s", service)
                enabled.append(service)
            except ClientError as e:
                logger.warning("Could not enable %s: %s", service, e.response["Error"].get("Message"))

        return enabled

    def configure_root_access(
        self, config: RootAccessConfig, account_id_map: dict[str, str] | None = None
    ) -> dict[str, bool]:
        """Configure centralized root access management and optional delegated administrator."""
        if not config.enabled:
            logger.info("Root access management is disabled in configuration.")
            return {
                "iam_trusted_access": False,
                "root_credentials_management": False,
                "root_sessions": False,
                "delegated_admin": False,
            }

        resolved_map = self._resolve_account_id_map(account_id_map) if config.delegated_admin_account else {}

        return {
            "iam_trusted_access": self._enable_iam_trusted_access(),
            "root_credentials_management": (
                self._enable_root_credentials() if config.enable_root_credentials_management else False
            ),
            "root_sessions": self._enable_root_sessions() if config.enable_root_sessions else False,
            "delegated_admin": (
                self._register_delegated_admin(config.delegated_admin_account, resolved_map)
                if config.delegated_admin_account and resolved_map
                else False
            ),
        }

    def _resolve_account_id_map(self, account_id_map: dict[str, str] | None) -> dict[str, str]:
        """Resolve map of active account names to account IDs."""
        if account_id_map is not None:
            return dict(account_id_map)
        try:
            paginator = self.org_client.get_paginator("list_accounts")
            return {
                a["Name"]: a["Id"]
                for page in paginator.paginate()
                for a in page.get("Accounts", [])
                if a.get("Status") == "ACTIVE"
            }
        except Exception as e:
            logger.warning("Could not query accounts for delegated admin: %s", e)
            return {}

    def _enable_iam_trusted_access(self) -> bool:
        """Enable trusted access for IAM in Organizations."""
        try:
            self.org_client.enable_aws_service_access(ServicePrincipal="iam.amazonaws.com")
            logger.info("Enabled trusted access for IAM in Organizations")
            return True
        except ClientError as e:
            msg = e.response["Error"].get("Message", str(e))
            self.last_error["iam_trusted_access"] = msg
            logger.warning("IAM trusted access: %s", msg)
            return False

    def _enable_root_credentials(self) -> bool:
        """Enable Organizations root credentials management."""
        try:
            self.iam_client.enable_organizations_root_credentials_management()
            logger.info("Enabled Organizations root credentials management")
            return True
        except ClientError as e:
            msg = e.response["Error"].get("Message", str(e))
            self.last_error["root_credentials_management"] = msg
            logger.warning("Root credentials management: %s", msg)
            return False

    def _enable_root_sessions(self) -> bool:
        """Enable Organizations privileged root sessions."""
        try:
            self.iam_client.enable_organizations_root_sessions()
            logger.info("Enabled Organizations privileged root sessions")
            return True
        except ClientError as e:
            msg = e.response["Error"].get("Message", str(e))
            self.last_error["root_sessions"] = msg
            logger.warning("Root sessions: %s", msg)
            return False

    def _register_delegated_admin(self, admin_account: str, account_id_map: dict[str, str]) -> bool:
        """Register IAM delegated administrator account."""
        admin_acct_id = account_id_map.get(admin_account)
        if not admin_acct_id:
            norm_target = normalize_account_name(admin_account)
            for k, v in account_id_map.items():
                if normalize_account_name(k) == norm_target:
                    admin_acct_id = v
                    break
        if not admin_acct_id:
            err_msg = (
                f"Delegated admin account '{admin_account}' not found in active accounts: "
                f"{list(account_id_map.keys())}"
            )
            self.last_error["delegated_admin"] = err_msg
            logger.warning(err_msg)
            return False
        try:
            self.org_client.register_delegated_administrator(
                AccountId=admin_acct_id,
                ServicePrincipal="iam.amazonaws.com",
            )
            logger.info("Registered %s (%s) as IAM delegated admin", admin_account, admin_acct_id)
            return True
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            err_msg = e.response.get("Error", {}).get("Message", "")
            if err_code == "AccountAlreadyRegisteredException":
                logger.info("Account %s is already registered as IAM delegated admin", admin_acct_id)
                return True
            detailed_err = f"[{err_code}] {err_msg}"
            self.last_error["delegated_admin"] = detailed_err
            logger.warning("Delegated admin registration: %s", detailed_err)
            return False

    def get_completed_phases(self, mgmt_account_id: str) -> set[str]:
        """Retrieve the set of completed deployment phases from Management Account tags."""
        try:
            paginator = self.org_client.get_paginator("list_tags_for_resource")
            for page in paginator.paginate(ResourceId=mgmt_account_id):
                for tag in page.get("Tags", []):
                    if tag.get("Key") == TAG_COMPLETED_PHASES:
                        val = str(tag.get("Value", "")).strip()
                        return {p for p in re.split(r"[,+\s]+", val) if p}
        except ClientError as e:
            logger.debug("Could not query tags on management account %s: %s", mgmt_account_id, e)
        return set()

    def record_phase_completed(
        self, mgmt_account_id: str, phase_name: str, version: str = __version__
    ) -> set[str]:
        """Record a completed phase on the Management Account in AWS Organizations."""
        current_phases = self.get_completed_phases(mgmt_account_id)
        current_phases.add(phase_name)
        val = "+".join(sorted(current_phases))
        try:
            self.org_client.tag_resource(
                ResourceId=mgmt_account_id,
                Tags=[
                    {"Key": TAG_COMPLETED_PHASES, "Value": val},
                    {"Key": TAG_VERSION, "Value": version},
                    {"Key": TAG_STATUS, "Value": STATUS_IN_PROGRESS},
                    {"Key": TAG_MANAGED_BY, "Value": "tarmac"},
                ],
            )
            logger.info("Recorded phase '%s' on management account %s", phase_name, mgmt_account_id)
        except ClientError as e:
            logger.warning("Could not record phase '%s' tag on management account: %s", phase_name, e)
        return current_phases

    def mark_deployment_ready(self, mgmt_account_id: str, version: str = __version__) -> None:
        """Mark the overall landing zone deployment as 'ready' on the Management Account."""
        try:
            current_phases = self.get_completed_phases(mgmt_account_id)
            val = "+".join(sorted(current_phases)) if current_phases else "all"
            self.org_client.tag_resource(
                ResourceId=mgmt_account_id,
                Tags=[
                    {"Key": TAG_STATUS, "Value": STATUS_READY},
                    {"Key": TAG_VERSION, "Value": version},
                    {"Key": TAG_COMPLETED_PHASES, "Value": val},
                    {"Key": TAG_MANAGED_BY, "Value": "tarmac"},
                ],
            )
            logger.info("Marked landing zone status as 'ready' on management account %s", mgmt_account_id)
        except ClientError as e:
            logger.warning("Could not mark landing zone ready on management account: %s", e)

    def activate_cost_allocation_tags(self, tag_keys: list[str]) -> list[str]:
        """Activate user-defined and AWS-generated cost allocation tags in AWS Cost Explorer.

        Queries inactive tags in Cost Explorer (us-east-1 billing endpoint) and activates any
        that match the target tag keys. Returns list of activated tag keys.
        """
        if not tag_keys:
            return []

        target_keys = set(tag_keys)

        try:
            ce = self.session_mgr.get_client("ce", region_name="us-east-1")
            paginator = ce.get_paginator("list_cost_allocation_tags")
            to_activate: list[str] = []

            for page in paginator.paginate(Status="Inactive"):
                for tag in page.get("CostAllocationTags", []):
                    k = str(tag.get("TagKey", ""))
                    if k in target_keys:
                        to_activate.append(k)

            if not to_activate:
                logger.debug("No inactive cost allocation tags matching target keys found to activate.")
                return []

            logger.info("Activating %d cost allocation tag(s): %s", len(to_activate), to_activate)
            ce.update_cost_allocation_tags_status(
                CostAllocationTagsStatus=[{"TagKey": k, "Status": "Active"} for k in to_activate]
            )
            return to_activate
        except ClientError as e:
            logger.warning("Could not activate cost allocation tags: %s", e)
            return []
        except Exception as e:
            logger.warning("Cost allocation tag activation failed: %s", e)
            return []
