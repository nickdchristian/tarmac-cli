"""AWS Organizations and Management Account Governance Service."""

import logging
import re
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .. import __version__
from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import normalize_account_name
from ..core.config_schema import ContactsConfig, RootAccessConfig
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code, aws_error_message
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
    # Required before Phase 5 can delegate Config administration to the Audit account.
    "config-multiaccountsetup.amazonaws.com",
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
            return self._describe_organization_id()
        except self.org_client.exceptions.AWSOrganizationsNotInUseException:
            return self._create_organization()
        except ClientError as e:
            raise GovernanceError("Failed to describe AWS Organization", details=aws_error_message(e)) from e

    def _describe_organization_id(self) -> str:
        org_id = self.org_client.describe_organization()["Organization"]["Id"]
        logger.debug("AWS Organization active: %s", org_id)
        return str(org_id)

    def _create_organization(self) -> str:
        logger.debug("Creating new AWS Organization with FeatureSet='ALL'...")
        try:
            org_id = self.org_client.create_organization(FeatureSet="ALL")["Organization"]["Id"]
        except ClientError as e:
            if aws_error_code(e) == "AlreadyInOrganizationException":
                # Another run created it between our describe and create calls.
                try:
                    return self._describe_organization_id()
                except ClientError as describe_error:
                    raise GovernanceError(
                        "Failed to describe AWS Organization", details=aws_error_message(describe_error)
                    ) from describe_error
            raise GovernanceError("Failed to create AWS Organization", details=aws_error_message(e)) from e
        audit(
            "create",
            f"organization:{org_id}",
            Outcome.SUCCEEDED,
            f"Created AWS Organization {org_id} with all features enabled",
            org_id=org_id,
        )
        return str(org_id)

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
            if self._contact_already_set(contact_type, contact_data):
                audit(
                    "update",
                    f"alternate-contact:{contact_type}",
                    Outcome.UNCHANGED,
                    f"{contact_type} alternate contact is already {contact_data.email}",
                    contact_type=contact_type,
                )
                continue
            try:
                self.account_client.put_alternate_contact(
                    AlternateContactType=contact_type,
                    Name=contact_data.name,
                    Title=contact_data.title,
                    EmailAddress=contact_data.email,
                    PhoneNumber=contact_data.phone,
                )
                audit(
                    "update",
                    f"alternate-contact:{contact_type}",
                    Outcome.SUCCEEDED,
                    f"Set {contact_type} alternate contact on the management account to {contact_data.email}",
                    contact_type=contact_type,
                )
                updated.append(contact_type)
            except ClientError as e:
                audit(
                    "update",
                    f"alternate-contact:{contact_type}",
                    Outcome.FAILED,
                    f"Could not set {contact_type} alternate contact: {aws_error_message(e)}",
                    contact_type=contact_type,
                )
                raise GovernanceError(
                    f"Failed to set {contact_type} contact",
                    details=aws_error_message(e),
                ) from e

        return updated

    def _contact_already_set(self, contact_type: str, desired: Any) -> bool:
        """True when the management account already has this exact alternate contact."""
        try:
            response = self.account_client.get_alternate_contact(AlternateContactType=contact_type)
        except (ClientError, BotoCoreError):  # not set yet, or not readable: just write it
            return False
        current = response.get("AlternateContact") if isinstance(response, dict) else None
        if not isinstance(current, dict):
            return False
        wanted = {
            "Name": desired.name,
            "Title": desired.title,
            "EmailAddress": desired.email,
            "PhoneNumber": desired.phone,
        }
        return all(str(current.get(key, "")).strip() == str(value).strip() for key, value in wanted.items())

    def _enabled_service_principals(self) -> set[str]:
        """Service principals that already have trusted access (empty when it cannot be read)."""
        try:
            paginator = self.org_client.get_paginator("list_aws_service_access_for_organization")
            return {
                str(item.get("ServicePrincipal", ""))
                for page in paginator.paginate()
                for item in page.get("EnabledServicePrincipals", [])
            }
        except (ClientError, BotoCoreError, TypeError, AttributeError):
            return set()

    def _enabled_root_features(self) -> set[str]:
        """Centralized root access features that are already on (empty when they cannot be read)."""
        try:
            response = self.iam_client.list_organizations_features()
        except (ClientError, BotoCoreError, TypeError, AttributeError):
            return set()
        features = response.get("EnabledFeatures", []) if isinstance(response, dict) else []
        return {str(f) for f in features} if isinstance(features, list) else set()

    def enable_trusted_services(self, services: list[str] | None = None) -> list[str]:
        """Enable trusted service access for foundational AWS services in Organizations."""
        target_services = services or DEFAULT_TRUSTED_SERVICES
        enabled = []
        already_enabled = self._enabled_service_principals()

        for service in target_services:
            if service in already_enabled:
                audit(
                    "enable",
                    f"trusted-access:{service}",
                    Outcome.UNCHANGED,
                    f"Trusted service access for {service} is already enabled",
                    service=service,
                )
                enabled.append(service)
                continue
            try:
                self.org_client.enable_aws_service_access(ServicePrincipal=service)
                audit(
                    "enable",
                    f"trusted-access:{service}",
                    Outcome.SUCCEEDED,
                    f"Enabled trusted service access for {service} in AWS Organizations",
                    service=service,
                )
                enabled.append(service)
            except ClientError as e:
                logger.warning("Could not enable %s: %s", service, aws_error_message(e))

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
        enabled_features = self._enabled_root_features()

        return {
            "iam_trusted_access": self._enable_iam_trusted_access(),
            "root_credentials_management": (
                self._enable_root_credentials(enabled_features)
                if config.enable_root_credentials_management
                else False
            ),
            "root_sessions": (
                self._enable_root_sessions(enabled_features) if config.enable_root_sessions else False
            ),
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
        except AWS_ERRORS as e:
            logger.warning("Could not query accounts for delegated admin: %s", e)
            return {}

    def _enable_iam_trusted_access(self) -> bool:
        if "iam.amazonaws.com" in self._enabled_service_principals():
            audit(
                "enable",
                "trusted-access:iam.amazonaws.com",
                Outcome.UNCHANGED,
                "Trusted service access for IAM is already enabled",
            )
            return True
        try:
            self.org_client.enable_aws_service_access(ServicePrincipal="iam.amazonaws.com")
            audit(
                "enable",
                "trusted-access:iam.amazonaws.com",
                Outcome.SUCCEEDED,
                "Enabled trusted service access for IAM in AWS Organizations",
            )
            return True
        except ClientError as e:
            msg = aws_error_message(e)
            self.last_error["iam_trusted_access"] = msg
            logger.warning("IAM trusted access: %s", msg)
            return False

    def _enable_root_credentials(self, enabled_features: set[str] | None = None) -> bool:
        if "RootCredentialsManagement" in (enabled_features or set()):
            audit(
                "enable",
                "root-credentials-management",
                Outcome.UNCHANGED,
                "Centralized root credentials management is already enabled",
            )
            return True
        try:
            self.iam_client.enable_organizations_root_credentials_management()
            audit(
                "enable",
                "root-credentials-management",
                Outcome.SUCCEEDED,
                "Enabled centralized root credentials management",
            )
            return True
        except ClientError as e:
            msg = aws_error_message(e)
            self.last_error["root_credentials_management"] = msg
            logger.warning("Root credentials management: %s", msg)
            return False

    def _enable_root_sessions(self, enabled_features: set[str] | None = None) -> bool:
        if "RootSessions" in (enabled_features or set()):
            audit(
                "enable",
                "root-sessions",
                Outcome.UNCHANGED,
                "Privileged root sessions for member accounts are already enabled",
            )
            return True
        try:
            self.iam_client.enable_organizations_root_sessions()
            audit(
                "enable",
                "root-sessions",
                Outcome.SUCCEEDED,
                "Enabled privileged root sessions for member accounts",
            )
            return True
        except ClientError as e:
            msg = aws_error_message(e)
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
            audit(
                "register",
                f"delegated-admin:iam.amazonaws.com:{admin_acct_id}",
                Outcome.SUCCEEDED,
                f"Registered {admin_account} ({admin_acct_id}) as IAM delegated administrator",
                account_id=admin_acct_id,
            )
            return True
        except ClientError as e:
            err_code = aws_error_code(e)
            err_msg = aws_error_message(e)
            if err_code == "AccountAlreadyRegisteredException":
                audit(
                    "register",
                    f"delegated-admin:iam.amazonaws.com:{admin_acct_id}",
                    Outcome.UNCHANGED,
                    f"Account {admin_acct_id} is already the IAM delegated administrator",
                    account_id=admin_acct_id,
                )
                return True
            detailed_err = f"[{err_code}] {err_msg}"
            self.last_error["delegated_admin"] = detailed_err
            logger.warning("Delegated admin registration: %s", detailed_err)
            return False

    def register_service_delegated_administrators(
        self, account_id: str, service_principals: list[str]
    ) -> list[str]:
        """Register an account as delegated administrator for the given AWS service principals.

        Every principal is attempted. Raises GovernanceError listing the ones that failed (an
        already-registered principal counts as success).
        """
        registered: list[str] = []
        failures: list[str] = []
        for sp in service_principals:
            try:
                self.org_client.register_delegated_administrator(AccountId=account_id, ServicePrincipal=sp)
                audit(
                    "register",
                    f"delegated-admin:{sp}:{account_id}",
                    Outcome.SUCCEEDED,
                    f"Registered account {account_id} as delegated administrator for {sp}",
                    account_id=account_id,
                    service=sp,
                )
                registered.append(sp)
            except ClientError as e:
                err_code = aws_error_code(e)
                if err_code == "AccountAlreadyRegisteredException":
                    audit(
                        "register",
                        f"delegated-admin:{sp}:{account_id}",
                        Outcome.UNCHANGED,
                        f"Account {account_id} is already delegated administrator for {sp}",
                        account_id=account_id,
                        service=sp,
                    )
                    registered.append(sp)
                else:
                    msg = aws_error_message(e)
                    logger.warning("Delegated admin registration for %s failed: [%s] %s", sp, err_code, msg)
                    failures.append(f"{sp}: [{err_code}] {msg}")
        if failures:
            raise GovernanceError(
                f"Could not register account {account_id} as delegated administrator for "
                f"{len(failures)} service(s).",
                details="\n".join(failures),
            )
        return registered

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
            audit(
                "tag",
                f"account:{mgmt_account_id}",
                Outcome.SUCCEEDED,
                f"Recorded phase '{phase_name}' as complete on management account {mgmt_account_id}",
                phase_name=phase_name,
            )
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
            audit(
                "tag",
                f"account:{mgmt_account_id}",
                Outcome.SUCCEEDED,
                f"Marked landing zone as ready on management account {mgmt_account_id}",
            )
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

            ce.update_cost_allocation_tags_status(
                CostAllocationTagsStatus=[{"TagKey": k, "Status": "Active"} for k in to_activate]
            )
            audit(
                "activate",
                "cost-allocation-tags",
                Outcome.SUCCEEDED,
                f"Activated {len(to_activate)} cost allocation tag(s): {', '.join(to_activate)}",
                tag_keys=to_activate,
            )
            return to_activate
        except ClientError as e:
            logger.warning("Could not activate cost allocation tags: %s", e)
            return []
        except AWS_ERRORS as e:
            logger.warning("Cost allocation tag activation failed: %s", e)
            return []
