"""Pydantic data models for validating AWS Governance configuration files."""

import re
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator

from .tagging import validate_tags


def _validate_bucket_prefix(v: str) -> str:
    if not (3 <= len(v) <= 40):
        raise ValueError(f"S3 bucket prefix must be between 3 and 40 characters (received {len(v)}).")
    if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", v):
        raise ValueError(
            f"S3 bucket prefix '{v}' must be lowercase alphanumeric and may contain hyphens, "
            "and cannot start or end with a hyphen."
        )
    if "--" in v:
        raise ValueError(f"S3 bucket prefix '{v}' cannot contain consecutive hyphens ('--').")
    return v


class Contact(BaseModel):
    name: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    email: EmailStr
    phone: str = Field(..., min_length=5)


class ContactsConfig(BaseModel):
    billing: Contact
    operations: Contact
    security: Contact


class RootAccessConfig(BaseModel):
    """Centralized root access management configuration for AWS Organizations.

    AWS allows organizations to centrally govern member account root access:
    - Root credentials management: Centrally manage and recover root credentials for member
      accounts without needing console access or access to member email inboxes.
    - Privileged root sessions: Allow authorized administrators to open audited, short-lived
      temporary root sessions via AWS STS/SSM, eliminating permanent root passwords.
    - Delegated administration: Register a dedicated security account (e.g. 'audit') to issue
      and manage root sessions without logging into the management/payer account.
    """

    enabled: bool = Field(
        default=True,
        description="Enable centralized root access management features across the organization.",
    )
    enable_root_credentials_management: bool = Field(
        default=True,
        description=(
            "Centrally manage root user credentials (passwords, MFA, access keys) for member accounts "
            "from the organization level without requiring member console login."
        ),
    )
    enable_root_sessions: bool = Field(
        default=True,
        description=(
            "Allow authorized principals to initiate short-lived, privileged root sessions in member accounts "
            "via AWS STS/SSM for emergency break-glass operations, avoiding permanent root passwords."
        ),
    )
    delegated_admin_account: str | None = Field(
        default=None,
        description=(
            "Account name (e.g. 'audit') to register as the IAM delegated administrator, "
            "allowing security operators to manage root credentials and privileged sessions without payer access."
        ),
    )


class OUDef(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = ""
    children: list["OUDef"] = Field(default_factory=list)


class CloudTrailConfig(BaseModel):
    trail_name: str = Field(default="organization-trail")
    bucket_prefix: str = Field(default="org-cloudtrail")
    enable_kms: bool = Field(default=True)
    log_archive_account: str | None = Field(
        default="log-archive",
        description="Designates the account name hosting centralized CloudTrail logs.",
    )

    @field_validator("bucket_prefix")
    def validate_bucket_prefix(cls, v: str) -> str:
        return _validate_bucket_prefix(v)


class TerraformBackendConfig(BaseModel):
    account: str | None = Field(
        default="deployment",
        description="Designates the account name hosting Terraform remote state.",
    )
    bucket_prefix: str = Field(default="org-terraform-state")
    dynamodb_table_name: str = Field(default="terraform-state-lock")
    enable_dynamodb: bool = Field(default=True)

    @field_validator("bucket_prefix")
    def validate_bucket_prefix(cls, v: str) -> str:
        return _validate_bucket_prefix(v)


class OrgDetails(BaseModel):
    name: str = Field(..., min_length=2, max_length=32)
    domain: str = Field(..., min_length=3)
    primary_region: str = Field(
        default="eu-west-1", description="Primary AWS deployment and governance region."
    )
    additional_regions: list[str] = Field(
        default_factory=list,
        description=(
            "Additional operational regions for multi-region security services (GuardDuty, Security Hub) "
            "and preflight quota validations."
        ),
    )
    delete_default_vpc: bool = Field(
        default=True,
        description="Purge default VPCs, subnets, and internet gateways across all enabled AWS regions in the management account.",
    )
    tags: dict[str, str] = Field(default_factory=dict)
    cost_allocation_tags: list[str] = Field(default_factory=list)

    @field_validator("name")
    def name_must_be_lowercase_alphanumeric(cls, v: str) -> str:
        if not v.replace("-", "").isalnum() or not v.islower():
            raise ValueError("Organization name must be lowercase alphanumeric (hyphens allowed)")
        return v

    @field_validator("tags")
    def validate_org_details_tags(cls, v: dict[str, Any]) -> dict[str, str]:
        return validate_tags(v)


class SCPDef(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    policy_file: str = Field(..., min_length=1)
    targets: list[str] = Field(default_factory=lambda: ["root"])


class ServiceControlPoliciesConfig(BaseModel):
    enabled: bool = True
    policies: list[SCPDef] = Field(default_factory=list)


class GuardDutyFeaturesConfig(BaseModel):
    s3_data_events: bool = False
    eks_audit_logs: bool = False
    malware_protection: bool = False


class GuardDutyConfig(BaseModel):
    enabled: bool = False
    auto_enable_members: bool = True
    features: GuardDutyFeaturesConfig = Field(default_factory=GuardDutyFeaturesConfig)


class SecurityHubConfig(BaseModel):
    enabled: bool = False
    auto_enable_members: bool = True
    standards: list[str] = Field(default_factory=lambda: ["aws-foundational-security-best-practices"])


def _validate_webhook_url(v: str | None) -> str | None:
    if v is not None and not v.startswith("https://"):
        raise ValueError("Incident response webhook URL must start with 'https://'.")
    return v


def _validate_max_subscribers(v: list[EmailStr], service_name: str) -> list[EmailStr]:
    if len(v) > 10:
        raise ValueError(
            f"AWS {service_name} supports a maximum of 10 notification subscribers per budget (received {len(v)}). "
            "Enterprise best practice: consolidate multiple recipients into a shared team distribution list "
            "(e.g. finops-alerts@company.com) or SNS topic."
        )
    return v


class SecurityServicesConfig(BaseModel):
    delegated_account: str = "audit"
    guardduty: GuardDutyConfig = Field(default_factory=GuardDutyConfig)
    securityhub: SecurityHubConfig = Field(default_factory=SecurityHubConfig)
    incident_response_webhook_url: str | None = Field(
        default=None,
        description=(
            "Optional HTTPS webhook URL for security alerts (e.g., PagerDuty, Datadog, Splunk) "
            "subscribing directly to the Audit account security alerts SNS topic."
        ),
    )

    @field_validator("incident_response_webhook_url")
    def validate_webhook_url(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)


class CostAllocationTagsConfig(BaseModel):
    enabled: bool = True
    tags: list[str] = Field(
        default_factory=list,
        description=(
            "User-defined list of cost allocation tag keys to activate and monitor in AWS Billing & Cost Management."
        ),
    )

    @field_validator("tags", mode="before")
    def validate_tag_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [v]
        return list(v) if v is not None else []


class OrganizationConfig(BaseModel):
    organization: OrgDetails
    contacts: ContactsConfig
    root_access_management: RootAccessConfig = Field(default_factory=RootAccessConfig)
    service_control_policies: ServiceControlPoliciesConfig = Field(
        default_factory=ServiceControlPoliciesConfig
    )
    ou_structure: list[OUDef] = Field(default_factory=list)
    cloudtrail: CloudTrailConfig = Field(default_factory=CloudTrailConfig)
    terraform_backend: TerraformBackendConfig = Field(default_factory=TerraformBackendConfig)
    security_services: SecurityServicesConfig = Field(default_factory=SecurityServicesConfig)
    cost_allocation_tags: CostAllocationTagsConfig = Field(default_factory=CostAllocationTagsConfig)
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("cost_allocation_tags", mode="before")
    def parse_cost_allocation_tags(cls, v: Any) -> Any:
        if isinstance(v, list):
            return {"enabled": True, "tags": v}
        if isinstance(v, bool):
            return {"enabled": v, "tags": []}
        return v

    @field_validator("tags")
    def validate_org_config_tags(cls, v: dict[str, Any]) -> dict[str, str]:
        return validate_tags(v)


class BudgetConfig(BaseModel):
    monthly_limit_usd: float = Field(gt=0, description="Monthly budget limit in USD.")
    alert_threshold_percent: float = Field(
        default=80.0, gt=0, le=100, description="Percentage threshold to trigger budget alerts."
    )
    notification_emails: list[EmailStr] = Field(
        default_factory=list,
        description=(
            "Dynamic list of recipient email addresses for budget alerts (up to 10 per AWS limit). "
            "Enterprise best practice: use shared team distribution lists (e.g. finops-alerts@company.com) "
            "rather than personal mailboxes for operational continuity."
        ),
    )
    incident_response_webhook_url: str | None = Field(
        default=None,
        description=(
            "Optional HTTPS webhook URL for incident response tooling (e.g. PagerDuty, Opsgenie, Datadog) "
            "subscribing directly to the budget alerts SNS topic."
        ),
    )

    @field_validator("incident_response_webhook_url")
    def validate_webhook_url(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)

    @field_validator("notification_emails")
    def validate_notification_emails(cls, v: list[EmailStr]) -> list[EmailStr]:
        return _validate_max_subscribers(v, "Budgets")


class AnomalyDetectionConfig(BaseModel):
    enabled: bool = True
    threshold_usd: float = Field(default=100.0, gt=0, description="Anomaly alert threshold in USD.")
    notification_emails: list[EmailStr] = Field(
        default_factory=list,
        description=(
            "Dynamic list of recipient email addresses for anomaly alerts (up to 10 per AWS limit). "
            "Enterprise best practice: use shared team distribution lists (e.g. finops-alerts@company.com)."
        ),
    )

    @field_validator("notification_emails")
    def validate_notification_emails(cls, v: list[EmailStr]) -> list[EmailStr]:
        return _validate_max_subscribers(v, "Cost Anomaly Detection")


class AccountBaselineConfig(BaseModel):
    delete_default_vpc: bool = Field(
        default=True,
        description="Purge default VPCs, subnets, and internet gateways across all enabled AWS regions in this account.",
    )
    budget: BudgetConfig | None = None
    anomaly_detection: AnomalyDetectionConfig | None = None


class AccountDef(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    email: EmailStr
    ou: str = Field(..., min_length=1)
    tags: dict[str, str] = Field(default_factory=dict)
    baseline: AccountBaselineConfig = Field(default_factory=AccountBaselineConfig)

    @field_validator("tags")
    def validate_account_tags(cls, tags: dict[str, Any]) -> dict[str, str]:
        return validate_tags(tags)


class AccountsCatalog(BaseModel):
    accounts: list[AccountDef]
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("accounts")
    def validate_accounts_unique(cls, accounts: list[AccountDef]) -> list[AccountDef]:
        seen_names: set[str] = set()
        seen_emails: set[str] = set()
        for acct in accounts:
            norm_name = acct.name.lower().replace(" ", "-").replace("_", "-")
            if norm_name in seen_names:
                raise ValueError(f"Duplicate account name found in accounts catalog: '{acct.name}'")
            seen_names.add(norm_name)

            norm_email = str(acct.email).lower().strip()
            if norm_email in seen_emails:
                raise ValueError(
                    f"Duplicate account root email found in accounts catalog: '{acct.email}' for account '{acct.name}'. "
                    "AWS Organizations strictly requires each account to have a globally unique root email address."
                )
            seen_emails.add(norm_email)
        return accounts

    @field_validator("tags")
    def validate_catalog_tags(cls, v: dict[str, Any]) -> dict[str, str]:
        return validate_tags(v)


class UserDef(BaseModel):
    username: str = Field(..., min_length=1)
    email: EmailStr
    first_name: str = Field(default="User")
    last_name: str = Field(default="Account")


class PermissionSetDef(BaseModel):
    name: str = Field(..., min_length=1, max_length=32)
    description: str | None = ""
    session_duration: str = Field(default="PT4H")
    managed_policies: list[str] = Field(default_factory=list)
    inline_policy_file: str | None = None

    @field_validator("session_duration")
    def validate_session_duration(cls, v: str) -> str:
        if not re.match(r"^PT([1-9]|1[0-2])H$", v) and not re.match(r"^PT(1[5-9]|[2-5][0-9]|60)M$", v):
            raise ValueError(
                f"Invalid session duration '{v}'. Must be ISO 8601 duration between 15 minutes and 12 hours (e.g. PT15M to PT12H)."
            )
        return v


class AssignmentDef(BaseModel):
    permission_set: str
    accounts: list[str]  # Account names or ["all"]


class GroupDef(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = ""
    members: list[str] = Field(default_factory=list)
    assignments: list[AssignmentDef] = Field(default_factory=list)


class IdentityCenterConfig(BaseModel):
    region: str | None = None
    admin_user: UserDef
    breakglass_user: UserDef
    additional_users: list[UserDef] = Field(default_factory=list)
    permission_sets: list[PermissionSetDef] = Field(default_factory=list)
    groups: list[GroupDef] = Field(default_factory=list)


class IdentityConfigFile(BaseModel):
    identity_center: IdentityCenterConfig
