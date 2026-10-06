"""Scaffold configuration files for a new Tarmac project."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_ORGANIZATION_YAML = """# Organization Master Configuration
organization:
  name: "myorg"
  domain: "myorg.example.com"
  primary_region: "us-east-1"
  additional_regions:
    - "us-east-2"
    - "eu-west-1"
  delete_default_vpc: true               # Purge default VPCs across all enabled regions in the management account

# Required alternate contacts
contacts:
  billing:
    name: "Finance Team"
    title: "Billing Administrator"
    email: "billing@myorg.example.com"
    phone: "+1234567890"
  operations:
    name: "Cloud Ops Team"
    title: "Operations Lead"
    email: "ops@myorg.example.com"
    phone: "+1234567890"
  security:
    name: "Security Operations Center"
    title: "Security Administrator"
    email: "security@myorg.example.com"
    phone: "+1234567890"

# Centralized root access management
# - enable_root_credentials_management: Centrally manages and recovers member root credentials.
# - enable_root_sessions: Allows short-lived, audited temporary root sessions for emergency break-glass.
# - delegated_admin_account: Delegates root access operations to the security account (e.g. 'Audit').
root_access_management:
  enabled: true
  enable_root_credentials_management: true
  enable_root_sessions: true
  delegated_admin_account: "Audit"

# Declarative Service Control Policies (SCPs)
service_control_policies:
  enabled: true
  policies:
    - name: "FoundationalGuardrails"
      description: "Consolidated foundational guardrails: denies member account root user activity and prevents leaving the organization"
      policy_file: "policies/scp/foundational-guardrails.json"
      targets:
        - "root"

# Organizational Unit (OU) Hierarchy
ou_structure:
  - name: "Security"
    description: "Security and compliance accounts"
  - name: "Infrastructure"
    description: "Shared infrastructure and networking accounts"
  - name: "Production"
    description: "Production workloads"
  - name: "NonProduction"
    description: "Development, test, and staging environments"
  - name: "Sandbox"
    description: "Experimental workloads and developer playgrounds"
  - name: "Suspended"
    description: "Quarantined or decommissioned accounts"

# Organization-wide CloudTrail configuration
cloudtrail:
  trail_name: "myorg-organization-trail"
  bucket_prefix: "myorg-cloudtrail"
  log_archive_account: "Log-Archive"
  enable_kms: true

# Terraform Backend configuration
terraform_backend:
  account: "Deployment"
  bucket_prefix: "myorg-terraform-state"
  dynamodb_table_name: "terraform-state-lock"
  enable_dynamodb: true

# Cost Allocation Tags in AWS Cost Explorer & Billing
cost_allocation_tags:
  enabled: true
  tags:
    - "Environment"
    - "Owner"
"""

DEFAULT_ACCOUNTS_YAML = """# AWS Accounts Catalog
accounts:
  - name: "Log-Archive"
    email: "aws-log-archive@myorg.example.com"
    ou: "Security"
    tags:
      Environment: "Core"
      Compliance: "SOC2"
    baseline:
      delete_default_vpc: true
      budget:
        monthly_limit_usd: 150.0
        alert_threshold_percent: 80.0
        notification_emails:
          - "alerts@myorg.example.com"

  - name: "Audit"
    email: "aws-audit@myorg.example.com"
    ou: "Security"
    tags:
      Environment: "Core"
      Compliance: "SOC2"
    baseline:
      delete_default_vpc: true
      budget:
        monthly_limit_usd: 150.0
        alert_threshold_percent: 80.0
        notification_emails:
          - "alerts@myorg.example.com"

  - name: "Deployment"
    email: "aws-deployment@myorg.example.com"
    ou: "Infrastructure"
    tags:
      Environment: "Shared"
    baseline:
      delete_default_vpc: true
      budget:
        monthly_limit_usd: 200.0
        alert_threshold_percent: 80.0
        notification_emails:
          - "alerts@myorg.example.com"

  - name: "Production-App"
    email: "aws-prod-app@myorg.example.com"
    ou: "Production"
    tags:
      Environment: "Production"
    baseline:
      delete_default_vpc: true
      budget:
        monthly_limit_usd: 1000.0
        alert_threshold_percent: 80.0
        notification_emails:
          - "alerts@myorg.example.com"
"""

DEFAULT_IDENTITY_YAML = """# IAM Identity Center (SSO) Configuration
identity_center:
  # region: "us-east-1"  # Optional: specify if SSO instance is in a different region
  admin_user:
    username: "admin"
    email: "admin@myorg.example.com"
    first_name: "Admin"
    last_name: "User"

  breakglass_user:
    username: "breakglass"
    email: "breakglass@myorg.example.com"
    first_name: "Break"
    last_name: "Glass"

  additional_users: []

  permission_sets:
    - name: "AdministratorAccess"
      description: "Full AWS administrator access"
      session_duration: "PT4H"
      managed_policies:
        - "arn:aws:iam::aws:policy/AdministratorAccess"

    - name: "ReadOnlyAccess"
      description: "Read-only access across all services"
      session_duration: "PT8H"
      managed_policies:
        - "arn:aws:iam::aws:policy/ReadOnlyAccess"

  groups:
    - name: "CloudAdmins"
      description: "Cloud Engineering Administrators"
      members:
        - "admin"
      assignments:
        - permission_set: "AdministratorAccess"
          accounts:
            - "Production-App"
            - "Deployment"

    - name: "SecurityAuditors"
      description: "Security and Compliance Reviewers"
      members: []
      assignments:
        - permission_set: "ReadOnlyAccess"
          accounts:
            - "Log-Archive"
            - "Audit"
            - "Production-App"
"""


def scaffold_project(
    target_dir: Path, force: bool = False, with_templates: bool = False
) -> tuple[list[Path], list[Path]]:
    """Create starter configuration files in target_dir. Returns (created_files, skipped_files)."""
    from ..core.templates import export_bundled_templates

    target_dir.mkdir(parents=True, exist_ok=True)
    templates = {
        "organization.yaml": DEFAULT_ORGANIZATION_YAML,
        "accounts.yaml": DEFAULT_ACCOUNTS_YAML,
        "identity.yaml": DEFAULT_IDENTITY_YAML,
    }

    created: list[Path] = []
    skipped: list[Path] = []

    for filename, content in templates.items():
        dest = target_dir / filename
        if dest.exists() and not force:
            skipped.append(dest)
            logger.info("Skipping existing file: %s", dest)
        else:
            dest.write_text(content, encoding="utf-8")
            created.append(dest)
            logger.info("Created configuration file: %s", dest)

    if with_templates:
        project_root = target_dir.parent if target_dir.name == "config" else target_dir
        exported = export_bundled_templates(project_root, force=force)
        created.extend(exported)

    return created, skipped
