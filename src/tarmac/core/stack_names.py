"""Names of the CloudFormation stacks, StackSets and S3 buckets tarmac creates.

Every stack is named "<organization.name>-<suffix>". Buckets are "<organization.name>-<suffix>-<account id>", matching the templates.
"""

from enum import StrEnum


class Stack(StrEnum):
    ORGANIZATION_SCPS = "organization-scps"
    CLOUDTRAIL = "organization-cloudtrail"
    LOG_ARCHIVE = "log-archive-hardening"
    TERRAFORM_BACKEND = "terraform-backend"
    AUDIT_ACCOUNT = "audit-account-hardening"
    PERMISSION_SETS = "sso-permission-sets"
    ROOT_ALERT = "management-root-alert"
    CONFIG_RECORDER = "config-recorder"
    # Name used by earlier releases; teardown still removes it.
    LEGACY_PERMISSION_SETS = "permission-sets"

    def for_org(self, org_name: str) -> str:
        """The stack's name for an organization."""
        return f"{org_name}-{self.value}"


# Suffixes searched for when inferring organization.name from stacks that already exist.
TARMAC_STACK_SUFFIXES: tuple[str, ...] = (
    Stack.ORGANIZATION_SCPS,
    Stack.CLOUDTRAIL,
    Stack.LOG_ARCHIVE,
    Stack.TERRAFORM_BACKEND,
    Stack.AUDIT_ACCOUNT,
    Stack.PERMISSION_SETS,
)


class Bucket(StrEnum):
    """S3 buckets the templates create. Teardown empties and deletes exactly these, so keep them in step."""

    ACCESS_LOGS = "log-archive-access-logs"
    CLOUDTRAIL_LOGS = "org-cloudtrail-logs"
    CONFIG_LOGS = "org-config-logs"
    TERRAFORM_STATE = "terraform-state"

    def for_account(self, org_name: str, account_id: str) -> str:
        """The bucket's name for an organization and the account that holds it."""
        return f"{org_name}-{self.value}-{account_id}"


# Buckets in the log archive account (log-archive-hardening.yaml).
LOG_ARCHIVE_BUCKETS: tuple[Bucket, ...] = (Bucket.ACCESS_LOGS, Bucket.CLOUDTRAIL_LOGS, Bucket.CONFIG_LOGS)
