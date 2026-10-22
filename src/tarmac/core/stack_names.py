"""Names of the CloudFormation stacks and StackSets tarmac creates.

Every stack is named "<organization.name>-<suffix>".
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
    INVENTORY = "tarmac-inventory"

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
