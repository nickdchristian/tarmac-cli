"""Custom exception hierarchy for AWS Governance CLI."""


class GovernanceError(Exception):
    """Base exception for all AWS Governance domain errors."""

    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}\nDetails: {self.details}"
        return self.message


class ConfigurationError(GovernanceError):
    """Raised when configuration files are missing, malformed, or fail logical checks."""


class AWSAuthenticationError(GovernanceError):
    """Raised when AWS credentials, STS role assumption, or authentication fails."""


class AccountProvisioningError(GovernanceError):
    """Raised when account creation or OU movement encounters a failure."""


class OUManagementError(GovernanceError):
    """Raised when Organizational Unit synchronization or discovery fails."""


class BaselineExecutionError(GovernanceError):
    """Raised when applying security baselines (VPC cleanup, budgets) fails."""


class IdentityCenterError(GovernanceError):
    """Raised when IAM Identity Center operations fail."""


class DeploymentError(GovernanceError):
    """Raised when CloudFormation stack deployments fail or time out."""
