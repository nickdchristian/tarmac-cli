"""Core module for AWS Governance CLI."""

from .aws_client import AwsSessionManager
from .config_loader import ConfigBundle, load_all_configs, load_config_bundle, normalize_account_name
from .config_schema import AccountsCatalog, IdentityConfigFile, OrganizationConfig
from .exceptions import (
    AccountProvisioningError,
    AWSAuthenticationError,
    BaselineExecutionError,
    ConfigurationError,
    DeploymentError,
    GovernanceError,
    IdentityCenterError,
    OUManagementError,
)
from .logging import setup_logging
from .models import (
    AccountPlanItem,
    AccountProvisionResult,
    AccountSuspensionResult,
    AnomalyReport,
    BaselineReport,
    BudgetReport,
    IdentitySyncReport,
    OUSyncReport,
    PreflightCheckResult,
    PreflightCheckStatus,
    PreflightReport,
    SecurityServiceReport,
    StackDeployReport,
    VpcCleanupReport,
)
from .tagging import merge_tags, parse_cli_tags, to_cfn_tags, validate_tags

__all__ = [
    "OrganizationConfig",
    "AccountsCatalog",
    "IdentityConfigFile",
    "load_all_configs",
    "load_config_bundle",
    "normalize_account_name",
    "ConfigBundle",
    "AwsSessionManager",
    "GovernanceError",
    "ConfigurationError",
    "AWSAuthenticationError",
    "AccountProvisioningError",
    "OUManagementError",
    "BaselineExecutionError",
    "IdentityCenterError",
    "DeploymentError",
    "AccountPlanItem",
    "AccountProvisionResult",
    "AccountSuspensionResult",
    "VpcCleanupReport",
    "BudgetReport",
    "AnomalyReport",
    "BaselineReport",
    "OUSyncReport",
    "StackDeployReport",
    "IdentitySyncReport",
    "PreflightCheckStatus",
    "PreflightCheckResult",
    "PreflightReport",
    "SecurityServiceReport",
    "merge_tags",
    "to_cfn_tags",
    "validate_tags",
    "parse_cli_tags",
    "setup_logging",
]
