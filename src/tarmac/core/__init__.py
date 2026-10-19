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
    "AWSAuthenticationError",
    "AccountPlanItem",
    "AccountProvisionResult",
    "AccountProvisioningError",
    "AccountSuspensionResult",
    "AccountsCatalog",
    "AnomalyReport",
    "AwsSessionManager",
    "BaselineExecutionError",
    "BaselineReport",
    "BudgetReport",
    "ConfigBundle",
    "ConfigurationError",
    "DeploymentError",
    "GovernanceError",
    "IdentityCenterError",
    "IdentityConfigFile",
    "IdentitySyncReport",
    "OUManagementError",
    "OUSyncReport",
    "OrganizationConfig",
    "PreflightCheckResult",
    "PreflightCheckStatus",
    "PreflightReport",
    "SecurityServiceReport",
    "StackDeployReport",
    "VpcCleanupReport",
    "load_all_configs",
    "load_config_bundle",
    "merge_tags",
    "normalize_account_name",
    "parse_cli_tags",
    "setup_logging",
    "to_cfn_tags",
    "validate_tags",
]
