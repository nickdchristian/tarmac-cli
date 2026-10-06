"""Data Transfer Objects (DTOs) and execution result models."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from .config_schema import AccountBaselineConfig

TAG_MANAGED_BY = "tarmac:managed-by"
TAG_STATUS = "tarmac:status"
TAG_VERSION = "tarmac:version"
TAG_COMPLETED_PHASES = "tarmac:completed-phases"
TAG_BASELINE = "tarmac:baseline"

STATUS_READY = "ready"
STATUS_IN_PROGRESS = "in-progress"
STATUS_SUSPENDED = "suspended"
BASELINE_COMPLETED = "completed"


@dataclass(frozen=True)
class AccountPlanItem:
    """Represents a planned action for an AWS account."""

    name: str
    email: str
    ou: str
    action: Literal["CREATE", "MOVE", "NOOP", "SUSPEND", "SUSPENDED"]
    account_id: str | None
    reason: str
    baseline: AccountBaselineConfig


@dataclass(frozen=True)
class AccountSuspensionResult:
    """Result of suspending an account."""

    name: str
    account_id: str
    moved_to_ou: str | None
    tags_updated: bool
    closed: bool = False
    status: str = "SUCCEEDED"
    message: str = ""


@dataclass(frozen=True)
class AccountProvisionResult:
    """Result of provisioning or reconciling a single member account."""

    name: str
    email: str
    account_id: str
    ou_name: str
    ou_id: str
    action_taken: str
    status: str = "SUCCEEDED"


@dataclass(frozen=True)
class VpcCleanupReport:
    """Report on default VPC purge operations in a single region."""

    region: str
    vpc_id: str | None = None
    detached_igws: list[str] = field(default_factory=list)
    deleted_subnets: list[str] = field(default_factory=list)
    deleted_vpc: bool = False
    skipped: bool = False
    message: str = ""


@dataclass(frozen=True)
class BudgetReport:
    """Report on AWS Budget configuration."""

    account_name: str
    account_id: str
    budget_name: str
    limit_usd: float
    alert_threshold_percent: float
    status: str  # CREATED, UPDATED, SKIPPED, FAILED
    message: str = ""


@dataclass(frozen=True)
class AnomalyReport:
    """Report on AWS Cost Anomaly Detection configuration."""

    account_name: str
    account_id: str
    monitor_name: str
    threshold_usd: float
    status: str
    message: str = ""


@dataclass
class BaselineReport:
    """Consolidated report of all baseline operations on an account."""

    account_name: str
    account_id: str
    vpc_reports: list[VpcCleanupReport] = field(default_factory=list)
    budget_report: BudgetReport | None = None
    anomaly_report: AnomalyReport | None = None


@dataclass(frozen=True)
class OUSyncReport:
    """Report on Organizational Unit hierarchy synchronization."""

    synced_ous: dict[str, str] = field(default_factory=dict)
    created_ous: list[str] = field(default_factory=list)
    existing_ous: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StackDeployReport:
    """Report on CloudFormation stack deployment."""

    stack_name: str
    action: Literal["CREATED", "UPDATED", "NO_CHANGES", "SIMULATED", "IMPORTED"]
    outputs: dict[str, str] = field(default_factory=dict)
    status: str = "SUCCEEDED"


@dataclass
class IdentitySyncReport:
    """Report on IAM Identity Center synchronization."""

    permission_sets_synced: list[str] = field(default_factory=list)
    users_synced: list[str] = field(default_factory=list)
    groups_synced: list[str] = field(default_factory=list)
    assignments_created: int = 0
    memberships_added: int = 0


@dataclass(frozen=True)
class SCPReconciliationResult:
    """Result of reconciling a single Service Control Policy."""

    name: str
    policy_id: str | None
    action_taken: str
    attached_targets: list[str] = field(default_factory=list)
    newly_attached_targets: list[str] = field(default_factory=list)
    status: str = "SUCCEEDED"


class PreflightCheckStatus(StrEnum):
    """Status level for a preflight check."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"


@dataclass(frozen=True)
class PreflightCheckResult:
    """Outcome of a single pre-flight or posture check."""

    name: str
    target: str
    status: PreflightCheckStatus
    live_value: str
    action_required: str | None = None


@dataclass(frozen=True)
class PreflightReport:
    """Aggregated pre-flight inspection report."""

    checks: list[PreflightCheckResult]
    passed: int
    warnings: int
    failures: int
    info: int
    can_proceed: bool


@dataclass(frozen=True)
class SecurityServiceReport:
    """Report on security service delegation and configuration."""

    service_name: str
    delegated_account: str
    status: str
    regions: list[str] = field(default_factory=list)
    message: str = ""
