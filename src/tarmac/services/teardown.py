"""Safe, idempotent teardown of everything tarmac provisions.

The handlers live in the ``teardown_*`` modules; ``TeardownService`` composes them and runs them in phase order.
"""

import logging
from collections.abc import Callable, Sequence

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.inventory import Inventory
from ..core.models import TeardownItemReport
from .teardown_base import TeardownBase, TeardownReport
from .teardown_everything import EverythingTeardown
from .teardown_governance import GovernanceTeardown
from .teardown_logging import LoggingTeardown
from .teardown_s3 import cleanup_orphaned_bucket, empty_s3_bucket, is_s3_bucket_empty, normalize_bucket_name
from .teardown_workloads import WorkloadTeardown

logger = logging.getLogger(__name__)

__all__ = [
    "TeardownBase",
    "TeardownItemReport",
    "TeardownReport",
    "TeardownService",
    "cleanup_orphaned_bucket",
    "empty_s3_bucket",
    "is_s3_bucket_empty",
    "normalize_bucket_name",
    "teardown_deployment",
]


class TeardownService(LoggingTeardown, WorkloadTeardown, GovernanceTeardown, EverythingTeardown):
    """Orchestrates comprehensive teardown of Tarmac governance resources."""

    def teardown_phase(
        self,
        phase: int,
        bundle: ConfigBundle,
        target_region: str,
        dry_run: bool = False,
        account_id_map: dict[str, str] | None = None,
        disable_security_services: bool = False,
    ) -> list[TeardownItemReport]:
        """Tear down resources belonging to a specific phase."""
        accts = account_id_map or self._get_active_accounts()
        if phase == 2:
            self._notify_phase("Phase 2 | Organizational Units & Guardrails (SCPs)")
            return self.teardown_scps(bundle, dry_run=dry_run)
        if phase == 3:
            self._notify_phase("Phase 3 | CloudTrail & Central Logging")
            items: list[TeardownItemReport] = []
            items.extend(self.teardown_cloudtrail(bundle, target_region, dry_run=dry_run))
            items.extend(
                self.teardown_log_archive(bundle, target_region, dry_run=dry_run, account_id_map=accts)
            )
            return items
        if phase == 4:
            self._notify_phase("Phase 4 | Account Factory Provisioning & Baselining (Budgets)")
            return self.teardown_budgets(bundle, dry_run=dry_run, account_id_map=accts)
        if phase == 5:
            self._notify_phase("Phase 5 | Backend & Security Services Deployments")
            items = []
            if disable_security_services:
                items.extend(self.teardown_security_services(bundle, target_region, accts, dry_run=dry_run))
            items.extend(self.teardown_backend(bundle, target_region, dry_run=dry_run, account_id_map=accts))
            items.extend(self.teardown_audit(bundle, target_region, dry_run=dry_run, account_id_map=accts))
            return items
        if phase == 6:
            self._notify_phase("Phase 6 | IAM Identity Center (SSO)")
            return self.teardown_identity(bundle, target_region, dry_run=dry_run)
        return []

    def teardown_all(
        self,
        bundle: ConfigBundle,
        target_region: str | None = None,
        dry_run: bool = False,
        phases: Sequence[int] | None = None,
        preserve_backend: bool = False,
        disable_security_services: bool = False,
        inventory: Inventory | None = None,
    ) -> TeardownReport:
        """Tear down all deployment resources across all phases in safe dependency order.

        With an ``inventory`` the run is a full teardown: it also removes the Identity Center users and groups,
        OUs and organization settings recorded as created by tarmac, then the access role. Accounts are kept.
        """
        region = target_region or bundle.org.organization.primary_region
        accts = self._get_active_accounts()
        mgmt_id = self._get_management_account_id()
        items: list[TeardownItemReport] = []

        phases_set = set(phases) if phases is not None else {2, 3, 4, 5, 6}

        if 3 in phases_set:
            self._notify_phase("Phase 3 | Organization CloudTrail")
            items.extend(self.teardown_cloudtrail(bundle, region, dry_run=dry_run))

        if 3 in phases_set or 5 in phases_set:
            self._notify_phase("Phase 3/5 | Log Archive Hardening & Buckets")
            items.extend(self.teardown_log_archive(bundle, region, dry_run=dry_run, account_id_map=accts))

        if 4 in phases_set:
            self._notify_phase("Phase 4 | Budgets & Cost Monitors")
            items.extend(self.teardown_budgets(bundle, dry_run=dry_run, account_id_map=accts))

        if 5 in phases_set:
            self._notify_phase("Phase 5 | Terraform Backend & Audit Hardening")
            if disable_security_services:
                items.extend(self.teardown_security_services(bundle, region, accts, dry_run=dry_run))
            if not preserve_backend:
                items.extend(self.teardown_backend(bundle, region, dry_run=dry_run, account_id_map=accts))
            else:
                self._notify_progress("Preserving Terraform remote state backend S3 bucket and lock table.")
                items.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=f"{bundle.org.organization.name}-terraform-backend",
                        account_name=bundle.get_backend_account_name() or "deployment",
                        account_id="",
                        action="SKIPPED",
                        message="Preserved by --preserve-backend flag",
                    )
                )
            items.extend(self.teardown_audit(bundle, region, dry_run=dry_run, account_id_map=accts))

        if 6 in phases_set:
            self._notify_phase("Phase 6 | IAM Identity Center Permission Sets")
            items.extend(self.teardown_identity(bundle, region, dry_run=dry_run))

        if inventory is not None:
            self._notify_phase("Identity Center users and groups created by tarmac")
            items.extend(self.teardown_identity_principals(bundle, region, inventory, dry_run=dry_run))

        if 2 in phases_set:
            self._notify_phase("Phase 2 | Service Control Policies")
            items.extend(self.teardown_scps(bundle, dry_run=dry_run))

        if inventory is not None:
            self._notify_phase("Organizational Units created by tarmac")
            items.extend(self.teardown_ous(inventory, dry_run=dry_run))
            self._notify_phase("Phase 1 | Organization settings")
            items.extend(self.teardown_org_settings(bundle, inventory, dry_run=dry_run))

        if phases is None and mgmt_id:
            self._notify_phase("Milestones | Resetting Deployment Tags")
            items.extend(self.reset_milestones(mgmt_id, dry_run=dry_run))

        if inventory is not None:
            self._notify_phase("Member accounts (kept)")
            items.extend(self.report_accounts_kept(dry_run=dry_run))
            self._notify_phase("Tarmac access role and bootstrap user")
            items.extend(self.teardown_access(region, dry_run=dry_run))

        status = (
            "SIMULATED"
            if dry_run
            else ("FAILED" if any(i.action == "FAILED" for i in items) else "COMPLETED")
        )
        return TeardownReport(items=items, status=status)


def teardown_deployment(
    bundle: ConfigBundle,
    session_mgr: AwsSessionManager | None = None,
    region: str | None = None,
    phases: Sequence[int] | None = None,
    dry_run: bool = False,
    on_progress: Callable[[str], None] | None = None,
    on_item: Callable[[TeardownItemReport], None] | None = None,
    on_phase: Callable[[str], None] | None = None,
    preserve_backend: bool = False,
    disable_security_services: bool = False,
) -> TeardownReport:
    """Convenience function to tear down deployment resources."""
    target_region = region or bundle.org.organization.primary_region
    manager = session_mgr or AwsSessionManager(region_name=target_region)
    service = TeardownService(
        manager,
        on_progress=on_progress,
        on_item=on_item,
        on_phase=on_phase,
    )
    return service.teardown_all(
        bundle=bundle,
        target_region=target_region,
        dry_run=dry_run,
        phases=phases,
        preserve_backend=preserve_backend,
        disable_security_services=disable_security_services,
    )
