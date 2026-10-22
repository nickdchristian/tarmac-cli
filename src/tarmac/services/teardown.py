"""Safe, idempotent teardown of everything tarmac provisions.

The handlers live in the ``teardown_*`` modules; ``TeardownService`` composes them and runs them in phase order.
"""

import logging
from collections.abc import Sequence

from ..core.config_loader import ConfigBundle
from ..core.inventory import Inventory
from ..core.models import TeardownItemReport
from ..core.stack_names import Stack
from .teardown_base import TeardownReport
from .teardown_config import ConfigRecorderTeardown
from .teardown_everything import EverythingTeardown
from .teardown_governance import GovernanceTeardown
from .teardown_logging import LoggingTeardown
from .teardown_workloads import WorkloadTeardown

logger = logging.getLogger(__name__)


class TeardownService(
    LoggingTeardown, WorkloadTeardown, GovernanceTeardown, ConfigRecorderTeardown, EverythingTeardown
):
    """Orchestrates comprehensive teardown of Tarmac governance resources."""

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
        OUs and organization settings recorded as created by tarmac, then the TarmacDeployment permission set. Accounts
        are kept.
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
            self._notify_phase("Phase 5 | AWS Config Recorders")
            items.extend(self.teardown_config_recorder(bundle, region, dry_run=dry_run))

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
                        resource_name=Stack.TERRAFORM_BACKEND.for_org(bundle.org.organization.name),
                        account_name=bundle.get_backend_account_name() or "deployment",
                        account_id="",
                        action="SKIPPED",
                        message="Preserved by --preserve-backend flag",
                    )
                )
            items.extend(self.teardown_audit(bundle, region, dry_run=dry_run, account_id_map=accts))
            items.extend(self.teardown_root_alert(bundle, region, dry_run=dry_run))

        if 6 in phases_set:
            self._notify_phase("Phase 6 | IAM Identity Center Permission Sets")
            items.extend(self.teardown_identity(bundle, region, dry_run=dry_run))

        if inventory is not None:
            self._notify_phase("Identity Center users and groups created by tarmac")
            items.extend(self.teardown_identity_principals(region, inventory, dry_run=dry_run))

        if 2 in phases_set:
            self._notify_phase("Phase 2 | Service Control Policies")
            items.extend(self.teardown_scps(bundle, dry_run=dry_run))

        if inventory is not None:
            self._notify_phase("Organizational Units created by tarmac")
            items.extend(self.teardown_ous(inventory, dry_run=dry_run))
            self._notify_phase("Phase 1 | Organization settings")
            items.extend(self.teardown_org_settings(inventory, dry_run=dry_run))

        if phases is None and mgmt_id:
            self._notify_phase("Milestones | Resetting Deployment Tags")
            items.extend(self.reset_milestones(mgmt_id, dry_run=dry_run))

        if inventory is not None:
            self._notify_phase("Member accounts (kept)")
            items.extend(self.report_accounts_kept())
            self._notify_phase("Tarmac bootstrap permission sets")
            items.extend(self.teardown_access(dry_run=dry_run))

        status = (
            "SIMULATED"
            if dry_run
            else ("FAILED" if any(i.action == "FAILED" for i in items) else "COMPLETED")
        )
        return TeardownReport(items=items, status=status)
