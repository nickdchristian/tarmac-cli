"""Teardown of the StackSets deployed from ``baseline_stacks``."""

from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import TeardownItemReport
from .baseline_stacks import BaselineStacksService
from .teardown_base import TeardownBase


class BaselineStacksTeardown(TeardownBase):
    def teardown_baseline_stacks(
        self, bundle: ConfigBundle, target_region: str, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Remove every baseline StackSet of the organization, declared or not, with its stack instances."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        service = BaselineStacksService(self.session_mgr, target_region)
        try:
            rows = service.remove(service.undeclared(bundle.org.organization.name, []), dry_run=dry_run)
        except AWS_ERRORS as e:
            rows = [("StackSets baseline", "FAILED", f"Could not list the baseline StackSets: {e}")]
        for resource, action, message in rows:
            results.append(
                TeardownItemReport(
                    resource_type="Baseline StackSet",
                    resource_name=resource.partition(" ")[2],
                    account_name="Organization",
                    account_id=mgmt_id,
                    action=action,
                    message=message,
                )
            )
        return results
