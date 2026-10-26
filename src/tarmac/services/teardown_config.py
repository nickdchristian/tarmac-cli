"""Teardown of the AWS Config recorders tarmac deploys."""

from ..core.config_loader import ConfigBundle
from ..core.inventory import Inventory
from ..core.models import TeardownItemReport
from .config_recorder import ConfigRecorderService
from .teardown_base import TeardownBase


class ConfigRecorderTeardown(TeardownBase):
    """Removes the recorder StackSet and the management account recorder stacks."""

    def teardown_config_recorder(
        self,
        bundle: ConfigBundle,
        target_region: str,
        dry_run: bool = False,
        recorded: Inventory | None = None,
    ) -> list[TeardownItemReport]:
        """Remove the StackSet and the management stacks, in the declared Regions and every Region ``recorded`` has
        one in. Done before the log bucket, so Config is not left writing to a bucket being deleted."""
        declared = [target_region, *bundle.org.organization.additional_regions]
        kept = recorded.get("config-recorder") if recorded is not None else {}
        regions = list(dict.fromkeys([*declared, *sorted(kept)]))
        return self._remove_recorders(bundle, target_region, regions, dry_run, stack_set=True)

    def teardown_dropped_config_regions(
        self, bundle: ConfigBundle, target_region: str, regions: list[str], dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Remove the management stacks in Regions the config dropped; the StackSet serves the ones left."""
        return self._remove_recorders(bundle, target_region, regions, dry_run, stack_set=False)

    def _remove_recorders(
        self, bundle: ConfigBundle, target_region: str, regions: list[str], dry_run: bool, *, stack_set: bool
    ) -> list[TeardownItemReport]:
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        if not mgmt_id:
            return results
        rows = ConfigRecorderService(self.session_mgr, self.cfn_service).remove(
            org_name=bundle.org.organization.name,
            regions=regions,
            primary_region=target_region,
            management_account_id=mgmt_id,
            dry_run=dry_run,
            stack_set=stack_set,
        )
        for resource, action, message in rows:
            kind, _, name = resource.partition(" ")
            if action == "NOT_FOUND":
                continue  # never deployed (the feature is off by default); nothing worth listing
            results.append(
                TeardownItemReport(
                    resource_type=f"Config recorder {kind}",
                    resource_name=name,
                    account_name="Management" if kind == "Stack" else "Organization",
                    account_id=mgmt_id,
                    action=action,
                    message=message,
                )
            )
        return results
