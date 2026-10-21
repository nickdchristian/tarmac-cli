"""Teardown of SCPs, Identity Center, security services and organization milestones."""

import logging

from botocore.exceptions import ClientError

from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import TAG_MANAGED_BY, TeardownItemReport
from ..core.stack_names import Stack
from .identity import IdentityService
from .scp import SCPService
from .teardown_base import STACK, TeardownBase
from .teardown_security import SecurityServicesTeardown

logger = logging.getLogger(__name__)

SCP = "Service Control Policy"


class GovernanceTeardown(TeardownBase):
    """Teardown of SCPs, Identity Center, security services and organization milestones."""

    def teardown_scps(self, bundle: ConfigBundle, dry_run: bool = False) -> list[TeardownItemReport]:
        """Tear down SCP CloudFormation stack and detach/delete direct SCPs."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_name = Stack.ORGANIZATION_SCPS.for_org(bundle.org.organization.name)

        try:
            cfn_client = self.session_mgr.get_client(
                "cloudformation", region_name=self.session_mgr.default_region
            )
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)
            if item := self._remove_stack(
                cfn_client,
                stack_name,
                status,
                "Management",
                mgmt_id,
                dry_run,
                would="Would delete SCP stack",
                deleted="Deleted SCP CloudFormation stack",
                missing=None,
            ):
                results.append(item)
        except AWS_ERRORS as e:
            results.append(TeardownItemReport(STACK, stack_name, "Management", mgmt_id, "FAILED", str(e)))

        try:
            scp_service = SCPService(self.session_mgr)
            existing = scp_service.list_existing_scps()
            # Legacy default names are only removed when tagged as tarmac-owned; policies declared in
            # the user's own config are removed because the user named them as tarmac-managed.
            legacy_names: set[str] = {
                "FoundationalGuardrails",
                "DenyMemberRootActivity",
                "DenyLeaveOrganization",
            }
            declared_names: set[str] = set()
            if bundle.org.service_control_policies:
                declared_names = {p.name for p in bundle.org.service_control_policies.policies}
            policies_to_remove = legacy_names | declared_names

            org_client = self.session_mgr.get_client("organizations")
            for p_name in sorted(policies_to_remove):
                if p_name in existing:
                    pol_id = str(existing[p_name]["Id"])
                    if p_name not in declared_names and not scp_service.is_tarmac_managed(pol_id):
                        message = f"Not declared in config and lacks {TAG_MANAGED_BY}=tarmac tag"
                        results.append(
                            TeardownItemReport(SCP, p_name, "Management", mgmt_id, "SKIPPED", message)
                        )
                        continue
                    targets = scp_service.list_targets_for_policy(pol_id)
                    if dry_run:
                        message = f"Would detach from {len(targets)} target(s) and delete"
                        results.append(
                            TeardownItemReport(SCP, p_name, "Management", mgmt_id, "SIMULATED", message)
                        )
                    else:
                        self._notify_progress(
                            f"Detaching and deleting Service Control Policy '{p_name}' in Management..."
                        )
                        for t in targets:
                            try:
                                org_client.detach_policy(PolicyId=pol_id, TargetId=t)
                            except ClientError as e:
                                logger.warning("Could not detach policy %s from %s: %s", pol_id, t, e)
                        try:
                            org_client.delete_policy(PolicyId=pol_id)
                            message = f"Detached from {len(targets)} targets and deleted"
                            results.append(
                                TeardownItemReport(SCP, p_name, "Management", mgmt_id, "DELETED", message)
                            )
                        except ClientError as e:
                            results.append(
                                TeardownItemReport(SCP, p_name, "Management", mgmt_id, "FAILED", str(e))
                            )
        except AWS_ERRORS as e:
            logger.warning("Direct SCP cleanup failed: %s", e)
            message = f"Could not inspect or remove direct SCPs: {e}"
            results.append(
                TeardownItemReport(SCP, "(direct policies)", "Management", mgmt_id, "FAILED", message)
            )

        return results

    def _resolve_identity_teardown_context(
        self, bundle: ConfigBundle, target_region: str
    ) -> tuple[IdentityService | None, str | None, list[str]]:
        """Discover Identity Center instance and return (service, instance_arn, candidate_regions)."""
        id_cfg = bundle.identity.identity_center if bundle.identity else None
        cfg_region = getattr(id_cfg, "region", None) if id_cfg else None
        preferred_region = cfg_region if isinstance(cfg_region, str) and cfg_region else target_region
        identity_service: IdentityService | None = None
        inst_arn: str | None = None
        sso_region: str = preferred_region

        if id_cfg:
            try:
                identity_service = IdentityService(self.session_mgr, preferred_region=preferred_region)
                inst_arn, _ = identity_service.get_instance_details()
                disc_region = getattr(identity_service, "region", None)
                if isinstance(disc_region, str) and disc_region:
                    sso_region = disc_region
            except AWS_ERRORS as e:
                logger.debug("Identity Center discovery during teardown: %s", e)

        candidate_regions = list(
            dict.fromkeys([r for r in (sso_region, target_region) if isinstance(r, str) and r])
        )
        return identity_service, inst_arn, candidate_regions

    def teardown_identity(
        self, bundle: ConfigBundle, target_region: str, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Tear down Permission Sets CloudFormation stacks and clean up retained permission sets."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_names = [
            Stack.PERMISSION_SETS.for_org(bundle.org.organization.name),
            Stack.LEGACY_PERMISSION_SETS.for_org(bundle.org.organization.name),
        ]
        id_cfg = bundle.identity.identity_center if bundle.identity else None
        identity_service, inst_arn, candidate_regions = self._resolve_identity_teardown_context(
            bundle, target_region
        )

        for stack_name in stack_names:
            for stack_region in candidate_regions:
                try:
                    cfn_client = self.session_mgr.get_client("cloudformation", region_name=stack_region)
                    status = self.cfn_service._get_stack_status(cfn_client, stack_name)
                    if item := self._remove_stack(
                        cfn_client,
                        stack_name,
                        status,
                        "Management",
                        mgmt_id,
                        dry_run,
                        would="Would delete permission sets stack",
                        deleted="Deleted permission sets CloudFormation stack",
                        missing=None,
                    ):
                        results.append(item)
                        break
                except AWS_ERRORS as e:
                    results.append(
                        TeardownItemReport(STACK, stack_name, "Management", mgmt_id, "FAILED", str(e))
                    )
                    break

        if id_cfg and identity_service and inst_arn:
            try:
                existing_ps = identity_service.list_permission_sets(inst_arn)
                for ps_def in id_cfg.permission_sets:
                    if ps_def.name in existing_ps:
                        ps_arn = existing_ps[ps_def.name]
                        if not identity_service.is_tarmac_managed_permission_set(inst_arn, ps_arn):
                            action, message = (
                                "SKIPPED",
                                "Not tagged tarmac:managed-by=tarmac, so it was not created by "
                                "tarmac; delete it manually if intended",
                            )
                        elif dry_run:
                            action = "SIMULATED"
                            message = f"Would delete retained Permission Set '{ps_def.name}' ({ps_arn})"
                        else:
                            self._notify_progress(
                                f"Deleting retained Permission Set '{ps_def.name}' in IAM Identity Center..."
                            )
                            if identity_service.delete_permission_set(inst_arn, ps_arn) is False:
                                action, message = (
                                    "FAILED",
                                    f"Could not delete retained Permission Set '{ps_def.name}'",
                                )
                            else:
                                action, message = (
                                    "DELETED",
                                    f"Deleted retained Permission Set '{ps_def.name}'",
                                )
                        results.append(
                            TeardownItemReport(
                                "Permission Set", ps_def.name, "Management", mgmt_id, action, message
                            )
                        )
            except AWS_ERRORS as e:
                logger.debug("Identity Center direct cleanup: %s", e)

        return results

    def teardown_security_services(
        self,
        bundle: ConfigBundle,
        target_region: str,
        account_id_map: dict[str, str],
        dry_run: bool = False,
    ) -> list[TeardownItemReport]:
        """Opt-in: disable GuardDuty/Security Hub/Config/IAM delegation tarmac set up (see module docs)."""
        return SecurityServicesTeardown(self.session_mgr, self._new_results_list, self._notify_progress).run(
            bundle,
            target_region,
            account_id_map,
            self._get_management_account_id(),
            dry_run=dry_run,
        )

    def reset_milestones(self, mgmt_account_id: str, dry_run: bool = False) -> list[TeardownItemReport]:
        """Remove tarmac deployment tags and reset milestones on the Management Account."""
        results: list[TeardownItemReport] = self._new_results_list()
        if not mgmt_account_id:
            return results

        tag_keys = [
            "tarmac:completed-phases",
            "tarmac:status",
            "tarmac:version",
            "tarmac:deployment-ready",
        ]

        if dry_run:
            action, message = "SIMULATED", "Would remove milestone and status tags"
        else:
            try:
                self._notify_progress(
                    "Resetting deployment milestone and status tags on Management Account..."
                )
                org_client = self.session_mgr.get_client("organizations")
                org_client.untag_resource(ResourceId=mgmt_account_id, TagKeys=tag_keys)
                action, message = "DELETED", "Removed deployment milestone and status tags"
            except ClientError as e:
                action, message = "FAILED", str(e)
        results.append(
            TeardownItemReport(
                "Organization Tag", "tarmac:* tags", "Management", mgmt_account_id, action, message
            )
        )
        return results
