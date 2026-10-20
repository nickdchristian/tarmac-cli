"""Teardown of SCPs, Identity Center, security services and organization milestones."""

import logging

from botocore.exceptions import ClientError

from ..core.config_loader import ConfigBundle
from ..core.exceptions import AWS_ERRORS
from ..core.models import TAG_MANAGED_BY, TeardownItemReport
from .identity import IdentityService
from .scp import SCPService
from .teardown_base import TeardownBase
from .teardown_security import SecurityServicesTeardown

logger = logging.getLogger(__name__)


class GovernanceTeardown(TeardownBase):
    """Teardown of SCPs, Identity Center, security services and organization milestones."""

    def teardown_scps(self, bundle: ConfigBundle, dry_run: bool = False) -> list[TeardownItemReport]:
        """Tear down SCP CloudFormation stack and detach/delete direct SCPs."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_name = f"{bundle.org.organization.name}-organization-scps"

        try:
            cfn_client = self.session_mgr.get_client(
                "cloudformation", region_name=self.session_mgr.default_region
            )
            status = self.cfn_service._get_stack_status(cfn_client, stack_name)
            if status and status != "DELETE_COMPLETE":
                if dry_run:
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name="Management",
                            account_id=mgmt_id,
                            action="SIMULATED",
                            message=f"Would delete SCP stack (status: {status})",
                        )
                    )
                else:
                    self._notify_progress(
                        f"Deleting CloudFormation stack '{stack_name}' in Management (waiting for AWS)..."
                    )
                    self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                    results.append(
                        TeardownItemReport(
                            resource_type="CloudFormation Stack",
                            resource_name=stack_name,
                            account_name="Management",
                            account_id=mgmt_id,
                            action="DELETED",
                            message="Deleted SCP CloudFormation stack",
                        )
                    )
        except AWS_ERRORS as e:
            results.append(
                TeardownItemReport(
                    resource_type="CloudFormation Stack",
                    resource_name=stack_name,
                    account_name="Management",
                    account_id=mgmt_id,
                    action="FAILED",
                    message=str(e),
                )
            )

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
                        results.append(
                            TeardownItemReport(
                                resource_type="Service Control Policy",
                                resource_name=p_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="SKIPPED",
                                message=f"Not declared in config and lacks {TAG_MANAGED_BY}=tarmac tag",
                            )
                        )
                        continue
                    targets = scp_service.list_targets_for_policy(pol_id)
                    if dry_run:
                        results.append(
                            TeardownItemReport(
                                resource_type="Service Control Policy",
                                resource_name=p_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="SIMULATED",
                                message=f"Would detach from {len(targets)} target(s) and delete",
                            )
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
                            results.append(
                                TeardownItemReport(
                                    resource_type="Service Control Policy",
                                    resource_name=p_name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="DELETED",
                                    message=f"Detached from {len(targets)} targets and deleted",
                                )
                            )
                        except ClientError as e:
                            results.append(
                                TeardownItemReport(
                                    resource_type="Service Control Policy",
                                    resource_name=p_name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="FAILED",
                                    message=str(e),
                                )
                            )
        except AWS_ERRORS as e:
            logger.warning("Direct SCP cleanup failed: %s", e)
            results.append(
                TeardownItemReport(
                    resource_type="Service Control Policy",
                    resource_name="(direct policies)",
                    account_name="Management",
                    account_id=mgmt_id,
                    action="FAILED",
                    message=f"Could not inspect or remove direct SCPs: {e}",
                )
            )

        return results

    def teardown_identity(
        self, bundle: ConfigBundle, target_region: str, dry_run: bool = False
    ) -> list[TeardownItemReport]:
        """Tear down Permission Sets CloudFormation stacks and clean up retained permission sets."""
        results: list[TeardownItemReport] = self._new_results_list()
        mgmt_id = self._get_management_account_id()
        stack_names = [
            f"{bundle.org.organization.name}-sso-permission-sets",
            f"{bundle.org.organization.name}-permission-sets",
        ]

        for stack_name in stack_names:
            try:
                cfn_client = self.session_mgr.get_client("cloudformation", region_name=target_region)
                status = self.cfn_service._get_stack_status(cfn_client, stack_name)
                if status and status != "DELETE_COMPLETE":
                    if dry_run:
                        results.append(
                            TeardownItemReport(
                                resource_type="CloudFormation Stack",
                                resource_name=stack_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="SIMULATED",
                                message=f"Would delete permission sets stack (status: {status})",
                            )
                        )
                    else:
                        self._notify_progress(
                            f"Deleting CloudFormation stack '{stack_name}' in Management (waiting for AWS)..."
                        )
                        self.cfn_service.delete_stack(cfn_client, stack_name, on_progress=self.on_progress)
                        results.append(
                            TeardownItemReport(
                                resource_type="CloudFormation Stack",
                                resource_name=stack_name,
                                account_name="Management",
                                account_id=mgmt_id,
                                action="DELETED",
                                message="Deleted permission sets CloudFormation stack",
                            )
                        )
            except AWS_ERRORS as e:
                results.append(
                    TeardownItemReport(
                        resource_type="CloudFormation Stack",
                        resource_name=stack_name,
                        account_name="Management",
                        account_id=mgmt_id,
                        action="FAILED",
                        message=str(e),
                    )
                )

        if bundle.identity and bundle.identity.identity_center:
            try:
                identity_service = IdentityService(self.session_mgr, preferred_region=target_region)
                inst_arn, _ = identity_service.get_instance_details()
                existing_ps = identity_service.list_permission_sets(inst_arn)
                for ps_def in bundle.identity.identity_center.permission_sets:
                    if ps_def.name in existing_ps:
                        ps_arn = existing_ps[ps_def.name]
                        if not identity_service.is_tarmac_managed_permission_set(inst_arn, ps_arn):
                            results.append(
                                TeardownItemReport(
                                    resource_type="Permission Set",
                                    resource_name=ps_def.name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="SKIPPED",
                                    message=(
                                        "Not tagged tarmac:managed-by=tarmac, so it was not created by "
                                        "tarmac; delete it manually if intended"
                                    ),
                                )
                            )
                            continue
                        if dry_run:
                            results.append(
                                TeardownItemReport(
                                    resource_type="Permission Set",
                                    resource_name=ps_def.name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="SIMULATED",
                                    message=f"Would delete retained Permission Set '{ps_def.name}' ({ps_arn})",
                                )
                            )
                        else:
                            self._notify_progress(
                                f"Deleting retained Permission Set '{ps_def.name}' in IAM Identity Center..."
                            )
                            identity_service.delete_permission_set(inst_arn, ps_arn)
                            results.append(
                                TeardownItemReport(
                                    resource_type="Permission Set",
                                    resource_name=ps_def.name,
                                    account_name="Management",
                                    account_id=mgmt_id,
                                    action="DELETED",
                                    message=f"Deleted retained Permission Set '{ps_def.name}'",
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
            results.append(
                TeardownItemReport(
                    resource_type="Organization Tag",
                    resource_name="tarmac:* tags",
                    account_name="Management",
                    account_id=mgmt_account_id,
                    action="SIMULATED",
                    message="Would remove milestone and status tags",
                )
            )
            return results

        try:
            self._notify_progress("Resetting deployment milestone and status tags on Management Account...")
            org_client = self.session_mgr.get_client("organizations")
            org_client.untag_resource(ResourceId=mgmt_account_id, TagKeys=tag_keys)
            results.append(
                TeardownItemReport(
                    resource_type="Organization Tag",
                    resource_name="tarmac:* tags",
                    account_name="Management",
                    account_id=mgmt_account_id,
                    action="DELETED",
                    message="Removed deployment milestone and status tags",
                )
            )
        except ClientError as e:
            results.append(
                TeardownItemReport(
                    resource_type="Organization Tag",
                    resource_name="tarmac:* tags",
                    account_name="Management",
                    account_id=mgmt_account_id,
                    action="FAILED",
                    message=str(e),
                )
            )

        return results
