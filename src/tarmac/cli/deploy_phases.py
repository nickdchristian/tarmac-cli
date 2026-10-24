"""Phase runners for the live deployment pipeline (the dry-run plan is built by services.plan)."""

import logging
from pathlib import Path
from typing import Any

from ..core import inventory
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle, normalize_account_name
from ..core.exceptions import AccountProvisioningError, GovernanceError
from ..core.models import BaselineReport, StackDeployReport
from ..core.org_accounts import get_active_account_id_map
from ..core.stack_names import Stack
from ..core.templates import resolve_resource_path
from ..core.text import plural
from ..services.accounts import AccountService
from ..services.baseline import BaselineService
from ..services.cloudformation import CloudFormationService, lock_table_wanted
from ..services.identity import IdentityService
from ..services.log_encryption import resolve_log_encryption
from ..services.organization import OrganizationService
from ..services.ou import OUService
from ..services.scp import SCPService
from ..services.security import SecurityServicesService
from ..services.stack_parameters import (
    audit_hardening_parameters,
    backend_parameters,
    cloudtrail_parameters,
    log_archive_parameters,
    object_lock_advice,
)
from .deploy_config_recorder import deploy_config_recorder
from .deploy_root_alert import deploy_management_root_alert
from .ui import print_info, print_step, print_success, print_warning

logger = logging.getLogger(__name__)


def _record_phase(session_mgr: AwsSessionManager, milestone: str) -> None:
    """Mark a pipeline milestone as completed on the management account."""
    mgmt_id = session_mgr.get_caller_identity().get("Account", "")
    if mgmt_id:
        OrganizationService(session_mgr).record_phase_completed(mgmt_id, milestone)


def _existing_ou_map(session_mgr: AwsSessionManager, needed: set[str]) -> dict[str, str]:
    """Live OUs by name. Raises when a needed OU is missing: only phase 2 creates OUs, because it also
    attaches their SCPs, and an account must never land in an OU without its guardrails."""
    ou_map = OUService(session_mgr).list_all_ous()
    missing = sorted(needed - set(ou_map))
    if missing:
        raise GovernanceError(
            f"{plural(len(missing), 'OU')} not created yet: {', '.join(missing)}.",
            details="Run `tarmac deploy --phase 2` first: it creates the OUs and attaches their SCPs.",
        )
    return ou_map


def _suspended_account_guidance(name: str, email: str, account_id: str) -> str:
    return (
        f"Account '{name}' ({account_id}) is closed/suspended in AWS Organizations, so it cannot be reused or "
        f"re-created with the same email ({email}). AWS keeps a closed account's email reserved, so declare a "
        "new email address (and optionally a new name) for it in accounts.yaml, or reinstate the account "
        "within AWS's post-closure window."
    )


def _baseline_failures(report: BaselineReport) -> list[str]:
    """Describe every failed baseline step in a BaselineReport (empty list means success)."""
    problems = [f"default VPC cleanup in {r.region}: {r.message}" for r in report.vpc_reports if r.error]
    if report.budget_report is not None and report.budget_report.status == "FAILED":
        problems.append(f"budget: {report.budget_report.message}")
    if report.anomaly_report is not None and report.anomaly_report.status == "FAILED":
        problems.append(f"cost anomaly monitor: {report.anomaly_report.message}")
    return [f"{report.account_name} ({report.account_id}) {p}" for p in problems]


def _cleanup_management_default_vpcs(session_mgr: AwsSessionManager) -> None:
    baseliner = BaselineService(session_mgr)
    mgmt_id = session_mgr.get_caller_identity().get("Account", "")
    if not mgmt_id:
        return
    vpc_reports = baseliner.cleanup_default_vpcs(mgmt_id, "management", regions=None)
    for r in vpc_reports:
        if not r.skipped and r.deleted_vpc:
            print_success(f"Management Account: Purged default VPC ({r.vpc_id}) in {r.region}")
    vpc_failures = [f"{r.region}: {r.message}" for r in vpc_reports if r.error]
    if vpc_failures:
        for failure in vpc_failures:
            print_warning(f"Management Account default VPC cleanup failed in {failure}")
        raise GovernanceError(
            f"Phase 1 incomplete: default VPC cleanup failed in {plural(len(vpc_failures), 'region')}.",
            details=(
                "Fix the cause (the role needs ec2:DescribeVpcs/Subnets/InternetGateways/"
                "NetworkInterfaces and the matching Detach/Delete actions), or set "
                "organization.delete_default_vpc: false to leave the management account's VPCs alone."
            ),
        )
    baseliner.mark_account_baselined(mgmt_id)


def _deploy_inventory_stack(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Create the bucket that records what tarmac creates, then store this run's record there."""
    region = bundle.org.organization.primary_region
    CloudFormationService(session_mgr).deploy_stack(
        session_mgr.get_client("cloudformation", region_name=region),
        Stack.INVENTORY.for_org(bundle.org.organization.name),
        resolve_resource_path("cloudformation/tarmac-inventory.yaml", project_root=project_root),
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        termination_protection=True,
    )
    inventory.connect(session_mgr, bundle.org.organization.name, region, bundle.config_dir)


def connect_inventory_or_raise(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> None:
    """Store this run's record of what tarmac creates in the bucket phase 1 created."""
    inv = inventory.connect(
        session_mgr, bundle.org.organization.name, bundle.org.organization.primary_region, bundle.config_dir
    )
    if inv.bucket is None:
        raise GovernanceError(
            "The bucket that records what tarmac creates does not exist yet.",
            details="Run `tarmac deploy --phase 1` first: it creates the bucket.",
        )


def _run_phase_1_org(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 1: AWS Organizations Bootstrap, Contacts, and Management Account Hardening."""
    print_step("1", "Organizations Bootstrap & Contacts")

    _deploy_inventory_stack(session_mgr, bundle, project_root, custom_tags)
    org_service = OrganizationService(session_mgr)
    org_id = org_service.ensure_organization()
    org_service.set_account_contacts(bundle.org.contacts)
    org_service.enable_trusted_services()
    results = org_service.configure_root_access(bundle.org.root_access_management)
    if results.get("delegated_admin"):
        print_success(
            f"Delegated administrator ({bundle.org.root_access_management.delegated_admin_account}) for IAM is in place."
        )

    target_cost_tags = bundle.get_cost_allocation_tags()
    if target_cost_tags:
        activated_tags = org_service.activate_cost_allocation_tags(target_cost_tags)
        if activated_tags:
            print_success(
                f"Activated {plural(len(activated_tags), 'cost allocation tag')}: {', '.join(activated_tags)}"
            )

    if bundle.org.organization.delete_default_vpc:
        _cleanup_management_default_vpcs(session_mgr)

    mgmt_id = session_mgr.get_caller_identity().get("Account", "")
    if mgmt_id:
        org_service.record_phase_completed(mgmt_id, "org")
    print_success(f"Phase 1 complete: Org {org_id} configured.")


def _run_phase_2_ou(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 2: Organizational Units Synchronization & Guardrails."""
    print_step("2", "Organizational Units & Guardrails")

    ou_service = OUService(session_mgr)
    root_id = ou_service.get_root_id()
    report = ou_service.sync_ou_structure(bundle.org.ou_structure)
    print_success(
        f"Phase 2: {len(report.synced_ous)} OUs in place "
        f"({len(report.created_ous)} created, {len(report.existing_ous)} already existed)."
    )

    if bundle.org.service_control_policies and bundle.org.service_control_policies.enabled:
        results = SCPService(session_mgr).reconcile_via_cloudformation(
            bundle.org.service_control_policies,
            root_id,
            report.synced_ous,
            project_root=project_root,
            org_name=bundle.org.organization.name,
            org_tags=bundle.get_organization_tags(),
            tags=custom_tags,
        )
        unresolved = {r.name: r.unresolved_targets for r in results if r.unresolved_targets}
        if unresolved:
            raise GovernanceError(
                "Phase 2 failed: SCP targets not found in the organization.",
                details="; ".join(f"{name}: {', '.join(targets)}" for name, targets in unresolved.items()),
            )
        print_success(f"Phase 2 complete: Reconciled {len(results)} Service Control Policies.")
    else:
        print_success("Phase 2 complete: OUs synchronized.")

    _record_phase(session_mgr, "ou")


def _deploy_log_archive_hardening_stack(
    cfn_service: CloudFormationService,
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    org_id: str,
    log_archive_id: str,
    custom_tags: dict[str, str] | None = None,
) -> StackDeployReport:
    """Deploy the Log Archive account hardening stack containing the centralized S3 sink & KMS key."""
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    advice = object_lock_advice(bundle)
    if advice:
        print_warning(advice)
    cfn_client = session_mgr.get_member_client(log_archive_id, "cloudformation", region_name=target_region)
    template_file = resolve_resource_path(
        "cloudformation/log-archive-hardening.yaml", project_root=project_root
    )

    resolve_log_encryption(session_mgr, bundle, target_region, log_archive_id)

    return cfn_service.deploy_stack(
        cfn_client,
        Stack.LOG_ARCHIVE.for_org(bundle.org.organization.name),
        template_file,
        log_archive_parameters(bundle, org_id, str(session_mgr.get_caller_identity().get("Account", ""))),
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(log_archive_name),
        termination_protection=True,
    )


def _provision_log_archive_account(
    session_mgr: AwsSessionManager, bundle: ConfigBundle, log_archive_name: str, accts: dict[str, str]
) -> str:
    """Create the declared log archive account when it does not exist yet; return its ID ("" if undeclared)."""
    acct_def = bundle.get_account(log_archive_name)
    if not acct_def:
        return ""
    print_info(
        f"Phase 3: Foundational account '{acct_def.name}' ({acct_def.email}) not yet active. Provisioning..."
    )
    ou_map = _existing_ou_map(session_mgr, {acct_def.ou})
    prov_results = AccountService(session_mgr).provision_accounts(
        [acct_def], ou_map=ou_map, org_tags=bundle.get_organization_tags()
    )
    if prov_results and prov_results[0].status == "SKIPPED":
        raise GovernanceError(
            "Phase 3 failed: "
            + _suspended_account_guidance(
                acct_def.name, acct_def.email, prov_results[0].account_id or "unknown"
            )
        )
    if prov_results and prov_results[0].account_id:
        log_archive_id = prov_results[0].account_id
        accts[acct_def.name] = log_archive_id
        print_success(f"Phase 3: Provisioned foundational account '{acct_def.name}' ({log_archive_id}).")
        return log_archive_id
    return ""


def _run_phase_3_cloudtrail(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 3: Organization-wide CloudTrail deployment."""
    print_step("3", "Foundational Organization CloudTrail")

    cfn_service = CloudFormationService(session_mgr)
    org_id = str(session_mgr.get_client("organizations").describe_organization()["Organization"]["Id"])

    accts = get_active_account_id_map(session_mgr)
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    log_archive_id = bundle.resolve_account_id(log_archive_name, accts) or ""
    if not log_archive_id:
        log_archive_id = _provision_log_archive_account(session_mgr, bundle, log_archive_name, accts)
    if not log_archive_id:
        raise GovernanceError(
            f"Phase 3 failed: Log Archive account '{log_archive_name}' could not be resolved from active accounts. "
            "Ensure the account is declared in accounts.yaml and provisioned before deploying CloudTrail."
        )

    log_archive_report = _deploy_log_archive_hardening_stack(
        cfn_service,
        session_mgr,
        bundle,
        target_region,
        project_root,
        org_id,
        log_archive_id,
        custom_tags=custom_tags,
    )
    print_success(f"Phase 3: Log Archive hardening stack {log_archive_report.action}.")

    template_file = resolve_resource_path(
        "cloudformation/organization-cloudtrail.yaml", project_root=project_root
    )
    report = cfn_service.deploy_stack(
        session_mgr.get_client("cloudformation", region_name=target_region),
        Stack.CLOUDTRAIL.for_org(bundle.org.organization.name),
        template_file,
        cloudtrail_parameters(
            bundle,
            log_archive_id,
            log_archive_report.outputs.get("CloudTrailBucketName", ""),
            bool(bundle.org.cloudtrail.enable_kms),
        ),
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        termination_protection=True,
    )
    print_success(f"Phase 3 complete: CloudTrail stack {report.action}.")
    _record_phase(session_mgr, "cloudtrail")


def _run_phase_4_accounts(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
    only: list[str] | None = None,
) -> None:
    """Phase 4: Account Factory Provisioning & Baselining.

    ``only`` limits the run to those declared accounts; accounts missing from accounts.yaml are then left alone.
    """
    print_step("4", "Account Factory Provisioning & Baselining")

    account_service = AccountService(session_mgr)
    baseliner = BaselineService(session_mgr)

    wanted = {normalize_account_name(name) for name in only or []}
    declared = [a for a in bundle.accounts.accounts if not wanted or normalize_account_name(a.name) in wanted]
    ou_map = _existing_ou_map(session_mgr, {a.ou for a in declared})
    results = account_service.provision_accounts(
        declared, ou_map=ou_map, org_tags=bundle.get_organization_tags()
    )
    acct_def_map = {a.name: a for a in declared}

    baseline_problems: list[str] = []
    for result in results:
        acct_def = acct_def_map.get(result.name)
        if result.status == "SKIPPED":
            print_warning(
                _suspended_account_guidance(result.name, result.email, result.account_id or "unknown")
            )
            continue
        if acct_def and result.account_id:
            baseline_report = baseliner.baseline_account(
                acct_def,
                result.account_id,
                regions=None,
                org_tags=bundle.get_organization_tags(),
                custom_tags=custom_tags,
            )
            baseline_problems.extend(_baseline_failures(baseline_report))

    failed_results = [r for r in results if r.status == "FAILED"]
    if failed_results:
        failed_names = ", ".join(r.name for r in failed_results)
        raise AccountProvisioningError(
            f"Phase 4 failed: Account provisioning failed for {plural(len(failed_results), 'account')}: {failed_names}"
        )

    suspended_ou_id = ou_map.get("Suspended")
    for item in [] if wanted else account_service.plan(bundle.accounts, ou_map):
        if item.action == "SUSPEND" and item.account_id:
            account_service.suspend_account(
                account_id=item.account_id,
                account_name=item.name,
                suspended_ou_id=suspended_ou_id,
            )
            print_warning(
                f"Account '{item.name}' ({item.account_id}) removed from YAML -> Quarantined in Suspended OU and tagged."
            )

    account_service.export_inventory(bundle.accounts, ou_map, project_root / "outputs")
    _ensure_delegated_admin(session_mgr, bundle)

    if baseline_problems:
        # Do not record the "accounts" milestone: the accounts exist, but their baseline is incomplete.
        raise AccountProvisioningError(
            f"Phase 4 finished with {plural(len(baseline_problems), 'failed baseline step')}; "
            "fix the cause and re-run `tarmac deploy --phase 4`.",
            details="\n".join(baseline_problems),
        )

    if wanted:
        print_success(f"Phase 4 complete for {', '.join(a.name for a in declared)}.")
        return
    _record_phase(session_mgr, "accounts")
    print_success("Phase 4 complete: All accounts provisioned, baselined, and exported.")


def _ensure_delegated_admin(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> None:
    """Register delegated administrator for IAM if configured."""
    root_mgmt = bundle.org.root_access_management
    if not (root_mgmt.enabled and root_mgmt.delegated_admin_account):
        return
    if OrganizationService(session_mgr).configure_root_access(root_mgmt).get("delegated_admin"):
        print_success(f"Delegated administrator ({root_mgmt.delegated_admin_account}) for IAM is in place.")


def _deploy_backend_stack(
    cfn_service: CloudFormationService,
    cfn_client: Any,
    bundle: ConfigBundle,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
) -> None:
    template_file = resolve_resource_path("cloudformation/terraform-backend.yaml", project_root=project_root)

    backend_stack = Stack.TERRAFORM_BACKEND.for_org(bundle.org.organization.name)
    enable_dynamodb, lock_warning = lock_table_wanted(
        cfn_client, backend_stack, bundle.org.terraform_backend.enable_dynamodb
    )
    if lock_warning:
        print_warning(lock_warning)

    cfn_service.deploy_stack(
        cfn_client,
        backend_stack,
        template_file,
        backend_parameters(bundle, enable_dynamodb),
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(bundle.get_backend_account_name()),
        termination_protection=True,
    )


def _deploy_hardening_stacks(
    cfn_service: CloudFormationService,
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    org_id: str,
    accts: dict[str, str],
    custom_tags: dict[str, str] | None = None,
    skip_log_archive_hardening: bool = False,
) -> None:
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    log_archive_id = bundle.resolve_account_id(log_archive_name, accts)
    if log_archive_id and not skip_log_archive_hardening:
        _deploy_log_archive_hardening_stack(
            cfn_service,
            session_mgr,
            bundle,
            target_region,
            project_root,
            org_id,
            log_archive_id,
            custom_tags=custom_tags,
        )

    audit_name = bundle.get_audit_account_name() or "audit"
    audit_id = bundle.resolve_account_id(audit_name, accts)
    if not audit_id:
        print_warning(
            f"Audit account '{audit_name}' was not found among active accounts; "
            "skipping audit hardening and Config delegation."
        )
        return

    OrganizationService(session_mgr).register_service_delegated_administrators(
        audit_id,
        ["config-multiaccountsetup.amazonaws.com", "config.amazonaws.com", "cloudtrail.amazonaws.com"],
    )
    cfn_service.deploy_stack(
        session_mgr.get_member_client(audit_id, "cloudformation", region_name=target_region),
        Stack.AUDIT_ACCOUNT.for_org(bundle.org.organization.name),
        resolve_resource_path("cloudformation/audit-account-hardening.yaml", project_root=project_root),
        audit_hardening_parameters(bundle, org_id),
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(audit_name),
        termination_protection=True,
    )


def _delegate_security_services(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    accts: dict[str, str],
) -> None:
    """Delegate GuardDuty and Security Hub to Audit account if configured."""
    sec_cfg = bundle.org.security_services
    if not (sec_cfg.guardduty.enabled or sec_cfg.securityhub.enabled):
        return

    reports = SecurityServicesService(session_mgr).configure_security_services(
        config=sec_cfg,
        primary_region=target_region,
        all_regions=[target_region, *bundle.org.organization.additional_regions],
        account_id_map=accts,
    )
    failed: list[str] = []
    for rep in reports:
        if rep.status in ("ENABLED", "ALREADY_CONFIGURED"):
            print_success(f"Security Delegation ({rep.service_name}): {rep.message}")
        else:
            print_warning(f"Security Delegation ({rep.service_name}): {rep.message}")
            if rep.status == "FAILED":
                failed.append(f"{rep.service_name}: {rep.message}")
    if failed:
        raise GovernanceError(
            "Phase 5 failed: security service delegation did not complete.", details="\n".join(failed)
        )


def _run_phase_5_hardening(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    custom_tags: dict[str, str] | None = None,
    skip_log_archive_hardening: bool = False,
) -> None:
    """Phase 5: Account Hardening, Terraform Backend & Security Services."""
    print_step("5", "Backend, Hardening & Security Services Deployments")

    cfn_service = CloudFormationService(session_mgr)
    org_id = str(session_mgr.get_client("organizations").describe_organization()["Organization"]["Id"])
    accts = get_active_account_id_map(session_mgr)

    backend_name = bundle.get_backend_account_name() or "deployment"
    deployment_id = bundle.resolve_account_id(backend_name, accts)
    if deployment_id:
        _deploy_backend_stack(
            cfn_service,
            session_mgr.get_member_client(deployment_id, "cloudformation", region_name=target_region),
            bundle,
            project_root,
            custom_tags=custom_tags,
        )
    else:
        print_warning(
            f"Backend account '{backend_name}' was not found among active accounts; "
            "skipping the Terraform backend stack."
        )

    _deploy_hardening_stacks(
        cfn_service,
        session_mgr,
        bundle,
        target_region,
        project_root,
        org_id,
        accts,
        custom_tags=custom_tags,
        skip_log_archive_hardening=skip_log_archive_hardening,
    )
    deploy_config_recorder(
        session_mgr, cfn_service, bundle, target_region, project_root, accts, custom_tags=custom_tags
    )
    deploy_management_root_alert(
        session_mgr, cfn_service, bundle, target_region, project_root, custom_tags=custom_tags
    )
    _delegate_security_services(session_mgr, bundle, target_region, accts)

    _record_phase(session_mgr, "hardening")
    print_success("Phase 5 complete: Foundation stacks deployed and security services delegated.")


def _run_phase_6_identity(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    region_override: str | None = None,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 6: IAM Identity Center (SSO)."""
    print_step("6", "IAM Identity Center (SSO)")

    id_cfg = bundle.identity.identity_center
    target_region = region_override or id_cfg.region or bundle.org.organization.primary_region
    sso_session_mgr = (
        session_mgr
        if session_mgr.default_region == target_region
        else AwsSessionManager(region_name=target_region)
    )
    report = IdentityService(sso_session_mgr, preferred_region=target_region).sync_identity(
        id_cfg,
        project_root=project_root,
        org_name=bundle.org.organization.name,
        org_tags=bundle.get_organization_tags(),
        custom_tags=custom_tags,
    )

    _record_phase(session_mgr, "identity")
    print_success(
        f"Phase 6 complete: Synced {plural(len(report.permission_sets_synced), 'permission set')}, "
        f"{plural(len(report.users_synced), 'user')}, {plural(report.assignments_created, 'assignment')}, "
        f"and {plural(report.memberships_added, 'membership')}."
    )
