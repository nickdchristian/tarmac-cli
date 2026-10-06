"""Phase runners for the multi-stage deployment pipeline."""

import logging
import sys
from pathlib import Path
from typing import Any

import typer

from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.exceptions import GovernanceError
from ..core.models import PreflightCheckStatus, PreflightReport, StackDeployReport
from ..core.templates import resolve_resource_path
from ..services.accounts import AccountService
from ..services.baseline import BaselineService
from ..services.cloudformation import CloudFormationService
from ..services.identity import IdentityService
from ..services.organization import OrganizationService
from ..services.ou import OUService
from ..services.scp import SCPService
from ..services.teardown import cleanup_orphaned_bucket
from .common import get_active_account_id_map
from .deploy_dry_run import (
    _render_phase_0_dry_run,
    _render_phase_1_dry_run,
    _render_phase_2_dry_run,
    _render_phase_3_dry_run,
    _render_phase_4_dry_run,
    _render_phase_5_dry_run,
    _render_phase_6_dry_run,
)
from .ui import (
    error_console,
    print_info,
    print_step,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)


def _get_service(name: str, fallback: Any) -> Any:
    """Retrieve service class from tarmac.cli.deploy if patched in tests, else fallback."""
    deploy_mod = sys.modules.get("tarmac.cli.deploy")
    if deploy_mod is not None and hasattr(deploy_mod, name):
        return getattr(deploy_mod, name)
    return fallback


def _handle_preflight_failures(report: PreflightReport) -> None:
    """Display preflight errors and abort deployment."""
    error_console.print(
        f"[red]✗ Pre-flight failed with {report.failures} blocking error(s) and {report.warnings} warning(s).[/red]"
    )
    for check in report.checks:
        if check.status == PreflightCheckStatus.FAIL:
            error_console.print(f"  [bold red]• {check.name}:[/bold red] {check.action_required}")
    error_console.print(
        "\n[yellow]Resolve the above issues or re-run with --skip-preflight to bypass.[/yellow]"
    )
    raise typer.Exit(code=1)


def _run_phase_0_preflight(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    dry_run: bool,
) -> None:
    """Phase 0: Pre-flight manual prerequisites and operational readiness checks."""
    print_step("0", "Pre-Flight Prerequisites & Health Diagnostics")
    if dry_run:
        _render_phase_0_dry_run(bundle)
        return

    from ..services.preflight import PreflightService

    service = PreflightService(session_mgr, bundle)
    report = service.run_all_checks()

    if report.failures > 0:
        _handle_preflight_failures(report)

    if report.warnings > 0:
        print_warning(
            f"Pre-flight completed with {report.warnings} non-blocking warning(s). Proceeding with deployment..."
        )
    else:
        print_success("Phase 0 complete: All pre-flight checks passed.")


def _run_phase_1_org(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    dry_run: bool,
) -> None:
    """Phase 1: AWS Organizations Bootstrap, Contacts, and Management Account Hardening."""
    print_step("1", "Organizations Bootstrap & Contacts")
    if dry_run:
        _render_phase_1_dry_run(bundle)
        return

    org_service = _get_service("OrganizationService", OrganizationService)(session_mgr)
    org_id = org_service.ensure_organization()
    org_service.set_account_contacts(bundle.org.contacts)
    org_service.enable_trusted_services()
    results = org_service.configure_root_access(bundle.org.root_access_management)
    if results.get("delegated_admin"):
        print_success(
            f"Registered delegated administrator ({bundle.org.root_access_management.delegated_admin_account}) for IAM."
        )

    target_cost_tags = bundle.get_cost_allocation_tags()
    if target_cost_tags:
        activated_tags = org_service.activate_cost_allocation_tags(target_cost_tags)
        if activated_tags:
            print_success(f"Activated Cost Allocation Tag(s): {', '.join(activated_tags)}")

    if bundle.org.organization.delete_default_vpc:
        baseliner = _get_service("BaselineService", BaselineService)(session_mgr)
        caller = session_mgr.get_caller_identity()
        mgmt_id = caller.get("Account", "")
        if mgmt_id:
            vpc_reports = baseliner.cleanup_default_vpcs(mgmt_id, "management", regions=None, dry_run=dry_run)
            for r in vpc_reports:
                if not r.skipped and r.deleted_vpc:
                    print_success(f"Management Account: Purged default VPC ({r.vpc_id}) in {r.region}")
            if not dry_run:
                baseliner.mark_account_baselined(mgmt_id)

    caller = session_mgr.get_caller_identity()
    mgmt_id = caller.get("Account", "")
    if not dry_run and mgmt_id:
        org_service.record_phase_completed(mgmt_id, "org")

    print_success(f"Phase 1 complete: Org {org_id} configured.")


def _run_phase_2_ou(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 2: Organizational Units Synchronization & Guardrails."""
    print_step("2", "Organizational Units & Guardrails")
    if dry_run:
        _render_phase_2_dry_run(bundle)
        return

    ou_service = _get_service("OUService", OUService)(session_mgr)
    root_id = ou_service.get_root_id()
    report = ou_service.sync_ou_structure(bundle.org.ou_structure)
    print_success(f"Phase 2: Synced {len(report.synced_ous)} OUs.")

    if bundle.org.service_control_policies and bundle.org.service_control_policies.enabled:
        scp_service = _get_service("SCPService", SCPService)(session_mgr)
        results = scp_service.reconcile_via_cloudformation(
            bundle.org.service_control_policies,
            root_id,
            report.synced_ous,
            project_root=project_root,
            org_name=bundle.org.organization.name,
            org_tags=bundle.get_organization_tags(),
            tags=custom_tags,
            dry_run=dry_run,
        )
        print_success(f"Phase 2 complete: Reconciled {len(results)} Service Control Policies.")
    else:
        print_success("Phase 2 complete: OUs synchronized.")

    caller = session_mgr.get_caller_identity()
    mgmt_id = caller.get("Account", "")
    if not dry_run and mgmt_id:
        _get_service("OrganizationService", OrganizationService)(session_mgr).record_phase_completed(
            mgmt_id, "ou"
        )


def _deploy_log_archive_hardening_stack(
    cfn_service: CloudFormationService,
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    org_id: str,
    log_archive_id: str,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> StackDeployReport:
    """Deploy the Log Archive account hardening stack containing the centralized S3 sink & KMS key."""
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    cfn_client = session_mgr.get_member_client(log_archive_id, "cloudformation", region_name=target_region)
    template_file = resolve_resource_path(
        "cloudformation/log-archive-hardening.yaml", project_root=project_root
    )

    def on_before_create() -> None:
        if not dry_run:
            s3_client = session_mgr.get_member_client(log_archive_id, "s3", region_name=target_region)
            buckets = [
                f"{bundle.org.organization.name}-log-archive-access-logs-{log_archive_id}",
                f"{bundle.org.organization.name}-org-cloudtrail-logs-{log_archive_id}",
                f"{bundle.org.cloudtrail.bucket_prefix}-{log_archive_id}",
            ]
            for b in set(buckets):
                cleanup_orphaned_bucket(s3_client, b, account_id=log_archive_id)

    return cfn_service.deploy_stack(
        cfn_client,
        f"{bundle.org.organization.name}-log-archive-hardening",
        template_file,
        {"OrganizationId": org_id, "OrgName": bundle.org.organization.name},
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(log_archive_name),
        dry_run=dry_run,
        on_before_create=on_before_create,
    )


def _run_phase_3_cloudtrail(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 3: Organization-wide CloudTrail deployment."""
    print_step("3", "Foundational Organization CloudTrail")
    if dry_run:
        _render_phase_3_dry_run(bundle, target_region)
        return

    cfn_service = _get_service("CloudFormationService", CloudFormationService)(session_mgr)
    org_client = session_mgr.get_client("organizations")
    org_id = str(org_client.describe_organization()["Organization"]["Id"])

    accts = get_active_account_id_map(session_mgr)
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    log_archive_id = bundle.resolve_account_id(log_archive_name, accts) or ""

    if not log_archive_id and not dry_run:
        acct_def = bundle.get_account(log_archive_name)
        if acct_def:
            print_info(
                f"Phase 3: Foundational account '{acct_def.name}' ({acct_def.email}) not yet active. Provisioning..."
            )
            ou_service = _get_service("OUService", OUService)(session_mgr)
            ou_map = ou_service.sync_ou_structure(bundle.org.ou_structure).synced_ous
            account_service = _get_service("AccountService", AccountService)(session_mgr)
            prov_results = account_service.provision_accounts([acct_def], ou_map=ou_map, dry_run=False)
            if prov_results and prov_results[0].account_id and prov_results[0].account_id != "DRY-RUN-ID":
                log_archive_id = prov_results[0].account_id
                accts[acct_def.name] = log_archive_id
                print_success(
                    f"Phase 3: Provisioned foundational account '{acct_def.name}' ({log_archive_id})."
                )

    if not log_archive_id and not dry_run:
        raise GovernanceError(
            f"Phase 3 failed: Log Archive account '{log_archive_name}' could not be resolved from active accounts. "
            "Ensure the account is declared in accounts.yaml and provisioned before deploying CloudTrail."
        )

    if log_archive_id and not dry_run:
        # 1. Deploy the Log Archive hardening stack (S3 sink & KMS key) to the Log Archive account first
        log_archive_report = _deploy_log_archive_hardening_stack(
            cfn_service,
            session_mgr,
            bundle,
            target_region,
            project_root,
            org_id,
            log_archive_id,
            dry_run,
            custom_tags=custom_tags,
        )
        print_success(f"Phase 3: Log Archive hardening stack {log_archive_report.action}.")
    elif dry_run:
        log_archive_id = log_archive_id or "DRY-RUN-LOG-ARCHIVE-ID"

    # 2. Deploy the Organization CloudTrail stack to the Management account
    template_file = resolve_resource_path(
        "cloudformation/organization-cloudtrail.yaml", project_root=project_root
    )
    stack_name = f"{bundle.org.organization.name}-organization-cloudtrail"

    params = {
        "OrgName": bundle.org.organization.name,
        "LogArchiveAccountId": log_archive_id,
        "TrailName": bundle.org.cloudtrail.trail_name,
        "EnableKmsEncryption": "true" if bundle.org.cloudtrail.enable_kms else "false",
    }
    cfn_client = session_mgr.get_client("cloudformation", region_name=target_region)
    report = cfn_service.deploy_stack(
        cfn_client,
        stack_name,
        template_file,
        params,
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        dry_run=dry_run,
    )
    print_success(f"Phase 3 complete: CloudTrail stack {report.action}.")

    caller = session_mgr.get_caller_identity()
    mgmt_id = caller.get("Account", "")
    if not dry_run and mgmt_id:
        _get_service("OrganizationService", OrganizationService)(session_mgr).record_phase_completed(
            mgmt_id, "cloudtrail"
        )


def _run_phase_4_accounts(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 4: Account Factory Provisioning & Baselining."""
    print_step("4", "Account Factory Provisioning & Baselining")
    if dry_run:
        _render_phase_4_dry_run(session_mgr, bundle)
        return

    ou_service = _get_service("OUService", OUService)(session_mgr)
    account_service = _get_service("AccountService", AccountService)(session_mgr)
    baseliner = _get_service("BaselineService", BaselineService)(session_mgr)

    ou_map = ou_service.sync_ou_structure(bundle.org.ou_structure).synced_ous
    results = account_service.provision_accounts(bundle.accounts.accounts, ou_map=ou_map, dry_run=False)
    acct_def_map = {a.name: a for a in bundle.accounts.accounts}

    for result in results:
        acct_def = acct_def_map.get(result.name)
        if acct_def and result.account_id and result.account_id != "DRY-RUN-ID":
            baseliner.baseline_account(
                acct_def,
                result.account_id,
                regions=None,
                dry_run=False,
                org_tags=bundle.get_organization_tags(),
                custom_tags=custom_tags,
            )

    suspended_ou_id = ou_map.get("Suspended")
    plan_items = account_service.plan(bundle.accounts, ou_map)
    for item in plan_items:
        if item.action == "SUSPEND" and item.account_id:
            account_service.suspend_account(
                account_id=item.account_id,
                account_name=item.name,
                suspended_ou_id=suspended_ou_id,
                dry_run=False,
            )
            print_warning(
                f"Account '{item.name}' ({item.account_id}) removed from YAML -> Quarantined in Suspended OU and tagged."
            )

    account_service.export_inventory(bundle.accounts, ou_map, project_root / "outputs")
    _ensure_delegated_admin(session_mgr, bundle)
    caller = session_mgr.get_caller_identity()
    mgmt_id = caller.get("Account", "")
    if mgmt_id:
        _get_service("OrganizationService", OrganizationService)(session_mgr).record_phase_completed(
            mgmt_id, "accounts"
        )
    print_success("Phase 4 complete: All accounts provisioned, baselined, and exported.")


def _ensure_delegated_admin(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> None:
    """Register delegated administrator for IAM if configured."""
    root_mgmt = bundle.org.root_access_management
    if not (root_mgmt.enabled and root_mgmt.delegated_admin_account):
        return

    org_service = _get_service("OrganizationService", OrganizationService)(session_mgr)
    delegated_res = org_service.configure_root_access(root_mgmt)
    if delegated_res.get("delegated_admin"):
        print_success(f"Delegated administrator ({root_mgmt.delegated_admin_account}) registered for IAM.")


def _deploy_backend_stack(
    cfn_service: CloudFormationService,
    cfn_client: Any,
    bundle: ConfigBundle,
    project_root: Path,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
    session_mgr: AwsSessionManager | None = None,
    deployment_id: str | None = None,
    target_region: str | None = None,
) -> None:
    template_file = resolve_resource_path("cloudformation/terraform-backend.yaml", project_root=project_root)
    backend_acct = bundle.get_backend_account_name()

    def on_before_create() -> None:
        if not dry_run and session_mgr and deployment_id:
            s3_client = session_mgr.get_member_client(deployment_id, "s3", region_name=target_region)
            state_buckets = [
                f"{bundle.org.organization.name}-terraform-state-{deployment_id}",
                f"{bundle.org.terraform_backend.bucket_prefix}-{deployment_id}",
            ]
            for b in set(state_buckets):
                cleanup_orphaned_bucket(s3_client, b, account_id=deployment_id)

    cfn_service.deploy_stack(
        cfn_client,
        f"{bundle.org.organization.name}-terraform-backend",
        template_file,
        {
            "OrgName": bundle.org.organization.name,
            "BucketPrefix": bundle.org.terraform_backend.bucket_prefix,
            "EnableDynamoDB": "true" if bundle.org.terraform_backend.enable_dynamodb else "false",
            "DynamoDBTableName": bundle.org.terraform_backend.dynamodb_table_name,
        },
        tags=custom_tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(backend_acct),
        dry_run=dry_run,
        on_before_create=on_before_create,
    )


def _deploy_hardening_stacks(
    cfn_service: CloudFormationService,
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    org_id: str,
    accts: dict[str, str],
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> None:
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    log_archive_id = bundle.resolve_account_id(log_archive_name, accts)
    if log_archive_id:
        _deploy_log_archive_hardening_stack(
            cfn_service,
            session_mgr,
            bundle,
            target_region,
            project_root,
            org_id,
            log_archive_id,
            dry_run,
            custom_tags=custom_tags,
        )

    audit_name = bundle.get_audit_account_name() or "audit"
    audit_id = bundle.resolve_account_id(audit_name, accts)
    if audit_id:
        org_client = session_mgr.get_client("organizations")
        for sp in ["config-multiaccountsetup.amazonaws.com", "config.amazonaws.com"]:
            try:
                org_client.register_delegated_administrator(AccountId=audit_id, ServicePrincipal=sp)
            except Exception as e:
                logger.debug("Delegated admin registration for %s: %s", sp, e)

        cfn_client = session_mgr.get_member_client(audit_id, "cloudformation", region_name=target_region)
        template_file = resolve_resource_path(
            "cloudformation/audit-account-hardening.yaml", project_root=project_root
        )
        hardening_params = {
            "OrgName": bundle.org.organization.name,
            "OrganizationId": org_id,
            "AlertEmail": str(bundle.org.contacts.security.email)
            if bundle.org.contacts.security.email
            else "",
        }
        if bundle.org.security_services.incident_response_webhook_url:
            hardening_params["IncidentResponseWebhookUrl"] = str(
                bundle.org.security_services.incident_response_webhook_url
            )
        cfn_service.deploy_stack(
            cfn_client,
            f"{bundle.org.organization.name}-audit-account-hardening",
            template_file,
            hardening_params,
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
            account_tags=bundle.get_account_tags(audit_name),
            dry_run=dry_run,
        )


def _delegate_security_services(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    accts: dict[str, str],
    dry_run: bool,
) -> None:
    """Delegate GuardDuty and Security Hub to Audit account if configured."""
    sec_cfg = bundle.org.security_services
    if not (sec_cfg.guardduty.enabled or sec_cfg.securityhub.enabled):
        return

    from ..services.security import SecurityServicesService

    sec_service = SecurityServicesService(session_mgr)
    all_regions = [target_region] + bundle.org.organization.additional_regions
    reports = sec_service.configure_security_services(
        config=sec_cfg,
        primary_region=target_region,
        all_regions=all_regions,
        account_id_map=accts,
        dry_run=dry_run,
    )
    for rep in reports:
        if rep.status in ("ENABLED", "ALREADY_CONFIGURED", "SIMULATED"):
            print_success(f"Security Delegation ({rep.service_name}): {rep.message}")
        else:
            print_warning(f"Security Delegation ({rep.service_name}): {rep.message}")


def _run_phase_5_hardening(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    target_region: str,
    project_root: Path,
    dry_run: bool,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 5: Account Hardening, Terraform Backend & Security Services."""
    print_step("5", "Backend, Hardening & Security Services Deployments")
    if dry_run:
        _render_phase_5_dry_run(bundle, target_region)
        return

    cfn_service = _get_service("CloudFormationService", CloudFormationService)(session_mgr)
    org_client = session_mgr.get_client("organizations")
    org_id = str(org_client.describe_organization()["Organization"]["Id"])
    accts = get_active_account_id_map(session_mgr)

    backend_name = bundle.get_backend_account_name() or "deployment"
    deployment_id = bundle.resolve_account_id(backend_name, accts)
    if deployment_id:
        cfn_client = session_mgr.get_member_client(deployment_id, "cloudformation", region_name=target_region)
        _deploy_backend_stack(
            cfn_service,
            cfn_client,
            bundle,
            project_root,
            dry_run,
            custom_tags=custom_tags,
            session_mgr=session_mgr,
            deployment_id=deployment_id,
            target_region=target_region,
        )

    _deploy_hardening_stacks(
        cfn_service,
        session_mgr,
        bundle,
        target_region,
        project_root,
        org_id,
        accts,
        dry_run,
        custom_tags=custom_tags,
    )

    _delegate_security_services(session_mgr, bundle, target_region, accts, dry_run)

    caller = session_mgr.get_caller_identity()
    mgmt_id = caller.get("Account", "")
    if mgmt_id:
        _get_service("OrganizationService", OrganizationService)(session_mgr).record_phase_completed(
            mgmt_id, "hardening"
        )
    print_success("Phase 5 complete: Foundation stacks deployed and security services delegated.")


def _run_phase_6_identity(
    session_mgr: AwsSessionManager,
    bundle: ConfigBundle,
    project_root: Path,
    dry_run: bool,
    region_override: str | None = None,
    custom_tags: dict[str, str] | None = None,
) -> None:
    """Phase 6: IAM Identity Center (SSO)."""
    print_step("6", "IAM Identity Center (SSO)")
    id_cfg = bundle.identity.identity_center
    if dry_run:
        _render_phase_6_dry_run(bundle, region_override)
        return

    target_region = region_override or id_cfg.region or bundle.org.organization.primary_region
    sso_session_mgr = (
        session_mgr
        if session_mgr.default_region == target_region
        else _get_service("AwsSessionManager", AwsSessionManager)(region_name=target_region)
    )
    identity_service = _get_service("IdentityService", IdentityService)(
        sso_session_mgr, preferred_region=target_region
    )

    report = identity_service.sync_identity(
        id_cfg,
        project_root=project_root,
        org_name=bundle.org.organization.name,
        dry_run=dry_run,
        org_tags=bundle.get_organization_tags(),
        custom_tags=custom_tags,
    )

    caller = session_mgr.get_caller_identity()
    mgmt_id = caller.get("Account", "")
    if mgmt_id:
        _get_service("OrganizationService", OrganizationService)(session_mgr).record_phase_completed(
            mgmt_id, "identity"
        )

    print_success(
        f"Phase 6 complete: Synced {len(report.permission_sets_synced)} permission set(s), "
        f"{len(report.users_synced)} user(s), {report.assignments_created} assignment(s), "
        f"and {report.memberships_added} membership(s)."
    )
