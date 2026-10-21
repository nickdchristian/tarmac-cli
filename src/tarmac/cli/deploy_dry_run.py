"""Simulation and dry-run plan rendering for the deployment pipeline."""

import functools
import logging
from collections.abc import Callable
from typing import Any

from rich.panel import Panel

from ..core.audit import Outcome, audit
from ..core.aws_client import AwsSessionManager
from ..core.config_loader import ConfigBundle
from ..core.config_schema import AccountBaselineConfig, Contact, OUDef
from ..services.accounts import AccountService
from ..services.ou import OUService
from .deploy_config_recorder import warn_if_config_recorder_missing
from .ui import console, create_table, print_info, print_warning

logger = logging.getLogger(__name__)

_PLAN_ACTION_STYLES = {"CREATE": "green", "MOVE": "yellow", "SUSPEND": "red", "SUSPENDED": "red"}


def _records_plan(phase: int) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Record in the run log that a phase plan was previewed, so a dry run is never an empty log."""

    def decorator(render: Callable[..., None]) -> Callable[..., None]:
        @functools.wraps(render)
        def wrapper(*args: Any, **kwargs: Any) -> None:
            render(*args, **kwargs)
            audit(
                "plan",
                f"phase:{phase}",
                Outcome.SIMULATED,
                f"[DRY-RUN] Previewed the phase {phase} plan; nothing was executed",
                dry_run=True,
            )

        return wrapper

    return decorator


def _locking_label(backend_cfg: Any) -> str:
    """How the Terraform backend will lock state, for the plan output."""
    if backend_cfg.enable_dynamodb is None:
        return "S3-only (use_lockfile) for a new backend; an existing DynamoDB table is kept"
    if backend_cfg.enable_dynamodb:
        return f"DynamoDB table {backend_cfg.dynamodb_table_name}"
    return "S3-only (use_lockfile)"


def _contacts(bundle: ConfigBundle) -> list[tuple[str, Contact]]:
    contacts = bundle.org.contacts
    return [
        ("security", contacts.security),
        ("operations", contacts.operations),
        ("billing", contacts.billing),
    ]


def _budget_label(baseline: AccountBaselineConfig) -> str:
    return f"${baseline.budget.monthly_limit_usd:,.0f} USD" if baseline.budget else "None"


def _baseline_controls(baseline: AccountBaselineConfig) -> str:
    enabled = (
        (baseline.delete_default_vpc, "Purge VPC"),
        (baseline.anomaly_detection, "Anomaly Alert"),
        (baseline.budget, "Budget Alert"),
    )
    return ", ".join(label for on, label in enabled if on) or "Default"


def _account_plan_entry(
    name: str, ou: str, email: str, action: str, baseline: AccountBaselineConfig
) -> dict[str, Any]:
    return {
        "name": name,
        "ou": ou,
        "email": email,
        "action": action,
        "monthly_budget_usd": baseline.budget.monthly_limit_usd if baseline.budget else None,
        "delete_default_vpc": baseline.delete_default_vpc,
        "anomaly_detection": bool(baseline.anomaly_detection),
    }


def _collect_ou_tree(ous: list[OUDef], parent: str = "Root") -> list[tuple[str, str, str]]:
    """Flatten declared OU hierarchy into a list of (name, parent, description) tuples."""
    items: list[tuple[str, str, str]] = []
    for ou in ous:
        items.append((ou.name, parent, ou.description or ""))
        if ou.children:
            items.extend(_collect_ou_tree(ou.children, parent=ou.name))
    return items


def _format_policy_name(policy_arn_or_name: str) -> str:
    """Format IAM policy ARN into concise readable name."""
    prefix = "arn:aws:iam::aws:policy/"
    if policy_arn_or_name.startswith(prefix):
        return policy_arn_or_name[len(prefix) :]
    return policy_arn_or_name


@_records_plan(0)
def _render_phase_0_dry_run(bundle: ConfigBundle) -> None:
    table = create_table(title="Phase 0 Plan: Pre-Flight Operational Readiness Scope")
    table.add_column("Category", style="cyan")
    table.add_column("Audit Target", style="white")
    table.add_column("Verification Scope & Intent", style="dim")
    table.add_column("Planned Check", style="bold yellow", justify="center")

    cost_tags = bundle.get_cost_allocation_tags()
    cost_tag_desc = f"Declared: {', '.join(cost_tags)}" if cost_tags else "None declared (will warn)"

    table.add_row(
        "Root Security",
        "Root Account MFA",
        "Verify hardware or virtual MFA device enforced on payer account",
        "AUDIT PREREQ",
    )
    table.add_row(
        "Root Security",
        "Root Access Keys",
        "Verify absence of active access keys on management root user",
        "AUDIT PREREQ",
    )
    table.add_row(
        "Billing Health",
        "Currency & Thresholds",
        "Audit default currency code, free tier notifications, and anomaly threshold",
        "AUDIT PREREQ",
    )
    table.add_row(
        "Billing Health",
        "Cost Allocation Tags",
        cost_tag_desc,
        "AUDIT PREREQ",
    )
    table.add_row(
        "Service Readiness",
        "Service Quotas",
        "Ensure AWS Organizations account quota is sufficient for factory provisioning",
        "AUDIT PREREQ",
    )
    table.add_row(
        "Account Contacts",
        "Alternate Contacts",
        "Verify valid security, operations, and billing contact entries",
        "AUDIT PREREQ",
    )
    console.print(table)
    print_info("Live diagnostics bypassed in dry-run mode. Run 'tarmac preflight' to evaluate against AWS.")


@_records_plan(1)
def _render_phase_1_dry_run(bundle: ConfigBundle) -> None:
    table = create_table(title="Phase 1 Plan: Organization Bootstrap & Management Baseline")
    table.add_column("Component", style="cyan")
    table.add_column("Declared Configuration", style="white")
    table.add_column("Planned Action", style="bold green", justify="center")

    table.add_row(
        "AWS Organization",
        f"Name: {bundle.org.organization.name} | FeatureSet: ALL | Primary Region: {bundle.org.organization.primary_region}",
        "ENSURE / VERIFY",
    )
    for label, contact in _contacts(bundle):
        table.add_row(
            f"{label.title()} Contact", f"{contact.name} <{contact.email}> ({contact.phone})", "SET CONTACT"
        )
    root_mgmt = bundle.org.root_access_management
    root_desc = (
        f"Delegated Admin: {root_mgmt.delegated_admin_account}"
        if root_mgmt.enabled
        else "Root Access Management: Disabled"
    )
    root_action = "DELEGATE ADMIN" if root_mgmt.enabled else "[dim]NO-OP[/dim]"
    table.add_row("Root Governance", root_desc, root_action)

    cost_tags = bundle.get_cost_allocation_tags()
    cost_desc = f"{', '.join(cost_tags)} ({len(cost_tags)} tag(s))" if cost_tags else "None defined"
    cost_action = "ACTIVATE IN CE" if cost_tags else "[dim]NONE[/dim]"
    table.add_row("Cost Allocation Tags", cost_desc, cost_action)

    vpc_action = "PURGE DEFAULT VPCS" if bundle.org.organization.delete_default_vpc else "[dim]PRESERVE[/dim]"
    table.add_row(
        "Default VPC Cleanup",
        f"Management Account (delete_default_vpc={bundle.org.organization.delete_default_vpc})",
        vpc_action,
    )
    table.add_row(
        "Trusted AWS Services",
        "CloudTrail, Organizations, SSO, Config, GuardDuty, Security Hub",
        "ENABLE ACCESS",
    )
    console.print(table)


@_records_plan(2)
def _render_phase_2_dry_run(bundle: ConfigBundle) -> None:
    ou_items = _collect_ou_tree(bundle.org.ou_structure)
    table_ou = create_table(title="Phase 2 Plan: Organizational Units Hierarchy")
    table_ou.add_column("OU Name", style="cyan")
    table_ou.add_column("Parent", style="magenta")
    table_ou.add_column("Description", style="dim")
    table_ou.add_column("Planned Action", style="bold green", justify="center")

    for name, parent, desc in ou_items:
        table_ou.add_row(name, parent, desc or "-", "WOULD SYNC / CREATE")
    console.print(table_ou)

    scp_cfg = bundle.org.service_control_policies
    if scp_cfg and scp_cfg.enabled and scp_cfg.policies:
        table_scp = create_table(title="Phase 2 Plan: Service Control Policies (SCPs)")
        table_scp.add_column("Policy Name", style="cyan")
        table_scp.add_column("Target Attachments", style="magenta")
        table_scp.add_column("Policy File", style="white")
        table_scp.add_column("Planned Action", style="bold green", justify="center")

        for p in scp_cfg.policies:
            targets_str = ", ".join(p.targets)
            table_scp.add_row(p.name, targets_str, p.policy_file, "DEPLOY VIA CFN")
        console.print(table_scp)
    else:
        print_info("Service Control Policies (SCPs) are disabled or none declared in configuration.")


@_records_plan(3)
def _render_phase_3_dry_run(bundle: ConfigBundle, target_region: str) -> None:
    table = create_table(title="Phase 3 Plan: Foundational Organization CloudTrail")
    table.add_column("Property", style="cyan")
    table.add_column("Configuration Value", style="white")
    table.add_column("Planned Action", style="bold green", justify="center")

    trail_cfg = bundle.org.cloudtrail
    stack_name = f"{bundle.org.organization.name}-organization-cloudtrail"
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    if trail_cfg.enable_kms is None:
        kms_desc = "Unset: SSE-S3 for a new deployment; an existing KMS key is kept"
    else:
        kms_desc = "Enabled (Customer Managed Key)" if trail_cfg.enable_kms else "Disabled (SSE-S3 AES-256)"

    table.add_row("CloudFormation Stack", stack_name, "DEPLOY STACK")
    table.add_row(
        "Log Archive Hardening",
        f"{bundle.org.organization.name}-log-archive-hardening",
        "DEPLOY S3 & KMS SINK",
    )
    table.add_row("Organization Trail", trail_cfg.trail_name, "CREATE MULTI-REGION")
    table.add_row("Primary Region", target_region, "STACK REGION")
    table.add_row("Log Archive Account", log_archive_name, "AGGREGATE S3 SINK")
    table.add_row(
        "KMS Encryption",
        kms_desc,
        "CONSTRUCT KEY POLICY"
        if trail_cfg.enable_kms
        else "KEEP EXISTING KEY, ELSE NONE"
        if trail_cfg.enable_kms is None
        else "NO KEY NEEDED",
    )
    if trail_cfg.retention_days:
        table.add_row(
            "Log Retention", f"Delete after {trail_cfg.retention_days} days", "APPLY LIFECYCLE RULE"
        )
    else:
        table.add_row("Log Retention", "Keep indefinitely", "NO EXPIRATION")
    lock = trail_cfg.object_lock
    if lock:
        table.add_row(
            "Object Lock",
            f"{lock.mode}, {lock.retention_days} days",
            "LOCK NEW LOG OBJECTS (CANNOT BE UNDONE)",
        )
    else:
        table.add_row("Object Lock", "Off", "RECOMMENDED: GOVERNANCE, 365 DAYS")
    if bundle.org.security_services.config_recorder.enabled:
        table.add_row(
            "AWS Config Bucket",
            f"{bundle.org.organization.name}-org-config-logs-<log-archive-id>",
            "CREATE (SEPARATE FROM CLOUDTRAIL, NO OBJECT LOCK)",
        )
    table.add_row("Trail Scope", "Multi-Region (All accounts in organization)", "APPLY ORG-WIDE")
    console.print(table)


def _fetch_live_account_plan(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> list[Any]:
    """Fetch live OU map and compute account plan items if credentials are available."""
    try:
        if session_mgr._root_session.get_credentials() is not None:
            ou_service = OUService(session_mgr)
            account_service = AccountService(session_mgr)
            root_id = ou_service.get_root_id()
            ou_map = ou_service.list_all_ous(root_id)
            return account_service.plan(bundle.accounts, ou_map)
    except Exception as e:
        logger.debug("Live AWS account query bypassed during dry-run: %s", e)
    return []


@_records_plan(4)
def _render_phase_4_dry_run(session_mgr: AwsSessionManager, bundle: ConfigBundle) -> None:
    table = create_table(title="Phase 4 Plan: Account Factory Provisioning & Baselining")
    table.add_column("Account Name", style="cyan")
    table.add_column("Target OU", style="magenta")
    table.add_column("Account Email", style="white")
    table.add_column("Planned Action", style="bold green", justify="center")
    table.add_column("Monthly Budget", style="yellow", justify="right")
    table.add_column("Baseline Security Controls", style="dim")

    plan_items = _fetch_live_account_plan(session_mgr, bundle)
    for item in plan_items:
        style = _PLAN_ACTION_STYLES.get(item.action, "dim")
        table.add_row(
            item.name,
            item.ou,
            item.email,
            f"[{style}]{item.action}[/{style}]",
            _budget_label(item.baseline),
            _baseline_controls(item.baseline),
        )
        audit(
            "plan",
            f"account:{item.name}",
            Outcome.SIMULATED,
            f"[DRY-RUN] Account '{item.name}' would be {item.action} (target OU {item.ou})",
            dry_run=True,
            planned_action=item.action,
        )
    if not plan_items:
        for acct in bundle.accounts.accounts:
            table.add_row(
                acct.name,
                acct.ou,
                acct.email,
                "WOULD PROVISION",
                _budget_label(acct.baseline),
                _baseline_controls(acct.baseline),
            )

    console.print(table)
    quarantined = [i.name for i in plan_items if i.action == "SUSPEND"]
    if quarantined:
        print_warning(
            f"{len(quarantined)} account(s) are tagged as managed by Tarmac but are missing from accounts.yaml "
            f"and would be moved to the Suspended OU: {', '.join(quarantined)}. Add them to accounts.yaml to keep "
            "them where they are, or set 'quarantine_removed_accounts: false' to turn this off."
        )
    print_info(
        "Account IDs, access credentials, and baselines will be exported to 'outputs/accounts-inventory.json' during live execution."
    )


@_records_plan(5)
def _render_phase_5_dry_run(bundle: ConfigBundle) -> None:
    table = create_table(title="Phase 5 Plan: Foundation Infrastructure & Security Delegation")
    table.add_column("Component / Stack", style="cyan")
    table.add_column("Target Account", style="magenta")
    table.add_column("Key Parameters & Settings", style="white")
    table.add_column("Planned Action", style="bold green", justify="center")

    backend_name = bundle.get_backend_account_name() or "deployment"
    backend_cfg = bundle.org.terraform_backend
    backend_params = f"BucketPrefix: {backend_cfg.bucket_prefix}, Locking: {_locking_label(backend_cfg)}"
    table.add_row(
        f"{bundle.org.organization.name}-terraform-backend",
        backend_name,
        backend_params,
        "DEPLOY CFN STACK",
    )

    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    table.add_row(
        f"{bundle.org.organization.name}-log-archive-hardening",
        log_archive_name,
        "Log Vault Bucket Policy, Retention, Cross-Account Aggregation",
        "DEPLOY CFN STACK",
    )

    audit_name = bundle.get_audit_account_name() or "audit"
    alert_email = str(bundle.org.contacts.security.email) if bundle.org.contacts.security.email else "None"
    audit_params = f"Config Delegated Admin, Security Alerts SNS ({alert_email})"
    table.add_row(
        f"{bundle.org.organization.name}-audit-account-hardening",
        audit_name,
        audit_params,
        "DEPLOY CFN STACK",
    )

    sec_services = bundle.org.security_services
    gd_action = "DELEGATE & ENABLE" if sec_services.guardduty.enabled else "[dim]DISABLED[/dim]"
    gd_params = f"Delegated Admin: {audit_name}, AutoEnable: {sec_services.guardduty.auto_enable_members}"
    table.add_row("GuardDuty Service", audit_name, gd_params, gd_action)

    sh_action = "DELEGATE & ENABLE" if sec_services.securityhub.enabled else "[dim]DISABLED[/dim]"
    sh_params = f"Delegated Admin: {audit_name}, AutoEnable: {sec_services.securityhub.auto_enable_members}"
    table.add_row("Security Hub Service", audit_name, sh_params, sh_action)

    config_cfg = sec_services.config_recorder
    if config_cfg.enabled:
        regions = list(
            dict.fromkeys(
                [bundle.org.organization.primary_region, *bundle.org.organization.additional_regions]
            )
        )
        scope = (
            f"global resources in {regions[0]}"
            if config_cfg.include_global_resources
            else "no global resources"
        )
        table.add_row(
            "AWS Config recorders",
            "All accounts (StackSet) + management",
            f"Regions: {', '.join(regions)}; {scope}; {config_cfg.recording_frequency.lower()} recording"
            + ("" if config_cfg.record_resource_compliance else "; no ResourceCompliance items"),
            "DEPLOY STACKSET",
        )
    else:
        table.add_row(
            "AWS Config recorders", "-", "Delivers to the central log bucket", "[dim]DISABLED[/dim]"
        )

    root_alert = sec_services.root_alert
    table.add_row(
        f"{bundle.org.organization.name}-management-root-alert",
        "Management",
        f"Root activity alert to {alert_email}, in us-east-1 and the primary Region"
        + (" and every declared Region" if root_alert.all_regions else ""),
        "DEPLOY CFN STACK" if root_alert.enabled else "[dim]DISABLED[/dim]",
    )

    console.print(table)
    warn_if_config_recorder_missing(bundle)


@_records_plan(6)
def _render_phase_6_dry_run(bundle: ConfigBundle, region_override: str | None) -> None:
    id_cfg = bundle.identity.identity_center
    target_region = region_override or id_cfg.region or bundle.org.organization.primary_region

    table_ps = create_table(title="Phase 6 Plan: IAM Identity Center Permission Sets")
    table_ps.add_column("Permission Set", style="cyan")
    table_ps.add_column("Session Duration", style="white")
    table_ps.add_column("AWS Managed Policies", style="dim")
    table_ps.add_column("Planned Action", style="bold green", justify="center")

    for ps in id_cfg.permission_sets:
        policies_str = (
            ", ".join(_format_policy_name(p) for p in ps.managed_policies)
            if ps.managed_policies
            else "Inline only"
        )
        table_ps.add_row(ps.name, ps.session_duration, policies_str, "CREATE / SYNC")
    console.print(table_ps)

    table_ug = create_table(title="Phase 6 Plan: Identity Center Users & Groups")
    table_ug.add_column("Entity Type", style="magenta")
    table_ug.add_column("Name / Username", style="cyan")
    table_ug.add_column("Details", style="white")
    table_ug.add_column("Planned Action", style="bold green", justify="center")

    table_ug.add_row("USER", id_cfg.admin_user.username, str(id_cfg.admin_user.email), "CREATE / SYNC")
    table_ug.add_row(
        "USER", id_cfg.breakglass_user.username, str(id_cfg.breakglass_user.email), "CREATE / SYNC"
    )
    for u in id_cfg.additional_users:
        table_ug.add_row("USER", u.username, str(u.email), "CREATE / SYNC")

    for g in id_cfg.groups:
        members_str = f"Members: {', '.join(g.members)}" if g.members else "No initial members"
        table_ug.add_row("GROUP", g.name, members_str, "CREATE / SYNC")
    console.print(table_ug)

    assignments: list[tuple[str, str, str]] = []
    for g in id_cfg.groups:
        for a in g.assignments:
            targets_str = ", ".join(a.accounts)
            assignments.append((g.name, a.permission_set, targets_str))

    if assignments:
        table_as = create_table(title="Phase 6 Plan: Group Account Assignments")
        table_as.add_column("Group Principal", style="cyan")
        table_as.add_column("Permission Set", style="magenta")
        table_as.add_column("Target Account(s)", style="white")
        table_as.add_column("Planned Action", style="bold green", justify="center")

        for group_name, perm_set, targets in assignments:
            table_as.add_row(group_name, perm_set, targets, "ASSIGN")
        console.print(table_as)

    print_info(f"Target Identity Center Region: {target_region}")


def _compute_dry_run_summary_counts(bundle: ConfigBundle) -> dict[str, int]:
    ou_count = len(_collect_ou_tree(bundle.org.ou_structure))
    acct_count = len(bundle.accounts.accounts)
    scp_count = (
        len(bundle.org.service_control_policies.policies)
        if (bundle.org.service_control_policies and bundle.org.service_control_policies.enabled)
        else 0
    )
    id_cfg = bundle.identity.identity_center
    sec_cfg = bundle.org.security_services
    stack_count = (
        4
        + (1 if scp_count > 0 else 0)
        + (1 if sec_cfg.config_recorder.enabled else 0)
        + (1 if sec_cfg.root_alert.enabled else 0)
        + (1 if id_cfg.permission_sets else 0)
    )
    user_count = 2 + len(id_cfg.additional_users)
    perm_count = len(id_cfg.permission_sets)
    group_count = len(id_cfg.groups)
    return {
        "ou_count": ou_count,
        "acct_count": acct_count,
        "scp_count": scp_count,
        "stack_count": stack_count,
        "user_count": user_count,
        "perm_count": perm_count,
        "group_count": group_count,
    }


def _render_dry_run_summary(phases_run: list[int], bundle: ConfigBundle) -> None:
    counts = _compute_dry_run_summary_counts(bundle)
    phases_str = ", ".join(f"Phase {p}" for p in sorted(phases_run))

    summary_text = (
        f"[bold white]Simulation Scope:[/bold white] {phases_str}\n\n"
        f"  [bold cyan]• Organizational Units (OUs):[/bold cyan] {counts['ou_count']} declared in hierarchy\n"
        f"  [bold cyan]• Member Accounts:[/bold cyan] {counts['acct_count']} declared in factory catalog\n"
        f"  [bold cyan]• Service Control Policies:[/bold cyan] {counts['scp_count']} policies configured\n"
        f"  [bold cyan]• CloudFormation Stacks:[/bold cyan] {counts['stack_count']} foundation stacks\n"
        f"  [bold cyan]• IAM Identity Center:[/bold cyan] {counts['perm_count']} permission sets, {counts['user_count']} users, {counts['group_count']} groups\n\n"
        f"[bold green]Simulation Outcome:[/bold green] All configurations validated successfully. No AWS resources modified.\n\n"
        f"[bold yellow]Next Step:[/bold yellow] To execute this deployment against live AWS infrastructure, run:\n"
        f"  [bold white]tarmac deploy run[/bold white]"
    )

    console.print(
        Panel(
            summary_text,
            title="[bold yellow]Tarmac Landing Zone: Dry-Run Plan Summary[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )


def _build_dry_run_plan_dict(
    phases_to_run: list[int],
    bundle: ConfigBundle,
    session_mgr: AwsSessionManager,
    target_region: str,
    region_override: str | None = None,
) -> dict[str, Any]:
    """Compile structured execution plan dictionary across simulated phases."""
    phases_data: dict[str, Any] = {}

    if 0 in phases_to_run:
        phases_data["0_preflight"] = {
            "checks_audited": [
                "Root Account MFA",
                "Root Access Keys",
                "Currency & Thresholds",
                "Cost Allocation Tags",
                "Service Quotas",
                "Alternate Contacts",
            ],
            "cost_allocation_tags": bundle.get_cost_allocation_tags(),
        }

    if 1 in phases_to_run:
        phases_data["1_org"] = {
            "organization_name": bundle.org.organization.name,
            "feature_set": "ALL",
            "primary_region": bundle.org.organization.primary_region,
            "additional_regions": bundle.org.organization.additional_regions,
            "contacts": {
                label: {"name": c.name, "email": str(c.email), "phone": c.phone}
                for label, c in _contacts(bundle)
            },
            "root_access_management": {
                "enabled": bundle.org.root_access_management.enabled,
                "delegated_admin_account": bundle.org.root_access_management.delegated_admin_account,
            },
            "cost_allocation_tags": bundle.get_cost_allocation_tags(),
            "delete_default_vpc": bundle.org.organization.delete_default_vpc,
        }

    if 2 in phases_to_run:
        ou_items = _collect_ou_tree(bundle.org.ou_structure)
        scp_cfg = bundle.org.service_control_policies
        scp_items = [
            {"name": p.name, "targets": p.targets, "policy_file": p.policy_file, "description": p.description}
            for p in (scp_cfg.policies if scp_cfg and scp_cfg.enabled else [])
        ]
        phases_data["2_ou"] = {
            "ous": [{"name": name, "parent": parent, "description": desc} for name, parent, desc in ou_items],
            "service_control_policies": scp_items,
        }

    if 3 in phases_to_run:
        phases_data["3_cloudtrail"] = {
            "stack_name": f"{bundle.org.organization.name}-organization-cloudtrail",
            "log_archive_stack": f"{bundle.org.organization.name}-log-archive-hardening",
            "trail_name": bundle.org.cloudtrail.trail_name,
            "primary_region": target_region,
            "log_archive_account": bundle.get_log_archive_account_name() or "log-archive",
            "kms_enabled": bundle.org.cloudtrail.enable_kms,
            "log_retention_days": bundle.org.cloudtrail.retention_days,
        }

    if 4 in phases_to_run:
        plan_items = _fetch_live_account_plan(session_mgr, bundle)
        accounts_plan = [
            {**_account_plan_entry(i.name, i.ou, i.email, i.action, i.baseline), "reason": i.reason}
            for i in plan_items
        ] or [
            _account_plan_entry(a.name, a.ou, a.email, "WOULD PROVISION", a.baseline)
            for a in bundle.accounts.accounts
        ]
        phases_data["4_accounts"] = accounts_plan

    if 5 in phases_to_run:
        audit_name = bundle.get_audit_account_name() or "audit"
        phases_data["5_foundation"] = {
            "terraform_backend": {
                "stack_name": f"{bundle.org.organization.name}-terraform-backend",
                "account": bundle.get_backend_account_name() or "deployment",
                "bucket_prefix": bundle.org.terraform_backend.bucket_prefix,
                "dynamodb_table_name": bundle.org.terraform_backend.dynamodb_table_name,
                "enable_dynamodb": bundle.org.terraform_backend.enable_dynamodb,
                "locking": _locking_label(bundle.org.terraform_backend),
            },
            "log_archive_hardening": {
                "stack_name": f"{bundle.org.organization.name}-log-archive-hardening",
                "account": bundle.get_log_archive_account_name() or "log-archive",
            },
            "audit_account_hardening": {
                "stack_name": f"{bundle.org.organization.name}-audit-account-hardening",
                "account": audit_name,
                "alert_email": (
                    str(bundle.org.contacts.security.email) if bundle.org.contacts.security.email else None
                ),
            },
            "security_delegations": {
                "guardduty": {
                    "enabled": bundle.org.security_services.guardduty.enabled,
                    "delegated_admin": audit_name,
                    "auto_enable_members": bundle.org.security_services.guardduty.auto_enable_members,
                },
                "securityhub": {
                    "enabled": bundle.org.security_services.securityhub.enabled,
                    "delegated_admin": audit_name,
                    "auto_enable_members": bundle.org.security_services.securityhub.auto_enable_members,
                },
            },
            "config_recorder": {
                "enabled": bundle.org.security_services.config_recorder.enabled,
                "recording_frequency": bundle.org.security_services.config_recorder.recording_frequency,
                "include_global_resources": bundle.org.security_services.config_recorder.include_global_resources,
            },
            "root_alert": {
                "enabled": bundle.org.security_services.root_alert.enabled,
                "stack_name": f"{bundle.org.organization.name}-management-root-alert",
                "all_regions": bundle.org.security_services.root_alert.all_regions,
            },
        }

    if 6 in phases_to_run:
        id_cfg = bundle.identity.identity_center
        id_region = region_override or id_cfg.region or bundle.org.organization.primary_region
        permission_sets_data = [
            {
                "name": ps.name,
                "session_duration": ps.session_duration,
                "managed_policies": ps.managed_policies,
                "inline_policy_file": ps.inline_policy_file,
            }
            for ps in id_cfg.permission_sets
        ]
        users_data = [
            {"username": id_cfg.admin_user.username, "email": str(id_cfg.admin_user.email), "type": "ADMIN"},
            {
                "username": id_cfg.breakglass_user.username,
                "email": str(id_cfg.breakglass_user.email),
                "type": "BREAKGLASS",
            },
        ] + [
            {"username": u.username, "email": str(u.email), "type": "STANDARD"}
            for u in id_cfg.additional_users
        ]
        groups_data = [
            {
                "name": g.name,
                "members": g.members,
                "assignments": [
                    {"permission_set": a.permission_set, "accounts": a.accounts} for a in g.assignments
                ],
            }
            for g in id_cfg.groups
        ]
        phases_data["6_identity"] = {
            "region": id_region,
            "permission_sets": permission_sets_data,
            "users": users_data,
            "groups": groups_data,
        }

    counts = _compute_dry_run_summary_counts(bundle)

    return {
        "dry_run": True,
        "target_region": target_region,
        "organization": {
            "name": bundle.org.organization.name,
            "primary_region": bundle.org.organization.primary_region,
            "additional_regions": bundle.org.organization.additional_regions,
            "feature_set": "ALL",
            "delete_default_vpc": bundle.org.organization.delete_default_vpc,
        },
        "phases": phases_data,
        "summary": {
            "phases_simulated": sorted(phases_to_run),
            "total_ous": counts["ou_count"],
            "total_accounts": counts["acct_count"],
            "total_scps": counts["scp_count"],
            "total_stacks": counts["stack_count"],
            "total_permission_sets": counts["perm_count"],
            "total_users": counts["user_count"],
            "total_groups": counts["group_count"],
            "outcome": "SUCCESS",
        },
    }
