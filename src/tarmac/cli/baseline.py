"""CLI commands for foundational CloudFormation deployments."""

import logging
from typing import Annotated, Any

import typer

from ..core.aws_client import AwsSessionManager
from ..core.models import StackDeployReport
from ..core.templates import resolve_resource_path
from ..services.baseline import BaselineService
from ..services.cloudformation import CloudFormationService, lock_table_wanted
from ..services.log_encryption import resolve_log_encryption
from .common import (
    ConfigDirOption,
    RegionOption,
    TagsOption,
    audit_hardening_parameters,
    backend_parameters,
    cloudtrail_parameters,
    exit_on_error,
    get_active_account_id_map,
    load_configs_or_exit,
    log_archive_parameters,
    parse_tags_or_exit,
    warn_if_object_lock_unset,
)
from .ui import console, create_table, error_console, print_header, print_info, print_success, print_warning

logger = logging.getLogger(__name__)

app = typer.Typer(help="Foundational CloudFormation stack deployments.")

DryRunOption = Annotated[bool, typer.Option("--dry-run", help="Simulate deployment")]


@app.command("cloudtrail")
def deploy_cloudtrail(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    sse_s3: Annotated[
        bool,
        typer.Option(
            "--sse-s3", help="Use SSE-S3 (AES256) encryption instead of KMS CMK to eliminate KMS charges"
        ),
    ] = False,
    dry_run: DryRunOption = False,
    tags: TagsOption = None,
):
    """Deploy organization-wide CloudTrail stack in the Management Account."""
    print_header("Deploy Organization CloudTrail")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("CloudTrail Deployment Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)

        template_file = resolve_resource_path(
            "cloudformation/organization-cloudtrail.yaml", project_root=bundle.config_dir.parent
        )
        accts = get_active_account_id_map(session_mgr)
        log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
        log_archive_id = bundle.resolve_account_id(log_archive_name, accts) or ""
        if sse_s3:
            enable_kms = False
        elif dry_run:
            enable_kms = bool(bundle.org.cloudtrail.enable_kms)
        else:
            enable_kms = resolve_log_encryption(session_mgr, bundle, target_region, log_archive_id)

        report = service.deploy_stack(
            session_mgr.get_client("cloudformation", region_name=target_region),
            f"{bundle.org.organization.name}-organization-cloudtrail",
            template_file,
            cloudtrail_parameters(bundle, log_archive_id, enable_kms),
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
            termination_protection=True,
            dry_run=dry_run,
        )
        _print_stack_report(report)


@app.command("backend")
def deploy_backend(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    s3_only: Annotated[
        bool,
        typer.Option(
            "--s3-only", help="Deploy S3-only backend without DynamoDB (Terraform 1.10+ native S3 locking)"
        ),
    ] = False,
    dry_run: DryRunOption = False,
    tags: TagsOption = None,
):
    """Deploy Terraform state backend (S3 with optional DynamoDB) in the Deployment account."""
    print_header("Deploy Terraform Backend")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Backend Deployment Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)

        accts = get_active_account_id_map(session_mgr)
        backend_name = bundle.get_backend_account_name() or "deployment"
        deployment_acct_id = bundle.resolve_account_id(backend_name, accts)
        if not deployment_acct_id:
            error_console.print(
                f"[red]✗[/red] Backend account '{backend_name}' not found. Run 'tarmac account apply' first."
            )
            raise typer.Exit(code=1)

        template_file = resolve_resource_path(
            "cloudformation/terraform-backend.yaml", project_root=bundle.config_dir.parent
        )
        stack_name = f"{bundle.org.organization.name}-terraform-backend"
        cfn_client = session_mgr.get_member_client(
            deployment_acct_id, "cloudformation", region_name=target_region
        )
        enable_dynamodb, lock_warning = lock_table_wanted(
            cfn_client, stack_name, bundle.org.terraform_backend.enable_dynamodb, s3_only
        )
        if lock_warning:
            print_warning(lock_warning)

        report = service.deploy_stack(
            cfn_client,
            stack_name,
            template_file,
            backend_parameters(bundle, enable_dynamodb),
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
            account_tags=bundle.get_account_tags(backend_name),
            termination_protection=True,
            dry_run=dry_run,
        )
        _print_stack_report(report)


def _deploy_log_archive_stack(
    service: CloudFormationService,
    session_mgr: AwsSessionManager,
    bundle: Any,
    target_region: str,
    log_archive_id: str,
    org_id: str,
    dry_run: bool,
    tags: dict[str, str] | None = None,
) -> None:
    warn_if_object_lock_unset(bundle)
    print_info(f"Deploying hardening to Log-Archive ({log_archive_id})...")
    cfn_client = session_mgr.get_member_client(log_archive_id, "cloudformation", region_name=target_region)
    template_file = resolve_resource_path(
        "cloudformation/log-archive-hardening.yaml", project_root=bundle.config_dir.parent
    )
    if not dry_run:
        resolve_log_encryption(session_mgr, bundle, target_region, log_archive_id)
    params = log_archive_parameters(bundle, org_id, str(session_mgr.get_caller_identity().get("Account", "")))
    report = service.deploy_stack(
        cfn_client,
        f"{bundle.org.organization.name}-log-archive-hardening",
        template_file,
        params,
        tags=tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(bundle.get_log_archive_account_name() or "log-archive"),
        termination_protection=True,
        dry_run=dry_run,
    )
    _print_stack_report(report)


def _deploy_audit_stack(
    service: CloudFormationService,
    session_mgr: AwsSessionManager,
    org_client: Any,
    bundle: Any,
    target_region: str,
    audit_id: str,
    org_id: str,
    dry_run: bool,
    tags: dict[str, str] | None = None,
) -> None:
    print_info(f"Deploying hardening to Audit ({audit_id})...")
    for sp in ["config-multiaccountsetup.amazonaws.com", "config.amazonaws.com"]:
        try:
            org_client.register_delegated_administrator(AccountId=audit_id, ServicePrincipal=sp)
        except Exception as e:
            logger.debug("Delegated admin registration for %s: %s", sp, e)

    cfn_client = session_mgr.get_member_client(audit_id, "cloudformation", region_name=target_region)
    template_file = resolve_resource_path(
        "cloudformation/audit-account-hardening.yaml", project_root=bundle.config_dir.parent
    )
    report = service.deploy_stack(
        cfn_client,
        f"{bundle.org.organization.name}-audit-account-hardening",
        template_file,
        audit_hardening_parameters(bundle, org_id),
        tags=tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(bundle.get_audit_account_name() or "audit"),
        termination_protection=True,
        dry_run=dry_run,
    )
    _print_stack_report(report)


@app.command("security")
def deploy_security_hardening(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: DryRunOption = False,
    tags: TagsOption = None,
):
    """Deploy Log-Archive and Audit account hardening CloudFormation stacks."""
    print_header("Deploy Security Hardening Stacks")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Security Hardening Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)
        org_client = session_mgr.get_client("organizations")
        org_id = str(org_client.describe_organization()["Organization"]["Id"])
        accts = get_active_account_id_map(session_mgr)

        log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
        log_archive_id = bundle.resolve_account_id(log_archive_name, accts)
        if log_archive_id:
            _deploy_log_archive_stack(
                service, session_mgr, bundle, target_region, log_archive_id, org_id, dry_run, tags=custom_tags
            )
        else:
            print_warning(
                f"Log-Archive account '{log_archive_name}' not found. Skipping Log-Archive hardening."
            )

        audit_name = bundle.get_audit_account_name() or "audit"
        audit_id = bundle.resolve_account_id(audit_name, accts)
        if audit_id:
            _deploy_audit_stack(
                service,
                session_mgr,
                org_client,
                bundle,
                target_region,
                audit_id,
                org_id,
                dry_run,
                tags=custom_tags,
            )
        else:
            print_warning(f"Audit account '{audit_name}' not found. Skipping Audit hardening.")


@app.command("logs")
@app.command("harden-logs", hidden=True)
def deploy_log_archive(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: DryRunOption = False,
    tags: TagsOption = None,
):
    """Deploy Log-Archive account hardening CloudFormation stack."""
    print_header("Deploy Log-Archive Hardening Stack")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Log-Archive Hardening Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)
        org_id = str(session_mgr.get_client("organizations").describe_organization()["Organization"]["Id"])
        accts = get_active_account_id_map(session_mgr)

        log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
        log_archive_id = bundle.resolve_account_id(log_archive_name, accts)
        if not log_archive_id:
            error_console.print(f"[red]✗[/red] Log-Archive account '{log_archive_name}' not found.")
            raise typer.Exit(code=1)

        _deploy_log_archive_stack(
            service, session_mgr, bundle, target_region, log_archive_id, org_id, dry_run, tags=custom_tags
        )


@app.command("audit")
@app.command("harden-audit", hidden=True)
def deploy_audit(
    config_dir: ConfigDirOption = None,
    region: RegionOption = None,
    dry_run: DryRunOption = False,
    tags: TagsOption = None,
):
    """Deploy Audit account hardening CloudFormation stack."""
    print_header("Deploy Audit Hardening Stack")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Audit Hardening Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)
        org_client = session_mgr.get_client("organizations")
        org_id = str(org_client.describe_organization()["Organization"]["Id"])
        accts = get_active_account_id_map(session_mgr)

        audit_name = bundle.get_audit_account_name() or "audit"
        audit_id = bundle.resolve_account_id(audit_name, accts)
        if not audit_id:
            error_console.print(f"[red]✗[/red] Audit account '{audit_name}' not found.")
            raise typer.Exit(code=1)

        _deploy_audit_stack(
            service,
            session_mgr,
            org_client,
            bundle,
            target_region,
            audit_id,
            org_id,
            dry_run,
            tags=custom_tags,
        )


def _print_stack_report(report: StackDeployReport) -> None:
    print_success(f"Stack [cyan]{report.stack_name}[/cyan]: [{report.action}] - {report.status}")
    if report.outputs:
        table = create_table(title=f"{report.stack_name} Outputs")
        table.add_column("Output Key", style="cyan")
        table.add_column("Value", style="green")
        for k, v in report.outputs.items():
            table.add_row(k, v)
        console.print(table)


@app.command("anomaly-status")
def anomaly_status(config_dir: ConfigDirOption = None, region: RegionOption = None):
    """List all Cost Anomaly Detection monitors and subscriptions in the Management Account."""
    print_header("Cost Anomaly Detection Status")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    with exit_on_error("Anomaly Status Check Failed"):
        session_mgr = AwsSessionManager(region_name=target_region)
        monitors, subs = BaselineService(session_mgr).get_anomaly_overview()

        table = create_table(title="Cost Anomaly Monitors")
        table.add_column("Monitor Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Scope / Linked Account", style="green")
        for m in monitors:
            spec = m.get("MonitorSpecification", {})
            dim_values = spec.get("Dimensions", {}).get("Values", ["All Linked Accounts / Dimensional"])
            table.add_row(
                m.get("MonitorName", "Unknown"), m.get("MonitorType", "Unknown"), ", ".join(dim_values)
            )
        console.print(table)

        sub_table = create_table(title="Alert Subscriptions")
        sub_table.add_column("Subscription Name", style="cyan")
        sub_table.add_column("Threshold", style="yellow")
        sub_table.add_column("Frequency", style="magenta")
        sub_table.add_column("Subscribers", style="green")
        for s in subs:
            sub_table.add_row(
                s.get("SubscriptionName", "Unknown"),
                f"${s.get('Threshold', 0):.2f}",
                s.get("Frequency", "Unknown"),
                ", ".join(sub.get("Address", "") for sub in s.get("Subscribers", [])),
            )
        console.print(sub_table)
