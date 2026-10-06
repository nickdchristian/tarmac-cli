"""CLI commands for foundational CloudFormation deployments."""

import logging
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import GovernanceError
from ..core.models import StackDeployReport
from ..core.templates import resolve_resource_path
from ..services.baseline import BaselineService
from ..services.cloudformation import CloudFormationService
from .common import get_active_account_id_map, load_configs_or_exit, parse_tags_or_exit
from .ui import console, create_table, error_console, print_header, print_info, print_success, print_warning

logger = logging.getLogger(__name__)

app = typer.Typer(help="Foundational CloudFormation stack deployments.")


@app.command("cloudtrail")
def deploy_cloudtrail(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    sse_s3: bool = typer.Option(
        False, "--sse-s3", help="Use SSE-S3 (AES256) encryption instead of KMS CMK to eliminate KMS charges"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy organization-wide CloudTrail stack in the Management Account."""
    print_header("Deploy Organization CloudTrail")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)

        template_file = resolve_resource_path(
            "cloudformation/organization-cloudtrail.yaml", project_root=bundle.config_dir.parent
        )
        stack_name = f"{bundle.org.organization.name}-organization-cloudtrail"

        enable_kms = False if sse_s3 else bundle.org.cloudtrail.enable_kms
        accts = get_active_account_id_map(session_mgr)
        log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
        log_archive_id = bundle.resolve_account_id(log_archive_name, accts) or ""

        params = {
            "OrgName": bundle.org.organization.name,
            "LogArchiveAccountId": log_archive_id,
            "TrailName": bundle.org.cloudtrail.trail_name,
            "EnableKmsEncryption": "true" if enable_kms else "false",
        }

        cfn_client = session_mgr.get_client("cloudformation", region_name=target_region)
        report = service.deploy_stack(
            cfn_client,
            stack_name,
            template_file,
            params,
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
            dry_run=dry_run,
        )
        _print_stack_report(report)
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]CloudTrail Deployment Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("backend")
def deploy_backend(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    s3_only: bool = typer.Option(
        False, "--s3-only", help="Deploy S3-only backend without DynamoDB (Terraform 1.10+ native S3 locking)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy Terraform state backend (S3 with optional DynamoDB) in the Deployment account."""
    print_header("Deploy Terraform Backend")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    try:
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

        enable_dynamodb = False if s3_only else bundle.org.terraform_backend.enable_dynamodb
        params = {
            "OrgName": bundle.org.organization.name,
            "BucketPrefix": bundle.org.terraform_backend.bucket_prefix,
            "EnableDynamoDB": "true" if enable_dynamodb else "false",
            "DynamoDBTableName": bundle.org.terraform_backend.dynamodb_table_name,
        }

        cfn_client = session_mgr.get_member_client(
            deployment_acct_id, "cloudformation", region_name=target_region
        )
        report = service.deploy_stack(
            cfn_client,
            stack_name,
            template_file,
            params,
            tags=custom_tags,
            org_tags=bundle.get_organization_tags(),
            account_tags=bundle.get_account_tags(backend_name),
            dry_run=dry_run,
        )
        _print_stack_report(report)
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Backend Deployment Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


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
    print_info(f"Deploying hardening to Log-Archive ({log_archive_id})...")
    cfn_client = session_mgr.get_member_client(log_archive_id, "cloudformation", region_name=target_region)
    stack_name = f"{bundle.org.organization.name}-log-archive-hardening"
    template_file = resolve_resource_path(
        "cloudformation/log-archive-hardening.yaml", project_root=bundle.config_dir.parent
    )
    params = {"OrganizationId": org_id, "OrgName": bundle.org.organization.name}
    log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
    report = service.deploy_stack(
        cfn_client,
        stack_name,
        template_file,
        params,
        tags=tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(log_archive_name),
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
    stack_name = f"{bundle.org.organization.name}-audit-account-hardening"
    template_file = resolve_resource_path(
        "cloudformation/audit-account-hardening.yaml", project_root=bundle.config_dir.parent
    )
    params = {
        "OrgName": bundle.org.organization.name,
        "OrganizationId": org_id,
        "AlertEmail": str(bundle.org.contacts.security.email) if bundle.org.contacts.security.email else "",
    }
    if bundle.org.security_services.incident_response_webhook_url:
        params["IncidentResponseWebhookUrl"] = str(bundle.org.security_services.incident_response_webhook_url)
    audit_name = bundle.get_audit_account_name() or "audit"
    report = service.deploy_stack(
        cfn_client,
        stack_name,
        template_file,
        params,
        tags=tags,
        org_tags=bundle.get_organization_tags(),
        account_tags=bundle.get_account_tags(audit_name),
        dry_run=dry_run,
    )
    _print_stack_report(report)


@app.command("security")
def deploy_security_hardening(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy Log-Archive and Audit account hardening CloudFormation stacks."""
    print_header("Deploy Security Hardening Stacks")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    try:
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
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Security Hardening Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("logs")
def deploy_log_archive(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy Log-Archive account hardening CloudFormation stack."""
    print_header("Deploy Log-Archive Hardening Stack")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        service = CloudFormationService(session_mgr)
        org_client = session_mgr.get_client("organizations")
        org_id = str(org_client.describe_organization()["Organization"]["Id"])
        accts = get_active_account_id_map(session_mgr)

        log_archive_name = bundle.get_log_archive_account_name() or "log-archive"
        log_archive_id = bundle.resolve_account_id(log_archive_name, accts)
        if not log_archive_id:
            error_console.print(f"[red]✗[/red] Log-Archive account '{log_archive_name}' not found.")
            raise typer.Exit(code=1)

        _deploy_log_archive_stack(
            service, session_mgr, bundle, target_region, log_archive_id, org_id, dry_run, tags=custom_tags
        )
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Log-Archive Hardening Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("audit")
def deploy_audit(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy Audit account hardening CloudFormation stack."""
    print_header("Deploy Audit Hardening Stack")
    bundle = load_configs_or_exit(config_dir)
    custom_tags = parse_tags_or_exit(tags)
    target_region = region or bundle.org.organization.primary_region

    try:
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
    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Audit Hardening Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)


@app.command("harden-audit", hidden=True)
def deploy_audit_alias(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy Audit account hardening CloudFormation stack (backward-compatible alias)."""
    deploy_audit(config_dir=config_dir, region=region, dry_run=dry_run, tags=tags)


@app.command("harden-logs", hidden=True)
def deploy_logs_alias(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate deployment"),
    tags: list[str] | None = typer.Option(
        None, "--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"
    ),
):
    """Deploy Log-Archive account hardening CloudFormation stack (backward-compatible alias)."""
    deploy_log_archive(config_dir=config_dir, region=region, dry_run=dry_run, tags=tags)


def _print_stack_report(report: StackDeployReport) -> None:
    """Helper to render stack deployment outputs."""
    print_success(f"Stack [cyan]{report.stack_name}[/cyan]: [{report.action}] - {report.status}")
    if report.outputs:
        table = create_table(title=f"{report.stack_name} Outputs")
        table.add_column("Output Key", style="cyan")
        table.add_column("Value", style="green")
        for k, v in report.outputs.items():
            table.add_row(k, v)
        console.print(table)


@app.command("anomaly-status")
def anomaly_status(
    config_dir: Path | None = typer.Option(None, "--config-dir", "-c", help="Path to config directory"),
    region: str | None = typer.Option(None, "--region", "-r", help="Override primary AWS region"),
):
    """List all Cost Anomaly Detection monitors and subscriptions in the Management Account."""
    print_header("Cost Anomaly Detection Status")
    bundle = load_configs_or_exit(config_dir)
    target_region = region or bundle.org.organization.primary_region

    try:
        session_mgr = AwsSessionManager(region_name=target_region)
        baseliner = BaselineService(session_mgr)
        monitors, subs = baseliner.get_anomaly_overview()

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
            emails = [sub.get("Address", "") for sub in s.get("Subscribers", [])]
            sub_table.add_row(
                s.get("SubscriptionName", "Unknown"),
                f"${s.get('Threshold', 0):.2f}",
                s.get("Frequency", "Unknown"),
                ", ".join(emails),
            )
        console.print(sub_table)

    except GovernanceError as e:
        error_console.print(
            Panel(str(e), title="[bold red]Anomaly Status Check Failed[/bold red]", border_style="red")
        )
        raise typer.Exit(code=1)
