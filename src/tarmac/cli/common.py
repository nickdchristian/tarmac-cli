"""Shared CLI helpers, options and configuration handlers."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel

from ..core import inventory
from ..core.config_loader import ConfigBundle, get_default_config_dir, load_all_configs
from ..core.exceptions import AWSAuthenticationError, GovernanceError
from ..core.tagging import parse_cli_tags
from .ui import error_console, print_info, print_warning

ConfigDirOption = Annotated[
    Path | None, typer.Option("--config-dir", "-c", help="Path to configuration directory")
]
RegionOption = Annotated[str | None, typer.Option("--region", "-r", help="Override primary AWS region")]
JsonOption = Annotated[bool, typer.Option("--json", help="Output results in JSON format")]
YesOption = Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt")]
TagsOption = Annotated[
    list[str] | None,
    typer.Option("--tag", "-t", help="Custom tags in Key=Value format (can be specified multiple times)"),
]
AdoptExistingOption = Annotated[
    bool,
    typer.Option(
        "--adopt-existing",
        help="Take over existing SCPs and budgets with the same name that tarmac did not create (default: stop)",
    ),
]


@contextmanager
def exit_on_error(title: str) -> Iterator[None]:
    """Show a GovernanceError raised inside the block as a red panel and exit with code 1."""
    try:
        yield
    except GovernanceError as e:
        error_console.print(Panel(str(e), title=f"[bold red]{title}[/bold red]", border_style="red"))
        raise typer.Exit(code=1) from e


def confirm_or_exit(prompt: str, *, yes: bool, dry_run: bool, cancelled: str) -> None:
    """Ask before a live change unless --yes or --dry-run was given; exit 0 with `cancelled` on no."""
    if dry_run or yes:
        return
    if not typer.confirm(prompt, default=False):
        print_info(cancelled)
        raise typer.Exit(code=0)


def warn_if_example_newer(config_dir: Path | None = None) -> None:
    """Warn user if any .yaml.example was modified more recently than its active .yaml file."""
    resolved_dir = config_dir or get_default_config_dir()
    for base in ("organization", "accounts", "identity"):
        yaml_f = resolved_dir / f"{base}.yaml"
        example_f = resolved_dir / f"{base}.yaml.example"
        if yaml_f.is_file() and example_f.is_file():
            try:
                if example_f.stat().st_mtime > yaml_f.stat().st_mtime:
                    error_console.print(
                        f"[yellow]⚠️  Notice: {example_f.name} was modified more recently than {yaml_f.name}.\n"
                        f"   Tarmac loads {yaml_f.name}. Edit {yaml_f.name} directly to apply your updates.[/yellow]\n"
                    )
            except OSError:
                pass


def load_configs_or_exit(config_dir: Path | None = None) -> ConfigBundle:
    """Load configuration files and validate cross-references, exiting with code 1 on failure."""
    warn_if_example_newer(config_dir)
    error_console.print(f"[dim]Using configuration from: {config_dir or get_default_config_dir()}[/dim]")
    bundle, errors = load_all_configs(config_dir)
    if errors or bundle is None:
        for err in errors:
            error_console.print(f"[red]•[/red] {err}")
        if not errors:
            error_console.print("[red]•[/red] Failed to load configuration files.")
        raise typer.Exit(code=1)
    inventory.activate(config_dir or get_default_config_dir())
    return bundle


def parse_tags_or_exit(tags: list[str] | None) -> dict[str, str]:
    """Parse Key=Value CLI tags, exiting with code 1 on validation error."""

    try:
        return parse_cli_tags(tags)
    except ValueError as e:
        error_console.print(f"[red]✗ Invalid tag option:[/red] {e}")
        raise typer.Exit(code=1)


def warn_if_object_lock_unset(bundle: ConfigBundle) -> None:
    """Strongly recommend Object Lock while it is off and the user has not said so explicitly.

    It cannot be switched off once enabled, so tarmac never turns it on by itself; writing
    ``object_lock: null`` records the decision and silences this.
    """
    cloudtrail = bundle.org.cloudtrail
    if cloudtrail.object_lock is None and "object_lock" not in cloudtrail.model_fields_set:
        print_warning(
            "CloudTrail Object Lock is not configured, so anyone with delete rights on the log bucket can "
            "erase the audit trail. Best practice is `cloudtrail.object_lock: {mode: GOVERNANCE, "
            "retention_days: 365}`. Enable it before the first deploy if you can; S3 cannot turn it off "
            "again. Set `object_lock: null` to acknowledge and hide this warning."
        )


def log_archive_parameters(
    bundle: ConfigBundle, org_id: str, management_account_id: str = ""
) -> dict[str, str]:
    """CloudFormation parameters for the log-archive hardening stack (shared by deploy and baseline).

    ``management_account_id`` is needed only when AWS Config recorders are enabled: the log archive creates a
    separate bucket for Config history and lets the management account's recorder write to it.
    """
    cloudtrail = bundle.org.cloudtrail
    config_recorder = bundle.org.security_services.config_recorder
    params = {
        "OrganizationId": org_id,
        "OrgName": bundle.org.organization.name,
        "EnableKmsEncryption": "true" if cloudtrail.enable_kms else "false",
        "LogRetentionDays": str(cloudtrail.retention_days or 0),
        "EnableConfigDelivery": "true" if config_recorder.enabled else "false",
        "ManagementAccountId": management_account_id if config_recorder.enabled else "",
    }
    if cloudtrail.object_lock:
        params["ObjectLockMode"] = cloudtrail.object_lock.mode
        params["ObjectLockRetentionDays"] = str(cloudtrail.object_lock.retention_days)
    return params


def cloudtrail_parameters(bundle: ConfigBundle, log_archive_id: str, enable_kms: bool) -> dict[str, str]:
    """CloudFormation parameters for the organization CloudTrail stack (shared by deploy and baseline)."""
    return {
        "OrgName": bundle.org.organization.name,
        "LogArchiveAccountId": log_archive_id,
        "TrailName": bundle.org.cloudtrail.trail_name,
        "EnableKmsEncryption": "true" if enable_kms else "false",
    }


def backend_parameters(bundle: ConfigBundle, enable_dynamodb: bool) -> dict[str, str]:
    """CloudFormation parameters for the Terraform backend stack (shared by deploy and baseline)."""
    backend = bundle.org.terraform_backend
    return {
        "OrgName": bundle.org.organization.name,
        "BucketPrefix": backend.bucket_prefix,
        "EnableDynamoDB": "true" if enable_dynamodb else "false",
        "DynamoDBTableName": backend.dynamodb_table_name,
    }


def audit_hardening_parameters(bundle: ConfigBundle, org_id: str) -> dict[str, str]:
    """CloudFormation parameters for the audit account hardening stack (shared by deploy and baseline)."""
    security_email = bundle.org.contacts.security.email
    params = {
        "OrgName": bundle.org.organization.name,
        "OrganizationId": org_id,
        "AlertEmail": str(security_email) if security_email else "",
    }
    webhook = bundle.org.security_services.incident_response_webhook_url
    if webhook:
        params["IncidentResponseWebhookUrl"] = str(webhook)
    return params


def require_credentials_or_exit(session_mgr: Any) -> None:
    """Check once, up front, that the AWS credentials work; exit 1 with the likely fixes if they do not.

    Without this, expired or missing credentials only surface at the first AWS call, after prompts and config
    work, and as whatever error that call happens to raise.
    """
    try:
        session_mgr.get_caller_identity()
    except AWSAuthenticationError as exc:
        error_console.print(f"[red]✗ AWS credentials are not usable:[/red] {exc.details or exc}")
        error_console.print(
            "  Check that they are set and not expired: [bold]aws sts get-caller-identity[/bold]. "
            "For IAM Identity Center profiles run [bold]aws sso login[/bold]; make sure AWS_PROFILE "
            "(or AWS_ACCESS_KEY_ID / AWS_SESSION_TOKEN) points at the account and role you intend."
        )
        raise typer.Exit(code=1) from exc
