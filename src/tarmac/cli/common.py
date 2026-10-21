"""Shared CLI helpers and configuration handlers."""

import logging
from pathlib import Path
from typing import Any

import typer

from ..core import inventory
from ..core.config_loader import ConfigBundle, get_default_config_dir, load_all_configs
from ..core.exceptions import AWSAuthenticationError
from ..core.tagging import parse_cli_tags
from .ui import error_console, print_warning

logger = logging.getLogger(__name__)


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


def get_active_account_id_map(session_mgr: Any) -> dict[str, str]:
    """Fetch all ACTIVE accounts in the organization as {AccountName: AccountId} with paginator."""
    org_client = session_mgr.get_client("organizations")
    accts: dict[str, str] = {}
    try:
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            acct_list = page.get("Accounts", [])
            if isinstance(acct_list, list):
                for a in acct_list:
                    if isinstance(a, dict) and a.get("Status", "ACTIVE") in ("ACTIVE", None):
                        accts[a["Name"]] = str(a["Id"])
        if accts:
            return accts
    except Exception as exc:
        logger.debug("Paginated list_accounts failed, falling back to a single call: %s", exc)
    try:
        resp = org_client.list_accounts()
        if isinstance(resp, dict):
            for a in resp.get("Accounts", []):
                if isinstance(a, dict) and a.get("Status", "ACTIVE") in ("ACTIVE", None):
                    accts[a["Name"]] = str(a["Id"])
    except Exception as exc:
        logger.warning("Could not list organization accounts; account names will not resolve: %s", exc)
    return accts


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


def log_archive_parameters(bundle: ConfigBundle, org_id: str) -> dict[str, str]:
    """CloudFormation parameters for the log-archive hardening stack (shared by deploy and baseline)."""
    cloudtrail = bundle.org.cloudtrail
    params = {
        "OrganizationId": org_id,
        "OrgName": bundle.org.organization.name,
        "EnableKmsEncryption": "true" if cloudtrail.enable_kms else "false",
        "LogRetentionDays": str(cloudtrail.retention_days or 0),
    }
    if cloudtrail.object_lock:
        params["ObjectLockMode"] = cloudtrail.object_lock.mode
        params["ObjectLockRetentionDays"] = str(cloudtrail.object_lock.retention_days)
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
