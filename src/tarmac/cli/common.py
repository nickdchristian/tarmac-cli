"""Shared CLI helpers and configuration handlers."""

from pathlib import Path
from typing import Any

import typer

from ..core.config_loader import ConfigBundle, get_default_config_dir, load_all_configs
from .ui import error_console


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
    bundle, errors = load_all_configs(config_dir)
    if errors or bundle is None:
        for err in errors:
            error_console.print(f"[red]•[/red] {err}")
        if not errors:
            error_console.print("[red]•[/red] Failed to load configuration files.")
        raise typer.Exit(code=1)
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
    except Exception:
        pass
    try:
        resp = org_client.list_accounts()
        if isinstance(resp, dict):
            for a in resp.get("Accounts", []):
                if isinstance(a, dict) and a.get("Status", "ACTIVE") in ("ACTIVE", None):
                    accts[a["Name"]] = str(a["Id"])
    except Exception:
        pass
    return accts


def parse_tags_or_exit(tags: list[str] | None) -> dict[str, str]:
    """Parse Key=Value CLI tags, exiting with code 1 on validation error."""
    from ..core.tagging import parse_cli_tags

    try:
        return parse_cli_tags(tags)
    except ValueError as e:
        error_console.print(f"[red]✗ Invalid tag option:[/red] {e}")
        raise typer.Exit(code=1)
