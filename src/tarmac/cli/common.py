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
from .ui import error_console, print_info

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
                        f"[yellow]Warning: {example_f.name} is newer than {yaml_f.name}, but tarmac only "
                        f"reads {yaml_f.name}.\n   Copy any changes you want into {yaml_f.name}.[/yellow]\n"
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
    for message in bundle.deprecated_settings():
        error_console.print(f"[yellow]Warning: {message}[/yellow]")
    inventory.activate()
    return bundle


def parse_tags_or_exit(tags: list[str] | None) -> dict[str, str]:
    """Parse Key=Value CLI tags, exiting with code 1 on validation error."""

    try:
        return parse_cli_tags(tags)
    except ValueError as e:
        error_console.print(f"[red]Error: invalid tag option:[/red] {e}")
        raise typer.Exit(code=1)


def require_credentials_or_exit(session_mgr: Any) -> None:
    """Check once, up front, that the AWS credentials work; exit 1 with the likely fixes if they do not.

    Without this, expired or missing credentials only surface at the first AWS call, after prompts and config
    work, and as whatever error that call happens to raise.
    """
    try:
        session_mgr.get_caller_identity()
    except AWSAuthenticationError as exc:
        error_console.print(f"[red]Error: AWS credentials are not usable:[/red] {exc.details or exc}")
        error_console.print(
            "  Check that they are set and not expired: [bold]aws sts get-caller-identity[/bold]. "
            "For IAM Identity Center profiles run [bold]aws sso login[/bold]; make sure AWS_PROFILE "
            "(or AWS_ACCESS_KEY_ID / AWS_SESSION_TOKEN) points at the account and role you intend."
        )
        raise typer.Exit(code=1) from exc
