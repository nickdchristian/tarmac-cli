"""`tarmac import`: describe an existing AWS Organization as Tarmac configuration."""

from pathlib import Path

import typer

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS
from ..services.importer import ImportService
from .common import require_credentials_or_exit
from .ui import console, error_console, print_header, print_info, print_success, print_warning


def import_command(
    config_dir: Path = typer.Option(
        Path("config"),
        "--config-dir",
        "-c",
        help="Directory to write organization.yaml, accounts.yaml, identity.yaml",
    ),
    region: str | None = typer.Option(None, "--region", "-r", help="Primary region [default: AWS_REGION]"),
    name: str | None = typer.Option(
        None,
        "--name",
        help="organization.name. Defaults to the name of existing Tarmac stacks, else the management email domain.",
    ),
    no_identity: bool = typer.Option(False, "--no-identity", help="Do not read IAM Identity Center"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing configuration files"),
) -> None:
    """Read the live organization (read-only) and write matching Tarmac configuration.

    Run it as a role with read access to AWS Organizations (and Identity Center, unless --no-identity).
    Nothing in AWS is changed. Review the files, then run `tarmac validate` and `tarmac deploy run --dry-run`.
    """
    print_header("Import Existing Organization")
    try:
        session_mgr = AwsSessionManager(region_name=region)
        require_credentials_or_exit(session_mgr)
        service = ImportService(session_mgr, region or session_mgr.default_region)
        report = service.discover_and_write(
            config_dir, name=name, include_identity=not no_identity, force=force
        )
    except FileExistsError as exc:
        error_console.print(
            f"[red]✗[/red] {exc} already exist in {config_dir}. Use --force to overwrite, or pick another --config-dir."
        )
        raise typer.Exit(code=1) from exc
    except AWS_ERRORS as exc:
        error_console.print(f"[red]✗ Could not read the organization:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    print_success(
        f"Imported org {report.organization_id}: {report.ou_count} OUs, {len(report.accounts)} accounts, "
        f"{len(report.scps)} SCPs, {len(report.permission_sets)} permission sets, {len(report.groups)} groups"
    )
    for path in report.files:
        print_info(f"Wrote {path}")
    for skipped in report.skipped_accounts:
        print_warning(f"Skipped account: {skipped}")
    if report.todos:
        console.print("\n[bold yellow]Review these before deploying:[/bold yellow]")
        for todo in report.todos:
            console.print(f"  • {todo}")
    if report.validation_errors:
        console.print("\n[bold red]The generated configuration does not validate yet:[/bold red]")
        for err in report.validation_errors:
            console.print(f"  • {err}")
    console.print("\n[bold cyan]Next:[/bold cyan]")
    console.print(f"  1. Review the files in [bold]{config_dir}/[/bold]")
    console.print(
        "  2. [bold]tarmac validate[/bold]   3. [bold]tarmac drift[/bold]   4. [bold]tarmac deploy run --dry-run[/bold]"
    )
    if report.validation_errors:
        raise typer.Exit(code=1)
