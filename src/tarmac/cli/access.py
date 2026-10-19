"""Bootstrap access: the non-root role tarmac runs as."""

import shutil
from pathlib import Path

import typer

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWSAuthenticationError
from ..core.templates import resolve_resource_path
from .ui import console, error_console, print_header, print_info, print_success, print_warning

app = typer.Typer(help="Bootstrap the non-root role tarmac runs as", no_args_is_help=True)

TEMPLATE_PATH = "cloudformation/tarmac-access.yaml"


@app.command("template")
def access_template(
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the template here instead of stdout"
    ),
) -> None:
    """Print (or save) the CloudFormation template that creates the tarmac role and bootstrap user."""
    source = resolve_resource_path(TEMPLATE_PATH)
    if output is None:
        console.print(source.read_text(encoding="utf-8"), markup=False, highlight=False)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, output)
    print_success(f"Wrote {output}")
    print_info(
        "Deploy it in the management account (CloudFormation console, signed in as root or an admin, "
        "capability CAPABILITY_NAMED_IAM), then follow README: Bootstrap access."
    )


@app.command("check")
def access_check() -> None:
    """Verify the current credentials can run tarmac (non-root, management account)."""
    print_header("Tarmac Access Check")
    try:
        session_mgr = AwsSessionManager()
        identity = session_mgr.get_caller_identity()
        is_root = session_mgr.is_root_identity()
    except AWSAuthenticationError as e:
        error_console.print(f"[red]Not authenticated:[/red] {e}")
        raise typer.Exit(code=1)

    print_info(f"Authenticated as {identity.get('Arn', 'unknown')} (account {identity.get('Account', '?')})")
    if is_root:
        error_console.print(
            "[red]Root credentials cannot assume roles in member accounts.[/red] "
            "Run 'tarmac access template', deploy it, and use the tarmac role."
        )
        raise typer.Exit(code=1)
    try:
        session_mgr.get_client("organizations").describe_organization()
    except Exception as e:
        print_warning(f"Could not describe the organization: {e}")
        raise typer.Exit(code=1)
    print_success("Credentials are non-root and can read the organization.")
