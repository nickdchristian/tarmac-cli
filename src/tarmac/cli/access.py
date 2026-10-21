"""Bootstrap access: the non-root role tarmac runs as."""

import shutil
from pathlib import Path
from typing import Annotated

import typer
from botocore.exceptions import BotoCoreError, ClientError

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWSAuthenticationError, GovernanceError
from ..core.templates import resolve_resource_path
from ..services.cloudformation import CloudFormationService
from .ui import console, error_console, print_header, print_info, print_success, print_warning

app = typer.Typer(help="Bootstrap the non-root role tarmac runs as", no_args_is_help=True)

TEMPLATE_PATH = "cloudformation/tarmac-access.yaml"
BOOTSTRAP_USER = "tarmac-bootstrap"


def _write_role_profile(
    config_path: Path, profile: str, role_arn: str, source_profile: str, mfa_serial: str, region: str
) -> bool:
    """Append a role profile to the AWS config file; returns False when it already exists.

    The file is appended to rather than parsed and rewritten, so the user's comments and formatting survive.
    """
    section = f"[profile {profile}]"
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if any(line.strip() == section for line in existing.splitlines()):
        return False
    block = (
        f"{section}\nrole_arn = {role_arn}\nsource_profile = {source_profile}\n"
        f"mfa_serial = {mfa_serial}\nregion = {region}\n"
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    separator = "" if not existing else ("\n" if existing.endswith("\n") else "\n\n")
    with config_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{separator}{block}")
    return True


@app.command("bootstrap")
def access_bootstrap(
    stack_name: Annotated[
        str, typer.Option("--stack-name", help="CloudFormation stack name")
    ] = "tarmac-access",
    role_name: Annotated[
        str, typer.Option("--role-name", help="Name of the tarmac role")
    ] = "TarmacDeploymentRole",
    region: Annotated[
        str, typer.Option("--region", "-r", help="Region to deploy the stack in")
    ] = "us-east-1",
    with_bootstrap_user: Annotated[
        bool,
        typer.Option(
            "--with-bootstrap-user",
            help="Also create an assume-only IAM user (for use before IAM Identity Center exists)",
        ),
    ] = False,
    profile: Annotated[
        str, typer.Option("--profile-name", help="AWS CLI profile to write (with the bootstrap user)")
    ] = "tarmac",
    aws_config: Annotated[
        Path, typer.Option("--aws-config", help="AWS config file to add the role profile to")
    ] = Path("~/.aws/config"),
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would be deployed")] = False,
) -> None:
    """Create the tarmac role (and optionally a bootstrap user) in the management account.

    Run this once from AWS CloudShell while signed in as the root user: CloudShell uses your console
    session, so no root access keys are ever created.
    """
    print_header("Tarmac Access Bootstrap")
    try:
        session_mgr = AwsSessionManager(region_name=region)
        account_id = session_mgr.get_caller_identity().get("Account", "")
        service = CloudFormationService(session_mgr)
        report = service.deploy_stack(
            session_mgr.get_client("cloudformation", region_name=region),
            stack_name,
            resolve_resource_path(TEMPLATE_PATH),
            {
                "RoleName": role_name,
                "CreateBootstrapUser": "true" if with_bootstrap_user else "false",
                "BootstrapUserName": BOOTSTRAP_USER,
            },
            dry_run=dry_run,
            termination_protection=True,
        )
    except GovernanceError as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)

    if dry_run:
        print_info(f"[dry-run] Would deploy stack '{stack_name}' ({report.action}).")
        return

    role_arn = report.outputs.get("TarmacRoleArn") or f"arn:aws:iam::{account_id}:role/{role_name}"
    print_success(f"Role ready: {role_arn}")
    if with_bootstrap_user:
        mfa_serial = f"arn:aws:iam::{account_id}:mfa/{BOOTSTRAP_USER}"
        added = _write_role_profile(
            aws_config.expanduser(), profile, role_arn, BOOTSTRAP_USER, mfa_serial, region
        )
        print_info(
            f"{'Added' if added else 'Kept existing'} profile '{profile}' in {aws_config}. Next: in the IAM console "
            f"create an access key and an MFA device for '{BOOTSTRAP_USER}', add them to a '{BOOTSTRAP_USER}' "
            f"profile, then run: AWS_PROFILE={profile} tarmac access check"
        )
    else:
        print_info(
            "Next: enable IAM Identity Center (pick its Region deliberately: it can only be moved by deleting the "
            "instance), create an administrator user, sign in with 'aws sso login', then run: tarmac access check"
        )


@app.command("template")
def access_template(
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the template here instead of stdout")
    ] = None,
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
        error_console.print("Hint: run 'aws sso login' or set AWS_PROFILE to your tarmac profile.")
        raise typer.Exit(code=1)

    print_info(f"Authenticated as {identity.get('Arn', 'unknown')} (account {identity.get('Account', '?')})")
    if is_root:
        error_console.print(
            "[red]Root credentials cannot assume roles in member accounts.[/red] "
            "Run 'tarmac access bootstrap' from CloudShell, then use the tarmac role or an SSO admin."
        )
        raise typer.Exit(code=1)
    try:
        session_mgr.get_client("organizations").describe_organization()
    except (ClientError, BotoCoreError) as e:
        print_warning(f"Could not describe the organization: {e}")
        print_info(
            "Hint: use credentials for the management account, make sure the organization exists "
            "('tarmac org bootstrap'), and that this principal has Organizations read access."
        )
        raise typer.Exit(code=1)
    print_success("Credentials are non-root and can read the organization.")
