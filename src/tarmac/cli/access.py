"""Bootstrap access: the non-root role tarmac runs as."""

import shutil
from pathlib import Path
from typing import Annotated

import typer
from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS, GovernanceError, aws_error_code
from ..core.stack_names import ACCESS_STACK
from ..core.templates import resolve_resource_path
from ..services.cloudformation import CloudFormationService
from ..services.identity import IdentityService
from .common import ConfigDirOption, load_configs_or_exit
from .ui import console, error_console, print_header, print_info, print_success

app = typer.Typer(help="Bootstrap the non-root role tarmac runs as", no_args_is_help=True)

TEMPLATE_PATH = "cloudformation/tarmac-access.yaml"
BOOTSTRAP_USER = "tarmac-bootstrap"
ADMIN_PERMISSION_SET = "AdministratorAccess"


def _append_section(config_path: Path, name: str, fields: dict[str, str]) -> bool:
    """Append a section to the AWS config file; returns False when it already exists.

    The file is appended to rather than parsed and rewritten, so the user's comments and formatting survive.
    """
    section = f"[{name}]"
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    if any(line.strip() == section for line in existing.splitlines()):
        return False
    block = section + "\n" + "".join(f"{key} = {value}\n" for key, value in fields.items())
    config_path.parent.mkdir(parents=True, exist_ok=True)
    separator = "" if not existing else ("\n" if existing.endswith("\n") else "\n\n")
    with config_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{separator}{block}")
    return True


@app.command("bootstrap")
def access_bootstrap(
    stack_name: Annotated[str, typer.Option("--stack-name", help="CloudFormation stack name")] = ACCESS_STACK,
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
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show whether the stack would be created or updated")
    ] = False,
) -> None:
    """Create the tarmac role (and optionally a bootstrap user) in the management account.

    Run this once from AWS CloudShell while signed in as the root user: CloudShell uses your console
    session, so no root access keys are ever created.
    """
    print_header("Tarmac Access Bootstrap")
    parameters = {
        "RoleName": role_name,
        "CreateBootstrapUser": "true" if with_bootstrap_user else "false",
        "BootstrapUserName": BOOTSTRAP_USER,
    }
    try:
        session_mgr = AwsSessionManager(region_name=region)
        account_id = session_mgr.get_caller_identity().get("Account", "")
        service = CloudFormationService(session_mgr)
        cfn_client = session_mgr.get_client("cloudformation", region_name=region)
        if dry_run:
            action, detail = service.preview_stack(
                cfn_client, stack_name, resolve_resource_path(TEMPLATE_PATH), parameters
            )
            print_info(f"[dry-run] Stack '{stack_name}': {action}" + (f" ({detail})" if detail else ""))
            return
        report = service.deploy_stack(
            cfn_client,
            stack_name,
            resolve_resource_path(TEMPLATE_PATH),
            parameters,
            termination_protection=True,
        )
    except GovernanceError as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)

    role_arn = report.outputs.get("TarmacRoleArn") or f"arn:aws:iam::{account_id}:role/{role_name}"
    print_success(f"Role ready: {role_arn}")
    if with_bootstrap_user:
        mfa_serial = f"arn:aws:iam::{account_id}:mfa/{BOOTSTRAP_USER}"
        added = _append_section(
            aws_config.expanduser(),
            f"profile {profile}",
            {
                "role_arn": role_arn,
                "source_profile": BOOTSTRAP_USER,
                "mfa_serial": mfa_serial,
                "region": region,
            },
        )
        print_info(
            f"{'Added' if added else 'Kept existing'} profile '{profile}' in {aws_config}. Next: in the IAM console "
            f"create an access key and an MFA device for '{BOOTSTRAP_USER}', add them to a '{BOOTSTRAP_USER}' "
            f"profile, then run: AWS_PROFILE={profile} tarmac info --strict"
        )
    else:
        print_info(
            "Next: enable IAM Identity Center (pick its Region deliberately: it can only be moved by deleting the "
            "instance) and turn on 'Send email OTP', then run: tarmac access sso"
        )


@app.command("sso")
def access_sso(
    config_dir: ConfigDirOption = None,
    profile: Annotated[str, typer.Option("--profile-name", help="AWS CLI profile to write")] = "tarmac",
) -> None:
    """Create your IAM Identity Center login for the management account and write its AWS CLI profile.

    Run this once as root (from AWS CloudShell) after enabling IAM Identity Center in the console. It creates the
    admin_user from identity.yaml, an AdministratorAccess permission set, and assigns both to the management account.
    """
    admin = load_configs_or_exit(config_dir).identity.identity_center.admin_user
    try:
        session_mgr = AwsSessionManager()
        account_id = session_mgr.get_caller_identity()["Account"]
        instance_arn, store_id, sso_region = IdentityService.discover_instance(session_mgr)
        identity = IdentityService(session_mgr, preferred_region=sso_region)
        user_id = identity.get_or_create_user(admin)
        sso = identity.sso_client
        ps_arn = identity.list_permission_sets(instance_arn).get(ADMIN_PERMISSION_SET)
        if ps_arn is None:
            ps_arn = sso.create_permission_set(
                InstanceArn=instance_arn, Name=ADMIN_PERMISSION_SET, SessionDuration="PT4H"
            )["PermissionSet"]["PermissionSetArn"]
            sso.attach_managed_policy_to_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn,
                ManagedPolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
        try:
            sso.create_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType="AWS_ACCOUNT",
                PermissionSetArn=ps_arn,
                PrincipalType="USER",
                PrincipalId=user_id,
            )
        except ClientError as e:
            if aws_error_code(e) != "ConflictException":
                raise
    except AWS_ERRORS as e:
        error_console.print(f"[red]Could not set up the Identity Center login:[/red] {e}")
        raise typer.Exit(code=1)
    print_success(
        f"Identity Center user '{admin.username}' has {ADMIN_PERMISSION_SET} on account {account_id}."
    )

    config_path = Path("~/.aws/config").expanduser()
    _append_section(
        config_path,
        f"sso-session {profile}",
        {
            "sso_start_url": f"https://{store_id}.awsapps.com/start",
            "sso_region": sso_region,
            "sso_registration_scopes": "sso:account:access",
        },
    )
    added = _append_section(
        config_path,
        f"profile {profile}",
        {
            "sso_session": profile,
            "sso_account_id": account_id,
            "sso_role_name": ADMIN_PERMISSION_SET,
            "region": session_mgr.default_region,
        },
    )
    print_success(f"{'Added' if added else 'Kept existing'} profile '{profile}' in {config_path}.")
    print_info(
        f"Next: aws sso login --use-device-code --profile {profile}, then export AWS_PROFILE={profile} "
        "and run: tarmac deploy"
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
