"""tarmac bootstrap: the IAM Identity Center login tarmac runs as."""

from pathlib import Path

import typer

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS, IdentityCenterError
from ..core.models import TAG_MANAGED_BY
from ..services.identity import DEPLOYMENT_PERMISSION_SET, IdentityService, deployment_policy
from .common import ConfigDirOption, load_configs_or_exit
from .ui import error_console, print_info, print_success

PROFILE = "tarmac"


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


def bootstrap_command(config_dir: ConfigDirOption = None) -> None:
    """Create your IAM Identity Center login with tarmac's least-privilege permission set, and its AWS CLI profile.

    The deployment_user from identity.yaml gets the TarmacDeployment permission set on the management account. Run
    this once as root from AWS CloudShell after enabling IAM Identity Center, and again after upgrading tarmac to
    refresh the permission set's policy.
    """
    bundle = load_configs_or_exit(config_dir)
    user = bundle.identity.identity_center.deployment_user
    session_mgr = AwsSessionManager()
    try:
        account_id = session_mgr.get_caller_identity()["Account"]
        instance_arn, store_id, sso_region = IdentityService.discover_instance(session_mgr)
    except IdentityCenterError:
        error_console.print(
            "[red]IAM Identity Center is not enabled.[/red] In the console, enable it (on an account without an "
            "organization this also creates the organization) and turn on Settings → Authentication → Send email "
            "OTP, then run 'tarmac bootstrap' again."
        )
        raise typer.Exit(code=1)
    except AWS_ERRORS as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)

    try:
        identity = IdentityService(session_mgr, preferred_region=sso_region)
        user_id = identity.get_or_create_user(user)
        sso = identity.sso_client
        ps_arn = identity.list_permission_sets(instance_arn).get(DEPLOYMENT_PERMISSION_SET)
        if ps_arn is None:
            ps_arn = sso.create_permission_set(
                InstanceArn=instance_arn,
                Name=DEPLOYMENT_PERMISSION_SET,
                Description="Least-privilege access tarmac runs with",
                SessionDuration="PT4H",
                Tags=[{"Key": TAG_MANAGED_BY, "Value": "tarmac"}],
            )["PermissionSet"]["PermissionSetArn"]
        sso.put_inline_policy_to_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn, InlinePolicy=deployment_policy()
        )
        assignments = sso.list_account_assignments(
            InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=ps_arn
        )["AccountAssignments"]
        if any(a["PrincipalId"] == user_id for a in assignments):
            sso.provision_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn, TargetType="ALL_PROVISIONED_ACCOUNTS"
            )
        else:
            sso.create_account_assignment(
                InstanceArn=instance_arn,
                TargetId=account_id,
                TargetType="AWS_ACCOUNT",
                PermissionSetArn=ps_arn,
                PrincipalType="USER",
                PrincipalId=user_id,
            )
    except AWS_ERRORS as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)
    print_success(f"'{user.username}' can sign in to account {account_id} with {DEPLOYMENT_PERMISSION_SET}.")

    config_path = Path("~/.aws/config").expanduser()
    _append_section(
        config_path,
        f"sso-session {PROFILE}",
        {
            "sso_start_url": f"https://{store_id}.awsapps.com/start",
            "sso_region": sso_region,
            "sso_registration_scopes": "sso:account:access",
        },
    )
    added = _append_section(
        config_path,
        f"profile {PROFILE}",
        {
            "sso_session": PROFILE,
            "sso_account_id": account_id,
            "sso_role_name": DEPLOYMENT_PERMISSION_SET,
            "region": bundle.org.organization.primary_region,
        },
    )
    print_success(f"{'Added' if added else 'Kept existing'} profile '{PROFILE}' in {config_path}.")
    print_info(
        f"Next: aws sso login --use-device-code --profile {PROFILE}, then export AWS_PROFILE={PROFILE} "
        "and run: tarmac deploy"
    )
