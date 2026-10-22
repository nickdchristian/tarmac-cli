"""tarmac bootstrap: the IAM Identity Center login tarmac runs as."""

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS, IdentityCenterError
from ..core.models import TAG_MANAGED_BY
from ..services.identity import (
    DEPLOYMENT_PERMISSION_SET,
    MANAGEMENT_ADMIN_PERMISSION_SET,
    IdentityService,
    deployment_policy,
)
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


def _wait(describe: Callable[[], dict[str, Any]], key: str, what: str) -> None:
    """Wait for an Identity Center request to finish; raise with AWS's reason if it failed or never finished."""
    for _ in range(60):
        status = describe()[key]
        if status["Status"] == "SUCCEEDED":
            return
        if status["Status"] == "FAILED":
            raise IdentityCenterError(f"{what} failed: {status.get('FailureReason', 'no reason given')}")
        time.sleep(2)
    raise IdentityCenterError(f"{what} did not finish within 2 minutes; run 'tarmac bootstrap' again.")


def _grant(
    identity: IdentityService,
    instance_arn: str,
    account_id: str,
    user_id: str | None,
    name: str,
    policy: str | None,
) -> None:
    """Give the user permission set `name` on the account: with inline `policy`, or AdministratorAccess when None."""
    sso = identity.sso_client
    ps_arn = identity.list_permission_sets(instance_arn).get(name)
    if ps_arn is None:
        ps_arn = sso.create_permission_set(
            InstanceArn=instance_arn,
            Name=name,
            SessionDuration="PT4H",
            Tags=[{"Key": TAG_MANAGED_BY, "Value": "tarmac"}],
        )["PermissionSet"]["PermissionSetArn"]
        if policy is None:
            sso.attach_managed_policy_to_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn,
                ManagedPolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
    if policy is not None:
        sso.put_inline_policy_to_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn, InlinePolicy=policy
        )
    assignments = sso.list_account_assignments(
        InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=ps_arn
    )["AccountAssignments"]
    if not any(a["PrincipalId"] == user_id for a in assignments):
        request_id = sso.create_account_assignment(
            InstanceArn=instance_arn,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=ps_arn,
            PrincipalType="USER",
            PrincipalId=user_id,
        )["AccountAssignmentCreationStatus"]["RequestId"]
        _wait(
            lambda: sso.describe_account_assignment_creation_status(
                InstanceArn=instance_arn, AccountAssignmentCreationRequestId=request_id
            ),
            "AccountAssignmentCreationStatus",
            f"Assigning {name}",
        )
    elif policy is not None:
        request_id = sso.provision_permission_set(
            InstanceArn=instance_arn, PermissionSetArn=ps_arn, TargetType="ALL_PROVISIONED_ACCOUNTS"
        )["PermissionSetProvisioningStatus"]["RequestId"]
        _wait(
            lambda: sso.describe_permission_set_provisioning_status(
                InstanceArn=instance_arn, ProvisionPermissionSetRequestId=request_id
            ),
            "PermissionSetProvisioningStatus",
            f"Updating {name}",
        )


def bootstrap_command(config_dir: ConfigDirOption = None) -> None:
    """Create your IAM Identity Center login for the management account, and the AWS CLI profile tarmac runs with.

    The admin_user from identity.yaml gets two permission sets there: TarmacDeployment, tarmac's least-privilege
    policy, and ManagementAdministrator for the console. Run this once as root from AWS CloudShell after enabling
    IAM Identity Center, and again after upgrading tarmac to refresh TarmacDeployment's policy.
    """
    bundle = load_configs_or_exit(config_dir)
    admin = bundle.identity.identity_center.admin_user
    session_mgr = AwsSessionManager()
    try:
        account_id = session_mgr.get_caller_identity()["Account"]
        instance_arn, store_id, sso_region = IdentityService.discover_instance(session_mgr)
    except IdentityCenterError:
        error_console.print(
            "[red]IAM Identity Center is not enabled.[/red] In the console, enable it (on an account without an "
            "organization this also creates the organization), then run 'tarmac bootstrap' again."
        )
        raise typer.Exit(code=1)
    except AWS_ERRORS as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)

    try:
        identity = IdentityService(session_mgr, preferred_region=sso_region)
        user_id = identity.get_or_create_user(admin)
        _grant(identity, instance_arn, account_id, user_id, DEPLOYMENT_PERMISSION_SET, deployment_policy())
        _grant(identity, instance_arn, account_id, user_id, MANAGEMENT_ADMIN_PERMISSION_SET, None)
    except AWS_ERRORS as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)
    print_success(
        f"'{admin.username}' can sign in to account {account_id} as {DEPLOYMENT_PERMISSION_SET} (tarmac) "
        f"and {MANAGEMENT_ADMIN_PERMISSION_SET} (the console)."
    )

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
        f"Next, to sign in as '{admin.username}' for the first time:\n"
        f"  1. As root, in IAM Identity Center → Users → {admin.username}, register an MFA device.\n"
        f"  2. aws sso login --use-device-code --profile {PROFILE}, and open the URL it prints in a private window.\n"
        f"  3. In the console, Users → {admin.username} → Reset password → Generate a one-time password. Sign in with "
        "it in that window, set your own password, then enter the code.\n"
        f"  4. export AWS_PROFILE={PROFILE}, then: tarmac deploy"
    )
