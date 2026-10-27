"""tarmac bootstrap: the IAM Identity Center login tarmac runs as."""

import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

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
GITHUB_ROLE = "TarmacGitHubDeployment"
GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"


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


def _github_role(session_mgr: AwsSessionManager, repo: str, branch: str) -> str:
    """Let GitHub Actions runs on the repository's branch assume a role with tarmac's deployment policy.

    Pull requests get no role: anyone who can open one can change the workflow and use its credentials.
    """
    iam: Any = session_mgr.get_client("iam")
    caller = session_mgr.get_caller_identity()
    partition = str(caller["Arn"]).split(":")[1]
    provider_arn = f"arn:{partition}:iam::{caller['Account']}:oidc-provider/{GITHUB_OIDC_HOST}"
    tags = [{"Key": TAG_MANAGED_BY, "Value": "tarmac"}]
    try:
        iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    except iam.exceptions.NoSuchEntityException:
        iam.create_open_id_connect_provider(
            Url=f"https://{GITHUB_OIDC_HOST}", ClientIDList=["sts.amazonaws.com"], Tags=tags
        )
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": provider_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{GITHUB_OIDC_HOST}:aud": "sts.amazonaws.com",
                            f"{GITHUB_OIDC_HOST}:sub": f"repo:{repo}:ref:refs/heads/{branch}",
                        }
                    },
                }
            ],
        }
    )
    try:
        arn = iam.create_role(
            RoleName=GITHUB_ROLE,
            AssumeRolePolicyDocument=trust,
            MaxSessionDuration=14400,
            Tags=tags,
        )["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        iam.update_assume_role_policy(RoleName=GITHUB_ROLE, PolicyDocument=trust)
        arn = iam.get_role(RoleName=GITHUB_ROLE)["Role"]["Arn"]
    _update_github_role_policy(iam)
    return str(arn)


def _update_github_role_policy(iam: Any) -> bool:
    """Give the GitHub role the current deployment policy; False when there is no GitHub role."""
    try:
        iam.put_role_policy(
            RoleName=GITHUB_ROLE, PolicyName=DEPLOYMENT_PERMISSION_SET, PolicyDocument=deployment_policy()
        )
    except iam.exceptions.NoSuchEntityException:
        return False
    return True


def bootstrap_command(
    config_dir: ConfigDirOption = None,
    github_repo: Annotated[
        str | None,
        typer.Option(
            "--github-repo",
            help=(
                "OWNER/REPO whose GitHub Actions runs on --github-branch may deploy with tarmac; "
                "OWNER@ID/REPO@ID for repositories created, renamed or transferred after 15 July 2026"
            ),
        ),
    ] = None,
    github_branch: Annotated[str, typer.Option("--github-branch", help="Branch trusted to deploy")] = "main",
) -> None:
    """Create your IAM Identity Center login for the management account, and the AWS CLI profile tarmac runs with.

    The admin_user from identity.yaml gets two permission sets there: TarmacDeployment, tarmac's least-privilege
    policy, and ManagementAdministrator for the console. Run this once as root from AWS CloudShell after enabling
    IAM Identity Center, and again after upgrading tarmac to refresh TarmacDeployment's policy.

    With --github-repo it also lets GitHub Actions runs on that repository's --github-branch deploy, through the
    TarmacGitHubDeployment role with the same policy.
    """
    bundle = load_configs_or_exit(config_dir)
    github_message = None
    if github_repo is not None and not re.fullmatch(r"[\w.-]+/[\w.-]+|[\w.-]+@\d+/[\w.-]+@\d+", github_repo):
        error_console.print(
            f"[red]--github-repo must look like OWNER/REPO or OWNER@ID/REPO@ID, not '{github_repo}'.[/red]"
        )
        raise typer.Exit(code=1)
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

    role_arn = ""
    try:
        identity = IdentityService(session_mgr, preferred_region=sso_region)
        if bundle.identity.identity_center.external:
            user_id = identity.get_user_id_by_username(admin.username)
            if not user_id:
                error_console.print(
                    f"[red]'{admin.username}' is not in Identity Center.[/red] With an external identity provider, "
                    "tarmac doesn't create users: provision it from your identity provider (SCIM), then run "
                    "'tarmac bootstrap' again."
                )
                raise typer.Exit(code=1)
        else:
            user_id = identity.get_or_create_user(admin)
        _grant(identity, instance_arn, account_id, user_id, DEPLOYMENT_PERMISSION_SET, deployment_policy())
        _grant(identity, instance_arn, account_id, user_id, MANAGEMENT_ADMIN_PERMISSION_SET, None)
        if github_repo:
            role_arn = _github_role(session_mgr, github_repo, github_branch)
            github_message = f"GitHub Actions runs on {github_repo}@{github_branch} can deploy as {role_arn}."
        elif _update_github_role_policy(session_mgr.get_client("iam")):
            github_message = f"Updated the policy of {GITHUB_ROLE}, the role GitHub Actions deploys with."
    except AWS_ERRORS as e:
        error_console.print(f"[red]Bootstrap failed:[/red] {e}")
        raise typer.Exit(code=1)
    print_success(
        f"'{admin.username}' can sign in to account {account_id} as {DEPLOYMENT_PERMISSION_SET} (tarmac) "
        f"and {MANAGEMENT_ADMIN_PERMISSION_SET} (the console)."
    )
    if github_message:
        print_success(github_message)
    if role_arn:
        repo = re.sub(r"@\d+", "", github_repo or "")  # gh takes OWNER/REPO, without the immutable IDs
        print_info(
            "Give the workflow the role (examples/github/tarmac.yml reads it from this variable): "
            f"gh variable set TARMAC_ROLE_ARN --repo {repo} --body {role_arn}"
        )
    if github_repo and "@" not in github_repo:
        print_info(
            "Repositories created, renamed or transferred after 15 July 2026 need OWNER@ID/REPO@ID instead: "
            f"gh api repos/{github_repo} --jq '\"\\(.owner.login)@\\(.owner.id)/\\(.name)@\\(.id)\"'"
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
