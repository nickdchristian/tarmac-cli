# Tarmac

[![CI](https://github.com/nickdchristian/tarmac-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/nickdchristian/tarmac-cli/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/tarmac-cli)](https://pypi.org/project/tarmac-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/tarmac-cli)](https://pypi.org/project/tarmac-cli/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Tarmac sets up and maintains a multi-account AWS Organization from three YAML files: OUs, accounts, guardrail
SCPs, an organization CloudTrail, security services and IAM Identity Center. Change the YAML, run
`tarmac deploy`, and tarmac makes AWS match. Every run is safe to repeat.

## Install

```bash
uv tool install tarmac-cli     # or: pip install tarmac-cli
tarmac --help
```

## Quick start: a brand-new AWS account

Tarmac runs in the organization's management account. It can't run as the root user, because root can't reach
member accounts, so you first create an IAM Identity Center login for yourself. AWS CloudShell is the easiest
place to do this.

1. Sign in as root, turn on MFA, and add a payment method.
2. In the console, enable **IAM Identity Center**. Pick its Region carefully: moving it later means starting
   over. This also creates the organization.
3. In CloudShell:
   ```bash
   pip install tarmac-cli
   tarmac init          # writes config/organization.yaml, accounts.yaml, identity.yaml
   ```
   Tarmac reads `config/` in the folder you run it from; `--config-dir` or `TARMAC_CONFIG_DIR` points it
   elsewhere. Edit the files. Put yourself in `admin_user` in `identity.yaml`, and give every account in `accounts.yaml` a
   real, unique email (plus addresses such as `aws+prod@example.com` work if your mail provider supports them).
4. Still in CloudShell, as root:
   ```bash
   tarmac bootstrap
   ```
   This creates your Identity Center user, gives it two permission sets on the management account
   (`TarmacDeployment` for tarmac, `ManagementAdministrator` for the console), and adds a `tarmac` profile to
   `~/.aws/config`. It ends by printing the steps for your first sign-in.
5. Follow those steps to sign in, then deploy:
   ```bash
   export AWS_PROFILE=tarmac
   tarmac preflight           # checks the account is ready
   tarmac plan                # shows what would change, changes nothing
   tarmac deploy
   ```

**CloudShell tips:** always use `aws sso login --use-device-code`, because the normal login can't call back to
your browser. Re-run `export AWS_PROFILE=tarmac` after CloudShell restarts; without it, tarmac sees root and
stops.

## Using an existing organization

`tarmac import` reads your organization and writes matching config files, keeping any file it changes as
`<name>.bak`. It changes nothing in AWS. Besides OUs, accounts, SCPs and Identity Center, it reads the settings
that are running: GuardDuty and Security Hub when they are delegated to the audit account, the Regions they and
the AWS Config recorders cover, cost allocation tags, and what tarmac's own stacks were deployed with (log
encryption, retention and Object Lock, the Terraform lock table, baseline stacks, whose templates it writes to
`baseline/`). Anything it can't read is listed for you to check, because a setting left off turns that thing off
on the next deploy.

```bash
tarmac import --config-dir my-org
cd my-org
tarmac status --detail
tarmac plan
```

Read what it reports, and check the dry run before the first real deploy. Keep in mind:

- **Declare existing accounts with their real emails.** If a name matches but the email doesn't, tarmac stops
  rather than guess.
- **Accounts you don't declare are left alone,** except ones tarmac created earlier and you have since removed
  from `accounts.yaml`. Those are moved to the Suspended OU (`quarantine_removed_accounts: false` turns this off).
- **Never change `organization.name` or `primary_region` after the first deploy.** Every stack is named after the
  name, and tarmac keeps its inventory in the primary Region. Tarmac records both on the management account and
  stops with an explanation if the config no longer matches.
- **An existing organization trail isn't replaced.** Tarmac adds its own; delete the old one once the new one is
  delivering logs.
- **Set `delete_default_vpc: false`** for accounts that already run workloads.

## Deploying from GitHub Actions

Keep your config in a GitHub repository and let merges to `main` deploy it:

```bash
tarmac bootstrap --github-repo OWNER/REPO   # as root or ManagementAdministrator; --github-branch if not main
```

Repositories created, renamed or transferred after 15 July 2026 identify their workflow runs by
[immutable owner and repository IDs](https://docs.github.com/en/actions/reference/security/oidc), so pass
`--github-repo OWNER@ID/REPO@ID` for those. Get it with
`gh api repos/OWNER/REPO --jq '"\(.owner.login)@\(.owner.id)/\(.name)@\(.id)"'`. With the wrong form, AWS refuses
the workflow with "Not authorized to perform sts:AssumeRoleWithWebIdentity"; run `bootstrap` again with the other
form.

This adds GitHub's OIDC provider and the `TarmacGitHubDeployment` role, with the same policy as
`TarmacDeployment`, to the management account. Only workflow runs on that branch can assume it, so protect the
branch and require pull request reviews. Pull requests get no AWS access, because whoever opens one can change
the workflow; they run `tarmac validate`, and the dry run is printed in the deploy log before the real deploy.
Copy [`examples/github/tarmac.yml`](examples/github/tarmac.yml) to `.github/workflows/` and fill in the role ARN
and Region.

Running `tarmac bootstrap` after an upgrade also updates the role's policy.

`destroy --everything` doesn't remove the role or the OIDC provider. Delete them in the IAM console when you stop
deploying from GitHub.

## What it deploys

`tarmac deploy` runs six phases in order. `--phase N` runs one, and `--phase 4 --account NAME` updates a single
account.

| Phase | What it does |
| :--- | :--- |
| 1 | Organization settings, contacts, trusted services, root access management, cost tags, the inventory bucket |
| 2 | OUs and service control policies |
| 3 | Log archive buckets and the organization CloudTrail |
| 4 | Member accounts, their tags, alternate contacts, budgets and default VPC cleanup |
| 5 | Terraform state backend, audit account, AWS Config, GuardDuty, Security Hub, root user alert |
| 6 | Identity Center permission sets, users, groups and assignments |

Tarmac only takes away access it manages. Groups it created get exactly the members and account assignments
`identity.yaml` lists: phase 6 removes anyone else from the group, and the group's other assignments on the
accounts in `accounts.yaml`. A group that already existed is only added to, until `tarmac import` records it as
managed (once the inventory bucket exists); destroy still leaves imported groups in place. Assignments on the
management account and other accounts not in `accounts.yaml` are left alone, as are users and groups that aren't
in `identity.yaml`. The dry run lists every removal.

`accounts: [all]` in an assignment means every account in `accounts.yaml`. Accounts tarmac doesn't manage get
nothing from it, and the dry run names them. Nor does the management account: Identity Center creates the role
there with the caller's own IAM rights, which tarmac's role deliberately doesn't have. `tarmac bootstrap` gives your
admin user what it needs there; an administrator assigns anything else.

Following AWS's guidance, the management account holds only what has to live there:

- **Management account:** Organizations, SCPs, Identity Center, the trail's stack, the AWS Config StackSet, and
  the inventory bucket, which records the OUs, users, groups and settings tarmac created so everyone running
  tarmac shares it.
- **Audit account:** delegated administrator for CloudTrail, AWS Config, GuardDuty, Security Hub and IAM root
  access management.
- **Log archive account:** the CloudTrail and Config log buckets, and GuardDuty's exported findings.

`tarmac init` starts you with the OUs AWS recommends: Security, Infrastructure, Workloads (Prod and Test),
Deployments, Sandbox, Policy Staging and Suspended.

Everything comes from the [CloudFormation templates](src/tarmac/templates/cloudformation) and
[SCPs](src/tarmac/templates/policies/scp) bundled with tarmac. `tarmac init --with-templates` copies them into your
project; tarmac then uses your copies, so you can review and version them.

Tarmac itself runs with the least-privilege policy in
[`tarmac-deployment.json`](src/tarmac/templates/policies/iam/tarmac-deployment.json). After upgrading tarmac,
run `tarmac bootstrap` again to update it; `tarmac preflight` warns when it's out of date.

**The config is the source of truth.** Turning something off, or removing it, makes the next deploy remove what
tarmac created for it, and the dry run lists each removal first: service control policies (an empty
`service_control_policies.policies`), AWS Config recorders, the root activity alert, an
account's budget, and its cost anomaly monitors. Log buckets and the history in them are kept.

Settings tarmac turned on are turned back off when the config no longer asks for them: root access management
features and its IAM delegated administrator, and cost allocation tags. Groups tarmac created are deleted when they
leave `identity.yaml`, after their assignments are removed. So are permission sets tarmac created: removing one
deletes it and every assignment on it, in every account, so read the dry run first. The two that `tarmac bootstrap`
gives your admin user are never removed this way. Users are never deleted for being left out, and anything
tarmac didn't create is left alone.

Turning off GuardDuty suspends it in the member accounts: monitoring and charges stop, its findings are kept, and
turning it back on resumes it. It stays on in the audit account, because AWS only suspends an administrator's own
detector once its members are disassociated. Security Hub can't be suspended, so turning it off disables it, and AWS deletes its findings after
90 days (archived ones after 30) unless you turn it back on first; the dry run and the deploy both warn about this.

## Commands

| Command | What it does |
| :--- | :--- |
| `tarmac init` | Write starter config files |
| `tarmac validate` | Check the config files, without AWS |
| `tarmac bootstrap` | Once, as root: create your Identity Center login and the `tarmac` profile |
| `tarmac preflight` | Check the management account is ready |
| `tarmac plan` | Show what `deploy` would change, without changing it (same as `deploy --dry-run`) |
| `tarmac deploy` | Apply the config (`--phase N` for one phase) |
| `tarmac status` | Compare AWS with the config (`--detail` lists every difference) |
| `tarmac import` | Write config files from an existing organization |
| `tarmac destroy` | Remove what tarmac deployed (see [Tearing down](#tearing-down)) |
| `tarmac info` | Show who you're signed in as (`--strict` fails if tarmac can't run) |
| `tarmac account list` | List accounts in the organization |
| `tarmac account suspend NAME` | Move an account to the Suspended OU (`--close` closes it) |
| `tarmac logs FILE` | Summarize runs recorded with `--log-file` |
| `tarmac inventory` | Show what tarmac has recorded creating |

## Options

All of these go in `organization.yaml`. Options with a real cost are off until you turn them on. A setting tarmac
doesn't know is an error, so a typo can't be silently ignored.

**Log retention and locking.** CloudTrail logs are kept forever unless you set a retention. Object Lock stops anyone
deleting logs during the lock period. It's recommended, but S3 can never turn it off again, so tarmac leaves it off
until you set it, and `tarmac plan` recommends it while it's off.

```yaml
cloudtrail:
  retention_days: 365
  object_lock: {mode: GOVERNANCE, retention_days: 365}   # COMPLIANCE can't be bypassed, even by root
  enable_kms: true   # encrypt logs with a KMS key (~$1/month); CIS and Security Hub ask for it
```

**Security services.**

```yaml
security_services:
  audit_account: audit
  guardduty:
    enabled: true
    features: {s3_data_events: true}   # optional paid protections stay off unless listed
    export_findings: true            # keep findings past GuardDuty's 90 days in a log archive bucket (SSE-KMS)
  securityhub:
    enabled: true
    standards: [aws-foundational-security-best-practices]   # every account; newest version unless you add /v/X.Y.Z
  config_recorder:
    enabled: true                    # AWS Config in every account; Security Hub needs it
    recording_frequency: CONTINUOUS  # usually cheaper than DAILY
  root_alert:
    enabled: true                    # emails contacts.security.email when root is used (on by default)
```

**Terraform state.** Phase 5 creates a state bucket in the deployment account. Its name is in the
`<org>-terraform-backend` stack's `BucketName` output. Locking uses S3 (`use_lockfile = true`, Terraform 1.10+);
set `terraform_backend.enable_dynamodb: true` if you need a DynamoDB lock table.

**Baseline stacks.** Your own CloudFormation templates, deployed in phase 4 to every active account in the listed
OUs and their child OUs (`root` for all of them) through a StackSet, including accounts added later. StackSets can't deploy to the
management account. Removing an entry deletes its StackSet and stacks. Templates can't use macros or transforms.
`--phase 4 --account NAME` leaves baseline stacks alone, because they cover whole OUs.

```yaml
baseline_stacks:
  - name: iam-password-policy          # StackSet <org>-baseline-iam-password-policy
    template_file: templates/password-policy.yaml   # relative to your project, like policy_file
    target_ous: [Workloads, Sandbox]
    regions: [us-east-1]
    parameters: {MinimumLength: "14"}
```

**Example SCPs.** [`examples/policies/scp`](examples/policies/scp) has two optional policies, one restricting
Regions and one stopping member accounts turning off GuardDuty or Security Hub. Keep their
`OrganizationAccountAccessRole` exemption (tarmac works through that role), and test them on one OU before
attaching them to the root.

## Tearing down

```bash
tarmac destroy --dry-run
tarmac destroy
```

`destroy` removes the stacks, buckets, budgets, SCPs and permission sets tarmac deployed, so `deploy` can rebuild
them. It keeps the organization, OUs and member accounts. It also refuses to touch anything tagged as production
unless you pass `--force`, and skips anything tarmac didn't create.

- `--preserve-backend` keeps the Terraform state.
- `--disable-security-services` also turns off GuardDuty, Security Hub and Config. This deletes their findings.
- `--everything` also removes the OUs, Identity Center users and groups, and organization settings tarmac created,
  plus the `tarmac bootstrap` permission sets (except the one you're signed in with), and finally the inventory
  bucket once everything it records is gone. It never closes accounts.

## Logging

Add `-v` to see each change as it happens, or `--log-file run.jsonl` (or set `TARMAC_LOG_FILE`) to record a run.
Both go before the command. Inspect the results with `tarmac logs`:

```bash
tarmac -v --log-file run.jsonl deploy
tarmac logs run.jsonl --run latest            # what the last run did, and what failed
tarmac logs run.jsonl --outcome failed
```

## Upgrading

Tarmac is pre-1.0, so a minor release can change commands or config. Read the breaking changes in
[CHANGELOG.md](CHANGELOG.md) before upgrading; an entry names the commands of its own release, which a later
release may have renamed again.

## Development

```bash
uv sync --locked
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run basedpyright
uv run cfn-lint src/tarmac/templates/cloudformation/*.yaml
uv run tarmac validate --config-dir examples/config
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

[Apache License 2.0](LICENSE)
