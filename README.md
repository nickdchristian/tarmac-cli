# Tarmac CLI (`tarmac-cli`)

[![PyPI version](https://img.shields.io/pypi/v/tarmac-cli)](https://pypi.org/project/tarmac-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/tarmac-cli)](https://pypi.org/project/tarmac-cli/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Tarmac** is a declarative, idempotent Python CLI for bootstrapping and governing enterprise multi-account AWS Organizations.

Define your organizational units, account factory, SCP guardrails, baseline security (CloudTrail, GuardDuty, Security Hub), and IAM Identity Center (SSO) in simple YAML manifests—then reconcile your entire AWS estate with a single command.

---

## Quickstart

### 1. Installation & Setup

Install globally from **PyPI** with **[uv](https://docs.astral.sh/uv/)**:

```bash
uv tool install tarmac-cli
tarmac --help
```

Or install from source for local development:

```bash
git clone https://github.com/nickdchristian/tarmac-cli.git
cd tarmac-cli
uv sync --locked
uv run tarmac --help
```

### 2. Initialize Configuration

Scaffold a production-ready starter project with baseline YAML manifests and CloudFormation templates:

```bash
tarmac init --with-templates
```

This generates:
* **`config/organization.yaml`**: Organization settings, alternate contacts, OU hierarchy, and SCP guardrails.
* **`config/accounts.yaml`**: Account Factory catalog, OU placement, monthly budgets, and security baselines.
* **`config/identity.yaml`**: IAM Identity Center permission sets, users, groups, and multi-account assignments.

### 3. Validate & Inspect Readiness

Verify your configurations and audit your AWS Management Account before deploying:

```bash
# Validate YAML syntax, Pydantic schemas, and cross-references
tarmac validate

# Run automated pre-flight readiness checks (MFA, quotas, contacts, hygiene, existing trails)
tarmac preflight
```

### 4. Deploy Your Landing Zone

Preview proposed actions with a dry run, then execute the automated rollout:

```bash
# Preview what will be created and configured
tarmac deploy run --dry-run

# Execute the full 6-phase deployment pipeline
tarmac deploy run
```

### Starting from a brand-new AWS account

Tarmac runs as the **management account** of the organization it creates, and it cannot run as the root user
(root cannot assume the roles tarmac uses to configure member accounts). A fresh account therefore needs a few
one-time steps that AWS does not allow to be automated. The most direct path is IAM Identity Center (SSO):

1. Sign in as the root user, enable **MFA**, and add a payment method.
2. Open **AWS CloudShell** (it uses your console session, so no root access keys are created), install tarmac
   (`pip install --user tarmac-cli`) and create the organization: `tarmac org bootstrap`.
3. In the console, enable **IAM Identity Center** (it requires an existing organization).
4. In Identity Center create a user, create a permission set (for example `AdministratorAccess`), and **assign that
   user and permission set to the management account**. If this assignment is missing, `aws configure sso` stops
   with `No AWS accounts are available to you`.
5. In CloudShell run `aws configure sso`, then `aws sso login --use-device-code --profile <profile>` (see
   [Using AWS CloudShell](#using-aws-cloudshell) for why the device-code flag is needed).
6. `export AWS_PROFILE=<profile>`, then confirm with `tarmac access check`.
7. `tarmac preflight`, then `tarmac deploy run --dry-run`, then `tarmac deploy run`. Phases are idempotent, so a
   failed run can simply be repeated.

`tarmac preflight` and live `tarmac deploy run` refuse to run as root, so do not run them before step 6.
Each member account needs a **unique email address**; AWS never lets a closed account's email be reused, and
`tarmac validate` warns about the sample addresses written by `tarmac init`. Gmail users can create unique
addresses with the `+` trick (`you+prod@gmail.com`, `you+log@gmail.com`); all of them arrive in one inbox.

### Using AWS CloudShell

CloudShell is the easiest place to run tarmac the first time, with a few quirks:

* **Sign in with the device-code flow.** `aws sso login` normally redirects to `http://127.0.0.1:...`, which is the
  CloudShell machine and not your browser, so the callback fails. Use `aws sso login --use-device-code`: it prints a
  URL and a short code to enter in your own browser.
* **Set the profile and Region in every new shell.** `export AWS_PROFILE=<profile> AWS_REGION=<primary_region>`.
  Without `AWS_PROFILE`, tarmac uses CloudShell's own (root) credentials and refuses to continue. CloudShell uses
  the Region you opened it in, which may differ from `primary_region`.
* **Environment variables do not survive a restart; your home folder does.** Re-export `AWS_PROFILE`, `AWS_REGION`
  and `TARMAC_LOG_FILE` after CloudShell restarts. Your config directory and log file persist.
* **Use `--log-file`.** `export TARMAC_LOG_FILE=$HOME/run.jsonl` records every run, which makes a failed phase easy
  to diagnose with `tarmac logs`. Download it with the Actions menu.

### Adopting an existing organization

The quickest way to start is to let tarmac write the configuration for you:

```bash
tarmac import --config-dir my-lz          # read-only: nothing in AWS is changed
cd my-lz && tarmac validate && tarmac drift
tarmac deploy run --dry-run
```

`tarmac import` reads the OU tree, member accounts (name, email, OU, tags), customer-managed SCPs and where they
are attached, alternate contacts, trusted services, any existing organization trail, and IAM Identity Center
(users, groups, permission sets with their inline policies, and group assignments). It writes
`organization.yaml`, `accounts.yaml`, `identity.yaml` and the policy documents under `policies/`, sets
`delete_default_vpc: false` everywhere, and prints a list of things to review: accounts sitting directly under the
root (skipped), SCPs attached only to accounts or nowhere (not imported, because tarmac would attach them to
the root), SCP attachments tarmac cannot express, a pre-existing organization trail, and placeholder contacts.
`organization.name` comes from existing tarmac stacks when there are any (so a re-import never orphans them),
otherwise from `--name` or the management email domain. Use `--no-identity` to skip Identity Center and `--force`
to overwrite existing files.

Run `tarmac deploy run --dry-run` before the first real run and read the Phase 4 table. The rules that keep
adoption safe:

* **Declare the accounts you already have, with their real emails.** An existing account is matched by email first
  and then by name. If the name matches but the email differs, tarmac refuses to adopt or move it rather than guess.
* **Accounts you do not declare are left alone**, unless tarmac itself tagged them as managed earlier and you then
  removed them from `accounts.yaml`. Those are moved to the Suspended OU, and the Phase 4 plan shows them as
  `SUSPEND`. Set `quarantine_removed_accounts: false` in `accounts.yaml` to turn that off.
* **Do not change `organization.name` after the first deploy.** Every CloudFormation stack is named after it
  (`<name>-organization-scps`, ...). Renaming makes tarmac look for stacks that do not exist and try to import
  resources an older stack still owns, which fails. `tarmac preflight` warns when it sees stacks under a different
  name; the fix is to set the name back.
* **An organization trail that already exists is not replaced.** Tarmac adds its own, so you briefly pay for two
  copies of management events ($2.00 per 100,000 events beyond the first). Once the new trail is delivering logs
  (`aws cloudtrail get-trail-status --name <trail>` shows a delivery time), delete the old one. A multi-region trail
  can only be read or deleted in its home Region (`describe-trails --include-shadow-trails` shows it).
* **Default VPC purges are opt-out per account.** Set `delete_default_vpc: false` for accounts that already host
  workloads, and for the management account in `organization.yaml`.
* **What a full run changes in an existing organization:** the OU tree, the service control policy attached to the
  root (it affects every account, including the existing ones), account tags, a monthly budget stack in each member
  account, alternate contacts on the management account, trusted service access, and new Identity Center
  permission sets, users and group assignments. Existing permission sets and users that you did not declare are not
  touched.

### Bootstrap access (why tarmac cannot run as root)

Tarmac configures member accounts by assuming `OrganizationAccountAccessRole` in each of them, and the AWS root
user is not allowed to call `sts:AssumeRole`. (Root access keys are also discouraged.) So a brand-new account
needs one non-root principal first. `tarmac preflight` and live `tarmac deploy run` refuse to continue as root.

1. Sign in to the management account console as root and open **AWS CloudShell** (it uses your console session, so no root
   access keys are created). Install tarmac there (`pip install tarmac-cli`) and run:

   ```bash
   tarmac access bootstrap
   ```

   This deploys the `tarmac-access` stack: `TarmacDeploymentRole` with a least-privilege policy (see below; MFA enforced for IAM
   users, IAM Identity Center sessions pass; 4-hour sessions).
2. Create the organization (`tarmac org bootstrap` from CloudShell, or the console), enable **IAM Identity Center**, create an
   administrator user, and sign in with `aws sso login`. Run tarmac as that identity.
3. `tarmac access check` confirms the credentials are non-root and can read the organization; on failure it prints a hint.

Before Identity Center exists you can instead run `tarmac access bootstrap --with-bootstrap-user`. (The IAM Identity Center path above avoids creating an IAM user with a long-lived key and is the simpler route.) That also creates an
assume-only IAM user (`tarmac-bootstrap`) and adds a `[profile tarmac]` block to `~/.aws/config`. Create an access key and
an MFA device for the user in the IAM console, put the key in a `[profile tarmac-bootstrap]` profile, and run
`AWS_PROFILE=tarmac tarmac access check`. Delete the user and its key once SSO works.

`tarmac access template` prints the underlying CloudFormation template if you would rather deploy it yourself.

**What the role can do.** In the management account it gets only the API calls tarmac makes: Organizations, CloudFormation,
the organization trail, IAM Identity Center, GuardDuty/Security Hub delegation, Cost Explorer and a few read-only checks. For
member accounts it may only assume `OrganizationAccountAccessRole`. It has no `iam:PassRole`, cannot create IAM roles or
users, and an explicit deny stops it modifying its own role and policy, so changing the role is a root/admin task (re-run
`tarmac access bootstrap`). A test checks the policy against every AWS API call in tarmac's source, so adding a new call
without updating the policy fails CI. If a run reports `AccessDenied` for a new feature, deploy with
`ManagedPolicyArn=arn:aws:iam::aws:policy/AdministratorAccess` as a stopgap and report the missing action. The policy has not
yet been exercised end-to-end against a real organization; review it before relying on it in production.

Member accounts need nothing extra: Organizations creates `OrganizationAccountAccessRole` in every account tarmac
creates, trusting the management account, and the tarmac role reaches it through that. Accounts that were invited
(not created) need that role added by hand.

---

## Deployment Pipeline

Tarmac executes an idempotent multi-phase deployment:

```
[Phase 0: Preflight]   ──► Validate AWS prerequisites, quotas, & credentials
[Phase 1: Org & Root]  ──► Bootstrap AWS Organizations, contacts, & root access
[Phase 2: OUs & SCPs]  ──► Idempotently sync OU tree & attach guardrail SCPs
[Phase 3: Central Log] ──► Deploy Log-Archive bucket & Org-wide CloudTrail
[Phase 4: Accounts]    ──► Provision member accounts, purge default VPCs, set budgets
[Phase 5: Hardening]   ──► Delegate Security Hub / GuardDuty & anomaly monitors
[Phase 6: Identity]    ──► Sync IAM Identity Center permission sets & assignments
```

You can target a specific phase at any time:
```bash
tarmac deploy run --phase 4   # Run only Account Factory provisioning
```

---

## Command Reference

| Command | Description |
| :--- | :--- |
| **`tarmac init`** | Scaffold starter configuration manifests and CloudFormation templates. |
| **`tarmac validate`** | Validate configuration manifests against Pydantic schemas and cross-references. |
| **`tarmac preflight`** | Run 17 diagnostic checks for management account operational readiness (`doctor` alias). |
| **`tarmac info`** | Display caller identity, AWS account details, and Organization status. |
| **`tarmac deploy run`** | Execute the automated multi-phase landing zone rollout (`--dry-run` to preview). |
| **`tarmac status`** | Inspect live landing zone reconciliation and phase completion status. |
| **`tarmac drift`** | Audit IAM Identity Center permission sets and member account budget drift. |
| **`tarmac import`** | Read an existing organization (read-only) and write matching configuration files. |
| **`tarmac deploy destroy`** | Safely destroy deployed governance stacks (protected by production safety locks). `--everything` also removes OUs, Identity Center users/groups, org settings and the access role. |

<details>
<summary><strong>Granular Service Commands</strong></summary>

For targeted management outside the end-to-end pipeline:

* **Organizations & OUs**:
  * `tarmac org bootstrap` — Enable AWS Organizations and trusted services.
  * `tarmac org contacts` — Synchronize alternate contacts (Billing, Security, Ops).
  * `tarmac ou sync` — Idempotently synchronize OU tree hierarchy.
  * `tarmac org scp apply` — Reconcile and attach Service Control Policies.
* **Account Factory**:
  * `tarmac account plan` — Preview proposed account actions (Create, Move, No-op).
  * `tarmac account apply` — Provision missing accounts and assign to OUs.
  * `tarmac account sync-tags` — Synchronize governance tags with member accounts.
* **Security & Baseline**:
  * `tarmac baseline cloudtrail` — Deploy organization-wide CloudTrail.
  * `tarmac baseline backend` — Deploy Terraform S3 state and DynamoDB locks.
  * `tarmac baseline security` — Deploy GuardDuty, Security Hub, and log hardening.
* **IAM Identity Center**:
  * `tarmac identity status` — View Identity Center instance status and region.
  * `tarmac identity sync` — Synchronize permission sets, users, groups, and assignments.

</details>

---

## Logging and Audit Trail

| Option | Effect |
|---|---|
| *(default)* | Warnings and errors only, on stderr |
| `-v`, `--verbose` | Also print every recorded action (what was created, updated, attached, skipped) |
| `-d`, `--debug` | Full diagnostic output with tracebacks |
| `--log-file PATH` (or `TARMAC_LOG_FILE`) | Append a JSON-lines record of the run to `PATH` |

Each line of the log file is one JSON object with a timestamp, level, a `run_id` shared by the whole invocation, and (where known) the command, phase, account and Region. The first record (`run_start`) holds the version and arguments, and the last (`run_end`) holds the exit code and duration. Records with `"event": "audit"` describe a single action: what was done, to which resource, and whether it succeeded, was skipped, was only simulated by `--dry-run`, or failed. Secrets such as access keys and tokens are redacted before anything is written, and the file is created readable by its owner only.

```bash
tarmac --log-file run.jsonl run --yes
jq -r 'select(.event=="audit") | "\(.ts) \(.data.outcome) \(.message)"' run.jsonl
```

Outcomes mean what they say: `succeeded` is a change tarmac made, `unchanged` means AWS already held the requested state (tarmac reads before it writes, so a second run of the same command should be almost all `unchanged`), `skipped` was deliberately not done, `simulated` is what `--dry-run` would have done, and `failed` is an error. To prove a dry run changed nothing, check that the log has no `dry_run_violation` records: `tarmac logs run.jsonl --run latest --all --json | grep dry_run_violation` should print nothing. `deploy run --dry-run` also records each phase plan, and each account action in the Phase 4 plan, as `simulated`.

### Reading a log back

`tarmac logs` turns a log file into something a person can review without `jq`:

```bash
tarmac logs run.jsonl                       # one line per run: status, what changed, what failed
tarmac logs run.jsonl --run latest          # what the last run did, plus any warnings and errors
tarmac logs run.jsonl --run 20261020T1      # a run by id or id prefix
tarmac logs run.jsonl --outcome failed      # only actions that failed
tarmac logs run.jsonl --account dev --phase accounts
tarmac logs run.jsonl --run latest --all    # every record, including AWS calls
tarmac logs run.jsonl --run latest --json   # matching records, one JSON object per line
```

With `TARMAC_LOG_FILE` set, the file argument can be left out. Reading a log never writes to it. A run shows as `incomplete` if the process was killed before it could write its final record.

### AWS calls and CloudTrail

Every AWS call is recorded with its service, operation, Region, outcome, duration, request id and a redacted summary of its parameters. Calls that change something (`Create*`, `Put*`, `Delete*`, `Enable*`, ...) are logged at INFO, so they are in the log file and shown by `-v`; read-only calls (`Describe*`, `List*`, `Get*`) appear with `--debug`.

The run id is added to the AWS user agent (`app/tarmac-<run-id>`) and to the role session name (`tarmac-<run-id>`), so any CloudTrail event can be matched back to the run that caused it, for example by searching for the run id in `userAgent` or in the assumed-role session name.

During `--dry-run` and `plan` commands, any state-changing call (other than CloudFormation change sets) is logged as an `ERROR` with `"event": "dry_run_violation"`: a preview must not change anything.

### Keeping CloudTrail logs

By default CloudTrail logs are kept forever, which is the safe choice but means storage cost grows slowly. Set `cloudtrail.retention_days` to delete log files that many days after they are written:

```yaml
cloudtrail:
  retention_days: 365   # omit to keep logs indefinitely
```

Deleted objects are purged for good seven days later and cannot be recovered, so pick a value that meets your audit and compliance requirements (many frameworks ask for a year or more). `tarmac deploy run --dry-run` shows the retention that will be applied. The setting is applied to the log archive stack; changing it re-deploys that stack.

### Security Hub standards for every account

```yaml
security_services:
  delegated_account: audit
  securityhub:
    enabled: true
    standards: [aws-foundational-security-best-practices]
    central_configuration: true   # default; false = per-Region local configuration
```

With `central_configuration` (the default, used when `auto_enable_members` is true) the audit account switches Security
Hub to [central configuration](https://docs.aws.amazon.com/securityhub/latest/userguide/start-central-configuration.html)
and applies one policy, `tarmac-security-baseline`, to the organization root. Existing and new accounts then get Security
Hub with exactly the standards you list, in the primary Region (the aggregation Region) and the Regions linked to the
finding aggregator. The old local mode left new accounts with Security Hub on but no standards.

Notes: policies can only be managed from the primary Region, which must not be an opt-in Region. In central mode the
per-account settings are managed by the policy, so change standards in `organization.yaml` rather than by hand.
`tarmac deploy destroy --disable-security-services` removes the policy and returns the organization to local
configuration before disabling Security Hub.

### Encryption of the log archive

`cloudtrail.enable_kms: false` stores the CloudTrail logs with SSE-S3 (AES256) and does not create the log archive KMS key, which saves about $1 a month plus request charges. If you switch an existing deployment from `true` to `false`, the key already created is kept (logs written earlier still need it to be read); remove it yourself once those logs have expired.

### Existing resources with the same name

Tarmac will not overwrite or delete something it did not create. If an SCP or a budget it would manage already
exists with the same name:

* **SCP** that is not tagged `tarmac:managed-by=tarmac` and whose content differs from your policy file: the run stops
  and lists the live and declared statement IDs. (An untagged SCP that already matches is taken over quietly, which is
  what happens after `tarmac import`.)
* **Budget** named `<account>-monthly-budget` that tarmac did not create: the account's budget step fails with its
  current limit. Tarmac would otherwise delete it and create its own.

After reviewing, re-run with `--adopt-existing` (on `deploy run`, `org scp plan|apply`, `account apply` and
`account baseline`) to let tarmac take it over. The old budget's limit and period are recorded in the audit log.

## Safe Teardown

Tarmac includes built-in safeguards to prevent accidental infrastructure or state loss:
* **Production Environment Lock**: Refuses to destroy any environment whose `Environment`/`Env`/`Stage` tag is `production`, `prod` or `prd` unless `--force` is explicitly provided.
* **Ownership checks**: SCPs, the standalone CloudTrail trail and Identity Center permission sets that tarmac did not create (no `tarmac:managed-by=tarmac` tag) are skipped, not deleted.
* **Remote State Preservation**: Pass `--preserve-backend` to destroy infrastructure while protecting remote Terraform state buckets and lock tables.
* **Non-Empty Bucket Protection**: Halts if unmanaged data exists in S3 buckets unless explicitly confirmed.

```bash
# Preview teardown actions
tarmac deploy destroy --dry-run

# Execute teardown preserving Terraform state
tarmac deploy destroy --preserve-backend
```

### Starting over

A full `tarmac deploy destroy` removes everything tarmac deployed (stacks, buckets, budgets, SCPs, permission
sets, milestone tags) so `tarmac deploy run` can rebuild it. It deliberately **keeps**:

* the organization, **OUs and member accounts** (closing an account is irreversible and AWS reserves its email, so
  use `tarmac account suspend --close` per account and declare a new email if you want a truly fresh account);
* GuardDuty / Security Hub / AWS Config delegation and member detectors, which keep billing until disabled.
  Pass `--disable-security-services` to turn them off as part of Phase 5 (it turns off auto-enable, deregisters
  the delegated administrators, deletes the GuardDuty detectors and disables Security Hub in the audit,
  management and declared member accounts). **This deletes finding history**, so it is opt-in. Failures per
  account/region are reported, and a failed step makes the command exit non-zero;
* IAM Identity Center users and groups, OUs, organization settings and the access role (kept unless you pass
  `--everything`, below).

The log-archive KMS key is scheduled for deletion (30-day window, cancel with `aws kms cancel-key-deletion`)
once its buckets have been purged and deleted; if any log-archive cleanup failed the key is kept.

### Removing everything tarmac did

```bash
tarmac deploy destroy --everything --dry-run     # preview
tarmac deploy destroy --everything               # asks you to type the organization name
```

On top of a normal destroy, `--everything` removes, in dependency order: the Identity Center users and groups
tarmac created (and their assignments), the OUs tarmac created (only when empty), the organization settings tarmac
enabled (delegated administrators, root credentials management and root sessions, trusted service access,
alternate contacts, cost-allocation-tag activation), the milestone tags, and finally the `tarmac-access` stack
(`TarmacDeploymentRole`) and the `tarmac-bootstrap` IAM user with its keys and MFA device.

What counts as "created by tarmac" is decided by evidence, never by name:

* Stacks, SCPs, permission sets and accounts carry the `tarmac:managed-by=tarmac` tag.
* OUs, users, groups and organization settings cannot be tagged, so tarmac records each one in
  `<config dir>/.tarmac/inventory.json` the moment it changes it. Things that already existed (an event logged
  as "unchanged") are never recorded and therefore never removed. `tarmac deploy inventory` shows the record.
* For a deployment that predates the inventory, rebuild it from a run log:
  `tarmac deploy destroy --everything --inventory-from-log "$TARMAC_LOG_FILE"` (or
  `tarmac deploy inventory --from-log FILE` to inspect it first).

**Member accounts are never closed by this command.** It lists the accounts tarmac manages with the exact
`tarmac account suspend NAME --close` command for each. An alternate contact that replaced one which already existed is
left in place (tarmac cannot restore the old one), and the `tarmac-bootstrap` user is only deleted when it carries
the `tarmac:managed-by=tarmac` tag. Disabling Identity Center trusted access is also left to you, because it can
delete the Identity Center instance. If you run the teardown as `TarmacDeploymentRole`, the
access stack's deletion is started but not awaited. The role cannot manage IAM users, so when the access stack
contains a bootstrap user the stack is kept and the command tells you to remove the user as an administrator
(for example your SSO admin) and run it again.

If a teardown leaves a CloudFormation stack in `DELETE_FAILED` (for example a bucket that could not be emptied),
fix the cause and re-run teardown or deploy: both now delete and recreate stacks stuck in `DELETE_FAILED`,
`CREATE_FAILED` or `ROLLBACK_COMPLETE`.

> Templates exported with `tarmac init --with-templates` take precedence over the ones bundled with the CLI.
> After upgrading tarmac, delete or diff your local `cloudformation/` and `policies/` copies against the bundled ones to pick up fixes. (Do not use `tarmac init --force` for this: it also overwrites your YAML configuration.)

---

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| `Root credentials cannot assume roles in member accounts` | The shell is using root credentials (for example CloudShell's own session). | `export AWS_PROFILE=<sso-profile>` and re-run; see [Starting from a brand-new AWS account](#starting-from-a-brand-new-aws-account). |
| `aws configure sso` says `No AWS accounts are available to you` | Your Identity Center user has no permission set on any account. | In Identity Center, assign the user and a permission set to the management account, then run `aws configure sso` again. |
| The SSO sign-in page redirects to `127.0.0.1` and fails | CloudShell has no browser to receive the callback. | Use `aws sso login --use-device-code`. |
| `The config profile (...) could not be found` | `aws configure sso` stopped before writing the profile. | Fix the cause above, then run `aws configure sso` again. |
| `tarmac info` shows Identity Center as not found | Identity Center lives in one Region, which may not be your shell's. | Set `AWS_REGION` to it, or pass `--region`. |
| Phase 2: `Failed to import resources into stack '<name>-organization-scps'` and a change set reason of `p-... already exists in stack ...` | The SCP belongs to a stack named for a different `organization.name`. | Set `organization.name` back to the original name (the prefix of the stack in the message). |
| Phase 5: `You must enable service access before you delegate an administrator` (`config-multiaccountsetup`) | Trusted access for that service was not enabled (fixed in newer releases). | `aws organizations enable-aws-service-access --service-principal config-multiaccountsetup.amazonaws.com`, then re-run phase 5. |
| `refusing to create an account with the sample email` | `accounts.yaml` still has an address from `tarmac init`. | Use a real, unique address you can receive mail at. |
| `refusing to adopt or move it` | An account with that name exists under a different email. | Put the account's actual email in `accounts.yaml`. |
| Warning: `An organization trail already exists` | A trail from before tarmac is still recording. | Delete the old trail once the new one is delivering logs; see above. |
| `UPDATE_ROLLBACK_COMPLETE` on the `tarmac-access` stack | A stack update failed and was rolled back. | `aws cloudformation describe-stack-events --stack-name tarmac-access --query "StackEvents[?contains(ResourceStatus,'FAILED')].[LogicalResourceId,ResourceStatusReason]" --output text` shows why. |
| A warning such as `No updates are to be performed` or `already a delegated administrator` | AWS reporting that nothing needed doing. | Nothing; these are logged as `unchanged` and are not errors. |

Always start with `tarmac logs --run latest`: it shows the failing action, its AWS error and the phase it happened in.

---

## Development & Testing

```bash
# Sync environment dependencies from lockfile
uv sync --locked

# Run the Pytest suite
uv run pytest

# Run static analysis, formatting, and template/config validation
uv run ruff check .
uv run ruff format --check .
uv run basedpyright
uv run cfn-lint cloudformation/*.yaml src/tarmac/templates/cloudformation/*.yaml
uv run tarmac validate --config-dir examples/config
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
