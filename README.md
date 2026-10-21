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
* **`config/identity.yaml`**: IAM Identity Center permission sets, users, groups, and multi-account assignments. An
  assignment's `accounts` take names from `accounts.yaml`, `management` for the management account, or `all`.

### 3. Validate & Inspect Readiness

Verify your configurations and audit your AWS Management Account before deploying:

```bash
# Validate YAML syntax, Pydantic schemas, and cross-references
tarmac validate

# Run automated pre-flight readiness checks (MFA, quotas, contacts, hygiene, existing trails)
tarmac preflight
```

### 4. Deploy Your Landing Zone

Preview the changes with a dry run, then deploy:

```bash
# Compare the configuration with AWS, read-only, and list what each phase would change
tarmac deploy --dry-run

# Run all six phases (the pre-flight checks run first)
tarmac deploy
```

### Starting from a brand-new AWS account

Tarmac runs as the **management account** of the organization it creates, and it cannot run as the root user
(root cannot assume the roles tarmac uses to configure member accounts). Phases 1 and 6 only touch the management
account, so they can run as root to create the organization and your IAM Identity Center (SSO) login. Only the
steps AWS does not allow to be automated stay manual:

1. Sign in as the root user, enable **MFA**, and add a payment method.
2. Open **AWS CloudShell** (it uses your console session, so no root access keys are created), install tarmac
   (`pip install --user tarmac-cli`) and run `tarmac init`. Put your own email in `admin_user` in `identity.yaml`.
   Create the organization: `tarmac deploy --phase 1`.
3. In the console, enable **IAM Identity Center** (choose its Region deliberately) and, under **Settings →
   Authentication → Standard authentication**, turn on **Send email OTP**. Users created by tarmac have no password
   until they verify their email this way.
4. Back in CloudShell, still as root: `tarmac deploy --phase 6` creates the admin user, the permission sets, the
   groups and their assignments (the starter `identity.yaml` gives `CloudAdmins` the `management` account), then
   `tarmac access profile` writes a `tarmac` SSO profile to `~/.aws/config`.
5. `aws sso login --use-device-code --profile tarmac` (see [Using AWS CloudShell](#using-aws-cloudshell) for why
   the device-code flag is needed). The first sign-in emails you a code, then asks for a password and an MFA device.
6. `export AWS_PROFILE=tarmac`, then confirm with `tarmac info --strict`.
7. `tarmac preflight`, then `tarmac deploy --dry-run`, then `tarmac deploy`. Phases are idempotent, so a
   failed run can simply be repeated. This run of phase 6 adds the assignments on member accounts created since.

`tarmac preflight` and `tarmac deploy` (other than `--phase 1` and `--phase 6`) refuse to run as root, so do not
run them before step 6.
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
cd my-lz && tarmac validate && tarmac status --detail
tarmac deploy --dry-run
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

Run `tarmac deploy --dry-run` before the first real run and read the Phase 4 table. The rules that keep
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
needs one non-root principal first. `tarmac preflight` and `tarmac deploy` refuse to continue as root.

1. Sign in to the management account console as root and open **AWS CloudShell** (it uses your console session, so no root
   access keys are created). Install tarmac there (`pip install tarmac-cli`) and run:

   ```bash
   tarmac access bootstrap
   ```

   This deploys the `tarmac-access` stack: `TarmacDeploymentRole` with a policy scoped to what tarmac does (see below; MFA enforced for IAM
   users, IAM Identity Center sessions pass; 4-hour sessions).
2. Create the organization (`tarmac deploy --phase 1` from CloudShell, or the console), enable **IAM Identity Center**, create
   your administrator login with `tarmac deploy --phase 6` and `tarmac access profile` (see
   [Starting from a brand-new AWS account](#starting-from-a-brand-new-aws-account)), and sign in with `aws sso login`. Run
   tarmac as that identity. Choose the Identity Center Region
   deliberately: an organization can have it in one Region only, and moving it later means deleting the instance and creating
   another ([AWS docs](https://docs.aws.amazon.com/singlesignon/latest/userguide/enable-identity-center.html)).
3. `tarmac info --strict` confirms the credentials are non-root and can read the organization; it exits 1 and says why
   when they cannot.

Before Identity Center exists you can instead run `tarmac access bootstrap --with-bootstrap-user`. (The IAM Identity Center path above avoids creating an IAM user with a long-lived key and is the simpler route.) That also creates an
assume-only IAM user (`tarmac-bootstrap`) and adds a `[profile tarmac]` block to `~/.aws/config`. Create an access key and
an MFA device for the user in the IAM console, put the key in a `[profile tarmac-bootstrap]` profile, and run
`AWS_PROFILE=tarmac tarmac info --strict`. Delete the user and its key once SSO works.

`tarmac access template` prints the underlying CloudFormation template if you would rather deploy it yourself.

**What the role can do.** In the management account it gets only the API calls tarmac makes: Organizations, CloudFormation,
the organization trail, IAM Identity Center, GuardDuty/Security Hub delegation, Cost Explorer and a few read-only checks. For
member accounts it may only assume `OrganizationAccountAccessRole`. It has no `iam:PassRole`, cannot create IAM roles or
users, and an explicit deny stops it modifying its own role and policy, so changing the role is a root/admin task (re-run
`tarmac access bootstrap`). A test checks the policy against every AWS API call in tarmac's source, so adding a new call
without updating the policy fails CI, and another test keeps the policy under IAM's size limit with headroom. `tarmac preflight` compares the deployed `tarmac-access` stack with the template in your installed release and warns to re-run `tarmac access bootstrap` after an upgrade that changed it (it only looks at a stack with that default name). If a run reports `AccessDenied` for a new feature, deploy with
`ManagedPolicyArn=arn:aws:iam::aws:policy/AdministratorAccess` as a stopgap and report the missing action. The policy has not
yet been exercised end-to-end against a real organization; review it before relying on it in production.

Member accounts need nothing extra: Organizations creates `OrganizationAccountAccessRole` in every account tarmac
creates, trusting the management account, and the tarmac role reaches it through that. Accounts that were invited
(not created) need that role added by hand.

---

## Deployment Pipeline

Tarmac executes an idempotent multi-phase deployment. A full `tarmac deploy` first runs the same checks as
`tarmac preflight` and stops if any of them fails (`--skip-preflight` skips them):

```
[Phase 1: Org & Root]  ──► Bootstrap AWS Organizations, contacts, & root access
[Phase 2: OUs & SCPs]  ──► Idempotently sync OU tree & attach guardrail SCPs
[Phase 3: Central Log] ──► Deploy Log-Archive bucket & Org-wide CloudTrail
[Phase 4: Accounts]    ──► Provision member accounts, purge default VPCs, set budgets
[Phase 5: Hardening]   ──► Delegate Security Hub / GuardDuty & anomaly monitors
[Phase 6: Identity]    ──► Sync IAM Identity Center permission sets & assignments
```

You can target a specific phase at any time:
```bash
tarmac deploy --phase 4                     # Run only Account Factory provisioning
tarmac deploy --phase 4 --account dev-app   # Only this account: create or move it, tag it, apply its baseline
```

Phase 4 writes the account IDs to `outputs/accounts.json` and `outputs/accounts.env` (`export NAME_ACCOUNT_ID=...`
lines you can `source`).

### Dry runs

`tarmac deploy --dry-run` (optionally with `--phase N` and `--json`) changes nothing. It reads the current state
with read-only calls and lists, per phase, every item and what a live run would do with it: `CREATE`, `UPDATE`,
`REPLACE`, `IMPORT` (adopt an existing SCP or permission set), `MOVE`, `SUSPEND`, `APPLY` or `NO CHANGE`.
Stacks are compared on their exact template text, the parameters tarmac passes and their tags, and an `UPDATE`
names what differs. An item whose state cannot be read shows `UNKNOWN` with the error. A dry run needs the same
credentials as a deploy; to check configuration files without AWS, use `tarmac validate`.

---

## What tarmac deploys

Everything tarmac creates in AWS comes from the CloudFormation templates and SCP policies below, which ship with
the package. `<org>` is `organization.name` from `organization.yaml`.

| Template | Stack | Account / Region | Deployed by | What it creates |
| :--- | :--- | :--- | :--- | :--- |
| [`tarmac-access.yaml`](src/tarmac/templates/cloudformation/tarmac-access.yaml) | `tarmac-access` | Management / `us-east-1` by default | `tarmac access bootstrap` | The `TarmacDeploymentRole` tarmac runs as, its managed policy, and optionally an assume-only `tarmac-bootstrap` IAM user |
| [`log-archive-hardening.yaml`](src/tarmac/templates/cloudformation/log-archive-hardening.yaml) | `<org>-log-archive-hardening` | Log Archive / primary | Phase 3 | The central CloudTrail bucket, an access-logs bucket, a separate AWS Config bucket (when Config recorders are enabled) and a KMS key (when `cloudtrail.enable_kms` is on) |
| [`organization-cloudtrail.yaml`](src/tarmac/templates/cloudformation/organization-cloudtrail.yaml) | `<org>-organization-cloudtrail` | Management / primary | Phase 3 | One multi-Region organization trail with log file validation, delivering to the Log Archive bucket |
| [`account-budget.yaml`](src/tarmac/templates/cloudformation/account-budget.yaml) | `<account>-monthly-budget` | Each member account with a budget / primary | Phase 4 | A monthly cost budget and an SNS topic for its email and webhook alerts |
| [`terraform-backend.yaml`](src/tarmac/templates/cloudformation/terraform-backend.yaml) | `<org>-terraform-backend` | Deployment / primary | Phase 5 | The Terraform state bucket, plus a DynamoDB lock table only when `enable_dynamodb` asks for one |
| [`audit-account-hardening.yaml`](src/tarmac/templates/cloudformation/audit-account-hardening.yaml) | `<org>-audit-account-hardening` | Audit / primary | Phase 5 | An AWS Config aggregator, a KMS-encrypted SNS alert topic, and EventBridge rules forwarding Config non-compliance, GuardDuty findings, Security Hub findings and root activity to it |
| [`config-recorder.yaml`](src/tarmac/templates/cloudformation/config-recorder.yaml) | `<org>-config-recorder` (StackSet + management stack) | Every account / declared Regions | Phase 5, when `security_services.config_recorder.enabled` | An AWS Config recorder and delivery channel per account and Region, delivering to the Log Archive |
| [`management-root-alert.yaml`](src/tarmac/templates/cloudformation/management-root-alert.yaml) | `<org>-management-root-alert` | Management / `us-east-1` and primary (all declared Regions with `all_regions`) | Phase 5, when `security_services.root_alert.enabled` | An EventBridge rule and SNS topic that alert the security contact (and the incident webhook, if set) when the root user signs in or calls an API |

| SCP | What it denies |
| :--- | :--- |
| [`foundational-guardrails.json`](src/tarmac/templates/policies/scp/foundational-guardrails.json) | Root user activity in member accounts (centralized-root-access sessions stay allowed), leaving the organization, and closing an account. `tarmac init` attaches it to the organization root. |
| [`deny-member-root.json`](src/tarmac/templates/policies/scp/deny-member-root.json) | Only the member-account root user rule from `foundational-guardrails.json`. |
| [`deny-leave-organization.json`](src/tarmac/templates/policies/scp/deny-leave-organization.json) | Only the leave-organization and account-closure rules from `foundational-guardrails.json`. |

Two stacks are generated from your configuration rather than a template file: `<org>-organization-scps` (the SCPs
declared in `organization.yaml`) and `<org>-sso-permission-sets` (the permission sets in `identity.yaml`).

To review or change any of this before it reaches AWS:

* `tarmac init --with-templates` copies the templates and SCPs into your project (`cloudformation/`, `policies/scp/`).
  Tarmac uses your copies in preference to the bundled ones, so you can keep them in version control and review changes.
* `tarmac access template` prints the access-role template on its own.
* `tarmac deploy --dry-run` compares every stack with what is deployed (template, parameters and tags) and lists
  what each phase would change, without changing anything.

---

## Command Reference

| Command | Description |
| :--- | :--- |
| **`tarmac init`** | Scaffold starter configuration manifests and CloudFormation templates. |
| **`tarmac validate`** | Validate configuration manifests against Pydantic schemas and cross-references. |
| **`tarmac preflight`** | Run 17 diagnostic checks for management account operational readiness. |
| **`tarmac info`** | Display caller identity, AWS account details, and Organization status. `--strict` exits 1 unless the credentials can run tarmac. |
| **`tarmac deploy`** | Run the landing zone deployment. `--phase N` runs one phase, `--dry-run` shows what would change. |
| **`tarmac status`** | Compare the live environment with the configuration. `--detail` adds every drifted or missing item, the live OUs and the cost anomaly monitors; `--strict` exits 1 on drift. |
| **`tarmac import`** | Read an existing organization (read-only) and write matching configuration files. |
| **`tarmac destroy`** | Safely destroy deployed governance stacks (protected by production safety locks). `--everything` also removes OUs, Identity Center users/groups, org settings and the access role. |

Everything that changes AWS goes through `tarmac deploy`, one phase at a time if you like:

| To change | Run |
| :--- | :--- |
| Organization, contacts, trusted services, root access, cost tags, management default VPCs | `tarmac deploy --phase 1` |
| OUs and Service Control Policies | `tarmac deploy --phase 2` |
| Log Archive and organization CloudTrail | `tarmac deploy --phase 3` |
| Member accounts, their tags, budgets and default VPCs (`--account NAME` for one account) | `tarmac deploy --phase 4` |
| Terraform backend, audit hardening, Config recorders, root alert, GuardDuty / Security Hub | `tarmac deploy --phase 5` |
| IAM Identity Center permission sets, users, groups and assignments | `tarmac deploy --phase 6` |

<details>
<summary><strong>Other commands</strong></summary>

* **Accounts**:
  * `tarmac account list` — List every account with its status and parent OU.
  * `tarmac account suspend NAME` — Quarantine an account in the Suspended OU (`--close` to close it).
* **Inspection**:
  * `tarmac info` also shows the Identity Center instance, identity store and access portal URL.
  * `tarmac inventory` — Show what tarmac has recorded as created by it.
  * `tarmac logs FILE` — Summarize runs recorded with `--log-file`.
* **Access**:
  * `tarmac access bootstrap` / `tarmac access template` — Create, or print, the role tarmac runs as.
  * `tarmac access profile` — Write an IAM Identity Center profile for the management account to `~/.aws/config`.

</details>

---

## Example: restricting regions

Tarmac does not choose which regions you may use, so no region SCP is attached by default.
[`examples/policies/scp/deny-unused-regions.json`](examples/policies/scp/deny-unused-regions.json) is a starting
point you can copy into your project's `policies/scp/` and reference from `organization.yaml`:

1. Replace the `aws:RequestedRegion` list (`us-east-1`, `us-west-2` in the example) with the regions you use. Include
   your `primary_region` and the region of your IAM Identity Center instance.
2. Keep the `NotAction` list of global services (IAM, Organizations, Route 53, CloudFront, Support, STS, ...), or
   those calls are denied everywhere.
3. Keep the `TarmacDeploymentRole` and `OrganizationAccountAccessRole` exemption. Tarmac removes default VPCs in
   every enabled region of each member account, and Phase 2 (SCPs) runs before the Phase 4 baseline, so without
   the exemption that cleanup fails in the regions you blocked. Drop `OrganizationAccountAccessRole` from the
   exemption only if you set `delete_default_vpc: false` (or have already cleaned those VPCs). The example names the
   default role, `TarmacDeploymentRole`; if you bootstrapped with `--role-name`, change the exemption to that name, or
   tarmac is locked out of the regions you blocked.

SCPs do not apply to the management account. Test it on one OU before attaching it to the root.

## Example: protecting GuardDuty and Security Hub

Nothing stops an administrator of a member account from turning off GuardDuty or Security Hub there, so tarmac does not attach
a protecting SCP by default (an SCP can lock you out; see above).
[`examples/policies/scp/protect-security-services.json`](examples/policies/scp/protect-security-services.json) denies only the
actions that switch them off or detach the account from the audit account: deleting the detector, disassociating from the
administrator, stopping member monitoring, disabling Security Hub and its standards. Reading and configuring stay allowed. The
action names are taken from the AWS Service Authorization Reference
([GuardDuty](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonguardduty.html),
[Security Hub](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecurityhub.html)).

The policy exempts `TarmacDeploymentRole` and `OrganizationAccountAccessRole`, which is how tarmac reaches member accounts, so
`tarmac destroy --disable-security-services` keeps working. Add the role your own administrators use (for example an
`AWSReservedSSO_*` role) to the `aws:PrincipalARN` list, or they cannot turn the services off either; change `TarmacDeploymentRole`
if you bootstrapped with `--role-name`. It is not run against a live organization; attach it to one test OU first.

AWS Config is left out on purpose. AWS publishes an
[example SCP for Config](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_config.html)
(`config:DeleteConfigurationRecorder`, `StopConfigurationRecorder`, `DeleteDeliveryChannel`, `DeleteConfigRule`), but tarmac
deploys recorders with StackSets, and I could not confirm which role name StackSets uses in member accounts, so a Config SCP could
block its own updates.

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

Outcomes mean what they say: `succeeded` is a change tarmac made, `unchanged` means AWS already held the requested state (tarmac reads before it writes, so a second run of the same command should be almost all `unchanged`), `skipped` was deliberately not done, `simulated` is what `--dry-run` would have done, and `failed` is an error. To prove a dry run changed nothing, check that the log has no `dry_run_violation` records: `tarmac logs run.jsonl --run latest --all --json | grep dry_run_violation` should print nothing. `tarmac deploy --dry-run` records every item of the plan, with the action a live run would take, as `simulated`.

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

During a `--dry-run`, any state-changing call is logged as an `ERROR` with `"event": "dry_run_violation"`: a preview must not change anything.

### Keeping CloudTrail logs

By default CloudTrail logs are kept forever, which is the safe choice but means storage cost grows slowly. Set `cloudtrail.retention_days` to delete log files that many days after they are written:

```yaml
cloudtrail:
  retention_days: 365   # omit to keep logs indefinitely
```

Deleted objects are purged for good seven days later and cannot be recovered, so pick a value that meets your audit and compliance requirements (many frameworks ask for a year or more). `tarmac deploy --dry-run` shows the retention that will be applied. The setting is applied to the log archive stack; changing it re-deploys that stack.

### Locking CloudTrail logs (S3 Object Lock)

**Recommended, but off unless you set it.** Object Lock gives the log bucket a default retention so log files cannot be
deleted or overwritten for that period, which is what makes the audit trail trustworthy. tarmac does not turn it on by
itself because S3 cannot disable Object Lock on a bucket once it is on. While it is unset, `deploy` and `baseline` print
a warning and the dry run shows it as off.

```yaml
cloudtrail:
  object_lock:
    mode: GOVERNANCE      # or COMPLIANCE
    retention_days: 365
  # object_lock: null     # decided against it: hides the warning
```

`GOVERNANCE` can be bypassed by principals with `s3:BypassGovernanceRetention`. `COMPLIANCE` cannot be shortened or
removed by anyone, including the root user, until each object's period ends. The lock applies to objects written after
it is enabled, and can be added to an existing log bucket later by setting it and re-running deploy. A lock longer than
`cloudtrail.retention_days` (log expiry) is rejected, because lifecycle cannot delete locked versions.

This changes teardown. `tarmac destroy` retries locked deletes with the governance bypass, so GOVERNANCE
locks do not block it (the audit log records it). COMPLIANCE locks cannot be removed: destroy stops with an error
and the log bucket stays until the retention period ends. Use `GOVERNANCE` in test organizations.

### AWS Config recorders (optional)

Off by default: AWS Config bills per configuration item, so the cost grows with accounts x Regions x resource changes.
Turn it on to record resource configuration in every account:

```yaml
security_services:
  config_recorder:
    enabled: true
    include_global_resources: true   # IAM and similar types, recorded in the primary region only
    recording_frequency: CONTINUOUS  # DAILY is $0.012/item vs $0.003: cheaper only above 4 changes a day
  # config_recorder: null            # decided against it: hides the Security Hub warning below
```

Recorders are created in `primary_region` plus `additional_regions`, the same Regions GuardDuty and Security Hub use.
They record every supported type except `AWS::Config::ResourceCompliance`: Security Hub updates that item on every
compliance change, AWS says its checks do not need it, and it recommends not recording it when the recorder serves
only Security Hub. Set `record_resource_compliance: true` if you use that history, or if a Region where IAM global types
are not supported rejects the recorder.

`DAILY` is billed at $0.012 per configuration item against $0.003 for `CONTINUOUS`, and records an item only when a
resource differs from its previous one. It therefore saves money only for resources that change more than four times a
day; for most accounts `CONTINUOUS` is the cheaper choice. Firewall Manager needs `CONTINUOUS`.
Member accounts get them from one service-managed StackSet (`<org>-config-recorder`) targeting the organization root, so
accounts created later receive the recorder without re-running tarmac. StackSets cannot target the management account,
so it gets the same template as an ordinary stack in each Region, using AWS Config's service-linked role (the
deployment role is not allowed to create IAM roles). Suspended accounts are left out.

History and snapshots go to their own bucket in the log archive account (`<org>-org-config-logs-<account id>`), created
by the log archive stack in phase 3 when this is enabled. It is separate from the CloudTrail bucket because AWS Config
cannot deliver to a bucket with Object Lock default retention, so Config history is **not** locked. It uses the same KMS
key setting and log expiry (`cloudtrail.retention_days`) as the CloudTrail bucket. Enabling the setting later means
running phase 3 again before phase 5.

Security Hub CSPM standards need a recorder to evaluate most of their controls (unless the newer AWS Security Hub is also
enabled, which manages its own). While Security Hub is enabled and `config_recorder` is not mentioned in your
configuration, `deploy` warns; write `config_recorder: null` (or `enabled: false`) to acknowledge it.

`cloudtrail.object_lock: null` works the same way: both warnings are silenced by the key being present in
`organization.yaml`, which tarmac never writes for you (neither `tarmac init` nor `tarmac import` adds it). If you
generate that file with another tool, keep the key, or the warning comes back.

Notes:

* An account and Region can have only one customer-managed recorder. If one already exists (for example from Control
  Tower), that instance fails and the run reports it; tarmac does not replace recorders it did not create, and it never
  updates a StackSet that lacks its `tarmac:managed-by` tag. Service-linked recorders (such as Security Hub's) coexist.
* Re-running with fewer Regions removes the recorders from the dropped Regions.
* `tarmac destroy` removes the StackSet, its instances and the management stacks before it touches the log
  buckets. It leaves StackSets trusted access enabled.

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

The linked Regions are exactly the Regions you declare (the primary Region aggregates; the rest are linked, or none for a
single-Region deployment). A central policy turns Security Hub on in every linked Region of every account, so tarmac
never links "all Regions" in this mode. An existing aggregator is narrowed to match.

Switching an existing organization is guarded. tarmac stops, rather than guess, when Security Hub already has member
accounts configured one by one, or when the root already uses a configuration policy tarmac did not create, because a
policy can replace what those accounts enabled themselves. Review the difference and re-run with `--adopt-existing`, or
set `central_configuration: false` to keep local configuration. The home Region (`organization.primary_region`) cannot be an
opt-in Region such as `af-south-1` or `me-south-1`, because Security Hub does not allow it; tarmac checks this and stops
before changing anything. This behaviour has not been verified against a live organization yet.

Notes: policies can only be managed from the primary Region, which must not be an opt-in Region. In central mode the
per-account settings are managed by the policy, so change standards in `organization.yaml` rather than by hand.
`tarmac destroy --disable-security-services` removes the policy and returns the organization to local
configuration before disabling Security Hub.

### Encryption of the log archive

CloudTrail encrypts delivered logs with SSE-S3 (AES256) by default, and AWS describes a customer managed KMS key as "an added layer of security". The key costs about $1 a month plus request charges, so Tarmac leaves it off for a new deployment.

* `cloudtrail.enable_kms` unset (the default): a new deployment uses SSE-S3. A deployment that already has the key keeps it, so upgrading never lowers its encryption.
* `enable_kms: true` adds the key. Set it if you follow the CIS benchmark or Security Hub, whose CloudTrail checks (CloudTrail.2, CIS 3.5) ask for SSE-KMS.
* `enable_kms: false` switches an existing deployment back to SSE-S3 for new logs. The key already created is kept (logs written earlier still need it to be read); remove it yourself once those logs have expired.
* If Tarmac cannot read the existing log archive stack to find out, it stops and says so instead of guessing.

### Existing resources with the same name

Tarmac will not overwrite or delete something it did not create. If an SCP or a budget it would manage already
exists with the same name:

* **SCP** that is not tagged `tarmac:managed-by=tarmac` and whose content differs from your policy file: the run stops
  and lists the live and declared statement IDs. (An untagged SCP that already matches is taken over quietly, which is
  what happens after `tarmac import`.)
* **Budget** named `<account>-monthly-budget` that tarmac did not create: the account's budget step fails with its
  current limit. Tarmac would otherwise delete it and create its own.

After reviewing, re-run with `--adopt-existing` (on `tarmac deploy`) to let tarmac take it over. The old budget's limit and period are recorded in the audit log.

### GuardDuty features (all off unless you ask)

`security_services.guardduty` turns on GuardDuty's foundational detection only. The optional protection plans are billed on
top of it, so they stay off until you set them:

```yaml
security_services:
  guardduty:
    enabled: true
    features:
      s3_data_events: true      # S3 Protection
      # eks_audit_logs, malware_protection (EBS), rds_login_events, lambda_network_logs
```

AWS switches on every optional feature (except Runtime Monitoring) when a detector is created without a feature list
([CreateDetector](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateDetector.html)), so tarmac sends the list
explicitly, and sets the same choice for new member accounts. On a detector that already exists tarmac only turns requested
features on; it never turns one off, and it reports any optional feature that is on but not requested. Runtime Monitoring is
not managed by tarmac.

### Terraform state locking

Phase 5 creates a versioned, encrypted S3 bucket for Terraform state. Locking is S3-only by default, so
Terraform needs `use_lockfile = true` (Terraform 1.10 or later) and there is no DynamoDB table to pay for. Terraform now marks
DynamoDB-based locking as deprecated
([S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)). Set `terraform_backend.enable_dynamodb: true`
to create the lock table anyway. A backend that already has the table keeps it unless you set `enable_dynamodb: false`, and tarmac
warns before removing it, because Terraform configurations that still set `dynamodb_table` would
stop locking.

## Safe Teardown

Tarmac includes built-in safeguards to prevent accidental infrastructure or state loss:
* **Production Environment Lock**: Refuses to destroy any environment whose `Environment`/`Env`/`Stage` tag is `production`, `prod` or `prd` unless `--force` is explicitly provided.
* **Ownership checks**: SCPs, the standalone CloudTrail trail and Identity Center permission sets that tarmac did not create (no `tarmac:managed-by=tarmac` tag) are skipped, not deleted.
* **Remote State Preservation**: Pass `--preserve-backend` to destroy infrastructure while protecting remote Terraform state buckets and lock tables.
* **Non-Empty Bucket Protection**: Halts if unmanaged data exists in S3 buckets unless explicitly confirmed.

```bash
# Preview teardown actions
tarmac destroy --dry-run

# Execute teardown preserving Terraform state
tarmac destroy --preserve-backend
```

### Termination protection

The stacks that hold data or access are created with CloudFormation termination protection: the organization trail, the
log-archive and audit-account hardening stacks, the Terraform state backend and the `tarmac-access` stack. A stray
`aws cloudformation delete-stack` is refused for them. `tarmac destroy` is the deliberate way to remove them: it turns
protection off on each stack just before deleting it and prints a warning saying so (and `--dry-run` shows what it would
delete). `--preserve-backend` leaves the state backend, and its protection, untouched. Enabling protection needs
`cloudformation:UpdateTerminationProtection`, so re-run `tarmac access bootstrap` once to refresh the access role; until then
a deploy reports that protection could not be turned on and carries on.

### Root user alerts

SCPs do not apply to the management account, so the deny-root SCP cannot stop root being used there. Tarmac deploys a
`<org>-management-root-alert` stack that emails `contacts.security.email` (and posts to
`security_services.incident_response_webhook_url`, if set) when the root user signs in or makes an API call in the management
account. It is on by default and costs next to nothing: EventBridge ingests AWS management events for free, and the only
charge is a few SNS emails. AWS records root sign-in events in us-east-1, so the stack is deployed there and in your
primary Region; each Region has its own SNS topic, so confirm the subscription email in each. Root use in member accounts is
denied by the SCP, and the attempts are in the organization trail; the audit account also alerts on its own root activity.

```yaml
security_services:
  root_alert:
    enabled: true        # false turns the alert off
    all_regions: false   # true also watches every declared Region for root API calls
```

Without a security contact email or webhook there is nobody to alert, so tarmac skips the stack and says so. The access role
needs the `events:` and `sns:` actions this adds: re-run `tarmac access bootstrap` once.

### Starting over

A full `tarmac destroy` removes everything tarmac deployed (stacks, buckets, budgets, SCPs, permission
sets, milestone tags) so `tarmac deploy` can rebuild it. It deliberately **keeps**:

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
tarmac destroy --everything --dry-run     # preview
tarmac destroy --everything               # asks you to type the organization name
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
  as "unchanged") are never recorded and therefore never removed. `tarmac inventory` shows the record.
* For a deployment that predates the inventory, rebuild it from a run log:
  `tarmac destroy --everything --inventory-from-log "$TARMAC_LOG_FILE"` (or
  `tarmac inventory --from-log FILE` to inspect it first).

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
| `aws sso login` or `aws configure sso` says `No AWS accounts are available to you` | Your Identity Center user has no permission set on the management account. | Add `management` to the accounts of a group assignment the user is a member of in `identity.yaml` and run `tarmac deploy --phase 6`. |
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
uv run cfn-lint src/tarmac/templates/cloudformation/*.yaml
uv run tarmac validate --config-dir examples/config
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
