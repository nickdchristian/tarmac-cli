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

# Run 17 automated pre-flight readiness checks (MFA, quotas, contacts, hygiene)
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

Tarmac runs as the **management account** of the organization it creates. A fresh account needs a few
one-time manual steps that AWS does not allow to be automated:

1. Sign in as the root user, enable **MFA**, and add a payment method (`tarmac preflight` checks this).
2. Create the tarmac role (see **Bootstrap access** below) and configure AWS credentials for it. Do not run tarmac as root.
3. Run `tarmac deploy run --phase 1` (or `tarmac org bootstrap`) to create the organization.
4. Enable **IAM Identity Center** once in the AWS console (it requires an existing organization). Phase 6 fails without it.
5. Run `tarmac deploy run` for the remaining phases. Phases are idempotent, so a failed run can simply be repeated.

Each member account needs a **unique email address**; AWS never lets a closed account's email be reused.

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

Before Identity Center exists you can instead run `tarmac access bootstrap --with-bootstrap-user`. That also creates an
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
| **`tarmac deploy destroy`** | Safely destroy deployed governance stacks (protected by production safety locks). |

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

### Encryption of the log archive

`cloudtrail.enable_kms: false` stores the CloudTrail logs with SSE-S3 (AES256) and does not create the log archive KMS key, which saves about $1 a month plus request charges. If you switch an existing deployment from `true` to `false`, the key already created is kept (logs written earlier still need it to be read); remove it yourself once those logs have expired.

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
* IAM Identity Center users and groups (always kept; remove them in the console or your identity provider).

The log-archive KMS key is scheduled for deletion (30-day window, cancel with `aws kms cancel-key-deletion`)
once its buckets have been purged and deleted; if any log-archive cleanup failed the key is kept.

If a teardown leaves a CloudFormation stack in `DELETE_FAILED` (for example a bucket that could not be emptied),
fix the cause and re-run teardown or deploy: both now delete and recreate stacks stuck in `DELETE_FAILED`,
`CREATE_FAILED` or `ROLLBACK_COMPLETE`.

> Templates exported with `tarmac init --with-templates` take precedence over the ones bundled with the CLI.
> After upgrading tarmac, delete or diff your local `cloudformation/` and `policies/` copies against the bundled ones to pick up fixes. (Do not use `tarmac init --force` for this: it also overwrites your YAML configuration.)

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
