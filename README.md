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
uv sync --frozen
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

1. `tarmac access template -o tarmac-access.yaml`
2. In the CloudFormation console of the management account (signed in as root, once), create a stack from that file
   with capability `CAPABILITY_NAMED_IAM`. It creates `TarmacDeploymentRole` (MFA required to assume, 4-hour
   sessions, `AdministratorAccess` by default; override `ManagedPolicyArn` to tighten) and an optional
   `tarmac-bootstrap` IAM user that can only assume that role and manage its own MFA and access key.
3. Sign in once as `tarmac-bootstrap` (or set a console password for it), register an MFA device, create an access key,
   and add profiles to `~/.aws/config`:

   ```ini
   [profile tarmac-bootstrap]
   region = us-east-1

   [profile tarmac]
   role_arn = arn:aws:iam::<management-account-id>:role/TarmacDeploymentRole
   source_profile = tarmac-bootstrap
   mfa_serial = arn:aws:iam::<management-account-id>:mfa/tarmac-bootstrap
   region = us-east-1
   ```

4. `AWS_PROFILE=tarmac tarmac access check` should report a non-root identity.
5. Once Identity Center is set up, sign in through SSO (grant the permission set rights to assume the role, or use an
   administrator permission set), then delete the `tarmac-bootstrap` access key and user.

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
uv sync --frozen

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
