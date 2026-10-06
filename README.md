# Tarmac CLI (`tarmac-cli`)

[![PyPI version](https://img.shields.io/pypi/v/tarmac-cli.svg)](https://pypi.org/project/tarmac-cli/)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Tarmac** is a declarative, idempotent Python CLI for bootstrapping and governing enterprise multi-account AWS Organizations.

Define your organizational units, account factory, SCP guardrails, baseline security (CloudTrail, GuardDuty, Security Hub), and IAM Identity Center (SSO) in simple YAML manifests—then reconcile your entire AWS estate with a single command.

---

## Quickstart

### 1. Installation & Setup

Install from source with **[uv](https://docs.astral.sh/uv/)**:

```bash
git clone https://github.com/nickdchristian/tarmac-cli.git
cd tarmac-cli
uv sync
```

You can then run commands with `uv run tarmac` or install it into your local environment:
```bash
uv pip install -e .
tarmac --help
```

*(Once published to PyPI, you can install globally with `uv tool install tarmac-cli`)*

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
* **Production Environment Lock**: Refuses to destroy any environment tagged with `production` or `prod` unless `--force` is explicitly provided.
* **Remote State Preservation**: Pass `--preserve-backend` to destroy infrastructure while protecting remote Terraform state buckets and lock tables.
* **Non-Empty Bucket Protection**: Halts if unmanaged data exists in S3 buckets unless explicitly confirmed.

```bash
# Preview teardown actions
tarmac deploy destroy --dry-run

# Execute teardown preserving Terraform state
tarmac deploy destroy --preserve-backend
```

---

## Development & Testing

```bash
# Sync environment dependencies
uv sync

# Run the 247-test Pytest suite
uv run pytest

# Run static analysis and formatting
uv run ruff check .
uv run ruff format --check .
uv run basedpyright
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
