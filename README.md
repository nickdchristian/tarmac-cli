# Tarmac CLI (`tarmac` / `tarmac-cli`)

A modern, declarative Python CLI for bootstrapping and governing enterprise multi-account AWS Organizations. Published as **`tarmac-cli`** on PyPI and invoked via the **`tarmac`** command. Built using **[UV](https://docs.astral.sh/uv/)**, Python 3.11+, [Boto3](https://boto3.amazonaws.com/), [Typer](https://typer.tiangolo.com/), [Rich](https://rich.readthedocs.io/), and [Pydantic](https://docs.pydantic.dev/).

---

## Architecture & Design Principles

The project follows a clean **Layered Architecture** with strict separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│           src/tarmac/cli/*.py (Typer + Rich)                │
│          - Consumes Result DTOs, renders tables/spinners    │
│          - ui.py: Shared terminal UI formatting utilities   │
│          - Top-level GovernanceError handling               │
└──────────────────────────────┬──────────────────────────────┘
                               │ calls
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       Service Layer                         │
│              src/tarmac/services/*.py                       │
│  - AccountService, BaselineService, OUService,              │
│    OrganizationService, CloudFormationService,             │
│    IdentityService                                          │
│  - Emits standard Python logging                            │
│  - Returns strongly typed DTOs (models.py)                  │
└──────────────────────────────┬──────────────────────────────┘
                               │ uses
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     Infrastructure Layer                    │
│                src/tarmac/core/*.py                         │
│  - aws_client.py (Boto3 session & STS AssumeRole cache)     │
│  - config_loader.py & config_schema.py (Pydantic validation)│
│  - exceptions.py (Domain exception hierarchy)               │
│  - models.py (Strongly typed Result DTOs)                   │
└─────────────────────────────────────────────────────────────┘
```

### Key Architectural Highlights
- **Decoupled Services & Presentation**: Domain services perform purely functional state management, emit standard Python diagnostic logging, and return immutable Result Data Transfer Objects (DTOs). The CLI layer is solely responsible for terminal rendering.
- **Strongly Typed Exception Hierarchy**: Custom `GovernanceError` hierarchy with domain-specific errors (`ConfigurationError`, `AWSAuthenticationError`, `AccountProvisioningError`, `OUManagementError`, etc.) providing clean, actionable error messages without raw stack traces (unless `--debug` is enabled).
- **Automated Account Baselining**:
  - **Default VPC Cleanup**: Purges unneeded default VPCs, subnets, and internet gateways across active AWS regions.
  - **AWS Budgets**: Automated monthly cost limits with customizable percentage thresholds and notification emails.
  - **AWS Cost Anomaly Detection**: Configures anomaly monitors and alert subscriptions in the management account.
- **Zero-Mutation Configuration**: Replaces runtime shell file mutation with declarative YAML manifests and machine-readable exports (`outputs/inventory.json` and `outputs/env.sh`).
- **Standard UV Toolchain & Static Typing**: Deterministic dependency resolution via `uv.lock`, sub-second environment syncs via `uv sync`, fast linting/formatting via `ruff`, and strict static type checking via `basedpyright`.

---

## Directory Structure

```
tarmac-cli/
├── pyproject.toml                     # Project packaging, UV config, Ruff and basedpyright settings
├── uv.lock                            # Deterministic UV lockfile
├── .python-version                    # Pinned Python version
├── README.md                          # Project documentation and CLI guide
├── examples/                          # Reference examples and templates
│   └── config/                        # Reference configuration manifests
│       ├── organization.yaml          # Organization settings, contacts, root access, OUs
│       ├── accounts.yaml              # Account Factory catalog, baselines, and budgets
│       └── identity.yaml              # IAM Identity Center permission sets, groups, users
│
├── config/                            # Active configuration manifests (GitOps committed)
│   └── local/                         # Local development overrides (git-ignored for testing)
│
├── policies/                          # Declarative Policies & Guardrails
│   ├── scp/                           # Service Control Policies (deny leave org, deny member root)
│   └── iam/                           # Custom IAM inline policies for Identity Center (SSO)
│
├── cloudformation/                    # Foundational CloudFormation templates
│   ├── organization-cloudtrail.yaml   # Centralized organization CloudTrail & S3 bucket
│   ├── terraform-backend.yaml         # S3 state bucket + DynamoDB table in Deployment acct
│   ├── log-archive-hardening.yaml     # Log Archive KMS & lifecycle policies
│   └── audit-account-hardening.yaml   # AWS Config aggregator & SNS alerting
│
├── src/tarmac/                        # Core Python application
│   ├── cli/                           # Presentation Layer (Typer + Rich)
│   │   ├── main.py                    # Root entrypoint (`tarmac`)
│   │   ├── preflight.py               # `tarmac preflight` and `tarmac doctor` commands
│   │   ├── org.py                     # `tarmac org` subcommands
│   │   ├── ou.py                      # `tarmac ou` subcommands
│   │   ├── account.py                 # `tarmac account` subcommands (Account Factory)
│   │   ├── identity.py                # `tarmac identity` subcommands
│   │   ├── baseline.py                # `tarmac baseline` subcommands
│   │   ├── deploy.py                  # `tarmac deploy` end-to-end orchestrator
│   │   ├── common.py                  # Shared CLI configuration loader and error exit
│   │   └── ui.py                      # Rich terminal console formatting utilities
│   ├── core/                          # Infrastructure & Cross-Cutting Layer
│   │   ├── aws_client.py              # STS cross-account session & client manager
│   │   ├── config_schema.py           # Pydantic data validation models
│   │   ├── config_loader.py           # YAML parser and cross-reference validator
│   │   ├── exceptions.py              # Custom domain exception hierarchy
│   │   ├── models.py                  # Strongly typed Result DTOs
│   │   └── templates.py               # Smart template & policy resolver with fallback
│   ├── services/                      # Domain Services
│   │   ├── preflight.py               # 15-domain automated pre-flight inspection engine
│   │   ├── organization.py            # AWS Organizations & alternate contacts
│   │   ├── ou.py                      # OU tree reconciliation
│   │   ├── accounts.py                # Account creation, status waiters, and OU placement
│   │   ├── baseline.py                # Default VPC cleanup, budgets, and anomaly alerts
│   │   ├── cloudformation.py          # CloudFormation stack deployer with waiters
│   │   ├── identity.py                # IAM Identity Center manager
│   │   ├── scp.py                     # Service Control Policy manager
│   │   ├── scaffold.py                # Project template generator
│   │   └── status.py                  # Landing zone reconciliation status
│   └── templates/                     # Bundled package resources for PyPI distribution
│       ├── cloudformation/            # Bundled CloudFormation YAML templates
│       └── policies/scp/              # Bundled SCP JSON policies
│
├── tests/                             # Pytest test suite (247 passing tests)
│   ├── conftest.py
│   ├── test_account_factory.py
│   ├── test_aws_client.py
│   ├── test_baseliner.py
│   ├── test_cli.py
│   ├── test_config_schema.py
│   ├── test_logging.py
│   ├── test_models.py
│   ├── test_ou_engine.py
│   ├── test_preflight.py
│   ├── test_scp.py
│   ├── test_security_services.py
│   ├── test_services.py
│   ├── test_tagging.py
│   ├── test_teardown.py
│   └── test_templates.py
│
├── LICENSE                            # Apache-2.0 License
└── outputs/                           # Machine-readable inventory (gitignored)
    ├── inventory.json                 # JSON catalog of created accounts and IDs
    └── env.sh                         # Shell exports for downstream automation
```

---

## Getting Started with UV

### 1. Prerequisites

- Install **[uv](https://docs.astral.sh/uv/)**:
  ```bash
  # macOS / Linux
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # or via Homebrew:
  brew install uv
  ```
- AWS CLI v2 configured with Management Account administrative credentials:
  ```bash
  aws sts get-caller-identity
  ```

### AWS Prerequisites & Operational Considerations

Before deploying to a real AWS environment, ensure the following AWS-specific requirements are met:

1. **Management Account Authority**:
   - The CLI must be run using credentials from the **AWS Management Account** (Master Account). Run `uv run tarmac info` to verify caller identity and Management Account role verification.
2. **Payment & Billing Verification**:
   - The Management Account must have a verified payment method and valid tax information. Without this, AWS `organizations:CreateAccount` will fail with `PAYMENT_INSTRUMENT_REQUIRED`.
3. **AWS Organization Account Quotas**:
   - Brand-new AWS Organizations often default to an initial limit of 5 to 10 accounts. If your `accounts.yaml` defines more accounts than your quota, request an increase via **AWS Service Quotas** (`AWS Organizations -> Default maximum number of accounts`).
4. **Unique Root Email Addresses**:
   - Each member account requires a globally unique email address across all AWS accounts worldwide. Use email sub-addressing (e.g. `cloudadmin+audit@company.com`, `cloudadmin+prod@company.com`).
5. **One-Time AWS Console Steps (API Limitations)**:
   - **IAM Identity Center (AWS SSO)**: Must be enabled once via the AWS Management Console to establish the organization instance in your `primary_region`.
   - **AWS Cost Explorer**: Must be opened once in the AWS Billing & Cost Management console so AWS initializes cost data ingestion for Cost Anomaly Detection.
6. **SNS Alert Confirmation**:
   - When deploying security hardening and anomaly monitors, AWS sends automated subscription confirmation emails. Designated email recipients must click the confirmation link in the email.

### 2. Project Setup

Clone the repository and sync dependencies with UV:

```bash
git clone https://github.com/nickdchristian/tarmac-cli.git
cd tarmac-cli
uv sync
```

Verify installation:
```bash
uv run tarmac --help
```

### 3. Configuration Setup

Copy the example configuration files and customize them for your organization:

```bash
# Initialize active configuration from reference examples
mkdir -p config
cp examples/config/organization.yaml config/
cp examples/config/accounts.yaml config/
cp examples/config/identity.yaml config/
```

> [!TIP]
> **Local Testing & Development:**
> If you are testing locally or developing Tarmac and do not want to commit private AWS account numbers or test email addresses to Git, place your configurations in `config/local/` (e.g. `config/local/organization.yaml`). Tarmac automatically prioritizes `config/local/` over `config/` when present, and `.gitignore` ensures your test configurations remain private.

Validate your configurations for syntax and referential integrity:

```bash
uv run tarmac validate
```

---

## CLI Command Reference

All commands are executed via `uv run tarmac <command>`:

### Validation, Health Diagnostics & Pre-Flight

```bash
# Validate configuration files against Pydantic schema
uv run tarmac validate

# Audit management account manual prerequisites and operational readiness
uv run tarmac preflight

# Alias for preflight
uv run tarmac doctor

# Output in JSON format for automation / CI/CD
uv run tarmac preflight --json

# Strict mode: fail with exit code 1 if any warnings or failures exist
uv run tarmac preflight --strict

# Check current AWS credentials, caller identity, and Organization status
uv run tarmac info

# Reconcile declared configuration against live AWS environment
uv run tarmac status

# Enable verbose debug logging across any command
uv run tarmac --debug <command>
```

### Phase 1: Organizations & Management Account

```bash
# Enable AWS Organizations with all features, trusted services, and contacts
uv run tarmac org bootstrap

# Update alternate contacts (Billing, Operations, Security)
uv run tarmac org contacts

# Enable centralized root credentials management and privileged sessions
uv run tarmac org root-access

# Scan and purge default VPCs in the Management Account
uv run tarmac org cleanup-vpc
```

### Phase 2: Organizational Units (OUs) & Guardrails (SCPs)

```bash
# Idempotently sync declared OU hierarchy
uv run tarmac ou sync

# List existing OUs
uv run tarmac ou list

# Preview Service Control Policy reconciliation (dry-run)
uv run tarmac org scp plan

# Reconcile and attach declared Service Control Policies
uv run tarmac org scp apply
```

### Phase 3: Declarative Account Factory

```bash
# Preview proposed actions (CREATE, MOVE, NOOP)
uv run tarmac account plan

# Provision missing accounts and move to target OUs
uv run tarmac account apply

# Apply security baselines (default VPC purge, budgets, anomaly alerts)
uv run tarmac account baseline

# Synchronize declared tags with member accounts
uv run tarmac account sync-tags

# Export account metadata and IDs to outputs/inventory.json and outputs/env.sh
uv run tarmac account export
```

### Phase 4: Foundational CloudFormation Deployments

```bash
# Deploy organization-wide CloudTrail stack
uv run tarmac baseline cloudtrail

# Deploy Terraform S3 state bucket + DynamoDB table in Deployment account
uv run tarmac baseline backend

# Deploy Log-Archive and Audit account hardening stacks together
uv run tarmac baseline security

# Deploy individual hardening stacks
uv run tarmac baseline audit
uv run tarmac baseline logs

# Check Cost Anomaly Detection monitors & subscriptions
uv run tarmac baseline anomaly-status
```

### Phase 5: IAM Identity Center (SSO)

```bash
# Check Identity Center instance status and region
uv run tarmac identity status

# Sync permission sets, users, groups, and multi-account assignments
uv run tarmac identity sync
```

### End-to-End Orchestrated Deployment

```bash
# Preview deployment (Dry-Run mode)
uv run tarmac deploy run --dry-run

# Execute full pipeline (runs Phase 0 preflight checks, then Phases 1 to 6)
uv run tarmac deploy run

# Bypass preflight readiness checks if needed
uv run tarmac deploy run --skip-preflight

# Execute a specific phase (0: preflight, 1: org, 2: ou, 3: cloudtrail, 4: accounts, 5: hardening, 6: identity)
uv run tarmac deploy run --phase 0
uv run tarmac deploy run --phase 4
```

---

## Code Quality & Testing (UV Tools)

Run the full automated test suite:
```bash
uv run pytest -v
```

Static type checking with Basedpyright:
```bash
uv run basedpyright
```

Lint Python code with Ruff:
```bash
uv run ruff check .
```

Check code formatting with Ruff:
```bash
uv run ruff format --check .
```

Format code automatically with Ruff:
```bash
uv run ruff format .
```

Lint CloudFormation templates:
```bash
uv run cfn-lint cloudformation/*.yaml
```
