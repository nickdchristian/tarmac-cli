# Contributing to Tarmac CLI

Thank you for your interest in contributing to **Tarmac CLI** (`tarmac-cli`)!

## Prerequisites

- **Python:** `>=3.11` (local development defaults to `3.13`)
- **[uv](https://docs.astral.sh/uv/):** Used for dependency management, lockfile resolution, and isolated command execution.

## Local Development Setup

1. Clone the repository and sync dependencies from `uv.lock`:
   ```bash
   git clone https://github.com/nickdchristian/tarmac-cli.git
   cd tarmac-cli
   uv sync --frozen
   ```

2. (Optional) Install pre-commit hooks:
   ```bash
   uvx pre-commit install
   ```

## Running Quality Gates

We provide a `Makefile` so you can run the exact same checks locally that execute in GitHub Actions CI:

```bash
# Run all quality gates (lint, format, typecheck, cfn-lint, validate, test)
make check
```

Or run individual checks directly with `uv`:

```bash
# 1. Lint & Format (Ruff)
uv run ruff check .
uv run ruff format --check .

# 2. Static Type Checking (Basedpyright)
uv run basedpyright

# 3. CloudFormation Template Linting (cfn-lint)
uv run cfn-lint cloudformation/*.yaml src/tarmac/templates/cloudformation/*.yaml

# 4. Validate Example Governance Manifests
uv run tarmac validate --config-dir examples/config

# 5. Run Pytest Suite
uv run pytest
```

## Pull Request & Commit Guidelines

- **Conventional Commits:** All Pull Request titles are validated in CI using [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `refactor:`, `test:`, `perf:`, `build:`, `style:`, `revert:`).
- **Release Automation:** Versioning and `CHANGELOG.md` generation are managed automatically by **Release Please** on merge to `main`. Do not manually bump versions in `pyproject.toml` or `CHANGELOG.md`.
- **Template Parity:** If you modify CloudFormation templates in `cloudformation/` or SCP policies in `policies/scp/`, ensure the corresponding packaged templates under `src/tarmac/templates/` are kept in sync.
- **No Live AWS Calls in Unit Tests:** All tests under `tests/` must mock `AwsSessionManager` or boto3 clients and must never require live AWS credentials or network access.
