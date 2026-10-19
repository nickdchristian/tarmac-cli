.PHONY: help sync check lint format typecheck cfn-lint validate test build

help: ## Display available developer commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

sync: ## Sync environment dependencies from uv.lock
	uv sync --frozen

check: lint format typecheck cfn-lint validate test ## Run all CI quality gates locally

lint: ## Lint Python code with Ruff
	uv run ruff check .

format: ## Verify code formatting with Ruff
	uv run ruff format --check .

typecheck: ## Run static type checking with Basedpyright
	uv run basedpyright

cfn-lint: ## Lint CloudFormation templates
	uv run cfn-lint cloudformation/*.yaml src/tarmac/templates/cloudformation/*.yaml

validate: ## Validate example governance configurations
	uv run tarmac validate --config-dir examples/config

test: ## Run Pytest suite
	uv run pytest

build: ## Build distributions and verify metadata with Twine
	uv build
	uv run twine check dist/*
