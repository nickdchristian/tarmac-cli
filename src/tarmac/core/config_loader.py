"""Configuration loader and cross-file validator."""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from .config_schema import (
    AccountDef,
    AccountsCatalog,
    IdentityConfigFile,
    OrganizationConfig,
    OUDef,
)
from .exceptions import ConfigurationError
from .templates import resolve_resource_path

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def normalize_account_name(name: str) -> str:
    """Normalize account name for case- and separator-insensitive comparison."""
    return re.sub(r"-+", "-", name.strip().lower().replace(" ", "-").replace("_", "-"))


def get_default_config_dir() -> Path:
    """Return default configuration directory in order of precedence:

    1. TARMAC_CONFIG_DIR environment variable
    2. Path.cwd() / "config" / "local" (local dev/testing overrides)
    3. Path.cwd() / "config" (standard GitOps / production location)
    4. Path.cwd() (if organization.yaml exists in cwd)

    There is deliberately no fallback to the repository's examples/config: a missing config
    directory must fail loudly rather than deploy the sample organization. To use the examples,
    pass --config-dir examples/config explicitly.
    """
    if env_dir := os.environ.get("TARMAC_CONFIG_DIR"):
        return Path(env_dir)

    local_config = Path.cwd() / "config" / "local"
    if local_config.is_dir() and (local_config / "organization.yaml").is_file():
        return local_config

    cwd_config = Path.cwd() / "config"
    if cwd_config.is_dir() and (cwd_config / "organization.yaml").is_file():
        return cwd_config

    if (Path.cwd() / "organization.yaml").is_file():
        return Path.cwd()

    if local_config.is_dir():
        return local_config

    if cwd_config.is_dir():
        return cwd_config

    return cwd_config


def resolve_file(config_dir: Path, base_name: str) -> Path:
    """Resolve a config file, checking for .local.yaml, .yaml and local/<name>.yaml.

    *.yaml.example files are templates and are never loaded as real configuration.
    """
    local_path = config_dir / f"{base_name}.local.yaml"
    if local_path.is_file():
        return local_path

    yaml_path = config_dir / f"{base_name}.yaml"
    if yaml_path.is_file():
        return yaml_path

    nested_local = config_dir / "local" / f"{base_name}.yaml"
    if nested_local.is_file():
        return nested_local

    raise ConfigurationError(
        f"Configuration file not found for '{base_name}'.",
        details=f"Looked for {local_path.name} and {yaml_path.name} in {config_dir}",
    )


def load_yaml(file_path: Path) -> dict[str, Any]:
    try:
        with file_path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise ConfigurationError(f"Failed to parse YAML file: {file_path.name}", details=str(e)) from e


class ConfigBundle:
    """Encapsulates all loaded and validated governance configurations."""

    def __init__(
        self,
        org_config: OrganizationConfig,
        accounts_config: AccountsCatalog,
        identity_config: IdentityConfigFile,
        config_dir: Path,
    ):
        self.org = org_config
        self.accounts = accounts_config
        self.identity = identity_config
        self.config_dir = config_dir

    def validate_cross_references(self) -> list[str]:
        """Validate logical relationships across configuration files."""
        account_names = {a.name for a in self.accounts.accounts}
        errors: list[str] = []
        errors.extend(self._check_ou_uniqueness())
        errors.extend(self._check_account_ous())
        errors.extend(self._check_delegated_admin(account_names))
        errors.extend(self._check_identity_assignments(account_names))
        errors.extend(self._check_inline_policies())
        errors.extend(self._check_scp_policies())
        errors.extend(self._check_scp_targets())
        errors.extend(self._check_baseline_stacks())
        return errors

    def _check_ou_uniqueness(self) -> list[str]:
        """Validate that OU names are unique across the hierarchy (OUService indexes OUs by name)."""
        errors: list[str] = []
        seen: dict[str, str] = {}

        def _walk(ous: list[OUDef]) -> None:
            for ou in ous:
                key = ou.name.strip().lower()
                if key in seen:
                    errors.append(
                        f"Duplicate OU name '{ou.name}' in organization.yaml (conflicts with '{seen[key]}'). "
                        "OU names must be unique across the organization hierarchy."
                    )
                else:
                    seen[key] = ou.name
                if ou.children:
                    _walk(ou.children)

        _walk(self.org.ou_structure)
        return errors

    @staticmethod
    def _collect_ou_names(ous: list[OUDef]) -> set[str]:
        names: set[str] = set()
        for ou in ous:
            names.add(ou.name)
            if ou.children:
                names.update(ConfigBundle._collect_ou_names(ou.children))
        return names

    @staticmethod
    def count_declared_ous(ous: list[OUDef]) -> int:
        """Count total declared OUs recursively across all tree depths."""
        return sum(1 + ConfigBundle.count_declared_ous(ou.children) for ou in ous)

    def _check_account_ous(self) -> list[str]:
        """Validate that all account OUs are defined in organization OU structure."""
        errors: list[str] = []
        valid_ous = self._collect_ou_names(self.org.ou_structure)
        for acct in self.accounts.accounts:
            if acct.ou not in valid_ous:
                errors.append(
                    f"Account '{acct.name}' references undefined OU '{acct.ou}'. "
                    f"Valid OUs are: {sorted(valid_ous)}"
                )
        return errors

    def _check_delegated_admin(self, account_names: set[str]) -> list[str]:
        """Validate that the audit account exists in the accounts catalog when something is delegated to it."""
        errors: list[str] = []
        norm_names = {normalize_account_name(a) for a in account_names}
        sec_cfg = self.org.security_services
        users = [
            name
            for name, on in (
                ("security_services.guardduty", sec_cfg.guardduty.enabled),
                ("security_services.securityhub", sec_cfg.securityhub.enabled),
                (
                    "root_access_management.delegate_to_audit",
                    self.org.root_access_management.delegate_to_audit,
                ),
            )
            if on
        ]
        sec_admin = sec_cfg.audit_account
        if users and normalize_account_name(sec_admin) not in norm_names:
            errors.append(
                f"Audit account '{sec_admin}' (security_services.audit_account) is not in accounts.yaml, but it is "
                f"used by {', '.join(users)}. Add the account, point audit_account at one that exists, or turn "
                f"those off (false). Valid accounts: {sorted(account_names)}"
            )
        return errors

    def _check_identity_assignments(self, account_names: set[str]) -> list[str]:
        """Validate identity center group assignments point to valid permission sets and accounts."""
        errors: list[str] = []
        all_acct_names = account_names.union({"all"})
        valid_perm_sets = {ps.name for ps in self.identity.identity_center.permission_sets}

        for grp in self.identity.identity_center.groups:
            for assignment in grp.assignments:
                if assignment.permission_set not in valid_perm_sets:
                    errors.append(
                        f"Group '{grp.name}' references undefined PermissionSet '{assignment.permission_set}'"
                    )
                for acct_target in assignment.accounts:
                    if acct_target not in all_acct_names:
                        errors.append(
                            f"Group '{grp.name}' assignment references undefined account '{acct_target}'"
                        )
        return errors

    def _check_inline_policies(self) -> list[str]:
        """Check that referenced inline policy files exist."""

        errors: list[str] = []
        for ps in self.identity.identity_center.permission_sets:
            if ps.inline_policy_file:
                try:
                    resolve_resource_path(ps.inline_policy_file, project_root=self.config_dir.parent)
                except ConfigurationError:
                    errors.append(
                        f"Permission set '{ps.name}' inline policy file not found: {ps.inline_policy_file}"
                    )
        return errors

    def _check_scp_policies(self) -> list[str]:
        """Validate SCP policy file existence, syntax, and size limit (5,120 bytes)."""
        errors: list[str] = []
        scp_cfg = self.org.service_control_policies
        for scp in scp_cfg.policies:
            try:
                resolved_path = resolve_resource_path(scp.policy_file, project_root=self.config_dir.parent)
                file_size = resolved_path.stat().st_size
                if file_size > 5120:
                    errors.append(
                        f"SCP '{scp.name}' policy file '{scp.policy_file}' exceeds AWS limit of 5,120 bytes ({file_size} bytes)."
                    )
                content = resolved_path.read_text(encoding="utf-8")
                try:
                    json.loads(content)
                except json.JSONDecodeError as e:
                    errors.append(
                        f"SCP '{scp.name}' policy file '{scp.policy_file}' contains invalid JSON: {e}"
                    )
            except ConfigurationError:
                errors.append(f"SCP '{scp.name}' policy file not found: {scp.policy_file}")
        return errors

    def _check_scp_targets(self) -> list[str]:
        """Validate that every SCP target is the root or a declared OU (matching is case-insensitive)."""
        errors: list[str] = []
        scp_cfg = self.org.service_control_policies
        valid_ous = self._collect_ou_names(self.org.ou_structure)
        valid_lower = {name.lower() for name in valid_ous}
        for scp in scp_cfg.policies:
            for target in scp.targets:
                if target.lower() in ("root", "organization_root") or target.lower() in valid_lower:
                    continue
                errors.append(
                    f"SCP '{scp.name}' targets undefined OU '{target}'. "
                    f"Use 'root' or one of: {sorted(valid_ous)}"
                )
        return errors

    def _check_baseline_stacks(self) -> list[str]:
        """Validate baseline stack names are unique, templates exist and targets are 'root' or declared OUs, none
        of them inside another (a StackSet targeting an OU includes its child OUs)."""
        errors: list[str] = []
        valid_ous = self._collect_ou_names(self.org.ou_structure)
        descendants: dict[str, set[str]] = {}

        def _walk(ous: list[OUDef]) -> None:
            for ou in ous:
                descendants[ou.name] = self._collect_ou_names(ou.children)
                _walk(ou.children)

        _walk(self.org.ou_structure)
        seen: set[str] = set()
        for stack in self.org.baseline_stacks:
            if stack.name.lower() in seen:
                errors.append(f"Baseline stack name '{stack.name}' is used more than once.")
            seen.add(stack.name.lower())
            try:
                resolve_resource_path(stack.template_file, project_root=self.config_dir.parent)
            except ConfigurationError:
                errors.append(f"Baseline stack '{stack.name}' template file not found: {stack.template_file}")
            for target in stack.target_ous:
                if target.lower() != "root" and target not in valid_ous:
                    errors.append(
                        f"Baseline stack '{stack.name}' targets undefined OU '{target}'. "
                        f"Use 'root' or one of: {sorted(valid_ous)}"
                    )
            targets = set(stack.target_ous)
            covered = (
                valid_ous
                if any(t.lower() == "root" for t in targets)
                else set().union(*(descendants.get(t, set()) for t in targets))
            )
            for target in sorted(targets & covered):
                errors.append(
                    f"Baseline stack '{stack.name}' targets '{target}', which another entry in target_ous "
                    "already includes."
                )
        return errors

    def get_backend_account_name(self) -> str | None:
        """Find the declared account name configured to host the Terraform backend."""
        if self.org.terraform_backend.account:
            return self.org.terraform_backend.account
        for acct in self.accounts.accounts:
            if normalize_account_name(acct.name).replace("-", "") == "deployment":
                return acct.name
        return "deployment"

    def get_log_archive_account_name(self) -> str | None:
        """Find the declared account name configured to host centralized log archive."""
        if self.org.cloudtrail.log_archive_account:
            return self.org.cloudtrail.log_archive_account
        for acct in self.accounts.accounts:
            if normalize_account_name(acct.name).replace("-", "") == "logarchive":
                return acct.name
        return "log-archive"

    def get_audit_account_name(self) -> str:
        """The audit account: security_services.audit_account."""
        return self.org.security_services.audit_account

    def resolve_account_id(self, account_name: str | None, live_accounts: dict[str, str]) -> str | None:
        """Resolve a declared account name to its live AWS account ID (case-insensitive)."""
        if not account_name:
            return None
        if account_name in live_accounts:
            return live_accounts[account_name]
        target_norm = normalize_account_name(account_name)
        for name, acct_id in live_accounts.items():
            if normalize_account_name(name) == target_norm:
                return acct_id
        return None

    def get_account(self, account_name: str | None) -> AccountDef | None:
        """Find an AccountDef by name (case-insensitive and hyphen-agnostic)."""
        if not account_name:
            return None
        norm = normalize_account_name(account_name)
        for acct in self.accounts.accounts:
            if normalize_account_name(acct.name) == norm:
                return acct
        return None

    def get_organization_tags(self) -> dict[str, str]:
        """The tags in ``organization.tags``, applied to everything tarmac creates."""
        return dict(self.org.organization.tags)

    def get_cost_allocation_tags(self) -> list[str]:
        """The cost allocation tag keys to activate."""
        return sorted(set(self.org.cost_allocation_tags))

    def get_account_tags(self, account_name: str | None) -> dict[str, str]:
        """Fetch declared tags for an account."""
        acct = self.get_account(account_name)
        return dict(acct.tags) if acct else {}


def _load_model(config_dir: Path, base_name: str, model_cls: type[T], errors: list[str]) -> T | None:
    """Helper to safely parse and instantiate a Pydantic configuration model."""
    try:
        path = resolve_file(config_dir, base_name)
        data = load_yaml(path)
        return model_cls(**data)
    except ValidationError as e:
        errors.append(f"Validation error in {base_name} configuration: {e}")
    except ConfigurationError as e:
        errors.append(str(e))
    except TypeError as e:
        errors.append(f"Error loading {base_name} config: {e}")
    return None


def load_all_configs(config_dir: Path | None = None) -> tuple[ConfigBundle | None, list[str]]:
    """Load and validate all configurations, returning a bundle and any validation errors."""
    resolved_dir = config_dir or get_default_config_dir()
    errors: list[str] = []

    org_config = _load_model(resolved_dir, "organization", OrganizationConfig, errors)
    accounts_config = _load_model(resolved_dir, "accounts", AccountsCatalog, errors)
    identity_config = _load_model(resolved_dir, "identity", IdentityConfigFile, errors)

    if errors or org_config is None or accounts_config is None or identity_config is None:
        return None, errors

    bundle = ConfigBundle(org_config, accounts_config, identity_config, resolved_dir)
    errors.extend(bundle.validate_cross_references())

    return (None if errors else bundle), errors
