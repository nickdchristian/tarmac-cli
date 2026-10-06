"""Tests for configuration schemas and cross-reference validation."""

import pytest
from pydantic import ValidationError

from tarmac.core.config_loader import load_all_configs
from tarmac.core.config_schema import (
    AccountsCatalog,
    Contact,
    OrgDetails,
)


def test_org_name_lowercase_validation():
    """Verify that organization name must be lowercase alphanumeric with hyphens."""
    assert OrgDetails(name="myorg", domain="example.com").name == "myorg"
    assert OrgDetails(name="my-org-123", domain="example.com").name == "my-org-123"

    with pytest.raises(ValidationError):
        OrgDetails(name="MyOrg", domain="example.com")

    with pytest.raises(ValidationError):
        OrgDetails(name="my_org", domain="example.com")


def test_contact_email_validation():
    """Verify that email addresses must be RFC-compliant."""
    valid_contact = Contact(
        name="Security Team",
        title="SecOps",
        email="security@example.com",
        phone="+1-555-0100",
    )
    assert valid_contact.email == "security@example.com"

    with pytest.raises(ValidationError):
        Contact(
            name="Security Team",
            title="SecOps",
            email="not-an-email",
            phone="+1-555-0100",
        )


def test_load_all_example_configs(sample_config_dir):
    """Verify that the example configuration files in config/ load and validate cleanly."""
    bundle, errors = load_all_configs(sample_config_dir)
    assert not errors, f"Config validation errors: {errors}"
    assert bundle is not None
    assert len(bundle.accounts.accounts) >= 4
    assert len(bundle.identity.identity_center.permission_sets) >= 2


def test_cross_reference_validation_catches_invalid_ou(sample_config_dir):
    """Verify that cross-reference validator catches accounts mapped to undeclared OUs."""
    bundle, errors = load_all_configs(sample_config_dir)
    assert not errors
    assert bundle is not None

    # Intentionally corrupt an account OU
    corrupted_accounts = bundle.accounts.model_dump()
    corrupted_accounts["accounts"].append(
        {
            "name": "OrphanAccount",
            "email": "orphan@example.com",
            "ou": "NonExistentOU",
        }
    )
    new_catalog = AccountsCatalog(**corrupted_accounts)
    bundle.accounts = new_catalog

    cross_errors = bundle.validate_cross_references()
    assert any("references undefined OU 'NonExistentOU'" in e for e in cross_errors)


def test_bundle_declarative_account_resolution(sample_config_dir):
    """Verify that ConfigBundle resolves backend, log archive, and audit accounts declaratively."""
    bundle, errors = load_all_configs(sample_config_dir)
    assert not errors
    assert bundle is not None

    assert bundle.get_backend_account_name() == "deployment"
    assert bundle.get_log_archive_account_name() == "log-archive"
    assert bundle.get_audit_account_name() == "audit"

    live_accounts = {
        "deployment": "111111111111",
        "log-archive": "222222222222",
        "audit": "333333333333",
    }
    assert bundle.resolve_account_id("deployment", live_accounts) == "111111111111"
    assert bundle.resolve_account_id("Deployment", live_accounts) == "111111111111"
    assert bundle.resolve_account_id("Log Archive", live_accounts) == "222222222222"
    assert bundle.resolve_account_id("Log-Archive", live_accounts) == "222222222222"
    assert bundle.resolve_account_id("AUDIT", live_accounts) == "333333333333"
    assert bundle.resolve_account_id("non-existent", live_accounts) is None
    assert bundle.resolve_account_id(None, live_accounts) is None


def test_account_tags_validation():
    from tarmac.core.config_schema import AccountDef

    acct = AccountDef(
        name="test",
        email="test@example.com",
        ou="Workload",
        tags={"Environment": "Dev", "Purpose": "Testing - Sandbox"},
    )
    assert acct.tags["Purpose"] == "Testing - Sandbox"

    with pytest.raises(ValidationError) as excinfo:
        AccountDef(
            name="test",
            email="test@example.com",
            ou="Workload",
            tags={"Purpose": "Testing, Sandbox, and Dev"},
        )
    assert "commas are not permitted by AWS Organizations" in str(excinfo.value)


def test_nested_ou_counting_and_validation():
    from tarmac.core.config_loader import ConfigBundle
    from tarmac.core.config_schema import AccountDef, AccountsCatalog, OrganizationConfig, OUDef

    ous = [
        OUDef(name="Security"),
        OUDef(
            name="Workloads",
            children=[
                OUDef(name="Production"),
                OUDef(name="Staging", children=[OUDef(name="QA")]),
            ],
        ),
    ]

    # Total declared count: Security (1) + Workloads (1) + Production (1) + Staging (1) + QA (1) = 5
    assert ConfigBundle.count_declared_ous(ous) == 5
    names = ConfigBundle._collect_ou_names(ous)
    assert names == {"Security", "Workloads", "Production", "Staging", "QA"}

    # Validate that accounts referencing nested OUs succeed
    catalog = AccountsCatalog(
        accounts=[
            AccountDef(name="prod-app", email="prod@example.com", ou="Production"),
            AccountDef(name="qa-app", email="qa@example.com", ou="QA"),
        ]
    )
    # Empty mock bundle to test _check_account_ous
    mock_bundle = ConfigBundle.__new__(ConfigBundle)
    mock_bundle.org = OrganizationConfig.model_construct(ou_structure=ous)
    mock_bundle.accounts = catalog
    errors = mock_bundle._check_account_ous()
    assert errors == []


def test_budget_notification_emails_validation():
    from tarmac.core.config_schema import BudgetConfig

    valid_emails = [f"user{i}@example.com" for i in range(10)]
    budget = BudgetConfig(
        monthly_limit_usd=100.0,
        alert_threshold_percent=80.0,
        notification_emails=valid_emails,  # pyright: ignore[reportArgumentType]
    )
    assert len(budget.notification_emails) == 10

    import pytest
    from pydantic import ValidationError

    too_many_emails = [f"user{i}@example.com" for i in range(11)]
    with pytest.raises(ValidationError) as excinfo:
        BudgetConfig(
            monthly_limit_usd=100.0,
            alert_threshold_percent=80.0,
            notification_emails=too_many_emails,  # pyright: ignore[reportArgumentType]
        )
    assert "maximum of 10 notification subscribers" in str(excinfo.value)


def test_budget_incident_response_webhook_url_validation():
    import pytest
    from pydantic import ValidationError

    from tarmac.core.config_schema import BudgetConfig

    valid_budget = BudgetConfig(
        monthly_limit_usd=100.0,
        incident_response_webhook_url="https://events.pagerduty.com/integration/xxx",
    )
    assert valid_budget.incident_response_webhook_url == "https://events.pagerduty.com/integration/xxx"
    assert valid_budget.notification_emails == []

    with pytest.raises(ValidationError) as excinfo:
        BudgetConfig(
            monthly_limit_usd=100.0,
            incident_response_webhook_url="http://insecure.example.com/webhook",
        )
    assert "Incident response webhook URL must start with 'https://'" in str(excinfo.value)


def test_security_services_incident_response_webhook_url_validation():
    import pytest
    from pydantic import ValidationError

    from tarmac.core.config_schema import SecurityServicesConfig

    sec = SecurityServicesConfig(
        incident_response_webhook_url="https://hooks.datadoghq.com/api/v2/webhook/sec",
    )
    assert sec.incident_response_webhook_url == "https://hooks.datadoghq.com/api/v2/webhook/sec"

    with pytest.raises(ValidationError) as excinfo:
        SecurityServicesConfig(
            incident_response_webhook_url="http://insecure.datadoghq.com/api/v2/webhook/sec",
        )
    assert "Incident response webhook URL must start with 'https://'" in str(excinfo.value)


def test_custom_core_account_designations_and_clean_baseline(sample_config_dir):
    """Verify custom core account designations in org config and focused baseline schema."""
    from tarmac.core.config_schema import AccountBaselineConfig

    bundle, errors = load_all_configs(sample_config_dir)
    assert not errors
    assert bundle is not None

    # Verify custom designations override convention
    bundle.org.cloudtrail.log_archive_account = "custom-security-archive"
    bundle.org.terraform_backend.account = "custom-ci-deploy"
    bundle.org.root_access_management.delegated_admin_account = "custom-sec-audit"

    assert bundle.get_log_archive_account_name() == "custom-security-archive"
    assert bundle.get_backend_account_name() == "custom-ci-deploy"
    assert bundle.get_audit_account_name() == "custom-sec-audit"

    # Verify AccountBaselineConfig strictly holds operational switches
    baseline = AccountBaselineConfig(
        delete_default_vpc=False,
    )
    assert baseline.delete_default_vpc is False
    assert not hasattr(baseline, "block_s3_public_access")
    assert not hasattr(baseline, "harden_log_archive")
    assert not hasattr(baseline, "harden_audit")
    assert not hasattr(baseline, "deploy_tf_backend")


def test_normalize_account_name_and_resolution(sample_config_dir):
    from tarmac.core.config_loader import normalize_account_name

    assert normalize_account_name("Log-Archive") == "log-archive"
    assert normalize_account_name("Log Archive") == "log-archive"
    assert normalize_account_name("log_archive") == "log-archive"
    assert normalize_account_name("AUDIT") == "audit"

    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None
    live_map = {"Log-Archive": "111111111111", "audit": "222222222222"}
    assert bundle.resolve_account_id("log_archive", live_map) == "111111111111"
    assert bundle.resolve_account_id("LOG ARCHIVE", live_map) == "111111111111"
    assert bundle.resolve_account_id("Audit", live_map) == "222222222222"
    assert bundle.resolve_account_id("non-existent", live_map) is None
    assert bundle.resolve_account_id(None, live_map) is None


def test_cost_allocation_tags_config_schema(sample_config_dir):
    from tarmac.core.config_schema import CostAllocationTagsConfig

    # Default is empty list (no tags assumed unless user defines them)
    cfg = CostAllocationTagsConfig()
    assert cfg.enabled is True
    assert cfg.tags == []

    # Explicit list in tags
    cfg2 = CostAllocationTagsConfig(tags=["Environment", "CostCenter"])
    assert cfg2.tags == ["Environment", "CostCenter"]

    # In bundle
    bundle, _ = load_all_configs(sample_config_dir)
    assert bundle is not None
    tags = bundle.get_cost_allocation_tags()
    assert "Environment" in tags

    # Disabled
    bundle.org.cost_allocation_tags.enabled = False
    assert bundle.get_cost_allocation_tags() == []


def test_bucket_prefix_boundary_validation():
    """Verify S3 bucket prefix rules: 3-40 chars, lowercase alphanumeric + single hyphens."""
    from tarmac.core.config_schema import CloudTrailConfig, TerraformBackendConfig

    # Valid prefixes
    assert CloudTrailConfig(bucket_prefix="my-trail-logs").bucket_prefix == "my-trail-logs"
    assert TerraformBackendConfig(bucket_prefix="tf-state-123").bucket_prefix == "tf-state-123"

    # Too short (< 3)
    with pytest.raises(ValidationError) as exc:
        CloudTrailConfig(bucket_prefix="ab")
    assert "between 3 and 40 characters" in str(exc.value)

    # Too long (> 40)
    with pytest.raises(ValidationError) as exc:
        CloudTrailConfig(bucket_prefix="a" * 41)
    assert "between 3 and 40 characters" in str(exc.value)

    # Starts or ends with hyphen
    with pytest.raises(ValidationError):
        CloudTrailConfig(bucket_prefix="-invalid-prefix")
    with pytest.raises(ValidationError):
        CloudTrailConfig(bucket_prefix="invalid-prefix-")

    # Consecutive hyphens
    with pytest.raises(ValidationError) as exc:
        CloudTrailConfig(bucket_prefix="invalid--prefix")
    assert "consecutive hyphens" in str(exc.value)

    # Uppercase or underscores
    with pytest.raises(ValidationError):
        CloudTrailConfig(bucket_prefix="InvalidPrefix")
    with pytest.raises(ValidationError):
        CloudTrailConfig(bucket_prefix="invalid_prefix")


def test_session_duration_validation():
    """Verify ISO 8601 session duration format PT15M through PT12H."""
    from tarmac.core.config_schema import PermissionSetDef

    # Valid durations
    assert PermissionSetDef(name="Admin", session_duration="PT15M").session_duration == "PT15M"
    assert PermissionSetDef(name="Admin", session_duration="PT1H").session_duration == "PT1H"
    assert PermissionSetDef(name="Admin", session_duration="PT12H").session_duration == "PT12H"

    # Invalid durations (too short, too long, non-ISO)
    with pytest.raises(ValidationError):
        PermissionSetDef(name="Admin", session_duration="PT10M")
    with pytest.raises(ValidationError):
        PermissionSetDef(name="Admin", session_duration="PT13H")
    with pytest.raises(ValidationError):
        PermissionSetDef(name="Admin", session_duration="1 hour")


def test_accounts_catalog_rejects_duplicates():
    """Verify AccountsCatalog rejects duplicate account names or duplicate root emails."""
    from tarmac.core.config_schema import AccountDef, AccountsCatalog

    # Duplicate account names
    with pytest.raises(ValidationError) as exc:
        AccountsCatalog(
            accounts=[
                AccountDef(name="Audit", email="audit1@example.com", ou="Security"),
                AccountDef(name="audit", email="audit2@example.com", ou="Security"),
            ]
        )
    assert "Duplicate account name" in str(exc.value)

    # Duplicate emails
    with pytest.raises(ValidationError) as exc:
        AccountsCatalog(
            accounts=[
                AccountDef(name="Audit1", email="same@example.com", ou="Security"),
                AccountDef(name="Audit2", email="same@example.com", ou="Security"),
            ]
        )
    assert "Duplicate account root email" in str(exc.value)


def test_normalize_account_name_whitespace_and_hyphen_collapsing():
    """Verify normalize_account_name strips whitespace and collapses multiple consecutive hyphens."""
    from tarmac.core.config_loader import normalize_account_name

    assert normalize_account_name("  Log-Archive  ") == "log-archive"
    assert normalize_account_name("log---archive") == "log-archive"
    assert normalize_account_name("  Security _ Audit  ") == "security-audit"
