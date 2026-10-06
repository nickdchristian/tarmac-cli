"""Tests for template and policy resolution and export."""

from pathlib import Path

import pytest

from tarmac.core.exceptions import ConfigurationError
from tarmac.core.templates import (
    export_bundled_templates,
    read_resource_text,
    resolve_resource_path,
)
from tarmac.services.scaffold import scaffold_project


def test_resolve_resource_path_bundled_cloudtrail():
    """Verify resolving bundled CloudTrail template."""
    path = resolve_resource_path("cloudformation/organization-cloudtrail.yaml")
    assert path.exists()
    assert "organization-cloudtrail.yaml" in str(path)


def test_resolve_resource_path_bundled_single_filename():
    """Verify resolving by template filename alone."""
    path = resolve_resource_path("organization-cloudtrail.yaml")
    assert path.exists()
    assert path.name == "organization-cloudtrail.yaml"


def test_resolve_resource_path_bundled_scp():
    """Verify resolving bundled SCP policy."""
    path = resolve_resource_path("policies/scp/deny-leave-organization.json")
    assert path.exists()
    assert "deny-leave-organization.json" in str(path)


def test_resolve_resource_path_local_override(tmp_path: Path):
    """Verify local project override takes precedence over bundled templates."""
    custom_dir = tmp_path / "cloudformation"
    custom_dir.mkdir(parents=True)
    custom_file = custom_dir / "organization-cloudtrail.yaml"
    custom_file.write_text("AWSTemplateFormatVersion: '2010-09-09'\nDescription: Custom")

    resolved = resolve_resource_path("cloudformation/organization-cloudtrail.yaml", project_root=tmp_path)
    assert resolved == custom_file
    assert read_resource_text("cloudformation/organization-cloudtrail.yaml", project_root=tmp_path) == (
        "AWSTemplateFormatVersion: '2010-09-09'\nDescription: Custom"
    )


def test_resolve_resource_path_not_found(tmp_path: Path):
    """Verify ConfigurationError raised when resource does not exist anywhere."""
    with pytest.raises(ConfigurationError) as exc_info:
        resolve_resource_path("non-existent-template.yaml", project_root=tmp_path)
    assert "Resource file not found" in str(exc_info.value)


def test_export_bundled_templates(tmp_path: Path):
    """Verify exporting bundled templates to a target directory."""
    exported = export_bundled_templates(tmp_path)
    assert len(exported) >= 7
    assert (tmp_path / "cloudformation" / "organization-cloudtrail.yaml").exists()
    assert (tmp_path / "cloudformation" / "terraform-backend.yaml").exists()
    assert (tmp_path / "policies" / "scp" / "deny-leave-organization.json").exists()
    assert (tmp_path / "policies" / "scp" / "foundational-guardrails.json").exists()


def test_scaffold_project_with_templates(tmp_path: Path):
    """Verify scaffold_project with with_templates=True creates both config and templates."""
    config_dir = tmp_path / "config"
    created, skipped = scaffold_project(config_dir, with_templates=True)
    assert len(created) >= 10  # 3 configs + 7+ templates/policies
    assert (config_dir / "organization.yaml").exists()
    assert (tmp_path / "cloudformation" / "organization-cloudtrail.yaml").exists()
    assert (tmp_path / "policies" / "scp" / "deny-leave-organization.json").exists()
    assert (tmp_path / "policies" / "scp" / "foundational-guardrails.json").exists()


def test_bundled_cloudformation_templates_are_valid_yaml():
    """Verify all bundled CloudFormation YAML templates are valid and have standard CFN structure."""
    import yaml

    class CfnYamlLoader(yaml.SafeLoader):
        pass

    def cfn_tag_constructor(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag_suffix: loader.construct_scalar(node)}
        elif isinstance(node, yaml.SequenceNode):
            return {tag_suffix: loader.construct_sequence(node)}
        elif isinstance(node, yaml.MappingNode):
            return {tag_suffix: loader.construct_mapping(node)}

    CfnYamlLoader.add_multi_constructor("!", cfn_tag_constructor)

    cfn_templates = [
        "cloudformation/organization-cloudtrail.yaml",
        "cloudformation/log-archive-hardening.yaml",
        "cloudformation/audit-account-hardening.yaml",
        "cloudformation/account-budget.yaml",
        "cloudformation/terraform-backend.yaml",
    ]

    for rel_path in cfn_templates:
        p = resolve_resource_path(rel_path)
        assert p.exists(), f"Template {rel_path} does not exist"
        content = yaml.load(p.read_text(encoding="utf-8"), Loader=CfnYamlLoader)
        assert isinstance(content, dict), f"Template {rel_path} root is not a mapping"
        assert content.get("AWSTemplateFormatVersion") == "2010-09-09", (
            f"Template {rel_path} missing valid AWSTemplateFormatVersion"
        )
        assert "Resources" in content and isinstance(content["Resources"], dict), (
            f"Template {rel_path} missing Resources mapping"
        )
        assert len(content["Resources"]) > 0, f"Template {rel_path} has empty Resources"
        for res_id, res_def in content["Resources"].items():
            assert "Type" in res_def, f"Resource {res_id} in {rel_path} missing Type"
            assert str(res_def["Type"]).startswith("AWS::"), (
                f"Resource {res_id} in {rel_path} has invalid Type '{res_def['Type']}'"
            )


def test_alerting_templates_support_optional_email_and_webhooks():
    """Verify that both budget and audit hardening templates support optional emails and HTTPS webhooks."""
    import yaml

    class CfnYamlLoader(yaml.SafeLoader):
        pass

    def cfn_tag_constructor(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag_suffix: loader.construct_scalar(node)}
        elif isinstance(node, yaml.SequenceNode):
            return {tag_suffix: loader.construct_sequence(node)}
        elif isinstance(node, yaml.MappingNode):
            return {tag_suffix: loader.construct_mapping(node)}

    CfnYamlLoader.add_multi_constructor("!", cfn_tag_constructor)

    targets = [
        (
            "cloudformation/account-budget.yaml",
            "NotificationEmail",
            "BudgetEmailSubscription",
            "BudgetWebhookSubscription",
        ),
        (
            "cloudformation/audit-account-hardening.yaml",
            "AlertEmail",
            "SecurityAlertsSubscription",
            "SecurityWebhookSubscription",
        ),
    ]

    for rel_path, email_param, email_sub, webhook_sub in targets:
        p = resolve_resource_path(rel_path)
        content = yaml.load(p.read_text(encoding="utf-8"), Loader=CfnYamlLoader)
        params = content.get("Parameters", {})
        assert email_param in params
        assert params[email_param].get("Default") == ""
        assert "IncidentResponseWebhookUrl" in params
        assert params["IncidentResponseWebhookUrl"].get("Default") == ""

        conditions = content.get("Conditions", {})
        assert "HasWebhookEndpoint" in conditions

        resources = content.get("Resources", {})
        assert email_sub in resources
        assert webhook_sub in resources
        assert resources[webhook_sub]["Properties"]["Protocol"] == "https"


def test_bundled_scp_policies_are_valid_json_and_under_size_limit():
    """Verify all bundled SCP JSON policies are valid JSON, contain Statement, and fit in the AWS 5120-byte limit."""
    import json

    policies = [
        "policies/scp/deny-leave-organization.json",
        "policies/scp/deny-member-root.json",
        "policies/scp/foundational-guardrails.json",
    ]

    for rel_path in policies:
        p = resolve_resource_path(rel_path)
        assert p.exists(), f"Policy {rel_path} does not exist"
        raw_text = p.read_text(encoding="utf-8")
        byte_size = len(raw_text.encode("utf-8"))
        assert byte_size <= 5120, f"Policy {rel_path} exceeds AWS 5120 byte limit: {byte_size} bytes"

        data = json.loads(raw_text)
        assert isinstance(data, dict), f"Policy {rel_path} root is not a JSON object"
        assert "Statement" in data, f"Policy {rel_path} missing Statement block"
        assert isinstance(data["Statement"], list), f"Policy {rel_path} Statement is not a list"
        assert len(data["Statement"]) > 0, f"Policy {rel_path} has empty Statement"


def test_template_parity_and_export_consistency():
    """Verify 100% parity between root and packaged templates, and consistent stack exports."""
    from pathlib import Path

    import yaml

    class CfnYamlLoader(yaml.SafeLoader):
        pass

    def cfn_tag_constructor(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return {tag_suffix: loader.construct_scalar(node)}
        elif isinstance(node, yaml.SequenceNode):
            return {tag_suffix: loader.construct_sequence(node)}
        elif isinstance(node, yaml.MappingNode):
            return {tag_suffix: loader.construct_mapping(node)}

    CfnYamlLoader.add_multi_constructor("!", cfn_tag_constructor)

    template_names = [
        "account-budget.yaml",
        "audit-account-hardening.yaml",
        "log-archive-hardening.yaml",
        "organization-cloudtrail.yaml",
        "terraform-backend.yaml",
    ]

    root_dir = Path(__file__).resolve().parent.parent / "cloudformation"
    pkg_dir = Path(__file__).resolve().parent.parent / "src" / "tarmac" / "templates" / "cloudformation"

    for name in template_names:
        root_file = root_dir / name
        pkg_file = pkg_dir / name
        assert root_file.exists(), f"Missing root template: {root_file}"
        assert pkg_file.exists(), f"Missing packaged template: {pkg_file}"
        assert root_file.read_text(encoding="utf-8") == pkg_file.read_text(encoding="utf-8"), (
            f"Templates out of sync: {name}"
        )

        content = yaml.load(root_file.read_text(encoding="utf-8"), Loader=CfnYamlLoader)
        outputs = content.get("Outputs", {})
        assert outputs, f"Template {name} should declare Outputs"
        for out_name, out_spec in outputs.items():
            assert "Export" in out_spec, f"Output {out_name} in {name} missing Export block"
            export_name = out_spec["Export"].get("Name", {})
            sub_str = export_name.get("Sub", "") if isinstance(export_name, dict) else str(export_name)
            assert "${AWS::StackName}-" in sub_str, (
                f"Output {out_name} export name '{sub_str}' in {name} not prefixed with '${{AWS::StackName}}-'"
            )

    # Specific assertion for terraform-backend OrgName support
    tf_content = yaml.load(
        (root_dir / "terraform-backend.yaml").read_text(encoding="utf-8"), Loader=CfnYamlLoader
    )
    assert "OrgName" in tf_content["Parameters"]
    assert "HasOrgName" in tf_content["Conditions"]


def test_scp_policy_parity():
    """Verify 100% parity between root policies/scp and packaged src/tarmac/templates/policies/scp."""
    root_scp_dir = Path(__file__).resolve().parent.parent / "policies" / "scp"
    pkg_scp_dir = Path(__file__).resolve().parent.parent / "src" / "tarmac" / "templates" / "policies" / "scp"

    root_files = {p.name for p in root_scp_dir.glob("*.json")}
    pkg_files = {p.name for p in pkg_scp_dir.glob("*.json")}
    assert root_files == pkg_files, f"SCP file sets differ: {root_files} vs {pkg_files}"

    for filename in root_files:
        root_text = (root_scp_dir / filename).read_text(encoding="utf-8")
        pkg_text = (pkg_scp_dir / filename).read_text(encoding="utf-8")
        assert root_text == pkg_text, f"SCP policy content mismatch for {filename}"
