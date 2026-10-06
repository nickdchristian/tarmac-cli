"""Tests for Tarmac multi-tier tagging hierarchy and validation."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_loader import ConfigBundle
from tarmac.core.config_schema import (
    AccountDef,
    AccountsCatalog,
    Contact,
    ContactsConfig,
    IdentityCenterConfig,
    IdentityConfigFile,
    OrganizationConfig,
    OrgDetails,
    UserDef,
)
from tarmac.core.tagging import (
    MAX_AWS_TAGS,
    merge_tags,
    to_cfn_tags,
    validate_tag_key,
    validate_tag_value,
    validate_tags,
)
from tarmac.services.cloudformation import CloudFormationService


def test_validate_tag_key_valid():
    valid_keys = [
        "Environment",
        "CostCenter",
        "app:name",
        "dept/subdept",
        "team_lead-1",
        "contact@domain.com",
        "tier.level",
        "key=value",
        "with+plus",
    ]
    for key in valid_keys:
        validate_tag_key(key)


def test_validate_tag_key_invalid():
    with pytest.raises(ValueError, match="must be between 1 and 128"):
        validate_tag_key("")

    with pytest.raises(ValueError, match="must be between 1 and 128"):
        validate_tag_key("a" * 129)

    with pytest.raises(ValueError, match="reserved prefix 'aws:'"):
        validate_tag_key("aws:createdBy")

    with pytest.raises(ValueError, match="reserved prefix 'aws:'"):
        validate_tag_key("AWS:tag")

    with pytest.raises(ValueError, match="invalid characters"):
        validate_tag_key("invalid$key")


def test_validate_tag_value_valid():
    assert validate_tag_value("Env", "Production") == "Production"
    assert validate_tag_value("Count", 123) == "123"
    assert validate_tag_value("Empty", "") == ""


def test_validate_tag_value_invalid():
    with pytest.raises(ValueError, match="must not exceed 256"):
        validate_tag_value("Key", "v" * 257)

    with pytest.raises(ValueError, match="invalid characters"):
        validate_tag_value("Key", "bad$value#")


def test_validate_tags_limit():
    valid_dict = {f"Key{i}": f"Val{i}" for i in range(MAX_AWS_TAGS)}
    validated = validate_tags(valid_dict)
    assert len(validated) == MAX_AWS_TAGS

    invalid_dict = {f"Key{i}": f"Val{i}" for i in range(MAX_AWS_TAGS + 1)}
    with pytest.raises(ValueError, match="maximum of 50 tags"):
        validate_tags(invalid_dict)


def test_merge_tags_hierarchy():
    res1 = merge_tags()
    assert res1 == {"ManagedBy": "tarmac"}

    org_tags = {"Environment": "Production", "CostCenter": "1001", "Owner": "FinOps"}
    res2 = merge_tags(org_tags)
    assert res2 == {
        "ManagedBy": "tarmac",
        "Environment": "Production",
        "CostCenter": "1001",
        "Owner": "FinOps",
    }

    account_tags = {"CostCenter": "2002", "ComplianceTier": "PCI-DSS"}
    res3 = merge_tags(org_tags, account_tags)
    assert res3 == {
        "ManagedBy": "tarmac",
        "Environment": "Production",
        "CostCenter": "2002",
        "Owner": "FinOps",
        "ComplianceTier": "PCI-DSS",
    }

    custom_tags = {"ManagedBy": "custom-tool", "Environment": "Staging"}
    res4 = merge_tags(org_tags, account_tags, custom_tags)
    assert res4["ManagedBy"] == "custom-tool"
    assert res4["Environment"] == "Staging"
    assert res4["CostCenter"] == "2002"
    assert res4["ComplianceTier"] == "PCI-DSS"


def test_merge_tags_limit_exceeded():
    dict1 = {f"OrgKey{i}": f"V{i}" for i in range(30)}
    dict2 = {f"AcctKey{i}": f"V{i}" for i in range(30)}
    with pytest.raises(ValueError, match="exceed AWS limit of 50 tags"):
        merge_tags(dict1, dict2)


def test_to_cfn_tags():
    tags = {"Environment": "Production", "ManagedBy": "tarmac"}
    cfn_tags = to_cfn_tags(tags)
    assert {"Key": "Environment", "Value": "Production"} in cfn_tags
    assert {"Key": "ManagedBy", "Value": "tarmac"} in cfn_tags


def test_config_bundle_tag_resolution(tmp_path: Path):
    org = OrganizationConfig(
        organization=OrgDetails(
            name="acme",
            domain="acme.com",
            primary_region="us-east-1",
            tags={"OrgLevel": "True", "CostCenter": "Global-100"},
        ),
        contacts=ContactsConfig(
            billing=Contact(name="B", title="B", email="b@a.com", phone="+15550001"),
            operations=Contact(name="O", title="O", email="o@a.com", phone="+15550002"),
            security=Contact(name="S", title="S", email="s@a.com", phone="+15550003"),
        ),
        tags={"TopLevel": "Yes"},
    )
    accounts = AccountsCatalog(
        accounts=[
            AccountDef(
                name="audit",
                email="audit@acme.com",
                ou="Security",
                tags={"AccountLevel": "AuditAcct", "CostCenter": "Sec-200"},
            )
        ],
        tags={"CatalogLevel": "CatalogDefault"},
    )
    identity = IdentityConfigFile(
        identity_center=IdentityCenterConfig(
            admin_user=UserDef(username="admin", email="admin@acme.com"),
            breakglass_user=UserDef(username="breakglass", email="breakglass@acme.com"),
        )
    )

    bundle = ConfigBundle(
        org_config=org,
        accounts_config=accounts,
        identity_config=identity,
        config_dir=tmp_path,
    )

    org_tags = bundle.get_organization_tags()
    assert org_tags["OrgLevel"] == "True"
    assert org_tags["TopLevel"] == "Yes"
    assert org_tags["CatalogLevel"] == "CatalogDefault"
    assert org_tags["CostCenter"] == "Global-100"

    acct_tags = bundle.get_account_tags("audit")
    assert acct_tags["AccountLevel"] == "AuditAcct"
    assert acct_tags["CostCenter"] == "Sec-200"

    resolved = bundle.get_resolved_tags(
        account_name="audit",
        custom_tags={"InvocationTag": "ManualRun"},
    )
    assert resolved["ManagedBy"] == "tarmac"
    assert resolved["OrgLevel"] == "True"
    assert resolved["CatalogLevel"] == "CatalogDefault"
    assert resolved["AccountLevel"] == "AuditAcct"
    assert resolved["CostCenter"] == "Sec-200"  # Account overrides Org
    assert resolved["InvocationTag"] == "ManualRun"


def test_cloudformation_service_merges_tags_in_deploy_stack(tmp_path: Path):
    template = tmp_path / "test.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

    mock_session_mgr = MagicMock()
    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.side_effect = [
        ClientError(
            {"Error": {"Message": "Stack does not exist", "Code": "ValidationError"}}, "DescribeStacks"
        ),
        {"Stacks": [{"Outputs": []}]},
    ]
    mock_waiter = MagicMock()
    mock_cfn.get_waiter.return_value = mock_waiter

    service = CloudFormationService(mock_session_mgr)
    report = service.deploy_stack(
        cfn_client=mock_cfn,
        stack_name="test-stack",
        template_file=template,
        org_tags={"Environment": "Prod", "CostCenter": "100"},
        account_tags={"CostCenter": "200", "Tier": "App"},
        tags={"CustomTag": "Val"},
        dry_run=False,
    )

    assert report.status == "SUCCEEDED"
    mock_cfn.create_stack.assert_called_once()
    _, kwargs = mock_cfn.create_stack.call_args
    passed_tags = {t["Key"]: t["Value"] for t in kwargs["Tags"]}

    assert passed_tags["ManagedBy"] == "tarmac"
    assert passed_tags["Environment"] == "Prod"
    assert passed_tags["CostCenter"] == "200"  # account overrides org
    assert passed_tags["Tier"] == "App"
    assert passed_tags["CustomTag"] == "Val"


def test_parse_cli_tags_valid():
    from tarmac.core.tagging import parse_cli_tags

    raw = ["Env=Prod", "CostCenter=CC-100", "App=Web=Server", " SpacedKey = Spaced Value "]
    tags = parse_cli_tags(raw)
    assert tags == {
        "Env": "Prod",
        "CostCenter": "CC-100",
        "App": "Web=Server",
        "SpacedKey": "Spaced Value",
    }


def test_parse_cli_tags_empty_or_none():
    from tarmac.core.tagging import parse_cli_tags

    assert parse_cli_tags(None) == {}
    assert parse_cli_tags([]) == {}


def test_parse_cli_tags_invalid_format():
    from tarmac.core.tagging import parse_cli_tags

    with pytest.raises(ValueError, match="Invalid tag format 'NoEquals'"):
        parse_cli_tags(["NoEquals"])

    with pytest.raises(ValueError, match=r"Tag key cannot be empty in '=EmptyKey'"):
        parse_cli_tags(["=EmptyKey"])


def test_parse_cli_tags_invalid_characters():
    from tarmac.core.tagging import parse_cli_tags

    with pytest.raises(ValueError, match="cannot start with reserved prefix 'aws:'"):
        parse_cli_tags(["aws:forbidden=value"])

    with pytest.raises(ValueError, match="contains invalid characters"):
        parse_cli_tags(["Invalid,Key=value"])
