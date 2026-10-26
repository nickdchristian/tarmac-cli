"""`tarmac import`: a live organization becomes valid Tarmac configuration."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml
from botocore.exceptions import ClientError
from typer.testing import CliRunner

from tarmac.cli.main import app
from tarmac.core.config_loader import load_all_configs
from tarmac.core.placeholders import find_placeholder_values
from tarmac.services.importer import ImportService


def _client(pages: dict[str, list[dict[str, Any]]], **calls: Any) -> MagicMock:
    client = MagicMock()

    def get_paginator(name: str) -> MagicMock:
        pag = MagicMock()
        pag.paginate.side_effect = lambda **kw: pages.get(name, [{}])
        return pag

    client.get_paginator.side_effect = get_paginator
    for method, value in calls.items():
        getattr(client, method).side_effect = value if callable(value) else None
        if not callable(value):
            getattr(client, method).return_value = value
    return client


def _ou_pages(**kw: Any) -> list[dict[str, Any]]:
    parent = kw["ParentId"]
    tree = {
        "r-1": [{"Id": "ou-sec", "Name": "Security"}, {"Id": "ou-prod", "Name": "Production"}],
        "ou-sec": [],
        "ou-prod": [{"Id": "ou-app", "Name": "App"}],
        "ou-app": [],
    }
    return [{"OrganizationalUnits": tree[parent]}]


class FakeSession:
    default_region = "us-east-1"

    def get_caller_identity(self) -> dict[str, str]:
        return {"Account": "111", "Arn": "arn:aws:sts::111:assumed-role/Reader/me"}

    def __init__(self, with_sso: bool = True):
        self.with_sso = with_sso
        org = MagicMock()
        org.describe_organization.return_value = {
            "Organization": {"Id": "o-abc", "MasterAccountId": "111", "MasterAccountEmail": "me@acme-corp.io"}
        }
        org.list_roots.return_value = {"Roots": [{"Id": "r-1"}]}
        accounts = [
            {"Id": "111", "Name": "mgmt", "Email": "me@acme-corp.io", "Status": "ACTIVE"},
            {"Id": "222", "Name": "Audit", "Email": "me+audit@acme-corp.io", "Status": "ACTIVE"},
            {"Id": "333", "Name": "gone", "Email": "me+gone@acme-corp.io", "Status": "SUSPENDED"},
            {"Id": "444", "Name": "loose", "Email": "me+loose@acme-corp.io", "Status": "ACTIVE"},
        ]
        parents = {"222": "ou-sec", "444": "r-1"}
        org.list_parents.side_effect = lambda ChildId: {"Parents": [{"Id": parents[ChildId]}]}
        policy_content = json.dumps({"Version": "2012-10-17", "Statement": []})

        def paginator(name: str) -> MagicMock:
            pag = MagicMock()
            if name == "list_organizational_units_for_parent":
                pag.paginate.side_effect = _ou_pages
            else:
                data = {
                    "list_accounts": [{"Accounts": accounts}],
                    "list_tags_for_resource": [
                        {
                            "Tags": [
                                {"Key": "Environment", "Value": "Core"},
                                {"Key": "tarmac:managed-by", "Value": "tarmac"},
                            ]
                        }
                    ],
                    "list_policies": [
                        {
                            "Policies": [
                                {"Id": "p-full", "Name": "FullAWSAccess", "AwsManaged": True},
                                {
                                    "Id": "p-1",
                                    "Name": "Deny Regions",
                                    "Description": "d",
                                    "AwsManaged": False,
                                },
                            ]
                        }
                    ],
                    "list_targets_for_policy": [
                        {
                            "Targets": [
                                {"Type": "ORGANIZATIONAL_UNIT", "TargetId": "ou-prod"},
                                {"Type": "ACCOUNT", "TargetId": "222", "Name": "Audit"},
                            ]
                        }
                    ],
                    "list_aws_service_access_for_organization": [
                        {"EnabledServicePrincipals": [{"ServicePrincipal": "iam.amazonaws.com"}]}
                    ],
                    "list_delegated_administrators": [
                        {"DelegatedAdministrators": [{"Id": "222", "Name": "Audit"}]}
                    ],
                }.get(name, [{}])
                pag.paginate.side_effect = lambda **kw: data
            return pag

        org.get_paginator.side_effect = paginator
        org.describe_policy.return_value = {"Policy": {"Content": policy_content}}
        self.clients: dict[str, MagicMock] = {"organizations": org}

        account = MagicMock()
        account.get_alternate_contact.side_effect = [
            {
                "AlternateContact": {
                    "Name": "Fin",
                    "Title": "CFO",
                    "EmailAddress": "fin@acme-corp.io",
                    "PhoneNumber": "+15550001",
                }
            },
            ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "none"}}, "GetAlternateContact"
            ),
            ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "none"}}, "GetAlternateContact"
            ),
        ]
        self.clients["account"] = account

        trail = MagicMock()
        trail.describe_trails.return_value = {
            "trailList": [{"Name": "old-org-trail", "IsOrganizationTrail": True}]
        }
        self.clients["cloudtrail"] = trail

        cfn = MagicMock()
        stacks = MagicMock()
        stacks.paginate.return_value = [
            {"StackSummaries": [{"StackName": "acme-organization-scps"}, {"StackName": "unrelated"}]}
        ]
        cfn.get_paginator.return_value = stacks
        self.clients["cloudformation"] = cfn
        self.clients["sso-admin"] = MagicMock()
        self.clients["identitystore"] = MagicMock()
        if not with_sso:
            self.clients["sso-admin"].list_instances.return_value = {"Instances": []}

    def get_client(self, service: str, region_name: str | None = None) -> MagicMock:
        return self.clients[service]


@pytest.fixture
def imported(tmp_path: Path):
    session = FakeSession(with_sso=False)
    svc = ImportService(session, "us-east-1")  # type: ignore[arg-type]
    report = svc.discover_and_write(tmp_path / "cfg", include_identity=False)
    return tmp_path / "cfg", report


def test_root_access_is_only_delegated_when_it_already_is(tmp_path: Path, monkeypatch):
    """Import describes the organization: it must not make the next deploy register a delegated administrator."""
    monkeypatch.setattr(ImportService, "_iam_delegated_admins", lambda self: set())
    ImportService(FakeSession(with_sso=False), "us-east-1").discover_and_write(  # type: ignore[arg-type]
        tmp_path / "cfg", include_identity=False
    )
    org = yaml.safe_load((tmp_path / "cfg" / "organization.yaml").read_text())
    assert org["root_access_management"]["delegate_to_audit"] is False


def test_writes_files_that_describe_the_organization(imported):
    cfg, report = imported
    org = yaml.safe_load((cfg / "organization.yaml").read_text())
    accounts = yaml.safe_load((cfg / "accounts.yaml").read_text())

    assert org["organization"]["name"] == "acme"  # taken from the existing Tarmac stacks
    assert org["organization"]["domain"] == "acme-corp.io"
    assert org["organization"]["delete_default_vpc"] is False
    assert [o["name"] for o in org["ou_structure"]] == ["Production", "Security"]
    assert org["ou_structure"][0]["children"][0]["name"] == "App"
    assert org["root_access_management"]["delegate_to_audit"] is True
    assert org["contacts"]["billing"]["email"] == "fin@acme-corp.io"
    assert org["contacts"]["operations"]["phone"] == "+1234567890"  # the sample number, so validate flags it
    assert [a["name"] for a in accounts["accounts"]] == ["Audit"]
    assert accounts["accounts"][0]["ou"] == "Security"
    assert accounts["accounts"][0]["tags"] == {"Environment": "Core"}  # ownership tag is not imported
    assert report.ou_count == 3


def test_scp_content_and_targets_are_imported(imported):
    cfg, report = imported
    org = yaml.safe_load((cfg / "organization.yaml").read_text())
    scps = org["service_control_policies"]["policies"]

    assert [s["name"] for s in scps] == ["Deny Regions"]  # AWS-managed FullAWSAccess is left out
    assert scps[0]["targets"] == ["Production"]
    assert json.loads((cfg / scps[0]["policy_file"]).read_text())["Version"] == "2012-10-17"
    assert any("account" in t and "Deny Regions" in t for t in report.todos)


def test_report_flags_what_needs_a_human(imported):
    _, report = imported
    text = "\n".join(report.todos)

    assert "old-org-trail" in text
    assert any("loose" in s for s in report.skipped_accounts)
    assert any("gone" in s for s in report.skipped_accounts)
    assert "operations alternate contact" in text


def test_generated_config_loads(imported):
    _, report = imported
    assert not any("policy file" in e or "Duplicate" in e for e in report.validation_errors)


def test_a_relative_config_dir_is_validated_where_it_was_written(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    svc = ImportService(FakeSession(with_sso=False), "us-east-1")  # type: ignore[arg-type]
    report = svc.discover_and_write(Path("my-org"), include_identity=False)
    assert not any("not found" in e for e in report.validation_errors)


def test_replaced_files_are_kept_as_bak_only_when_they_change(tmp_path: Path):
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "organization.yaml").write_text("x: 1")
    svc = ImportService(FakeSession(with_sso=False), "us-east-1")  # type: ignore[arg-type]
    svc.discover_and_write(cfg, include_identity=False)
    assert (cfg / "organization.yaml.bak").read_text() == "x: 1"
    assert svc.report.backups == [cfg / "organization.yaml.bak"]

    again = ImportService(FakeSession(with_sso=False), "us-east-1")  # type: ignore[arg-type]
    again.discover_and_write(cfg, include_identity=False)
    assert again.report.backups == []
    assert (cfg / "organization.yaml.bak").read_text() == "x: 1"


def test_name_option_overrides_stack_prefix(tmp_path: Path):
    svc = ImportService(FakeSession(with_sso=False), "us-east-1")  # type: ignore[arg-type]
    svc.discover_and_write(tmp_path, name="custom", include_identity=False)
    assert yaml.safe_load((tmp_path / "organization.yaml").read_text())["organization"]["name"] == "custom"


def test_cli_command_is_registered_and_reports(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("tarmac.cli.importer.AwsSessionManager", lambda region_name=None: FakeSession(False))
    result = CliRunner().invoke(app, ["import", "-c", str(tmp_path / "out"), "--no-identity"])
    assert "Imported org o-abc" in result.output
    assert (tmp_path / "out" / "organization.yaml").is_file()


def _fake_identity_center(monkeypatch) -> None:
    """Identity Center with users alice-admin and breakglass, and group Admins (alice-admin, Admin on Audit)."""
    sso, store = MagicMock(), MagicMock()
    pages = {
        "list_users": [
            {
                "Users": [
                    {
                        "UserId": "u1",
                        "UserName": "alice-admin",
                        "Emails": [{"Value": "a@acme-corp.io", "Primary": True}],
                        "Name": {"GivenName": "Alice", "FamilyName": "A"},
                    },
                    {"UserId": "u2", "UserName": "breakglass", "Emails": [{"Value": "b@acme-corp.io"}]},
                ]
            }
        ],
        "list_groups": [{"Groups": [{"GroupId": "g1", "DisplayName": "Admins", "Description": "x"}]}],
        "list_group_memberships": [{"GroupMemberships": [{"MemberId": {"UserId": "u1"}}]}],
        "list_permission_sets": [{"PermissionSets": ["arn:ps1"]}],
        "list_managed_policies_in_permission_set": [
            {"AttachedManagedPolicies": [{"Arn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
        ],
        "list_accounts_for_provisioned_permission_set": [{"AccountIds": ["222"]}],
        "list_account_assignments": [
            {"AccountAssignments": [{"PrincipalType": "GROUP", "PrincipalId": "g1"}]}
        ],
    }

    def paginator(name: str) -> MagicMock:
        pag = MagicMock()
        pag.paginate.side_effect = lambda **kw: pages[name]
        return pag

    sso.get_paginator.side_effect = paginator
    store.get_paginator.side_effect = paginator
    sso.describe_permission_set.return_value = {
        "PermissionSet": {"Name": "Admin", "SessionDuration": "PT4H", "Description": "d"}
    }
    sso.get_inline_policy_for_permission_set.return_value = {
        "InlinePolicy": json.dumps({"Version": "2012-10-17", "Statement": []})
    }

    class FakeIdentity:
        region = "us-east-1"
        sso_client = sso
        identitystore_client = store

        def __init__(self, *a: Any, **k: Any) -> None: ...

        def get_instance_details(self) -> tuple[str, str]:
            return "arn:instance", "d-123"

    monkeypatch.setattr("tarmac.services.importer.IdentityService", FakeIdentity)


def test_identity_center_is_imported(monkeypatch, tmp_path: Path):
    session = FakeSession()
    _fake_identity_center(monkeypatch)
    report = ImportService(session, "us-east-1").discover_and_write(tmp_path / "cfg")  # type: ignore[arg-type]

    ident = yaml.safe_load((tmp_path / "cfg" / "identity.yaml").read_text())["identity_center"]
    assert ident["admin_user"]["username"] == "alice-admin"
    assert ident["breakglass_user"]["username"] == "breakglass"
    assert ident["groups"][0]["members"] == ["alice-admin"]
    assert ident["groups"][0]["assignments"] == [{"permission_set": "Admin", "accounts": ["Audit"]}]
    assert ident["permission_sets"][0]["inline_policy_file"] == "policies/permission-sets/admin.json"
    assert "_id" not in ident["groups"][0]
    assert report.permission_sets == ["Admin"]


def test_scp_attached_only_to_an_account_is_not_imported(tmp_path: Path):
    session = FakeSession(with_sso=False)
    original = session.clients["organizations"].get_paginator.side_effect

    def paginator(name: str) -> MagicMock:
        if name == "list_targets_for_policy":
            pag = MagicMock()
            pag.paginate.side_effect = lambda **kw: [
                {"Targets": [{"Type": "ACCOUNT", "TargetId": "222", "Name": "Audit"}]}
            ]
            return pag
        return original(name)

    session.clients["organizations"].get_paginator.side_effect = paginator
    report = ImportService(session, "us-east-1").discover_and_write(tmp_path / "cfg", include_identity=False)  # type: ignore[arg-type]

    org = yaml.safe_load((tmp_path / "cfg" / "organization.yaml").read_text())
    assert (
        org["service_control_policies"]["policies"] == []
    )  # importing it would have attached it to the root
    assert not (tmp_path / "cfg" / "policies" / "scp").exists()
    assert any("not attached to the root or an OU" in t for t in report.todos)


def test_placeholder_contacts_are_flagged_by_validate(imported, monkeypatch):
    cfg, _ = imported
    monkeypatch.chdir(cfg)
    bundle, _ = load_all_configs(cfg)
    assert bundle is not None
    assert any("phone" in p for p in find_placeholder_values(bundle))


def test_cli_exits_nonzero_when_the_result_does_not_validate(monkeypatch, tmp_path: Path):
    session = FakeSession(False)
    session.clients["organizations"].describe_policy.return_value = {"Policy": {"Content": "{}"}}
    monkeypatch.setattr("tarmac.cli.importer.AwsSessionManager", lambda region_name=None: session)
    monkeypatch.setattr(
        ImportService, "_validate", lambda self, d: self.report.validation_errors.append("boom")
    )
    result = CliRunner().invoke(app, ["import", "-c", str(tmp_path / "out"), "--no-identity"])
    assert result.exit_code == 1
    assert "boom" in result.output


def test_the_cli_says_which_files_it_kept_as_bak(monkeypatch, tmp_path: Path):
    (tmp_path / "organization.yaml").write_text("x: 1")
    monkeypatch.setattr("tarmac.cli.importer.AwsSessionManager", lambda region_name=None: FakeSession(False))
    result = CliRunner().invoke(app, ["import", "-c", str(tmp_path), "--no-identity"])
    assert "Kept the previous version" in result.output
    assert (tmp_path / "organization.yaml.bak").exists()


def test_assignments_outside_accounts_yaml_are_reported_not_written(monkeypatch, tmp_path: Path):
    """The management account and root-level accounts are not in accounts.yaml, so assigning to them would not validate."""
    session = FakeSession()
    sso, store = MagicMock(), MagicMock()
    pages = {
        "list_users": [
            {"Users": [{"UserId": "u1", "UserName": "alice-admin", "Emails": [{"Value": "a@acme-corp.io"}]}]}
        ],
        "list_groups": [{"Groups": [{"GroupId": "g1", "DisplayName": "Admins"}]}],
        "list_group_memberships": [{"GroupMemberships": []}],
        "list_permission_sets": [{"PermissionSets": ["arn:ps1"]}],
        "list_managed_policies_in_permission_set": [{"AttachedManagedPolicies": []}],
        "list_accounts_for_provisioned_permission_set": [{"AccountIds": ["222", "111", "444"]}],
        "list_account_assignments": [
            {
                "AccountAssignments": [
                    {"PrincipalType": "GROUP", "PrincipalId": "g1"},
                    {"PrincipalType": "USER", "PrincipalId": "u1"},
                ]
            }
        ],
    }

    def paginator(name: str) -> MagicMock:
        pag = MagicMock()
        pag.paginate.side_effect = lambda **kw: pages[name]
        return pag

    sso.get_paginator.side_effect = paginator
    store.get_paginator.side_effect = paginator
    sso.describe_permission_set.return_value = {"PermissionSet": {"Name": "Admin", "SessionDuration": "PT4H"}}
    sso.get_inline_policy_for_permission_set.return_value = {}

    class FakeIdentity:
        region = "us-east-1"
        sso_client = sso
        identitystore_client = store

        def __init__(self, *a: Any, **k: Any) -> None: ...

        def get_instance_details(self) -> tuple[str, str]:
            return "arn:inst", "d-1"

    monkeypatch.setattr("tarmac.services.importer.IdentityService", FakeIdentity)
    monkeypatch.chdir(tmp_path)
    report = ImportService(session, "us-east-1").discover_and_write(tmp_path / "cfg")  # type: ignore[arg-type]

    ident = yaml.safe_load((tmp_path / "cfg" / "identity.yaml").read_text())["identity_center"]
    assert ident["groups"][0]["assignments"] == [{"permission_set": "Admin", "accounts": ["Audit"]}]
    assert not any("undefined account" in e for e in report.validation_errors)
    text = "\n".join(report.todos)
    assert "Left out 2 group assignments on accounts not in accounts.yaml" in text
    assert "Left out 3 permission-set assignments made directly to users" in text


def test_tarmacs_own_trail_is_not_flagged_as_a_conflict(tmp_path: Path):
    session = FakeSession(with_sso=False)
    session.clients["cloudtrail"].describe_trails.return_value = {
        "trailList": [
            {"Name": "old-org-trail", "IsOrganizationTrail": True},
            {"Name": "acme-trail", "IsOrganizationTrail": True},
        ]
    }
    cfn = session.clients["cloudformation"]
    cfn.describe_stack_resources.return_value = {
        "StackResources": [{"ResourceType": "AWS::CloudTrail::Trail", "PhysicalResourceId": "acme-trail"}]
    }
    report = ImportService(session, "us-east-1").discover_and_write(  # type: ignore[arg-type]
        tmp_path / "cfg", include_identity=False
    )
    org = yaml.safe_load((tmp_path / "cfg" / "organization.yaml").read_text())

    cfn.describe_stack_resources.assert_called_once_with(StackName="acme-organization-cloudtrail")
    assert org["cloudtrail"]["trail_name"] == "acme-trail"
    trail_todos = [t for t in report.todos if "existing organization trail" in t]
    assert len(trail_todos) == 1
    assert "old-org-trail" in trail_todos[0]
    assert "acme-trail" not in trail_todos[0]


def test_no_trail_warning_when_only_tarmacs_trail_exists(tmp_path: Path):
    session = FakeSession(with_sso=False)
    session.clients["cloudtrail"].describe_trails.return_value = {
        "trailList": [
            {
                "Name": "acme-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111:trail/acme-trail",
                "IsOrganizationTrail": True,
            }
        ]
    }
    session.clients["cloudformation"].describe_stack_resources.return_value = {
        "StackResources": [
            {
                "ResourceType": "AWS::CloudTrail::Trail",
                "PhysicalResourceId": "arn:aws:cloudtrail:us-east-1:111:trail/acme-trail",
            }
        ]
    }
    report = ImportService(session, "us-east-1").discover_and_write(  # type: ignore[arg-type]
        tmp_path / "cfg", include_identity=False
    )

    assert not any("existing organization trail" in t for t in report.todos)


def test_imported_groups_are_recorded_as_managed_once_the_inventory_exists(monkeypatch, tmp_path: Path):
    session = FakeSession()
    _fake_identity_center(monkeypatch)
    session.clients["cloudformation"].describe_stacks.return_value = {
        "Stacks": [{"Outputs": [{"OutputKey": "BucketName", "OutputValue": "acme-tarmac-inventory"}]}]
    }
    s3 = MagicMock()
    s3.get_object.side_effect = ClientError({"Error": {"Code": "NoSuchKey", "Message": "none"}}, "GetObject")
    session.clients["s3"] = s3

    report = ImportService(session, "us-east-1").discover_and_write(tmp_path / "cfg")  # type: ignore[arg-type]

    assert report.adopted_groups == ["Admins"]
    stored = json.loads(s3.put_object.call_args.kwargs["Body"])
    assert stored["entries"]["identity-group"] == {"Admins": {"imported": True}}


def test_imported_groups_are_not_recorded_before_the_inventory_exists(monkeypatch, tmp_path: Path):
    session = FakeSession()
    _fake_identity_center(monkeypatch)
    session.clients["cloudformation"].describe_stacks.side_effect = ClientError(
        {"Error": {"Code": "ValidationError", "Message": "Stack acme-tarmac-inventory does not exist"}},
        "DescribeStacks",
    )

    report = ImportService(session, "us-east-1").discover_and_write(tmp_path / "cfg")  # type: ignore[arg-type]

    assert report.adopted_groups == []
    assert any("not recorded as managed" in todo for todo in report.todos)


def test_scim_groups_keep_their_members_in_the_idp(monkeypatch, tmp_path: Path):
    session = FakeSession()
    _fake_identity_center(monkeypatch)
    service = ImportService(session, "us-east-1")  # type: ignore[arg-type]
    real_list_groups = service._list_groups

    def scim_groups(store: Any, store_id: str) -> list[dict[str, Any]]:
        return [{**g, "_external": True} for g in real_list_groups(store, store_id)]

    monkeypatch.setattr(service, "_list_groups", scim_groups)
    report = service.discover_and_write(tmp_path / "cfg")

    ident = yaml.safe_load((tmp_path / "cfg" / "identity.yaml").read_text())["identity_center"]
    assert ident["groups"][0]["members"] == []
    assert "_external" not in ident["groups"][0]
    assert report.adopted_groups == []
    assert any("provisioned by your identity provider" in todo for todo in report.todos)
