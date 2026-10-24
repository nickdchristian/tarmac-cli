"""GuardDuty findings export from the audit detectors to the log archive's findings bucket."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import yaml

from tarmac.core.config_schema import CloudTrailConfig, GuardDutyConfig, SecurityServicesConfig
from tarmac.services import guardduty_export
from tarmac.services.guardduty_export import FindingsExport, findings_export, reconcile_findings_export
from tarmac.services.stack_parameters import log_archive_parameters

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "src/tarmac/templates/cloudformation/log-archive-hardening.yaml"
BUCKET = "arn:aws:s3:::acme-guardduty-findings-1a2b3c4d"
KEY = "arn:aws:kms:eu-west-1:222233334444:key/abc"
ON = FindingsExport("acme", BUCKET, KEY, "222233334444")
OFF = FindingsExport("acme")


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_multi_constructor("!", lambda loader, suffix, node: {suffix: _value(loader, node)})


def _value(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


def _gd(*destinations: dict[str, str]) -> MagicMock:
    gd = MagicMock()
    gd.list_publishing_destinations.return_value = {
        "Destinations": [
            {"DestinationId": f"d{i}", "DestinationType": "S3"} for i in range(len(destinations))
        ]
    }
    gd.describe_publishing_destination.side_effect = lambda DetectorId, DestinationId: {
        "DestinationProperties": destinations[int(DestinationId[1:])]
    }
    return gd


def _wanted() -> dict[str, str]:
    return {"DestinationArn": BUCKET, "KmsKeyArn": KEY, "ExpectedBucketOwner": "222233334444"}


def _bundle(guardduty: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        org=SimpleNamespace(
            organization=SimpleNamespace(name="acme"),
            security_services=SecurityServicesConfig(guardduty=GuardDutyConfig(**(guardduty or {}))),
            cloudtrail=CloudTrailConfig(),
        ),
        get_log_archive_account_name=lambda: "log-archive",
        resolve_account_id=lambda name, accts: accts.get(name),
    )


def test_creates_the_export_when_the_detector_has_none():
    gd = _gd()
    assert reconcile_findings_export(gd, "det", ON, "eu-west-1")[0] == "CREATE"
    gd.create_publishing_destination.assert_called_once_with(
        DetectorId="det", DestinationType="S3", DestinationProperties=_wanted()
    )


def test_an_export_described_without_its_bucket_owner_still_matches():
    gd = _gd({"DestinationArn": BUCKET, "KmsKeyArn": KEY})
    assert reconcile_findings_export(gd, "det", ON, "eu-west-1")[0] == "NO CHANGE"
    gd.update_publishing_destination.assert_not_called()


def test_leaves_a_matching_export_alone():
    gd = _gd(_wanted())
    assert reconcile_findings_export(gd, "det", ON, "eu-west-1")[0] == "NO CHANGE"
    gd.create_publishing_destination.assert_not_called()
    gd.update_publishing_destination.assert_not_called()


def test_repoints_tarmacs_own_export_when_it_changes():
    gd = _gd({**_wanted(), "KmsKeyArn": "arn:aws:kms:eu-west-1:1:key/old"})
    assert reconcile_findings_export(gd, "det", ON, "eu-west-1") == (
        "UPDATE",
        "acme-guardduty-findings-1a2b3c4d",
    )
    gd.update_publishing_destination.assert_called_once_with(
        DetectorId="det", DestinationId="d0", DestinationProperties=_wanted()
    )


def test_an_export_the_organization_set_up_is_left_alone():
    gd = _gd({"DestinationArn": "arn:aws:s3:::their-findings", "KmsKeyArn": "arn:aws:kms:eu-west-1:1:key/x"})
    action, detail = reconcile_findings_export(gd, "det", ON, "eu-west-1")
    assert (action, detail) == ("NO CHANGE", "already exports to their-findings, which tarmac leaves alone")
    gd.update_publishing_destination.assert_not_called()
    gd.create_publishing_destination.assert_not_called()


def test_turning_export_off_deletes_only_tarmacs_destination():
    gd = _gd(_wanted())
    assert reconcile_findings_export(gd, "det", OFF, "eu-west-1")[0] == "DELETE"
    gd.delete_publishing_destination.assert_called_once_with(DetectorId="det", DestinationId="d0")

    other = _gd({"DestinationArn": "arn:aws:s3:::someone-elses-bucket"})
    assert reconcile_findings_export(other, "det", OFF, "eu-west-1")[0] == "NO CHANGE"
    other.delete_publishing_destination.assert_not_called()


def test_dry_run_changes_nothing():
    for gd, export, action in ((_gd(), ON, "CREATE"), (_gd(_wanted()), OFF, "DELETE")):
        assert reconcile_findings_export(gd, "det", export, "eu-west-1", dry_run=True)[0] == action
        gd.create_publishing_destination.assert_not_called()
        gd.delete_publishing_destination.assert_not_called()


def test_ignores_non_s3_destinations():
    gd = MagicMock()
    gd.list_publishing_destinations.return_value = {
        "Destinations": [{"DestinationId": "x", "DestinationType": "OTHER"}]
    }
    assert reconcile_findings_export(gd, "det", ON, "eu-west-1")[0] == "CREATE"
    gd.describe_publishing_destination.assert_not_called()


def test_audit_account_is_passed_to_the_log_archive_only_when_exporting():
    def param(guardduty: dict) -> str:
        bundle = _bundle(guardduty)
        params = log_archive_parameters(bundle, "o-abc1234567", "", "111122223333")  # type: ignore[arg-type]
        return params["GuardDutyFindingsAccountId"]

    assert param({"enabled": True, "export_findings": True}) == "111122223333"
    assert param({"enabled": True}) == ""
    assert param({"enabled": False, "export_findings": True}) == ""


def test_findings_export_reads_the_log_archive_outputs(monkeypatch):
    accts = {"log-archive": "222233334444"}
    outputs = {"GuardDutyFindingsBucketArn": BUCKET, "GuardDutyFindingsKmsKeyArn": KEY}
    cfn = MagicMock()
    cfn.return_value._fetch_stack_outputs.return_value = outputs
    monkeypatch.setattr(guardduty_export, "CloudFormationService", cfn)
    on = _bundle({"enabled": True, "export_findings": True})

    assert findings_export(MagicMock(), _bundle({"enabled": True}), "eu-west-1", accts) == OFF  # type: ignore[arg-type]
    assert findings_export(MagicMock(), on, "eu-west-1", accts) == ON  # type: ignore[arg-type]
    assert findings_export(MagicMock(), on, "eu-west-1", {}) is None  # type: ignore[arg-type]
    cfn.return_value._fetch_stack_outputs.return_value = {}
    assert findings_export(MagicMock(), on, "eu-west-1", accts) is None  # type: ignore[arg-type]


def test_template_creates_the_bucket_and_key_for_the_audit_detectors():
    doc = yaml.load(TEMPLATE.read_text(), Loader=_Loader)
    res = doc["Resources"]
    assert doc["Parameters"]["GuardDutyFindingsAccountId"]["Default"] == ""
    # GuardDuty only exports to SSE-KMS, so the key exists for it even when enable_kms is off.
    assert res["LogArchiveKmsKey"]["Condition"] == "CreateKmsKey"
    assert doc["Conditions"]["CreateKmsKey"] == {
        "Or": [{"Condition": "UseKmsEncryption"}, {"Condition": "ExportGuardDutyFindings"}]
    }
    for name in ("GuardDutyFindingsBucket", "GuardDutyFindingsBucketPolicy"):
        assert res[name]["Condition"] == "ExportGuardDutyFindings"
    assert res["GuardDutyFindingsBucket"]["DeletionPolicy"] == "Retain"

    statements = res["GuardDutyFindingsBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    allows = [s for s in statements if s["Effect"] == "Allow"]
    assert {s["Action"] for s in allows} == {"s3:GetBucketLocation", "s3:PutObject"}
    for statement in allows:
        assert statement["Principal"] == {"Service": "guardduty.amazonaws.com"}
        assert statement["Condition"]["StringEquals"]["aws:SourceAccount"] == {
            "Ref": "GuardDutyFindingsAccountId"
        }

    key_statements = res["LogArchiveKmsKey"]["Properties"]["KeyPolicy"]["Statement"]
    guardduty = next(
        s["If"][1] for s in key_statements if "If" in s and s["If"][0] == "ExportGuardDutyFindings"
    )
    assert guardduty["Action"] == "kms:GenerateDataKey"
    assert set(doc["Outputs"]) >= {"GuardDutyFindingsBucketArn", "GuardDutyFindingsKmsKeyArn"}


def test_buckets_already_in_the_log_archive_stack_stay_when_their_feature_is_off():
    """Both are retained with fixed names: dropped from the stack, they could never be created again."""
    off = _bundle({"enabled": True})
    params = log_archive_parameters(off, "o-abc1234567", "999988887777", "111122223333")  # type: ignore[arg-type]
    assert (params["EnableConfigDelivery"], params["GuardDutyFindingsAccountId"]) == ("false", "")

    kept = {"ConfigLogsBucket", "GuardDutyFindingsBucket"}
    params = log_archive_parameters(off, "o-abc1234567", "999988887777", "111122223333", kept=kept)  # type: ignore[arg-type]
    assert params["EnableConfigDelivery"] == "true"
    assert params["ManagementAccountId"] == "999988887777"
    assert params["GuardDutyFindingsAccountId"] == "111122223333"
