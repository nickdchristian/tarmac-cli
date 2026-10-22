"""Log level policy: -v shows recorded actions, progress chatter stays at debug, failures are not hidden at INFO."""

import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from tarmac.core.config_schema import AnomalyDetectionConfig, OUDef
from tarmac.services.baseline import BaselineService
from tarmac.services.ou import OUService
from tarmac.services.scaffold import scaffold_project
from tarmac.services.teardown_s3 import empty_s3_bucket


def _audit(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [r.data for r in caplog.records if getattr(r, "event", None) == "audit"]  # type: ignore[attr-defined]


def _info_plain(caplog: pytest.LogCaptureFixture) -> list[str]:
    """INFO+ records that are not audit events."""
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.INFO and getattr(r, "event", None) != "audit"
    ]


def test_creating_an_ou_logs_one_info_record_the_audit_event(caplog):
    caplog.set_level(logging.DEBUG, logger="tarmac")
    mgr = MagicMock()
    client = MagicMock()
    mgr.get_client.return_value = client
    client.list_roots.return_value = {"Roots": [{"Id": "r-1"}]}
    client.get_paginator.return_value.paginate.return_value = [{"OrganizationalUnits": []}]
    client.create_organizational_unit.return_value = {"OrganizationalUnit": {"Id": "ou-1", "Name": "Sec"}}

    OUService(mgr).sync_ou_structure([OUDef(name="Sec")])

    assert _info_plain(caplog) == []
    assert len(_audit(caplog)) == 1
    assert any("Creating OU" in r.getMessage() and r.levelno == logging.DEBUG for r in caplog.records)


def test_failed_member_anomaly_monitor_is_a_warning_not_info(caplog):
    caplog.set_level(logging.INFO, logger="tarmac")
    mgr = MagicMock()
    ce = MagicMock()
    mgr.get_member_client.return_value = ce
    ce.get_anomaly_monitors.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "Op"
    )
    cfg = AnomalyDetectionConfig(enabled=True, threshold_usd=10, notification_emails=["a@example.com"])

    BaselineService(mgr)._setup_member_anomaly_monitor("123456789012", "Dev", cfg)

    [record] = [r for r in caplog.records if "anomaly monitor" in r.getMessage()]
    assert record.levelno == logging.WARNING


def test_scaffold_records_created_and_kept_files(caplog, tmp_path: Path):
    caplog.set_level(logging.INFO, logger="tarmac.audit")
    scaffold_project(tmp_path)
    created = _audit(caplog)
    assert created
    assert {e["outcome"] for e in created} == {"succeeded"}
    assert all(e["resource"].startswith("file:") for e in created)

    caplog.clear()
    scaffold_project(tmp_path)
    assert {e["outcome"] for e in _audit(caplog)} == {"skipped"}


def test_bucket_purge_is_audited_with_the_object_count(caplog):
    caplog.set_level(logging.INFO, logger="tarmac")
    s3 = MagicMock()
    s3.get_paginator.return_value.paginate.return_value = [
        {"Versions": [{"Key": "a", "VersionId": "1"}], "DeleteMarkers": []}
    ]
    s3.delete_objects.return_value = {}

    assert empty_s3_bucket(s3, "bkt") == 1

    [ev] = _audit(caplog)
    assert (ev["action"], ev["resource"]) == ("purge", "S3 Bucket:bkt")
    assert ev["details"]["objects_deleted"] == 1
