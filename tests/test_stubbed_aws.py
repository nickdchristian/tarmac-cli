"""Tests that run destructive/ownership code against botocore Stubber clients.

Unlike MagicMock, Stubber validates every request against the real AWS service model, so a
misspelled operation or parameter (for example `Delete={"Object": ...}`) fails here instead of
mid-teardown against a live account.
"""

from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.exceptions import GovernanceError
from tarmac.services.identity import IdentityService
from tarmac.services.scp import SCPService
from tarmac.services.teardown import TeardownService
from tarmac.services.teardown_s3 import empty_s3_bucket

OWNED = [{"Key": "tarmac:managed-by", "Value": "tarmac"}]


def _client(service: str) -> Any:
    name: Any = service
    return boto3.client(
        name,
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def _mgr(**clients: Any) -> MagicMock:
    mgr = MagicMock(spec=AwsSessionManager)
    mgr.default_region = "us-east-1"
    mgr.get_client.side_effect = lambda svc, **kw: clients[svc.replace("-", "_")]
    return mgr


def test_empty_s3_bucket_validates_requests_against_service_model():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions",
            {
                "Versions": [{"Key": "a", "VersionId": "v1"}],
                "DeleteMarkers": [{"Key": "b", "VersionId": "v2"}],
            },
            {"Bucket": "b"},
        )
        stub.add_response(
            "delete_objects",
            {},
            {
                "Bucket": "b",
                "Delete": {
                    "Objects": [{"Key": "a", "VersionId": "v1"}, {"Key": "b", "VersionId": "v2"}],
                    "Quiet": True,
                },
            },
        )
        stub.add_response("list_objects_v2", {"KeyCount": 0}, {"Bucket": "b"})

        assert empty_s3_bucket(s3, "b") == 2
        stub.assert_no_pending_responses()


_DENIED = {"Errors": [{"Key": "a", "VersionId": "v1", "Code": "AccessDenied", "Message": "locked"}]}
_DELETE = {"Bucket": "b", "Delete": {"Objects": [{"Key": "a", "VersionId": "v1"}], "Quiet": True}}
_BYPASS = {**_DELETE, "BypassGovernanceRetention": True}


def test_empty_s3_bucket_raises_when_s3_reports_per_object_errors():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions", {"Versions": [{"Key": "a", "VersionId": "v1"}]}, {"Bucket": "b"}
        )
        stub.add_response(
            "delete_objects",
            {"Errors": [{"Key": "a", "VersionId": "v1", "Code": "InternalError", "Message": "try again"}]},
            _DELETE,
        )
        with pytest.raises(GovernanceError, match="Failed to delete 1 object"):
            empty_s3_bucket(s3, "b")


def test_empty_s3_bucket_bypasses_governance_retention_when_allowed():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions", {"Versions": [{"Key": "a", "VersionId": "v1"}]}, {"Bucket": "b"}
        )
        stub.add_response("delete_objects", _DENIED, _DELETE)
        stub.add_response("delete_objects", {}, _BYPASS)
        stub.add_response("list_objects_v2", {"Contents": []}, {"Bucket": "b"})
        assert empty_s3_bucket(s3, "b") == 1


def test_empty_s3_bucket_explains_a_lock_it_cannot_bypass():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_response("head_bucket", {}, {"Bucket": "b"})
        stub.add_response(
            "list_object_versions", {"Versions": [{"Key": "a", "VersionId": "v1"}]}, {"Bucket": "b"}
        )
        stub.add_response("delete_objects", _DENIED, _DELETE)
        stub.add_response("delete_objects", _DENIED, _BYPASS)
        with pytest.raises(GovernanceError) as exc:
            empty_s3_bucket(s3, "b")
    assert "COMPLIANCE" in str(exc.value)


def test_delete_retained_bucket_issues_valid_delete_bucket_call():
    s3 = _client("s3")
    svc = TeardownService(_mgr(s3=s3))
    with Stubber(s3) as stub:
        stub.add_response("delete_bucket", {}, {"Bucket": "b"})
        assert svc._delete_retained_bucket(s3, "b", "log-archive", "111122223333") == []
        stub.add_client_error("delete_bucket", "BucketNotEmpty", "not empty", expected_params={"Bucket": "b"})
        items = svc._delete_retained_bucket(s3, "b", "log-archive", "111122223333")
    assert [i.action for i in items] == ["FAILED"]


@pytest.mark.parametrize(
    ("tags", "expected"), [(OWNED, True), ([{"Key": "x", "Value": "y"}], False), ([], False)]
)
def test_scp_ownership_tag_lookup(tags, expected):
    org = _client("organizations")
    svc = SCPService(_mgr(organizations=org))
    with Stubber(org) as stub:
        stub.add_response("list_tags_for_resource", {"Tags": tags}, {"ResourceId": "p-abc12345"})
        assert svc.is_tarmac_managed("p-abc12345") is expected


@pytest.mark.parametrize(("tags", "expected"), [(OWNED, True), ([], False)])
def test_permission_set_ownership_tag_lookup(tags, expected):
    sso = _client("sso-admin")
    ids = _client("identitystore")
    inst = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    ps = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef"
    svc = IdentityService(_mgr(sso_admin=sso, identitystore=ids), preferred_region="us-east-1")
    with Stubber(sso) as stub:
        stub.add_response("list_tags_for_resource", {"Tags": tags}, {"InstanceArn": inst, "ResourceArn": ps})
        assert svc.is_tarmac_managed_permission_set(inst, ps) is expected


@pytest.mark.parametrize(("tags", "expected"), [(OWNED, "arn:t"), ([], "")])
def test_trail_ownership_lookup_uses_valid_cloudtrail_calls(tags, expected):
    trail = _client("cloudtrail")
    with Stubber(trail) as stub:
        stub.add_response("get_trail", {"Trail": {"TrailARN": "arn:t"}}, {"Name": "t"})
        stub.add_response(
            "list_tags",
            {"ResourceTagList": [{"ResourceId": "arn:t", "TagsList": tags}]},
            {"ResourceIdList": ["arn:t"]},
        )
        assert TeardownService._find_tarmac_trail_arn(trail, "t") == expected


def test_empty_s3_bucket_raises_when_bucket_exists_but_is_inaccessible():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error(
            "head_bucket", "403", "Forbidden", http_status_code=403, expected_params={"Bucket": "b"}
        )
        with pytest.raises(GovernanceError, match="cannot be accessed"):
            empty_s3_bucket(s3, "b")


def test_empty_s3_bucket_returns_zero_when_bucket_missing():
    s3 = _client("s3")
    with Stubber(s3) as stub:
        stub.add_client_error(
            "head_bucket", "404", "Not Found", http_status_code=404, expected_params={"Bucket": "b"}
        )
        assert empty_s3_bucket(s3, "b") == 0
