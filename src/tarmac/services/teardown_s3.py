"""S3 helpers used by teardown: emptying versioned buckets and removing orphaned buckets."""

import logging
from collections.abc import Callable
from typing import Any

from botocore.exceptions import ClientError

from ..core.audit import Outcome, audit
from ..core.exceptions import GovernanceError
from ..core.text import plural

logger = logging.getLogger(__name__)


def normalize_bucket_name(name_or_arn: str) -> str:
    """Extract clean bucket name from S3 bucket name or ARN."""
    clean = name_or_arn.strip()
    if clean.startswith("arn:aws"):
        clean = clean.split(":")[-1].split("/")[-1]
    return clean


def _delete_s3_batch(s3_client: Any, bucket_name: str, batch: list[dict[str, str]]) -> int:
    """Delete one batch of objects; return how many were actually deleted.

    With Quiet=True S3 only reports failures, so inspect Errors rather than assuming success.

    Objects under Object Lock governance retention come back as AccessDenied. Teardown is an explicit,
    confirmed destruction, so those are retried once with BypassGovernanceRetention (which needs
    s3:BypassGovernanceRetention). Compliance-mode locks cannot be bypassed by anyone and fail with a clear message.
    """
    resp = s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": batch, "Quiet": True})
    errors = resp.get("Errors", [])
    denied = [e for e in errors if e.get("Code") == "AccessDenied"]
    if denied:
        retry = [{k: e[k] for k in ("Key", "VersionId") if e.get(k)} for e in denied]
        retried = s3_client.delete_objects(
            Bucket=bucket_name,
            Delete={"Objects": retry, "Quiet": True},
            BypassGovernanceRetention=True,
        )
        retry_errors = retried.get("Errors", [])
        bypassed = len(retry) - len(retry_errors)
        if bypassed > 0:
            audit(
                "purge",
                f"S3 Bucket:{bucket_name}",
                Outcome.SUCCEEDED,
                f"Deleted {plural(bypassed, 'object version')} in '{bucket_name}' by bypassing Object Lock governance retention",
                bypassed_governance_retention=bypassed,
            )
        errors = [e for e in errors if e.get("Code") != "AccessDenied"] + retry_errors
    if errors:
        first = errors[0]
        hint = (
            " If the bucket uses Object Lock in COMPLIANCE mode, nobody can delete these versions until their "
            "retention period ends."
            if first.get("Code") == "AccessDenied"
            else ""
        )
        raise GovernanceError(
            f"Failed to delete {plural(len(errors), 'object')} from bucket '{bucket_name}'.",
            details=f"{first.get('Code', 'Unknown')}: {first.get('Message', '')} (key: {first.get('Key', '')}){hint}",
        )
    return len(batch)


def _purge_object_versions(
    s3_client: Any, bucket_name: str, on_progress: Callable[[str], None] | None
) -> int:
    """Delete every object version and delete marker (versioned and version-suspended buckets)."""
    deleted = 0
    try:
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            to_delete: list[dict[str, str]] = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in (*page.get("Versions", []), *page.get("DeleteMarkers", []))
            ]
            for i in range(0, len(to_delete), 1000):
                deleted += _delete_s3_batch(s3_client, bucket_name, to_delete[i : i + 1000])
                if on_progress is not None and deleted > 0 and deleted % 1000 == 0:
                    on_progress(f"Purged {deleted} items from bucket '{bucket_name}' so far...")
    except ClientError as e:
        raise GovernanceError(
            f"Failed to purge object versions in bucket '{bucket_name}'.", details=str(e)
        ) from e
    return deleted


def _purge_unversioned_objects(
    s3_client: Any, bucket_name: str, on_progress: Callable[[str], None] | None, already_deleted: int
) -> int:
    """Delete plain objects (fallback for buckets that never had versioning)."""
    deleted = 0
    try:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            for i in range(0, len(keys), 1000):
                deleted += _delete_s3_batch(s3_client, bucket_name, keys[i : i + 1000])
                total = already_deleted + deleted
                if on_progress is not None and total > 0 and total % 1000 == 0:
                    on_progress(f"Purged {total} items from bucket '{bucket_name}' so far...")
    except ClientError as e:
        raise GovernanceError(f"Failed to purge objects in bucket '{bucket_name}'.", details=str(e)) from e
    return deleted


def empty_s3_bucket(
    s3_client: Any,
    bucket_name: str,
    on_progress: Callable[[str], None] | None = None,
) -> int:
    """Purge all object versions, delete markers, and unversioned objects from an S3 bucket.

    Returns the total number of deleted objects and delete markers.
    Raises GovernanceError if S3 refuses to delete objects (Object Lock, bucket policy, KMS, ...).
    """
    bucket_name = normalize_bucket_name(bucket_name)
    if not bucket_name:
        return 0
    total_deleted = 0
    try:
        s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            logger.debug("Bucket '%s' does not exist.", bucket_name)
            return 0
        raise GovernanceError(
            f"Bucket '{bucket_name}' exists but cannot be accessed, so it was not purged.", details=str(e)
        ) from e

    msg = f"Purging all contents, versions, and delete markers from bucket '{bucket_name}'..."
    logger.debug(msg)
    if on_progress is not None:
        on_progress(msg)

    total_deleted += _purge_object_versions(s3_client, bucket_name, on_progress)
    total_deleted += _purge_unversioned_objects(s3_client, bucket_name, on_progress, total_deleted)

    if total_deleted > 0:
        audit(
            "purge",
            f"S3 Bucket:{bucket_name}",
            Outcome.SUCCEEDED,
            f"Permanently deleted {plural(total_deleted, 'object version')} from S3 bucket '{bucket_name}'",
            objects_deleted=total_deleted,
        )
    return total_deleted
