"""Shared state and helpers for the teardown service."""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from ..core.aws_client import AwsSessionManager
from ..core.exceptions import AWS_ERRORS
from ..core.models import TeardownItemReport
from .cloudformation import CloudFormationService

logger = logging.getLogger(__name__)


class _ReportingList(list[TeardownItemReport]):
    """Internal list that immediately notifies a callback when items are appended."""

    def __init__(self, callback: Callable[[TeardownItemReport], None] | None = None) -> None:
        super().__init__()
        self._callback = callback

    def append(self, item: TeardownItemReport) -> None:
        super().append(item)
        if self._callback is not None:
            self._callback(item)


@dataclass
class TeardownReport:
    """Overall summary report of teardown operations."""

    items: list[TeardownItemReport] = field(default_factory=list)
    status: str = "COMPLETED"

    @property
    def deleted_count(self) -> int:
        return sum(1 for i in self.items if i.action in ("DELETED", "EMPTY"))

    @property
    def failed_count(self) -> int:
        return sum(1 for i in self.items if i.action == "FAILED")


class TeardownBase:
    """Session handling, progress reporting and shared lookups for the teardown handlers."""

    def __init__(
        self,
        session_mgr: AwsSessionManager,
        on_progress: Callable[[str], None] | None = None,
        on_item: Callable[[TeardownItemReport], None] | None = None,
        on_phase: Callable[[str], None] | None = None,
    ) -> None:
        self.session_mgr = session_mgr
        self.cfn_service = CloudFormationService(session_mgr)
        self.on_progress = on_progress
        self.on_item = on_item
        self.on_phase = on_phase

    def _new_results_list(self) -> _ReportingList:
        return _ReportingList(self.on_item)

    def _notify_progress(self, message: str) -> None:
        logger.info(message)
        if self.on_progress is not None:
            self.on_progress(message)

    def _notify_phase(self, phase_name: str) -> None:
        logger.info("=== %s ===", phase_name)
        if self.on_phase is not None:
            self.on_phase(phase_name)

    def _has_credentials(self) -> bool:
        """Return False only if a real boto3 session is present without resolved credentials."""
        root_session = getattr(self.session_mgr, "_root_session", None)
        if root_session is not None and callable(getattr(root_session, "get_credentials", None)):
            try:
                return root_session.get_credentials() is not None
            except AWS_ERRORS:
                return False
        return True

    def _get_active_accounts(self) -> dict[str, str]:
        """Fetch all ACTIVE accounts in the organization as {AccountName: AccountId}."""
        if not self._has_credentials():
            return {}
        org_client = self.session_mgr.get_client("organizations")
        accts: dict[str, str] = {}
        try:
            paginator = org_client.get_paginator("list_accounts")
            for page in paginator.paginate():
                for a in page.get("Accounts", []):
                    if isinstance(a, dict) and a.get("Status") in ("ACTIVE", None):
                        accts[a["Name"]] = str(a["Id"])
        except AWS_ERRORS as e:
            logger.debug("Could not query active accounts: %s", e)
        return accts

    def _get_management_account_id(self) -> str:
        """Resolve current management account ID."""
        if not self._has_credentials():
            return ""
        try:
            return str(self.session_mgr.get_caller_identity().get("Account", ""))
        except AWS_ERRORS:
            return ""

    def _delete_retained_bucket(
        self, s3_client: Any, bucket: str, account_name: str, account_id: str
    ) -> list[TeardownItemReport]:
        """Delete a bucket CloudFormation retained. Returns report items only for failures."""
        try:
            s3_client.delete_bucket(Bucket=bucket)
            logger.info("Deleted retained S3 bucket '%s' in %s.", bucket, account_name)
            return []
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchBucket", "NotFound"):
                return []
            message = e.response.get("Error", {}).get("Message", str(e))
        except AWS_ERRORS as e:
            message = str(e)
        logger.warning("Could not delete retained bucket '%s': %s", bucket, message)
        return [
            TeardownItemReport(
                resource_type="S3 Bucket",
                resource_name=bucket,
                account_name=account_name,
                account_id=account_id,
                action="FAILED",
                message=f"Could not delete bucket: {message}",
            )
        ]
