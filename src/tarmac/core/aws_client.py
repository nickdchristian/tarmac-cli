"""AWS Session and Cross-Account STS AssumeRole Manager."""

import logging
import os
import threading
import time
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .exceptions import AWSAuthenticationError

logger = logging.getLogger(__name__)


class AwsSessionManager:
    """Manages AWS sessions, regional clients, and cross-account STS credential caching."""

    def __init__(self, region_name: str | None = None, profile_name: str | None = None):
        resolved_region = (
            region_name or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
        )
        resolved_profile = profile_name or os.environ.get("AWS_PROFILE")
        self.default_region = resolved_region
        self.profile_name = resolved_profile
        self._root_session = boto3.Session(region_name=resolved_region, profile_name=resolved_profile)
        self.boto_config = Config(
            retries={"max_attempts": 10, "mode": "adaptive"},
            connect_timeout=10,
            read_timeout=30,
        )
        self._sts_client = self._root_session.client("sts", config=self.boto_config)
        self._cached_assumed_sessions: dict[str, dict[str, Any]] = {}
        self._cached_caller_identity: dict[str, str] | None = None
        # boto3 Session objects are not thread-safe; serialize client/session creation so callers
        # (e.g. the parallel default-VPC cleanup) can share one manager. The clients returned are safe to use.
        self._lock = threading.RLock()

    def is_root_identity(self) -> bool:
        """True when the current credentials belong to an account root user (ARN ends in ':root').

        Root credentials cannot call sts:AssumeRole, so tarmac cannot reach member accounts with them.
        """
        return str(self.get_caller_identity().get("Arn", "")).endswith(":root")

    def get_caller_identity(self) -> dict[str, str]:
        """Fetch caller identity (Account, UserId, Arn) for current root credentials."""
        if self._cached_caller_identity is not None:
            return self._cached_caller_identity
        try:
            identity = self._sts_client.get_caller_identity()
            self._cached_caller_identity = identity
            return identity
        except ClientError as e:
            logger.error("Failed to authenticate with AWS: %s", e)
            raise AWSAuthenticationError(
                "Failed to authenticate with AWS credentials.",
                details=e.response["Error"].get("Message", str(e)),
            ) from e
        except Exception as e:
            logger.error("Unexpected error obtaining caller identity: %s", e)
            raise AWSAuthenticationError("AWS authentication failed.", details=str(e)) from e

    def get_client(self, service_name: str, region_name: str | None = None) -> Any:
        """Get a boto3 client in the management account."""
        region = region_name or self.default_region
        with self._lock:
            return self._root_session.client(service_name, region_name=region, config=self.boto_config)

    def get_assumed_session(
        self,
        account_id: str,
        role_name: str = "OrganizationAccountAccessRole",
        session_name: str = "tarmac-session",
    ) -> boto3.Session:
        """Assume a role in a target member account and return a boto3.Session with cached credentials."""
        with self._lock:
            return self._get_assumed_session_locked(account_id, role_name, session_name)

    def _get_assumed_session_locked(
        self, account_id: str, role_name: str, session_name: str
    ) -> boto3.Session:
        cache_key = f"{account_id}:{role_name}"
        cached = self._cached_assumed_sessions.get(cache_key)

        if cached and cached["expiration"] > (time.time() + 300):
            return cached["session"]

        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        logger.debug("Assuming cross-account role: %s", role_arn)
        try:
            response = self._assume_role_with_propagation_retry(role_arn, session_name)
            creds = response["Credentials"]
            assumed_session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.default_region,
            )

            self._cached_assumed_sessions[cache_key] = {
                "session": assumed_session,
                "expiration": creds["Expiration"].timestamp(),
            }
            return assumed_session
        except ClientError as e:
            msg = e.response["Error"].get("Message", str(e))
            logger.error("Failed to assume role '%s': %s", role_arn, msg)
            raise AWSAuthenticationError(
                f"Failed to assume role '{role_arn}' in target account {account_id}.",
                details=msg,
            ) from e

    # OrganizationAccountAccessRole is created asynchronously after CreateAccount reports SUCCEEDED, so
    # the first AssumeRole into a brand-new account commonly fails with AccessDenied for a short while.
    ASSUME_ROLE_RETRY_SECONDS: float = 120.0
    ASSUME_ROLE_RETRY_DELAY: float = 5.0

    def _assume_role_with_propagation_retry(self, role_arn: str, session_name: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.ASSUME_ROLE_RETRY_SECONDS
        while True:
            try:
                return self._sts_client.assume_role(
                    RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=3600
                )
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code != "AccessDenied" or time.monotonic() + self.ASSUME_ROLE_RETRY_DELAY > deadline:
                    raise
                logger.info(
                    "AssumeRole into %s denied (role may still be propagating); retrying in %.0fs...",
                    role_arn,
                    self.ASSUME_ROLE_RETRY_DELAY,
                )
                time.sleep(self.ASSUME_ROLE_RETRY_DELAY)

    def get_member_client(
        self,
        account_id: str,
        service_name: str,
        role_name: str = "OrganizationAccountAccessRole",
        region_name: str | None = None,
    ) -> Any:
        """Get a client in a member account via cross-account role assumption."""
        caller_acct = self.get_caller_identity().get("Account")
        if caller_acct and account_id == caller_acct:
            return self.get_client(service_name, region_name=region_name)

        region = region_name or self.default_region
        with self._lock:
            assumed_session = self.get_assumed_session(account_id, role_name=role_name)
            return assumed_session.client(service_name, region_name=region, config=self.boto_config)
