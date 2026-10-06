"""AWS Session and Cross-Account STS AssumeRole Manager."""

import logging
import os
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
        self._sts_client = self._root_session.client("sts")
        self._cached_assumed_sessions: dict[str, dict[str, Any]] = {}
        self._cached_caller_identity: dict[str, str] | None = None
        self.boto_config = Config(
            retries={"max_attempts": 10, "mode": "adaptive"},
        )

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
        return self._root_session.client(service_name, region_name=region, config=self.boto_config)

    def get_assumed_session(
        self,
        account_id: str,
        role_name: str = "OrganizationAccountAccessRole",
        session_name: str = "tarmac-session",
    ) -> boto3.Session:
        """Assume a role in a target member account and return a boto3.Session with cached credentials."""
        cache_key = f"{account_id}:{role_name}"
        cached = self._cached_assumed_sessions.get(cache_key)

        if cached and cached["expiration"] > (time.time() + 300):
            return cached["session"]

        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        logger.debug("Assuming cross-account role: %s", role_arn)
        try:
            response = self._sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600,
            )
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

        assumed_session = self.get_assumed_session(account_id, role_name=role_name)
        region = region_name or self.default_region
        return assumed_session.client(service_name, region_name=region, config=self.boto_config)
