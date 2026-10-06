"""Unit tests for AwsSessionManager and AWS authentication handling."""

import time
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tarmac.core.aws_client import AwsSessionManager
from tarmac.core.exceptions import AWSAuthenticationError


def test_aws_session_manager_region_resolution(monkeypatch):
    """Verify region resolution priority: explicit > AWS_DEFAULT_REGION > AWS_REGION > default."""
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)

    # 1. Default fallback to us-east-1
    with patch("boto3.Session"):
        mgr = AwsSessionManager()
        assert mgr.default_region == "us-east-1"

    # 2. AWS_REGION environment variable
    monkeypatch.setenv("AWS_REGION", "eu-central-1")
    with patch("boto3.Session"):
        mgr = AwsSessionManager()
        assert mgr.default_region == "eu-central-1"

    # 3. AWS_DEFAULT_REGION takes precedence over AWS_REGION
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-west-2")
    with patch("boto3.Session"):
        mgr = AwsSessionManager()
        assert mgr.default_region == "us-west-2"

    # 4. Explicit region parameter takes highest precedence
    with patch("boto3.Session"):
        mgr = AwsSessionManager(region_name="ap-southeast-1")
        assert mgr.default_region == "ap-southeast-1"


def test_aws_session_manager_profile_resolution(monkeypatch):
    """Verify profile resolution priority: explicit > AWS_PROFILE."""
    monkeypatch.setenv("AWS_PROFILE", "env-profile")
    with patch("boto3.Session"):
        mgr = AwsSessionManager()
        assert mgr.profile_name == "env-profile"

        mgr_explicit = AwsSessionManager(profile_name="explicit-profile")
        assert mgr_explicit.profile_name == "explicit-profile"


def test_aws_session_manager_caller_identity_caching():
    """Verify caller identity is cached and doesn't call STS multiple times."""
    with patch("boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "UserId": "AIDAX",
            "Arn": "arn:aws:iam::123456789012:root",
        }
        mock_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_session

        mgr = AwsSessionManager()
        id1 = mgr.get_caller_identity()
        id2 = mgr.get_caller_identity()

        assert id1 == id2
        assert id1["Account"] == "123456789012"
        mock_sts.get_caller_identity.assert_called_once()


def test_aws_session_manager_caller_identity_error():
    """Verify STS client errors are converted to AWSAuthenticationError."""
    with patch("boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {
                "Error": {
                    "Code": "InvalidClientTokenId",
                    "Message": "The security token included in the request is invalid",
                }
            },
            "GetCallerIdentity",
        )
        mock_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_session

        mgr = AwsSessionManager()
        with pytest.raises(AWSAuthenticationError) as exc_info:
            mgr.get_caller_identity()

        assert "Failed to authenticate" in str(exc_info.value)
        assert "security token" in str(exc_info.value)


def test_aws_session_manager_assumed_session_caching():
    """Verify assumed sessions are cached until near expiration."""
    with patch("boto3.Session") as mock_session_cls:
        mock_root_session = MagicMock()
        mock_sts = MagicMock()
        future_exp = time.time() + 3600
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_TEST",
                "SecretAccessKey": "SECRET_TEST",
                "SessionToken": "TOKEN_TEST",
                "Expiration": MagicMock(timestamp=lambda: future_exp),
            }
        }
        mock_root_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_root_session

        mgr = AwsSessionManager()
        session1 = mgr.get_assumed_session("222222222222")
        session2 = mgr.get_assumed_session("222222222222")

        assert session1 is session2
        mock_sts.assume_role.assert_called_once()


def test_aws_session_manager_member_client_short_circuits_payer():
    """Verify get_member_client calls get_client directly when account_id matches management account."""
    with patch("boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "111111111111"}
        mock_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_session

        mgr = AwsSessionManager()
        mock_target_client = MagicMock()
        with patch.object(mgr, "get_client", return_value=mock_target_client) as mock_gc:
            client = mgr.get_member_client("111111111111", "cloudformation")
            assert client == mock_target_client
            mock_gc.assert_called_once_with("cloudformation", region_name=None)
