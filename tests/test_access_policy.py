"""The deployment permission set's policy: it must fit the inline policy limit, and preflight must notice a stale one."""

import json
import re
from typing import Any
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from tarmac.core.models import PreflightCheckResult, PreflightCheckStatus
from tarmac.services.identity import deployment_policy
from tarmac.services.preflight import PreflightService

# Identity Center rejects a permission set inline policy over 10,240 characters (whitespace excluded). Keep headroom so
# the next feature does not discover the limit in a customer's account.
INLINE_LIMIT = 10240
HEADROOM = 1000


def test_the_policy_stays_well_under_the_inline_policy_limit() -> None:
    size = len(re.sub(r"\s", "", deployment_policy()))
    assert size <= INLINE_LIMIT - HEADROOM, (
        f"The deployment policy is {size} characters; Identity Center allows {INLINE_LIMIT}. Trim it before adding more."
    )


def _check(permission_sets: dict[str, str], inline: Any = None) -> PreflightCheckResult:
    identity = MagicMock()
    identity.return_value.get_instance_details.return_value = ("arn:inst", "d-1")
    identity.return_value.list_permission_sets.return_value = permission_sets
    get_inline = identity.return_value.sso_client.get_inline_policy_for_permission_set
    if isinstance(inline, Exception):
        get_inline.side_effect = inline
    else:
        get_inline.return_value = {"InlinePolicy": inline}
    with patch("tarmac.services.preflight.IdentityService", identity):
        return PreflightService(MagicMock(), MagicMock()).check_deployment_policy_current()


def test_a_policy_matching_this_release_passes_however_it_is_formatted() -> None:
    minified = json.dumps(json.loads(deployment_policy()), separators=(",", ":"))
    assert _check({"TarmacDeployment": "arn:ps"}, minified).status is PreflightCheckStatus.PASS


def test_a_policy_from_another_release_warns_to_rebootstrap() -> None:
    result = _check({"TarmacDeployment": "arn:ps"}, '{"Version": "2012-10-17", "Statement": []}')
    assert result.status is PreflightCheckStatus.WARN
    assert "tarmac bootstrap" in (result.action_required or "")


def test_no_deployment_permission_set_is_informational() -> None:
    assert _check({}).status is PreflightCheckStatus.INFO


def test_missing_permission_to_read_it_is_informational() -> None:
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetInlinePolicy")
    assert _check({"TarmacDeployment": "arn:ps"}, denied).status is PreflightCheckStatus.INFO
