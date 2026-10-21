"""The shipped SCPs that deny the root user must exempt centralized-root-access sessions the documented way.

AWS documents ``aws:AssumedRoot`` as the key that is present only on credentials from ``sts:AssumeRoot``
(IAM User Guide, global condition keys), and shows exactly this pattern for an SCP that denies a member
account's long-term root credentials without denying AssumeRoot sessions.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    "src/tarmac/templates/policies/scp/deny-member-root.json",
    "src/tarmac/templates/policies/scp/foundational-guardrails.json",
]


def _root_statement(path: str) -> dict:
    document = json.loads((ROOT / path).read_text(encoding="utf-8"))
    return next(s for s in document["Statement"] if s["Sid"] == "DenyMemberAccountRootActivity")


@pytest.mark.parametrize("path", FILES)
def test_root_deny_exempts_assume_root_sessions_with_the_documented_key(path):
    condition = _root_statement(path)["Condition"]
    assert condition["ArnLike"] == {"aws:PrincipalArn": "arn:aws:iam::*:root"}
    assert condition["Null"] == {"aws:AssumedRoot": "true"}
    assert _root_statement(path)["Effect"] == "Deny"


@pytest.mark.parametrize("path", FILES)
def test_no_undocumented_session_tag_is_relied_on(path):
    assert "RootSessionArn" not in (ROOT / path).read_text(encoding="utf-8")
