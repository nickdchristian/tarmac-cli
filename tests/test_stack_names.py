from tarmac.core.stack_names import TARMAC_STACK_SUFFIXES, Stack


def test_stack_names_are_stable():
    """Renaming a stack would orphan every stack already deployed under the old name."""
    assert {s.for_org("acme") for s in Stack} == {
        "acme-organization-scps",
        "acme-organization-cloudtrail",
        "acme-log-archive-hardening",
        "acme-terraform-backend",
        "acme-audit-account-hardening",
        "acme-sso-permission-sets",
        "acme-management-root-alert",
        "acme-config-recorder",
    }


def test_suffixes_match_plain_strings():
    assert "organization-cloudtrail" in TARMAC_STACK_SUFFIXES
    assert all(isinstance(s, str) for s in TARMAC_STACK_SUFFIXES)
