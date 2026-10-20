"""Detects the sample values `tarmac init` writes, which must be replaced before a real deployment."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config_loader import ConfigBundle

PLACEHOLDER_PHONE = "+1234567890"
_PLACEHOLDER_DOMAINS = ("example.com", "example.org", "example.net")


def is_placeholder_email(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].lower()
    return any(domain == d or domain.endswith(f".{d}") for d in _PLACEHOLDER_DOMAINS)


def find_placeholder_values(bundle: "ConfigBundle") -> list[str]:
    """Human-readable list of sample values still present in the configuration (empty when none)."""
    problems: list[str] = []

    for label, contact in (
        ("billing", bundle.org.contacts.billing),
        ("operations", bundle.org.contacts.operations),
        ("security", bundle.org.contacts.security),
    ):
        if is_placeholder_email(str(contact.email)):
            problems.append(
                f"organization.yaml: the {label} contact email '{contact.email}' is a sample address"
            )
        if contact.phone.strip() == PLACEHOLDER_PHONE:
            problems.append(
                f"organization.yaml: the {label} contact phone is the sample number {PLACEHOLDER_PHONE}"
            )

    for account in bundle.accounts.accounts:
        if is_placeholder_email(str(account.email)):
            problems.append(
                f"accounts.yaml: account '{account.name}' uses the sample email '{account.email}'"
            )

    identity = bundle.identity.identity_center
    for user in (identity.admin_user, identity.breakglass_user, *identity.additional_users):
        if is_placeholder_email(str(user.email)):
            problems.append(f"identity.yaml: user '{user.username}' uses the sample email '{user.email}'")

    return problems
