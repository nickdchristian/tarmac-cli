"""Which settings recorded in the inventory the config no longer wants, so a deploy reverts them."""

from collections.abc import Callable

from ..core.config_loader import ConfigBundle
from ..core.inventory import Inventory

# IAM: "You must enable Privileged root actions in member accounts to allow member accounts to recover their root user
# credentials after they have been deleted."
ROOT_SESSIONS_WARNING = (
    "Turning off privileged root actions. Member accounts whose root user credentials were deleted can't recover them "
    "until it is turned back on."
)


def turns_off_root_sessions(bundle: ConfigBundle, recorded: Inventory) -> bool:
    off = settings_off(bundle)
    return any(off("root-sessions", key) for key in recorded.get("root-sessions"))


def settings_off(bundle: ConfigBundle) -> Callable[[str, str], bool]:
    """``off(kind, key)`` for an inventory entry (a cost tag is checked one tag at a time).

    Root access features and the IAM delegated administrator follow ``root_access_management``, cost tags follow
    ``cost_allocation_tags``, and groups follow ``identity.yaml``. Users are never deleted for being left out.
    """
    root = bundle.org.root_access_management
    tags = set(bundle.get_cost_allocation_tags())
    groups = {g.name for g in bundle.identity.identity_center.groups}

    def off(kind: str, key: str) -> bool:
        if kind == "root-credentials-management":
            return not root.enable_root_credentials_management
        if kind == "root-sessions":
            return not root.enable_root_sessions
        if kind == "delegated-admin":
            return key.startswith("iam.amazonaws.com:") and not root.delegate_to_audit
        if kind == "cost-allocation-tag":
            return key not in tags
        if kind == "identity-group":
            return key not in groups
        return False

    return off
