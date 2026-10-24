"""The config is the source of truth: what it turns off or no longer declares, a deploy removes."""

from ..core.exceptions import GovernanceError
from ..core.models import TeardownItemReport
from .ui import print_success


def apply_removals(what: str, items: list[TeardownItemReport]) -> None:
    """Report what removing ``what`` deleted, and fail the phase if any of it could not be removed."""
    for item in items:
        if item.action == "DELETED":
            print_success(f"{item.resource_type} {item.resource_name} ({item.account_name}): {item.message}.")
    failed = [i for i in items if i.action == "FAILED"]
    if failed:
        raise GovernanceError(
            f"Could not remove the {what} the config no longer declares.",
            details="\n".join(f"{i.resource_name}: {i.message}" for i in failed),
        )
