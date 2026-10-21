"""Whether this run may take over existing resources that tarmac did not create.

Set once per command from ``--adopt-existing``. Services read it when they find a resource with the name they
would create (an SCP, a budget). Off by default: changing something tarmac does not own needs an explicit yes.
"""

import contextvars

_adopt_existing: contextvars.ContextVar[bool] = contextvars.ContextVar("tarmac_adopt_existing", default=False)


def set_adopt_existing(value: bool) -> None:
    _adopt_existing.set(value)


def adopt_existing() -> bool:
    return _adopt_existing.get()


ADOPT_HINT = "Review the difference, then re-run with --adopt-existing to let tarmac take it over."
