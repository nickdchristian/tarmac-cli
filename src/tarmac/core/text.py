"""Wording helpers for user-facing messages."""


def plural(count: int, noun: str) -> str:
    """'1 account', '3 accounts'."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"
