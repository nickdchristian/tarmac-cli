"""Centralized logging configuration for Tarmac."""

import logging

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(debug: bool = False, console: Console | None = None) -> None:
    """Configure centralized Rich logging for Tarmac.

    When debug is True:
    - Sets Tarmac loggers to DEBUG with Rich formatting and rich tracebacks.
    - Suppresses noisy external loggers (botocore, urllib3, s3transfer) to WARNING
      so debug output remains clean, focused, and actionable.
    When debug is False:
    - Sets root logger to WARNING to avoid cluttering standard CLI terminal output.
    """
    level = logging.DEBUG if debug else logging.WARNING
    target_console = console if console is not None else Console(stderr=True)

    handler = RichHandler(
        console=target_console,
        show_time=True,
        show_path=debug,
        rich_tracebacks=debug,
        markup=True,
    )
    handler.setLevel(level)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[handler],
        force=True,
    )

    for noisy_pkg in ("botocore", "urllib3", "boto3", "s3transfer"):
        logging.getLogger(noisy_pkg).setLevel(logging.WARNING)

    logging.getLogger("tarmac").setLevel(level)
