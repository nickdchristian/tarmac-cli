"""Tests for centralized Rich logging configuration."""

import logging
from unittest.mock import patch

from tarmac.core.logging import setup_logging


def test_setup_logging_debug_mode():
    setup_logging(debug=True)

    tarmac_logger = logging.getLogger("tarmac")
    assert tarmac_logger.level == logging.DEBUG

    # Verify external libraries are suppressed to WARNING
    for noisy in ("botocore", "urllib3", "boto3", "s3transfer"):
        assert logging.getLogger(noisy).level == logging.WARNING


def test_setup_logging_default_mode():
    setup_logging(debug=False)

    tarmac_logger = logging.getLogger("tarmac")
    assert tarmac_logger.level == logging.WARNING


def test_setup_logging_configures_rich_handler():
    with patch("logging.basicConfig") as mock_basic:
        setup_logging(debug=True)
        assert mock_basic.called
        kwargs = mock_basic.call_args[1]
        assert kwargs["level"] == logging.DEBUG
        assert kwargs["force"] is True
        assert len(kwargs["handlers"]) == 1
