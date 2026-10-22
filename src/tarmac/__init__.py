"""AWS Governance CLI and Multi-Account Landing Zone Automation."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tarmac-cli")
except PackageNotFoundError:
    __version__ = "0.4.0"  # x-release-please-version
