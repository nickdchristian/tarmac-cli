"""Set up and maintain a multi-account AWS Organization from YAML."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("tarmac-cli")
except PackageNotFoundError:
    __version__ = "0.5.0"  # x-release-please-version
