"""Centralized tagging models, validation, and multi-tier hierarchy resolution for AWS resources."""

import re
from typing import Any

TAG_KEY_PATTERN = re.compile(r"^[\w\s.:/=+\-@]*$")
TAG_VALUE_PATTERN = re.compile(r"^[\w\s.:/=+\-@]*$")

DEFAULT_SYSTEM_TAGS: dict[str, str] = {
    "ManagedBy": "tarmac",
}

MAX_AWS_TAGS = 50


def validate_tag_key(key: str) -> None:
    """Validate an AWS tag key according to AWS Tagging Standards.

    - Length between 1 and 128 Unicode characters
    - Cannot begin with reserved prefix 'aws:'
    - Allowed characters: letters, numbers, spaces, and _ . : / = + - @
    """
    if not (1 <= len(key) <= 128):
        raise ValueError(f"Tag key '{key}' must be between 1 and 128 characters.")
    if key.lower().startswith("aws:"):
        raise ValueError(f"Tag key '{key}' cannot start with reserved prefix 'aws:'.")
    if not TAG_KEY_PATTERN.match(key):
        raise ValueError(
            f"Tag key '{key}' contains invalid characters. "
            "Allowed characters: letters, numbers, spaces, and _ . : / = + - @"
        )


def validate_tag_value(key: str, value: Any) -> str:
    """Validate an AWS tag value according to AWS Tagging Standards.

    - Length between 0 and 256 Unicode characters
    - Allowed characters: letters, numbers, spaces, and _ . : / = + - @
    """
    val_str = str(value)
    if len(val_str) > 256:
        raise ValueError(f"Tag value for key '{key}' must not exceed 256 characters.")
    if not TAG_VALUE_PATTERN.match(val_str):
        raise ValueError(
            f"Tag value '{val_str}' for key '{key}' contains invalid characters (e.g. commas are not permitted by AWS Organizations). "
            "Allowed characters: letters, numbers, spaces, and _ . : / = + - @"
        )
    return val_str


def validate_tags(tags: dict[str, Any]) -> dict[str, str]:
    """Validate a dictionary of tags against AWS standards and return clean dict[str, str]."""
    if len(tags) > MAX_AWS_TAGS:
        raise ValueError(
            f"AWS supports a maximum of {MAX_AWS_TAGS} tags per resource (received {len(tags)})."
        )
    validated: dict[str, str] = {}
    for k, v in tags.items():
        validate_tag_key(k)
        val_str = validate_tag_value(k, v)
        validated[k] = val_str
    return validated


def merge_tags(
    *sources: dict[str, Any] | None,
    default_tags: dict[str, str] | None = None,
) -> dict[str, str]:
    """Merge tags following the Tarmac Tagging Hierarchy:

    1. Default System Tags (e.g. {'ManagedBy': 'tarmac'})
    2. Organization / Global Governance Tags (from organization.yaml / accounts.yaml)
    3. Account-specific Tags (from accounts.yaml account definition)
    4. Stack-specific / Invocation Tags (from deploy command or CLI --tag)

    Later sources in `sources` override earlier sources for identical keys.
    Returns a validated, AWS-compliant dictionary of tags.
    """
    merged: dict[str, str] = dict(default_tags if default_tags is not None else DEFAULT_SYSTEM_TAGS)

    for src in sources:
        if src:
            for k, v in src.items():
                validate_tag_key(k)
                val_str = validate_tag_value(k, v)
                merged[k] = val_str

    if len(merged) > MAX_AWS_TAGS:
        raise ValueError(
            f"Merged tags exceed AWS limit of {MAX_AWS_TAGS} tags per resource (total: {len(merged)})."
        )

    return merged


def to_cfn_tags(tags: dict[str, str]) -> list[dict[str, str]]:
    """Convert a dictionary of tags to the AWS CloudFormation Tag list format:

    [{'Key': key, 'Value': value}, ...]
    """
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def parse_cli_tags(tag_list: list[str] | None) -> dict[str, str]:
    """Parse a list of 'Key=Value' strings from CLI arguments into a validated dictionary.

    Raises ValueError if any string is not in 'Key=Value' format or if validation fails.
    """
    if not tag_list:
        return {}
    tags: dict[str, str] = {}
    for item in tag_list:
        if "=" not in item:
            raise ValueError(f"Invalid tag format '{item}'. Expected format is 'Key=Value'.")
        k, v = item.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise ValueError(f"Tag key cannot be empty in '{item}'.")
        validate_tag_key(k)
        val_str = validate_tag_value(k, v)
        tags[k] = val_str
    if len(tags) > MAX_AWS_TAGS:
        raise ValueError(
            f"AWS supports a maximum of {MAX_AWS_TAGS} tags per resource (received {len(tags)})."
        )
    return tags
