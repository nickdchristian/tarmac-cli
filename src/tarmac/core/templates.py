"""Template and policy resolution utilities for Tarmac."""

import importlib.resources
import logging
import shutil
from pathlib import Path

from .exceptions import ConfigurationError

logger = logging.getLogger(__name__)


def resolve_resource_path(
    relative_path: str | Path,
    project_root: Path | None = None,
) -> Path:
    """Resolve a CloudFormation template or SCP policy file path.

    Lookup hierarchy:
    1. Absolute path if provided and exists.
    2. project_root / relative_path (if project_root provided and file exists).
    3. Path.cwd() / relative_path (if file exists).
    4. Bundled package templates in tarmac.templates.

    Raises ConfigurationError if the resource cannot be found anywhere.
    """
    rel = Path(relative_path)
    if rel.is_absolute() and rel.is_file():
        return rel

    if project_root:
        candidate = project_root / rel
        if candidate.is_file():
            return candidate

    cwd_candidate = Path.cwd() / rel
    if cwd_candidate.is_file():
        return cwd_candidate

    bundled = _find_bundled_resource(rel)
    if bundled is not None and bundled.is_file():
        return Path(str(bundled))

    raise ConfigurationError(
        f"Resource file not found: '{relative_path}'. "
        f"Checked project root ({project_root or 'none'}), cwd ({Path.cwd()}), and bundled templates."
    )


def _find_bundled_resource(rel: Path) -> Path | None:
    """Search within bundled tarmac.templates package."""
    try:
        traversable = importlib.resources.files("tarmac.templates")
        direct = traversable.joinpath(*rel.parts)
        if direct.is_file():
            return Path(str(direct))

        if len(rel.parts) == 1:
            cfn = traversable.joinpath("cloudformation", rel.name)
            if cfn.is_file():
                return Path(str(cfn))
            pol = traversable.joinpath("policies", "scp", rel.name)
            if pol.is_file():
                return Path(str(pol))
            iam = traversable.joinpath("policies", "iam", rel.name)
            if iam.is_file():
                return Path(str(iam))
    except Exception as e:
        logger.debug("Failed searching bundled resources for %s: %s", rel, e)
    return None


def read_resource_text(
    relative_path: str | Path,
    project_root: Path | None = None,
) -> str:
    """Read the string content of a template or policy file."""
    path = resolve_resource_path(relative_path, project_root=project_root)
    return path.read_text(encoding="utf-8")


def export_bundled_templates(target_dir: Path, force: bool = False) -> list[Path]:
    """Copy all bundled CloudFormation templates and policies to target_dir.

    Returns a list of created file paths.
    """
    exported: list[Path] = []
    base = importlib.resources.files("tarmac.templates")

    for category, subfolder in [
        ("cloudformation", "cloudformation"),
        ("policies/scp", "policies/scp"),
    ]:
        cat_resource = base
        for part in category.split("/"):
            cat_resource = cat_resource.joinpath(part)

        dest_dir = target_dir / subfolder
        dest_dir.mkdir(parents=True, exist_ok=True)

        for item in cat_resource.iterdir():
            if item.is_file() and not item.name.startswith("__"):
                dest_file = dest_dir / item.name
                if not dest_file.exists() or force:
                    shutil.copy2(str(item), dest_file)
                    exported.append(dest_file)
                    logger.info("Exported template: %s", dest_file)

    return exported
