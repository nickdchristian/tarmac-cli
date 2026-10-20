"""Shared builders for tests."""

from pathlib import Path

import yaml

from tarmac.services.scaffold import scaffold_project


def make_config(tmp_path: Path, environment: str | None) -> Path:
    cfg = tmp_path / "cfg"
    scaffold_project(cfg)
    org_file = cfg / "organization.yaml"
    data = yaml.safe_load(org_file.read_text())
    tags = data.setdefault("organization", {}).setdefault("tags", {})
    tags.pop("Environment", None)
    if environment is not None:
        tags["Environment"] = environment
    org_file.write_text(yaml.safe_dump(data))
    return cfg
