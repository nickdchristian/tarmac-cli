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


class CfnLoader(yaml.SafeLoader):
    """YAML loader that reads CloudFormation templates, treating ``!Ref``-style tags as plain values."""


def _construct(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]


CfnLoader.add_multi_constructor("!", _construct)
