"""A record of what Tarmac itself created, so a full teardown removes only that.

Tags identify the resources Tarmac owns outright (stacks, SCPs, permission sets, accounts). Some things
cannot be tagged or may predate Tarmac: OUs, Identity Center users and groups, trusted service access,
delegated administrators, root-access features, alternate contacts and cost-allocation tags. For those the
audit trail is the proof: whenever Tarmac *changes* one (outcome "succeeded", not "unchanged" and never a dry
run), it is written here. A teardown then deletes only what is listed, so an OU or user that existed before
Tarmac is never touched.

The file sits beside the configuration (``<config dir>/.tarmac/inventory.json``) and can be rebuilt from a
Tarmac run log with ``tarmac deploy inventory --from-log``.
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

INVENTORY_DIR = ".tarmac"
INVENTORY_FILE = "inventory.json"

#: resource prefix (before the first ":") -> audit actions that mean "Tarmac created or changed this".
TRACKED: dict[str, frozenset[str]] = {
    "ou": frozenset({"create"}),
    "identity-user": frozenset({"create"}),
    "identity-group": frozenset({"create"}),
    "trusted-access": frozenset({"enable"}),
    "root-credentials-management": frozenset({"enable"}),
    "root-sessions": frozenset({"enable"}),
    "delegated-admin": frozenset({"register"}),
    "alternate-contact": frozenset({"update"}),
    "cost-allocation-tags": frozenset({"activate"}),
}


def kind_of(resource: str) -> str:
    return resource.split(":", 1)[0]


def key_of(resource: str) -> str:
    return resource.split(":", 1)[1] if ":" in resource else resource


class Inventory:
    """JSON-backed {kind: {key: details}} map."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self.entries: dict[str, dict[str, dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.entries = {k: dict(v) for k, v in raw.get("entries", {}).items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError) as exc:
            logger.warning("Could not read inventory %s: %s", self.path, exc)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"version": 1, "entries": self.entries}, indent=2, sort_keys=True) + "\n"
            )
            os.replace(tmp, self.path)
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Could not write inventory %s: %s", self.path, exc)

    def record(self, resource: str, details: dict[str, Any] | None = None) -> bool:
        with self._lock:
            return self._record(resource, details)

    def _record(self, resource: str, details: dict[str, Any] | None) -> bool:
        kind, key = kind_of(resource), key_of(resource)
        if kind not in TRACKED:
            return False
        new = {k: v for k, v in (details or {}).items() if v is not None}
        if kind == "cost-allocation-tags":
            old = self.entries.get(kind, {}).get(key, {}).get("tag_keys", [])
            new["tag_keys"] = sorted(set(old) | set(new.get("tag_keys", [])))
        self.entries.setdefault(kind, {})[key] = new
        self.save()
        return True

    def forget(self, kind: str, key: str) -> None:
        with self._lock:
            if self.entries.get(kind, {}).pop(key, None) is not None:
                if not self.entries[kind]:
                    del self.entries[kind]
                self.save()

    def get(self, kind: str) -> dict[str, dict[str, Any]]:
        return dict(self.entries.get(kind, {}))

    def count(self) -> int:
        return sum(len(v) for v in self.entries.values())

    def observe(
        self, action: str, resource: str, outcome: str, dry_run: bool, details: dict[str, Any]
    ) -> bool:
        """Record an audit event if it proves Tarmac created or changed something trackable."""
        if outcome != "succeeded" or dry_run:
            return False
        if action not in TRACKED.get(kind_of(resource), frozenset()):
            return False
        return self.record(resource, details)

    def ingest_log(self, log_path: Path) -> int:
        """Replay the audit events of a Tarmac JSON-lines run log. Returns how many entries were recorded."""
        recorded = 0
        with log_path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                data = entry.get("data") if entry.get("event") == "audit" else None
                if not isinstance(data, dict):
                    continue
                if self.observe(
                    str(data.get("action", "")),
                    str(data.get("resource", "")),
                    str(data.get("outcome", "")),
                    bool(data.get("dry_run")),
                    dict(data.get("details") or {}),
                ):
                    recorded += 1
        return recorded


_active: Inventory | None = None


def default_path(config_dir: Path) -> Path:
    override = os.environ.get("TARMAC_INVENTORY_FILE")
    if override:
        return Path(override)
    return config_dir / INVENTORY_DIR / INVENTORY_FILE


def activate(config_dir: Path) -> Inventory:
    """Start recording audit events into the inventory beside this configuration."""
    global _active
    _active = Inventory(default_path(config_dir))
    return _active


def active() -> Inventory | None:
    return _active


def deactivate() -> None:
    global _active
    _active = None
