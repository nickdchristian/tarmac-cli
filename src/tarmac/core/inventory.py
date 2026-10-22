"""A record of what Tarmac itself created, so a full teardown removes only that.

Tags identify the resources Tarmac owns outright (stacks, SCPs, permission sets, accounts). Some things
cannot be tagged or may predate Tarmac: OUs, Identity Center users and groups, trusted service access,
delegated administrators, root-access features, alternate contacts and cost-allocation tags. For those the
audit trail is the proof: whenever Tarmac *changes* one (outcome "succeeded", not "unchanged" and never a dry
run), it is written here. A teardown then deletes only what is listed, so an OU or user that existed before
Tarmac is never touched.

It is stored in a bucket in the management account, created by phase 1 (the ``<org>-tarmac-inventory`` stack),
so everyone who runs tarmac for the organization shares it. Writes are conditional on the object being unchanged
since it was read; when another run wrote in between, this run's changes are applied again on top of that. It can
be rebuilt from a Tarmac run log with ``tarmac inventory --from-log``.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from .exceptions import aws_error_code, aws_error_message
from .stack_names import Stack

logger = logging.getLogger(__name__)

KEY = "inventory.json"
#: Where releases before the bucket kept the inventory, relative to the config directory. Read once to fill an
#: empty bucket.
LOCAL_FILE = Path(".tarmac") / "inventory.json"

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
    """{kind: {key: details}} map, kept in the organization's inventory bucket once connected."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.entries: dict[str, dict[str, dict[str, Any]]] = {}
        self._changes: list[tuple[str, dict[str, Any] | None]] = []
        self._s3: Any = None
        self.bucket: str | None = None
        self._etag: str | None = None
        self.location = "not stored yet"

    def connect(self, s3_client: Any, bucket: str | None, local_file: Path) -> None:
        """Load the stored inventory and store this run's changes in ``bucket`` from now on.

        Changes recorded before connecting are kept. Without a bucket, or while it holds no inventory yet, the
        local file earlier releases wrote is read instead; with a bucket it is then stored there.
        """
        with self._lock:
            self._s3, self.bucket = s3_client, bucket
            stored = self._pull() if bucket else False
            if not stored and local_file.is_file():
                raw = json.loads(local_file.read_text(encoding="utf-8"))
                self.entries = {k: dict(v) for k, v in raw.get("entries", {}).items()}
                self.location = str(local_file)
            self._replay()
            if bucket:
                self.location = f"s3://{bucket}/{KEY}"
                if self._changes or (self.entries and not stored):
                    self.save()

    def _pull(self) -> bool:
        """Read the stored inventory; False when the bucket holds none yet."""
        try:
            obj = self._s3.get_object(Bucket=self.bucket, Key=KEY)
        except ClientError as e:
            if aws_error_code(e) != "NoSuchKey":
                raise
            self.entries, self._etag = {}, None
            return False
        raw = json.loads(obj["Body"].read())
        self.entries = {k: dict(v) for k, v in raw.get("entries", {}).items()}
        self._etag = obj["ETag"]
        return True

    def _replay(self) -> None:
        for resource, details in self._changes:
            self._apply(resource, details)

    def save(self) -> None:
        if not self.bucket:
            return
        try:
            for _ in range(5):
                body = json.dumps({"version": 1, "entries": self.entries}, indent=2, sort_keys=True) + "\n"
                condition = {"IfMatch": self._etag} if self._etag else {"IfNoneMatch": "*"}
                try:
                    put = self._s3.put_object(
                        Bucket=self.bucket, Key=KEY, Body=body.encode("utf-8"), **condition
                    )
                    self._etag = put["ETag"]
                    return
                except ClientError as e:
                    if aws_error_code(e) not in ("PreconditionFailed", "ConditionalRequestConflict"):
                        raise
                    self._pull()
                    self._replay()
            logger.warning("Could not write inventory %s: other runs kept changing it", self.location)
        except (ClientError, BotoCoreError) as e:
            logger.warning("Could not write inventory %s: %s", self.location, e)

    def record(self, resource: str, details: dict[str, Any] | None = None) -> bool:
        with self._lock:
            return self._record(resource, details)

    def _record(self, resource: str, details: dict[str, Any] | None) -> bool:
        if kind_of(resource) not in TRACKED:
            return False
        details = details or {}
        self._changes.append((resource, details))
        self._apply(resource, details)
        self.save()
        return True

    def forget(self, kind: str, key: str) -> None:
        with self._lock:
            if key in self.entries.get(kind, {}):
                self._changes.append((f"{kind}:{key}", None))
                self._apply(f"{kind}:{key}", None)
                self.save()

    def _apply(self, resource: str, details: dict[str, Any] | None) -> None:
        """Record ``resource`` with ``details``, or forget it when ``details`` is None."""
        kind, key = kind_of(resource), key_of(resource)
        if details is None:
            self.entries.get(kind, {}).pop(key, None)
            if not self.entries.get(kind, True):
                del self.entries[kind]
            return
        new = {k: v for k, v in details.items() if v is not None}
        if kind == "cost-allocation-tags":
            old = self.entries.get(kind, {}).get(key, {}).get("tag_keys", [])
            new["tag_keys"] = sorted(set(old) | set(new.get("tag_keys", [])))
        self.entries.setdefault(kind, {})[key] = new

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


def find_bucket(cfn_client: Any, org_name: str) -> str | None:
    """The inventory bucket phase 1 created, or None before it exists."""
    try:
        stacks = cfn_client.describe_stacks(StackName=Stack.INVENTORY.for_org(org_name))["Stacks"]
    except ClientError as e:
        if "does not exist" in aws_error_message(e):
            return None
        raise
    return next(
        (str(o["OutputValue"]) for o in stacks[0].get("Outputs", []) if o["OutputKey"] == "BucketName"), None
    )


def connect(session_mgr: Any, org_name: str, region: str, config_dir: Path) -> Inventory:
    """Connect the active inventory to the organization's bucket (see ``Inventory.connect``)."""
    inv = active() or activate()
    cfn = session_mgr.get_client("cloudformation", region_name=region)
    s3 = session_mgr.get_client("s3", region_name=region)
    inv.connect(s3, find_bucket(cfn, org_name), config_dir / LOCAL_FILE)
    return inv


def activate() -> Inventory:
    """Start recording audit events; they are stored once the inventory is connected to its bucket."""
    global _active
    _active = Inventory()
    return _active


def active() -> Inventory | None:
    return _active


def deactivate() -> None:
    global _active
    _active = None
