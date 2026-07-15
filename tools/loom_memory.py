#!/usr/bin/env python3
"""loom_memory — scoped, bounded, per-install owner learning (stdlib only)."""

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import time
import uuid
from collections import deque
from pathlib import Path

SCHEMA_VERSION = 1
INSTANCE_MARKER = ".loom-instance-id"
SCOPES = {"global", "domain", "project", "temporary"}
CATEGORIES = {"preference", "calibration", "process", "domain"}
PROVENANCE = {"stated", "observed", "inferred"}
STATUSES = {"active", "dormant", "stale", "archived", "forgotten", "superseded"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PROJECT_ID_RE = re.compile(r"^p-[0-9a-f]{32}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ACTIVE_RECORDS = 256
MAX_SELECT_CHARS = 8000
MAX_FEEDBACK_ACTIVE = 100
MAX_OUTBOX_ENTRIES = 128
MAX_OUTBOX_BYTES = 256 * 1024
MAX_OUTCOMES_ACTIVE = 512
MAX_OUTCOME_PARTITIONS = 128
OUTCOME_WINDOW = 64
MAX_HARD_STOPS = 32
MAX_ACTIVE_STORE_BYTES = 8 * 1024 * 1024
MAX_TOMBSTONES = 4096
MAX_ARCHIVE_ENTRIES = 4096
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_LINE_BYTES = 256 * 1024
SAFETY_CAPACITY_ERROR = "mandatory safety floor exceeds hard-stop capacity"
PARTITION_CAPS = {"global": 64, "domain": 48, "project": 48, "temporary": 16}
INSTANCE_FIELDS = {"schema_version", "instance_id", "created_at"}
MEMORY_STORE_FIELDS = {"schema_version", "instance_id", "records"}
LEGACY_MEMORY_RECORD_FIELDS = {
    "id", "scope", "category", "statement", "provenance", "evidence_count",
    "confidence", "domain", "project_id", "created_at", "last_confirmed",
    "expires_at", "status", "supersedes", "preference_key", "preference_value",
}
UTILITY_FIELDS = {
    "last_selected", "last_applied", "last_helped", "last_hurt",
    "selection_count", "application_count", "helped_count", "hurt_count",
    "evidence_projects", "utility_score", "verify_by",
}
MEMORY_RECORD_FIELDS = LEGACY_MEMORY_RECORD_FIELDS | UTILITY_FIELDS
OUTCOME_STORE_FIELDS = {
    "schema_version", "instance_id", "total_count", "records", "partitions",
}
OUTCOME_RECORD_FIELDS = {
    "schema_version", "id", "instance_id", "metric", "predicted", "actual",
    "absolute_error", "domain", "project_id", "recorded_at",
}
OUTCOME_PARTITION_FIELDS = {
    "metric", "domain", "sample_count", "sum_absolute_error",
    "first_errors", "recent_errors", "updated_at",
}
FEEDBACK_PATTERNS = {
    "stale-state", "tier-overestimate", "missing-negative-check",
    "unverified-claim", "scope-leak", "round-trip-excess", "domain-gap",
    "verification-medium-mismatch", "acceptance-ambiguity",
}
FEEDBACK_ACTIONS = {
    "fail-closed", "tier-down", "add-negative-check", "verify-before-use",
    "tighten-scope", "batch-decisions", "discover-domain", "observe-real-medium",
    "rewrite-criterion",
}
OUTCOME_METRICS = {
    "confidence", "tier-estimate", "effort-estimate", "rework-rate",
    "verification-escape-rate",
}
GENERAL_PREFERENCE_KEYS = {
    "autonomy_default", "report_style", "decision_batching", "language",
    "hard_stop",
}
DOMAIN_PREFERENCE_KEYS = {"stack_preference"}
PREFERENCE_KEYS = GENERAL_PREFERENCE_KEYS | DOMAIN_PREFERENCE_KEYS
SINGLETON_PREFERENCE_KEYS = PREFERENCE_KEYS - {"hard_stop"}
RAW_PATH_RE = re.compile(
    r"(?:\b[A-Za-z]:[\\/]|/(?:Users|home|var|tmp|opt|srv|mnt)/)", re.I)


class MemoryError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise MemoryError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _is_link_or_junction(path):
    path = Path(path)
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        try:
            attributes = path.lstat().st_file_attributes
        except FileNotFoundError:
            return False
        except AttributeError:
            return False
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError as exc:
        raise MemoryError(f"cannot inspect storage path {path}: {exc}") from exc


def _reject_link(path, label):
    if _is_link_or_junction(path):
        raise MemoryError(f"{label} must not be a symlink or junction: {path}")


def _reject_link_ancestors(path, label):
    """Return an absolute lexical path only when no existing component redirects it."""
    try:
        absolute = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise MemoryError(f"{label} is not a valid local path: {exc}") from exc
    for component in [*reversed(absolute.parents), absolute]:
        if _is_link_or_junction(component):
            raise MemoryError(
                f"{label} must not traverse a symlink or junction: {component}")
    return absolute


def _require_exact_fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise MemoryError(f"{label} has unknown/missing fields")


class FileLock:
    def __init__(self, path, timeout=5.0, stale_after=None):
        self.path = Path(path)
        self.timeout = timeout
        self.fd = None
        self.token = f"{os.getpid()}:{uuid.uuid4().hex}\n"

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        self.path = _reject_link_ancestors(self.path, "lock path")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _reject_link_ancestors(self.path, "lock path")
        while True:
            try:
                self.fd = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self.fd, self.token.encode("ascii"))
                return self
            except (FileExistsError, PermissionError) as exc:
                # Windows can report transient sharing denial while a just-released lock is
                # being unlinked. Both existence observations race with that transition, so
                # retry either contention form until the same bounded deadline.
                if time.monotonic() >= deadline:
                    raise MemoryError(
                        f"memory store is busy or a prior process left {self.path}; "
                        "verify no writer is active before removing that lock") from exc
                time.sleep(0.05)

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            os.close(self.fd)
        try:
            if self.path.read_text(encoding="ascii") == self.token:
                self.path.unlink()
        except FileNotFoundError:
            pass


def _now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat() \
        .replace("+00:00", "Z")


def _now_at(value=None):
    if value is None:
        return _now()
    if isinstance(value, str):
        try:
            instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MemoryError("now must be an ISO-8601 timestamp") from exc
    elif isinstance(value, dt.datetime):
        instant = value
    else:
        raise MemoryError("now must be a timezone-aware timestamp")
    if instant.tzinfo is None:
        raise MemoryError("now must be timezone-aware")
    return instant.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat() \
        .replace("+00:00", "Z")


def _atomic_text(path, text):
    path = _reject_link_ancestors(path, "storage path")
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_link_ancestors(path, "storage path")
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _atomic_json(path, value):
    _atomic_text(path, json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _atomic_bytes(path, content):
    path = _reject_link_ancestors(path, "storage path")
    if not isinstance(content, bytes):
        raise MemoryError("binary storage content must be bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_link_ancestors(path, "storage path")
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _atomic_store(path, value):
    content = (json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if len(content) > MAX_ACTIVE_STORE_BYTES:
        raise MemoryError(
            f"active memory would exceed the {MAX_ACTIVE_STORE_BYTES}-byte active bound")
    _atomic_bytes(path, content)


def _semantic_fingerprint(record):
    fields = (
        "scope", "category", "statement", "domain", "project_id",
        "preference_key", "preference_value",
    )
    body = {field: record.get(field) for field in fields}
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def _read_tombstones(directory):
    path = _reject_link_ancestors(Path(directory) / "tombstones.json", "tombstones")
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "entries": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryError(f"tombstones are invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "entries"} \
            or value.get("schema_version") != SCHEMA_VERSION \
            or not isinstance(value.get("entries"), list) \
            or len(value["entries"]) > MAX_TOMBSTONES:
        raise MemoryError("tombstones have unknown, invalid, or excessive content")
    seen = set()
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != {
                "record_id", "semantic_fingerprint", "forgotten_at"} \
                or not isinstance(entry["record_id"], str) \
                or not DIGEST_RE.fullmatch(str(entry["semantic_fingerprint"])) \
                or entry["semantic_fingerprint"] in seen:
            raise MemoryError("tombstone entry is invalid or duplicated")
        try:
            uuid.UUID(entry["record_id"])
        except ValueError as exc:
            raise MemoryError("tombstone record id is invalid") from exc
        _validate_timestamp(entry["forgotten_at"], "forgotten_at")
        seen.add(entry["semantic_fingerprint"])
    return value


def _reject_forgotten(directory, record):
    fingerprint = _semantic_fingerprint(record)
    if any(entry["semantic_fingerprint"] == fingerprint
           for entry in _read_tombstones(directory)["entries"]):
        raise MemoryError(
            "this learning was explicitly forgotten and cannot be readmitted implicitly")


def _validate_instance_id(instance_id):
    try:
        parsed = str(uuid.UUID(str(instance_id)))
    except ValueError as exc:
        raise MemoryError(f"invalid instance id: {instance_id}") from exc
    if parsed != str(instance_id):
        raise MemoryError(f"instance id is not canonical: {instance_id}")
    return parsed


def _validate_timestamp(value, label, *, nullable=False):
    if value is None and nullable:
        return
    if not isinstance(value, str):
        raise MemoryError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MemoryError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise MemoryError(f"{label} timestamp must include a timezone")


def _timestamp_value(value):
    _validate_timestamp(value, "timestamp")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")) \
        .astimezone(dt.timezone.utc)


def _instance_dir(home, instance_id):
    base = _reject_link_ancestors(home, "Loom home")
    instances = base / "instances"
    directory = instances / _validate_instance_id(instance_id)
    _reject_link_ancestors(directory, "instance storage")
    try:
        directory.relative_to(base)
    except ValueError as exc:
        raise MemoryError("instance storage escapes the selected Loom home") from exc
    return directory


def project_identity(instance_id, project_root):
    """Return a path-derived identifier namespaced to one Loom installation."""
    namespace = uuid.UUID(_validate_instance_id(instance_id))
    root = os.path.normcase(str(Path(project_root).expanduser().resolve()))
    return "p-" + uuid.uuid5(namespace, root).hex


def initialize(home, loom_root):
    home = _reject_link_ancestors(home, "Loom home")
    loom_root = _reject_link_ancestors(loom_root, "Loom installation root")
    marker = loom_root / INSTANCE_MARKER
    _reject_link(marker, "installation marker")
    if marker.is_file():
        # Installed copies own an immutable marker in their installation receipt. Reading it
        # must not create an unowned lock file or otherwise mutate the verified installation.
        instance_id = _validate_instance_id(
            marker.read_text(encoding="utf-8").strip())
    else:
        with FileLock(loom_root / ".loom-instance-init.lock"):
            if marker.is_file():
                instance_id = _validate_instance_id(
                    marker.read_text(encoding="utf-8").strip())
            else:
                instance_id = str(uuid.uuid4())
                _atomic_text(marker, instance_id + "\n")
    directory = _instance_dir(home, instance_id)
    directory.mkdir(parents=True, exist_ok=True)
    _reject_link_ancestors(directory, "instance storage")
    with FileLock(directory / ".lock"):
        metadata = directory / "instance.json"
        if not metadata.is_file():
            _atomic_json(metadata, {
                "schema_version": SCHEMA_VERSION,
                "instance_id": instance_id,
                "created_at": _now(),
            })
        store = directory / "active.json"
        if not store.is_file():
            _atomic_store(store, {
                "schema_version": SCHEMA_VERSION,
                "instance_id": instance_id,
                "records": [],
            })
    # Legacy flat Markdown has no trustworthy scope. Quarantine a local inactive copy on first
    # initialization, but never infer/import any row into active memory.
    migrate_legacy(home, instance_id)
    return instance_id


def _read_store_locked(directory, instance_id):
    """Read a store while its instance lock is held; quarantine one unsafe v1 shape."""
    path = Path(directory) / "active.json"
    path = _reject_link_ancestors(path, "active memory")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise MemoryError(f"cannot stat active memory: {exc}") from exc
    if size > MAX_ACTIVE_STORE_BYTES:
        raise MemoryError(
            f"active memory exceeds the {MAX_ACTIVE_STORE_BYTES}-byte active bound; "
            "source left in place (use bounded oversized-store recovery)")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ACTIVE_STORE_BYTES + 1)
        if len(raw) > MAX_ACTIVE_STORE_BYTES:
            raise MemoryError(
                f"active memory changed above the {MAX_ACTIVE_STORE_BYTES}-byte "
                "active bound; source left in place")
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryError(f"cannot read active memory: {exc}") from exc
    _require_exact_fields(data, MEMORY_STORE_FIELDS, "active memory store")
    if type(data.get("schema_version")) is not int \
            or data.get("schema_version") != SCHEMA_VERSION \
            or data.get("instance_id") != instance_id \
            or not isinstance(data.get("records"), list):
        raise MemoryError("active memory header is invalid or cross-instance")
    if len(data["records"]) > MAX_ACTIVE_RECORDS + 64:
        raise MemoryError("active memory exceeds its hard record bound")
    legacy_unsafe = []
    safe_records = []
    lifecycle_migrated = False
    for record in data["records"]:
        if not isinstance(record, dict):
            raise MemoryError("active memory contains a non-object record")
        if set(record) == LEGACY_MEMORY_RECORD_FIELDS:
            record = dict(record)
            record["status"] = {
                "retired": "superseded", "tombstone": "forgotten",
            }.get(record.get("status"), record.get("status"))
            if record.get("scope") != "temporary" \
                    and record.get("provenance") in {"observed", "inferred"}:
                record["expires_at"] = None
            record.update({
                "last_selected": None, "last_applied": None,
                "last_helped": None, "last_hurt": None,
                "selection_count": 0, "application_count": 0,
                "helped_count": 0, "hurt_count": 0,
                "evidence_projects": (
                    [record["project_id"]] if record.get("project_id") else []),
                "utility_score": 0.0, "verify_by": None,
            })
            lifecycle_migrated = True
        try:
            _validate_record(record)
        except MemoryError:
            is_v1_unsafe_shape = (
                set(record) == MEMORY_RECORD_FIELDS
                and record.get("category") != "preference"
                and (record.get("preference_key") is not None
                     or record.get("preference_value") is not None)
            )
            if not is_v1_unsafe_shape:
                raise
            sanitized = dict(record)
            sanitized["preference_key"] = None
            sanitized["preference_value"] = None
            _validate_record(sanitized)
            legacy_unsafe.append(record)
            continue
        safe_records.append(record)
    if legacy_unsafe:
        # v1's schema/API admitted preference fields on ordinary records. Preserve an exact
        # semantic backup before atomically removing those ambiguous records from active context.
        # The digest makes retries idempotent and the backup makes the quarantine reversible.
        canonical = json.dumps(
            data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        backup_dir = _reject_link_ancestors(
            Path(directory) / "migration-quarantine",
            "safety migration quarantine")
        existing_backups = list(backup_dir.glob(
            "active-v1-unsafe-preference-fields-*.json")) \
            if backup_dir.is_dir() else []
        backup = _reject_link_ancestors(
            backup_dir /
            f"active-v1-unsafe-preference-fields-{digest}.json",
            "safety migration backup")
        if existing_backups and backup not in existing_backups:
            raise MemoryError(
                "new unsafe v1 records appeared after safety migration; "
                "refusing unbounded quarantine growth")
        if backup.is_file():
            try:
                if backup.stat().st_size > MAX_ACTIVE_STORE_BYTES:
                    raise MemoryError("safety migration backup exceeds its byte bound")
                with backup.open("rb") as stream:
                    backup_raw = stream.read(MAX_ACTIVE_STORE_BYTES + 1)
                if len(backup_raw) > MAX_ACTIVE_STORE_BYTES:
                    raise MemoryError("safety migration backup exceeds its byte bound")
                existing = json.loads(backup_raw.decode("utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise MemoryError(f"safety migration backup is unreadable: {exc}") from exc
            if existing != data:
                raise MemoryError("safety migration backup digest collision or corruption")
        else:
            _atomic_bytes(backup, raw)
        data["records"] = safe_records
        _atomic_store(path, data)
    elif lifecycle_migrated:
        data["records"] = safe_records
        _atomic_store(path, data)
    return data


def read_store(home, instance_id):
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        return _read_store_locked(directory, instance_id)


def _link_file_noreplace(source, destination, label):
    """Create a no-copy recovery name without replacing or deleting any entry."""
    source = _reject_link_ancestors(source, f"{label} source")
    destination = _reject_link_ancestors(destination, f"{label} destination")
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError as exc:
        try:
            if source.is_file() and destination.is_file() \
                    and os.path.samefile(source, destination):
                return "already-linked"
        except OSError as inspect_exc:
            raise MemoryError(
                f"cannot inspect existing {label} destination: {inspect_exc}") \
                from inspect_exc
        raise MemoryError(f"{label} destination appeared; refusing overwrite") from exc
    except OSError as exc:
        raise MemoryError(f"cannot create no-replace {label} link: {exc}") from exc
    return "linked"


def stage_oversized_recovery(home, instance_id):
    """Stage one no-copy recovery name; retain active so execution remains blocked."""
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        active = _reject_link_ancestors(
            directory / "active.json", "active memory")
        try:
            size = active.stat().st_size
        except OSError as exc:
            raise MemoryError(f"cannot stat oversized active memory: {exc}") from exc
        if size <= MAX_ACTIVE_STORE_BYTES:
            raise MemoryError("active memory is within its byte bound; recovery refused")
        recovery_dir = _reject_link_ancestors(
            directory / "oversized-recovery", "oversized recovery directory")
        try:
            recovery_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise MemoryError(f"cannot create oversized recovery directory: {exc}") from exc
        recovery = _reject_link_ancestors(
            recovery_dir / "active.json", "oversized recovery path")
        movement = _link_file_noreplace(
            active, recovery, "oversized recovery staging")
        return {"bytes": size, "status": "recovery-linked-blocking",
                "movement": movement}


def restore_oversized_store(home, instance_id):
    """Recreate a missing active name without overwriting or deleting the recovery name."""
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        active = _reject_link_ancestors(
            directory / "active.json", "active memory")
        recovery = _reject_link_ancestors(
            directory / "oversized-recovery" / "active.json",
            "oversized recovery path")
        try:
            if not recovery.is_file():
                raise MemoryError("oversized recovery source is unavailable")
            size = recovery.stat().st_size
        except OSError as exc:
            raise MemoryError(f"cannot inspect oversized recovery source: {exc}") from exc
        movement = _link_file_noreplace(
            recovery, active, "oversized restore")
        return {"bytes": size, "status": "restored-still-blocking",
                "movement": movement}


def _read_legacy_marker(path):
    path = _reject_link_ancestors(path, "legacy migration marker")
    if not path.is_file():
        return {"schema_version": SCHEMA_VERSION, "sources": {}}
    try:
        marker = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryError(f"legacy migration marker is unreadable: {exc}") from exc
    if not isinstance(marker, dict) or marker.get("schema_version") != SCHEMA_VERSION \
            or not isinstance(marker.get("sources"), dict) \
            or not all(isinstance(name, str)
                       and isinstance(digest, str)
                       and DIGEST_RE.fullmatch(digest)
                       for name, digest in marker.get("sources", {}).items()):
        raise MemoryError("legacy migration marker is invalid")
    return marker


def legacy_quarantine_digests(home):
    """Return source digests proven copied into at least one inactive instance quarantine."""
    home = _reject_link_ancestors(home, "Loom home")
    instances = home / "instances"
    _reject_link_ancestors(instances, "instance storage")
    result = {}
    if not instances.is_dir():
        return result
    for directory in sorted(path for path in instances.iterdir() if path.is_dir()):
        _reject_link_ancestors(directory, "instance partition")
        _validate_instance_id(directory.name)
        marker = _read_legacy_marker(directory / "legacy-migration.json")
        for name, digest in marker["sources"].items():
            result.setdefault(name, set()).add(digest)
    return result


def validate_instance(home, instance_id):
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    findings = []
    metadata = directory / "instance.json"
    metadata = _reject_link_ancestors(metadata, "instance metadata")
    try:
        meta = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        findings.append(f"invalid instance metadata: {exc}")
    else:
        if not isinstance(meta, dict):
            findings.append("instance metadata has unknown/missing fields")
        else:
            try:
                _require_exact_fields(meta, INSTANCE_FIELDS, "instance metadata")
            except MemoryError as exc:
                findings.append(str(exc))
            if type(meta.get("schema_version")) is not int \
                    or meta.get("schema_version") != SCHEMA_VERSION \
                    or meta.get("instance_id") != instance_id:
                findings.append("instance metadata header mismatch")
    store = read_store(home, instance_id)
    try:
        _read_legacy_marker(directory / "legacy-migration.json")
    except MemoryError as exc:
        findings.append(str(exc))
    if len(store["records"]) > MAX_ACTIVE_RECORDS + 64:
        findings.append("active store exceeds its hard record bound")
    preferences = {}
    hard_stop_count = 0
    for record in store["records"]:
        try:
            _validate_record(record)
        except MemoryError as exc:
            findings.append(f"record {record.get('id', '?')}: {exc}")
        if record.get("status") == "active" \
                and record.get("preference_key") in SINGLETON_PREFERENCE_KEYS:
            key = (record["preference_key"], record.get("domain"))
            if key in preferences:
                findings.append(
                    f"duplicate active preference key '{key[0]}' in scope '{key[1]}'")
            preferences[key] = record.get("id")
        if _is_mandatory_hard_stop(record):
            hard_stop_count += 1
    if hard_stop_count > MAX_HARD_STOPS:
        findings.append(SAFETY_CAPACITY_ERROR)
    for name in ("outbox.jsonl",):
        path = directory / name
        try:
            values = _read_jsonl(path)
        except MemoryError as exc:
            findings.append(str(exc))
            continue
        for value in values:
            try:
                _validate_feedback_entry(value, instance_id)
            except MemoryError as exc:
                findings.append(f"{name}: {exc}")
        if name == "outbox.jsonl" and len(values) > MAX_OUTBOX_ENTRIES:
            findings.append("feedback outbox exceeds its hard entry bound")
    try:
        outcomes = _read_outcome_store(directory, instance_id)
    except MemoryError as exc:
        findings.append(str(exc))
    else:
        if len(outcomes["records"]) > MAX_OUTCOMES_ACTIVE:
            findings.append("outcome store exceeds its hard active bound")
        if len(outcomes["partitions"]) > MAX_OUTCOME_PARTITIONS:
            findings.append("outcome store exceeds its hard partition bound")
    return findings


def _validate_record(record):
    _require_exact_fields(record, MEMORY_RECORD_FIELDS, "memory record")
    if not isinstance(record.get("id"), str):
        raise MemoryError("memory id must be a UUID string")
    try:
        uuid.UUID(record["id"])
    except ValueError as exc:
        raise MemoryError("memory id must be a UUID") from exc
    if record.get("scope") not in SCOPES:
        raise MemoryError("invalid memory scope")
    if record.get("category") not in CATEGORIES:
        raise MemoryError("invalid memory category")
    if record.get("provenance") not in PROVENANCE:
        raise MemoryError("invalid provenance")
    if record.get("status") not in STATUSES:
        raise MemoryError("invalid memory status")
    if not isinstance(record.get("statement"), str) \
            or not record["statement"].strip() or len(record["statement"]) > 1000:
        raise MemoryError("memory statement is empty")
    if type(record.get("confidence")) not in (int, float):
        raise MemoryError("memory confidence must be numeric")
    confidence = float(record["confidence"])
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise MemoryError("memory confidence must be in [0, 1]")
    _validate_timestamp(record.get("created_at"), "created_at")
    _validate_timestamp(record.get("last_confirmed"), "last_confirmed")
    _validate_timestamp(record.get("expires_at"), "expires_at", nullable=True)
    if not isinstance(record.get("supersedes"), list):
        raise MemoryError("supersedes must be a list")
    for prior_id in record["supersedes"]:
        if not isinstance(prior_id, str):
            raise MemoryError("supersedes contains a non-string UUID")
        try:
            uuid.UUID(prior_id)
        except ValueError as exc:
            raise MemoryError("supersedes contains an invalid UUID") from exc
    domain, project = record.get("domain"), record.get("project_id")
    if domain is not None and (not isinstance(domain, str)
                               or not ID_RE.fullmatch(domain)):
        raise MemoryError("domain must be a safe local identifier")
    if project is not None and (not isinstance(project, str)
                                or not PROJECT_ID_RE.fullmatch(project)):
        raise MemoryError("project_id must be generated by loom_memory project-id")
    if record["scope"] == "global" and (domain or project):
        raise MemoryError("global memory cannot carry domain/project identity")
    if record["scope"] == "global" and record["category"] == "domain":
        raise MemoryError("domain-category memory cannot be global")
    if record["scope"] == "domain" and (not domain or project):
        raise MemoryError("domain memory requires domain and forbids project_id")
    if record["scope"] == "project" and (not domain or not project):
        raise MemoryError("project memory requires both domain and project_id")
    if record["scope"] == "temporary" and not domain:
        raise MemoryError("temporary memory requires an explicit domain")
    if record["category"] == "domain" and not domain:
        raise MemoryError("domain-category memory requires an explicit domain")
    preference_key = record.get("preference_key")
    preference_value = record.get("preference_value")
    if record["category"] != "preference" \
            and (preference_key is not None or preference_value is not None):
        raise MemoryError("non-preference records must keep preference fields null")
    if record["status"] == "forgotten" \
            and (preference_key is not None or preference_value is not None):
        raise MemoryError("forgotten records must keep preference fields null")
    if record["status"] == "active" and record["category"] == "preference" \
            and (not preference_key or preference_value is None):
        raise MemoryError("preference records must use the typed preference API")
    if record["status"] == "active" and record["category"] == "preference" \
            and record["provenance"] != "stated":
        raise MemoryError("active preferences require stated provenance")
    if record["status"] == "active" and record["category"] == "preference":
        key = preference_key
        if key not in PREFERENCE_KEYS:
            raise MemoryError("preference key is unsupported")
        if key in DOMAIN_PREFERENCE_KEYS and record["scope"] != "domain":
            raise MemoryError("domain preference has the wrong scope")
        if key in GENERAL_PREFERENCE_KEYS and record["scope"] != "global":
            raise MemoryError("general preference has the wrong scope")
    for field in ("preference_key", "preference_value"):
        if record.get(field) is not None and not isinstance(record[field], str):
            raise MemoryError(f"{field} must be a string or null")
    if preference_key == "hard_stop" \
            and record.get("expires_at") is not None:
        raise MemoryError("mandatory hard stops cannot expire")
    if record["scope"] == "temporary" and not record.get("expires_at"):
        raise MemoryError("temporary memory requires expires_at")
    if isinstance(record.get("evidence_count"), bool) \
            or not isinstance(record.get("evidence_count"), int) \
            or record["evidence_count"] < 1:
        raise MemoryError("evidence_count must be a positive integer")
    for field in ("last_selected", "last_applied", "last_helped", "last_hurt",
                  "verify_by"):
        _validate_timestamp(record.get(field), field, nullable=True)
    for field in ("selection_count", "application_count", "helped_count", "hurt_count"):
        if type(record.get(field)) is not int or record[field] < 0:
            raise MemoryError(f"{field} must be a non-negative integer")
    if record["application_count"] > record["selection_count"] \
            or record["helped_count"] + record["hurt_count"] > record["application_count"]:
        raise MemoryError("memory usage counters are inconsistent")
    if not isinstance(record.get("evidence_projects"), list) \
            or len(record["evidence_projects"]) > 64 \
            or len(record["evidence_projects"]) != len(set(record["evidence_projects"])) \
            or not all(isinstance(item, str) and PROJECT_ID_RE.fullmatch(item)
                       for item in record["evidence_projects"]):
        raise MemoryError("evidence_projects must be bounded unique project IDs")
    if type(record.get("utility_score")) not in (int, float) \
            or not math.isfinite(record["utility_score"]) \
            or not -1 <= float(record["utility_score"]) <= 1:
        raise MemoryError("utility_score must be finite and in [-1, 1]")


def _new_record(*, scope, category, statement, provenance, evidence_count=1,
                domain=None, project_id=None, confidence=0.5, expires_at=None,
                preference_key=None, preference_value=None, evidence_projects=None,
                verify_by=None):
    now = _now()
    if not isinstance(statement, str):
        raise MemoryError("memory statement must be a string")
    record = {
        "id": str(uuid.uuid4()),
        "scope": scope,
        "category": category,
        "statement": re.sub(r"\s+", " ", statement).strip(),
        "provenance": provenance,
        "evidence_count": evidence_count,
        "confidence": confidence,
        "domain": domain,
        "project_id": project_id,
        "created_at": now,
        "last_confirmed": now,
        "expires_at": expires_at,
        "status": "active",
        "supersedes": [],
        "preference_key": preference_key,
        "preference_value": preference_value,
        "last_selected": None,
        "last_applied": None,
        "last_helped": None,
        "last_hurt": None,
        "selection_count": 0,
        "application_count": 0,
        "helped_count": 0,
        "hurt_count": 0,
        "evidence_projects": sorted(set(
            evidence_projects or ([project_id] if project_id else []))),
        "utility_score": 0.0,
        "verify_by": verify_by,
    }
    _validate_record(record)
    return record


def add_record(home, instance_id, *, scope, category, statement, provenance,
               evidence_count=1, domain=None, project_id=None, confidence=0.5,
               expires_at=None, preference_key=None, preference_value=None):
    if category == "preference" or preference_key is not None \
            or preference_value is not None:
        raise MemoryError(
            "generic records cannot carry preference fields; use the typed preference API")
    if scope == "global":
        raise MemoryError(
            "global observations require typed stated preferences or typed learning admission")
    instance_id = _validate_instance_id(instance_id)
    record = _new_record(
        scope=scope, category=category, statement=statement,
        provenance=provenance, evidence_count=evidence_count, domain=domain,
        project_id=project_id, confidence=confidence, expires_at=expires_at,
        preference_key=preference_key, preference_value=preference_value)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        _reject_forgotten(directory, record)
        store = _read_store_locked(directory, instance_id)
        store["records"].append(record)
        if len(store["records"]) > MAX_ACTIVE_RECORDS:
            store, _ = _compact_records(directory, store)
        _atomic_store(directory / "active.json", store)
    return record


def admit_learning(home, instance_id, *, scope, category, signal, future_decision,
                   evidence_count, confidence, domain=None, project_id=None,
                   evidence_projects=None, verify_by=None):
    """Admit only thresholded, controlled learning; never caller-authored prose."""
    if scope not in {"global", "domain", "project"} \
            or category not in {"calibration", "process", "domain"} \
            or not isinstance(signal, str) or not ID_RE.fullmatch(signal) \
            or not isinstance(future_decision, str) or not ID_RE.fullmatch(future_decision):
        raise MemoryError("typed learning admission fields are invalid")
    minimum = {"global": 3, "domain": 3, "project": 2}[scope]
    if type(evidence_count) is not int or evidence_count < minimum:
        raise MemoryError("typed learning admission lacks repeated evidence")
    statement = (
        f"When deciding {future_decision}, account for the observed signal {signal}."
    )
    instance_id = _validate_instance_id(instance_id)
    record = _new_record(
        scope=scope, category=category, statement=statement,
        provenance="inferred", evidence_count=evidence_count, domain=domain,
        project_id=project_id, confidence=confidence,
        evidence_projects=evidence_projects, verify_by=verify_by)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        _reject_forgotten(directory, record)
        store = _read_store_locked(directory, instance_id)
        existing = next((item for item in store["records"]
                         if item.get("status") == "active"
                         and item.get("scope") == scope
                         and item.get("category") == category
                         and item.get("domain") == domain
                         and item.get("project_id") == project_id
                         and item.get("statement") == statement), None)
        if existing is not None:
            return existing
        store["records"].append(record)
        store, _ = _compact_records(directory, store)
        _atomic_store(directory / "active.json", store)
    return record


def maintain_lifecycle(home, instance_id, *, now=None, inactive_days=90):
    """Lazily remove obsolete context while preserving all evidence reversibly."""
    if type(inactive_days) is not int or not 7 <= inactive_days <= 3650:
        raise MemoryError("inactive_days must be between 7 and 3650")
    instant_text = _now_at(now)
    instant = _timestamp_value(instant_text)
    cutoff = instant - dt.timedelta(days=inactive_days)
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    result = {"dormant": 0, "stale": 0, "archived": 0}
    archived = []
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, instance_id)
        kept = []
        for record in store["records"]:
            if _is_mandatory_hard_stop(record):
                kept.append(record)
                continue
            if record.get("status") == "active" and record.get("verify_by") \
                    and _timestamp_value(record["verify_by"]) < instant:
                record["status"] = "stale"
                result["stale"] += 1
            elif record.get("status") == "active" and record.get("scope") == "domain" \
                    and record.get("helped_count", 0) < 2:
                last_use = record.get("last_selected") or record.get("last_confirmed")
                if _timestamp_value(last_use) < cutoff:
                    record["status"] = "dormant"
                    result["dormant"] += 1
            if record.get("expires_at") \
                    and _timestamp_value(record["expires_at"]) < instant \
                    and record.get("status") not in {"forgotten", "superseded"}:
                record["status"] = "archived"
                archived.append(record)
                result["archived"] += 1
            else:
                kept.append(record)
        store["records"] = kept
        _append_archive(
            directory, archived, {item["id"]: "expired" for item in archived})
        _atomic_store(directory / "active.json", store)
    return result


def set_preference(home, instance_id, key, value, *, provenance="stated", domain=None):
    if key not in PREFERENCE_KEYS:
        raise MemoryError(f"unsupported preference key: {key}")
    value = str(value).strip()
    if not value or len(value) > 200 or "\n" in value or "\r" in value:
        raise MemoryError("preference value must be one non-empty line up to 200 characters")
    if key == "autonomy_default" and value not in {"A0", "A1", "A2", "A3"}:
        raise MemoryError("autonomy_default must be A0, A1, A2, or A3")
    if key in DOMAIN_PREFERENCE_KEYS:
        if not isinstance(domain, str) or not ID_RE.fullmatch(domain):
            raise MemoryError(f"{key} requires an explicit domain")
        scope = "domain"
    else:
        if domain:
            raise MemoryError(f"{key} is general and cannot carry a domain")
        scope = "global"
        if RAW_PATH_RE.search(value):
            raise MemoryError("global transferable memory cannot contain a raw local path")
    instance_id = _validate_instance_id(instance_id)
    record = _new_record(
        scope=scope, category="preference", statement=f"{key}={value}",
        provenance=provenance, domain=domain, preference_key=key,
        preference_value=value)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        _reject_forgotten(directory, record)
        store = _read_store_locked(directory, instance_id)
        if key == "hard_stop":
            active_hard_stops = [
                prior for prior in store["records"]
                if _is_mandatory_hard_stop(prior)
            ]
            duplicate = any(
                _normal_statement(prior.get("preference_value"))
                == _normal_statement(value) for prior in active_hard_stops)
            if not duplicate and len(active_hard_stops) >= MAX_HARD_STOPS:
                raise MemoryError(
                    f"hard-stop cap {MAX_HARD_STOPS} reached; explicitly forget an "
                    "obsolete hard stop before adding another")
        superseded = []
        for prior in store["records"]:
            if key in SINGLETON_PREFERENCE_KEYS \
                    and prior.get("status") == "active" \
                    and prior.get("preference_key") == key \
                    and prior.get("domain") == domain:
                prior["status"] = "superseded"
                superseded.append(prior["id"])
        record["supersedes"] = sorted(set(superseded))
        store["records"].append(record)
        store, _ = _compact_records(directory, store)
        _atomic_store(directory / "active.json", store)
    return record


def _normal_statement(value):
    return re.sub(r"\s+", " ", str(value)).strip().casefold()


def _is_mandatory_hard_stop(record):
    return (
        record.get("status") == "active"
        and record.get("category") == "preference"
        and record.get("provenance") == "stated"
        and record.get("scope") == "global"
        and record.get("domain") is None
        and record.get("project_id") is None
        and record.get("preference_key") == "hard_stop"
        and isinstance(record.get("preference_value"), str)
        and record.get("expires_at") is None
    )


def _record_rank(record):
    provenance_rank = {"stated": 3, "observed": 2, "inferred": 1}
    return (
        1 if _is_mandatory_hard_stop(record) else 0,
        float(record.get("utility_score", 0)),
        int(record.get("helped_count", 0)) - int(record.get("hurt_count", 0)),
        provenance_rank.get(record.get("provenance"), 0),
        int(record.get("evidence_count", 0)),
        str(record.get("last_confirmed", "")),
    )


def _append_archive(directory, records, reason):
    if not records:
        return
    archived_at = _now()
    values = []
    for record in records:
        values.append({
            "schema_version": SCHEMA_VERSION,
            "instance_id": _validate_instance_id(Path(directory).name),
            "archived_at": archived_at,
            "reason": reason.get(record["id"], "compacted"),
            "record": record,
        })
    _append_archive_lines(Path(directory) / "archive.jsonl", values)


def _compact_records(directory, store):
    now = dt.datetime.now(dt.timezone.utc)
    archived, reasons, deduplicated = [], {}, 0
    kept = []
    by_key = {}
    for record in store["records"]:
        if record.get("status") in {"archived", "forgotten", "superseded"} \
                or (record.get("expires_at")
                    and _timestamp_value(record["expires_at"]) < now):
            archived.append(record)
            reasons[record["id"]] = record.get("status", "expired")
            continue
        if record.get("status") not in {"active", "dormant", "stale"}:
            kept.append(record)
            continue
        key = (
            record["scope"], record.get("domain"), record.get("project_id"),
            record["category"], _normal_statement(record["statement"]),
        )
        prior = by_key.get(key)
        if prior is None:
            by_key[key] = record
            kept.append(record)
            continue
        winner, loser = (prior, record) if _record_rank(prior) >= _record_rank(record) \
            else (record, prior)
        winner["evidence_count"] = int(prior["evidence_count"]) \
            + int(record["evidence_count"])
        winner["last_confirmed"] = max(
            str(prior["last_confirmed"]), str(record["last_confirmed"]))
        winner["confidence"] = max(
            float(prior.get("confidence", 0)), float(record.get("confidence", 0)))
        winner["supersedes"] = sorted(set(
            prior.get("supersedes", []) + record.get("supersedes", []) + [loser["id"]]))
        winner["evidence_projects"] = sorted(set(
            prior.get("evidence_projects", []) + record.get("evidence_projects", [])))[-64:]
        for field in ("selection_count", "application_count", "helped_count", "hurt_count"):
            winner[field] = int(prior.get(field, 0)) + int(record.get(field, 0))
        for field in ("last_selected", "last_applied", "last_helped", "last_hurt"):
            winner[field] = max(
                (value for value in (prior.get(field), record.get(field)) if value),
                default=None)
        applications = winner["application_count"]
        winner["utility_score"] = (max(-1.0, min(1.0, (
            winner["helped_count"] - 1.5 * winner["hurt_count"]
        ) / applications)) if applications else max(
            float(prior.get("utility_score", 0)),
            float(record.get("utility_score", 0))))
        if winner is record:
            kept[kept.index(prior)] = record
            by_key[key] = record
        archived.append(loser)
        reasons[loser["id"]] = "deduplicated"
        deduplicated += 1

    active = [record for record in kept
              if record.get("status") in {"active", "dormant", "stale"}]
    partitions = {}
    for record in active:
        key = (record["scope"], record.get("domain"), record.get("project_id"))
        partitions.setdefault(key, []).append(record)
    survivors = []
    for key, records in partitions.items():
        records.sort(key=_record_rank, reverse=True)
        cap = PARTITION_CAPS[key[0]]
        survivors.extend(records[:cap])
        for record in records[cap:]:
            archived.append(record)
            reasons[record["id"]] = "partition-cap"
    survivors.sort(key=_record_rank, reverse=True)
    for record in survivors[MAX_ACTIVE_RECORDS:]:
        archived.append(record)
        reasons[record["id"]] = "global-cap"
    survivors = survivors[:MAX_ACTIVE_RECORDS]
    store["records"] = survivors
    _append_archive(directory, archived, reasons)
    return store, {
        "active": len(survivors),
        "inactive": sum(record.get("status") != "active" for record in survivors),
        "archived": len(archived),
        "deduplicated": deduplicated,
    }


def compact(home, instance_id):
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, _validate_instance_id(instance_id))
        store, result = _compact_records(directory, store)
        _atomic_store(directory / "active.json", store)
    return result


def close_project(home, instance_id, project_id, *, now=None):
    """Remove project-only operational memory from context without deleting it."""
    if not isinstance(project_id, str) or not PROJECT_ID_RE.fullmatch(project_id):
        raise MemoryError("close_project requires a generated project_id")
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    archived = []
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, instance_id)
        kept = []
        for record in store["records"]:
            if record.get("scope") == "project" \
                    and record.get("project_id") == project_id \
                    and record.get("status") in {"active", "dormant", "stale"}:
                record["status"] = "archived"
                record["last_confirmed"] = _now_at(now)
                archived.append(record)
            else:
                kept.append(record)
        store["records"] = kept
        _append_archive(
            directory, archived, {item["id"]: "project-closed" for item in archived})
        _atomic_store(directory / "active.json", store)
    return {"archived": len(archived), "project_id": project_id}


def inspect_record(home, instance_id, record_id):
    """Inspect one record across active and inactive storage without reactivating it."""
    try:
        canonical = str(uuid.UUID(record_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MemoryError("record_id must be a UUID") from exc
    if canonical != record_id:
        raise MemoryError("record_id must be canonical")
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        tombstones = _read_tombstones(directory)
        if any(item["record_id"] == record_id for item in tombstones["entries"]):
            return {"id": record_id, "status": "forgotten", "content_erased": True}
        store = _read_store_locked(directory, instance_id)
        active = next((item for item in store["records"] if item["id"] == record_id), None)
        if active is not None:
            return json.loads(json.dumps(active))
        for wrapper in reversed(_read_archive(directory / "archive.jsonl")):
            record = wrapper.get("record") if isinstance(wrapper, dict) else None
            if isinstance(record, dict) and record.get("id") == record_id:
                return json.loads(json.dumps(record))
    return None


def forget(home, instance_id, record_id):
    try:
        canonical = str(uuid.UUID(record_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MemoryError("record_id must be a UUID") from exc
    if canonical != record_id:
        raise MemoryError("record_id must be canonical")
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, _validate_instance_id(instance_id))
        archive_path = directory / "archive.jsonl"
        archived_wrappers = _read_archive(archive_path)
        target = next((record for record in store["records"]
                       if record.get("id") == record_id), None)
        if target is None:
            target = next((wrapper.get("record") for wrapper in archived_wrappers
                           if isinstance(wrapper, dict)
                           and isinstance(wrapper.get("record"), dict)
                           and wrapper["record"].get("id") == record_id), None)
        tombstones = _read_tombstones(directory)
        if target is None:
            return any(item["record_id"] == record_id for item in tombstones["entries"])
        fingerprint = _semantic_fingerprint(target)
        if not any(item["semantic_fingerprint"] == fingerprint
                   for item in tombstones["entries"]):
            if len(tombstones["entries"]) >= MAX_TOMBSTONES:
                raise MemoryError(
                    "forgetting ledger is full; compact it explicitly before forgetting more")
            tombstones["entries"].append({
                "record_id": record_id,
                "semantic_fingerprint": fingerprint,
                "forgotten_at": _now(),
            })
            _atomic_json(directory / "tombstones.json", tombstones)
        store["records"] = [record for record in store["records"]
                            if record.get("id") != record_id]
        _atomic_store(directory / "active.json", store)
        kept_wrappers = [
            wrapper for wrapper in archived_wrappers
            if not (isinstance(wrapper, dict)
                    and isinstance(wrapper.get("record"), dict)
                    and wrapper["record"].get("id") == record_id)
        ]
        if kept_wrappers != archived_wrappers:
            text = "".join(json.dumps(
                wrapper, sort_keys=True, ensure_ascii=False,
                separators=(",", ":")) + "\n" for wrapper in kept_wrappers)
            _atomic_text(archive_path, text)
    return True


def select(home, instance_id, *, domain=None, project_id=None,
           max_chars=MAX_SELECT_CHARS, now=None):
    if domain is None:
        domains = []
    elif isinstance(domain, str):
        domains = [domain]
    elif isinstance(domain, (list, tuple, set)):
        domains = list(domain)
    else:
        raise MemoryError("domain selection must be a string or list of strings")
    if any(not isinstance(value, str) for value in domains):
        raise MemoryError("domain selection must contain only strings")
    domains = list(dict.fromkeys(domains))
    if any(not ID_RE.fullmatch(value) for value in domains):
        raise MemoryError("domain must be a safe local identifier")
    domain_set = set(domains)
    if project_id and not domain_set:
        raise MemoryError("project selection requires an explicit domain")
    if project_id and (not isinstance(project_id, str)
                       or not PROJECT_ID_RE.fullmatch(project_id)):
        raise MemoryError("project_id must be generated by loom_memory project-id")
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError) as exc:
        raise MemoryError("max_chars must be an integer") from exc
    if not 1 <= max_chars <= MAX_SELECT_CHARS:
        raise MemoryError(
            f"max_chars must be between 1 and {MAX_SELECT_CHARS}")
    instant_text = _now_at(now)
    instant = _timestamp_value(instant_text)
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, instance_id)
        records = []
        for record in store["records"]:
            if record.get("status") != "active":
                continue
            if record.get("expires_at") \
                    and _timestamp_value(record["expires_at"]) < instant:
                continue
            scope = record.get("scope")
            relevant = (
                scope == "global"
                or (scope == "domain" and record.get("domain") in domain_set)
                or (scope == "project" and domain_set and project_id
                    and record.get("domain") in domain_set
                    and record.get("project_id") == project_id)
                or (scope == "temporary"
                    and record.get("domain") in domain_set
                    and (not record.get("project_id")
                         or record.get("project_id") == project_id))
            )
            if relevant:
                scope_weight = {
                    "global": 1.0, "domain": 2.0, "project": 3.0,
                    "temporary": 2.5,
                }[scope]
                recency_days = max(0.0, (instant - _timestamp_value(
                    record.get("last_confirmed"))).total_seconds() / 86400)
                recency = max(0.0, 1.0 - recency_days / 365.0)
                value = (
                    scope_weight + float(record["confidence"])
                    + min(1.0, math.log2(record["evidence_count"] + 1) / 4)
                    + recency + float(record.get("utility_score", 0))
                )
                cost = len(json.dumps(record, ensure_ascii=False)) + 1
                records.append((record, value, cost, value / cost))
        hard_stops = [item for item in records if _is_mandatory_hard_stop(item[0])]
        if len(hard_stops) > MAX_HARD_STOPS:
            raise MemoryError(SAFETY_CAPACITY_ERROR)
        ordinary = [item for item in records if item not in hard_stops]
        ordinary.sort(key=lambda item: (
            item[3], item[1], item[0]["evidence_count"],
            item[0]["last_confirmed"]), reverse=True)
        selected, used = [item[0] for item in hard_stops], 2
        used += sum(item[2] for item in hard_stops)
        for record, _value, cost, marginal in ordinary:
            if marginal < 0.003:
                break
            if used + cost > max_chars:
                continue
            selected.append(record)
            used += cost
        for record in selected:
            record["last_selected"] = instant_text
            record["selection_count"] += 1
        if selected:
            _atomic_store(directory / "active.json", store)
        return json.loads(json.dumps(selected))


def record_application(home, instance_id, record_id, *, outcome, project_id=None,
                       now=None):
    """Record actual use separately from selection and update observed utility."""
    if outcome not in {"helped", "hurt", "neutral"}:
        raise MemoryError("application outcome must be helped, hurt, or neutral")
    if project_id is not None and (not isinstance(project_id, str)
                                   or not PROJECT_ID_RE.fullmatch(project_id)):
        raise MemoryError("application project_id is invalid")
    instant = _now_at(now)
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, instance_id)
        record = next((item for item in store["records"]
                       if item.get("id") == record_id
                       and item.get("status") in {"active", "dormant"}), None)
        if record is None:
            raise MemoryError("applied memory is unavailable or inactive")
        if record["application_count"] >= record["selection_count"]:
            raise MemoryError("memory cannot be applied without a prior unused selection")
        record["last_applied"] = instant
        record["application_count"] += 1
        if project_id:
            record["evidence_projects"] = sorted(set(
                record["evidence_projects"] + [project_id]))[-64:]
        if outcome == "helped":
            if record["status"] == "dormant":
                record["status"] = "active"
            record["last_helped"] = instant
            record["last_confirmed"] = instant
            record["helped_count"] += 1
        elif outcome == "hurt":
            record["last_hurt"] = instant
            record["hurt_count"] += 1
        applications = record["application_count"]
        record["utility_score"] = max(-1.0, min(1.0, (
            record["helped_count"] - 1.5 * record["hurt_count"]
        ) / applications))
        if record["hurt_count"] >= 2 \
                and record["hurt_count"] > record["helped_count"]:
            record["status"] = "dormant"
        _atomic_store(directory / "active.json", store)
        return json.loads(json.dumps(record))


def rehydrate_domain(home, instance_id, *, domain, project_id=None,
                     max_records=3, max_chars=1600, now=None):
    """Return one bounded exact-domain capsule without scanning archived history."""
    if not isinstance(domain, str) or not ID_RE.fullmatch(domain):
        raise MemoryError("rehydration requires one safe domain")
    if project_id is not None and (not isinstance(project_id, str)
                                   or not PROJECT_ID_RE.fullmatch(project_id)):
        raise MemoryError("rehydration project_id is invalid")
    if type(max_records) is not int or not 1 <= max_records <= 4:
        raise MemoryError("rehydration max_records must be between 1 and 4")
    if type(max_chars) is not int or not 256 <= max_chars <= 4000:
        raise MemoryError("rehydration max_chars must be between 256 and 4000")
    instant_text = _now_at(now)
    instant = _timestamp_value(instant_text)
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, instance_id)
        candidates = []
        for record in store["records"]:
            if record.get("scope") != "domain" or record.get("domain") != domain \
                    or record.get("status") not in {"dormant", "stale"}:
                continue
            if record.get("verify_by") \
                    and _timestamp_value(record["verify_by"]) < instant:
                record["status"] = "stale"
            useful = (
                record.get("status") == "dormant"
                and record.get("helped_count", 0) > record.get("hurt_count", 0)
                and float(record.get("utility_score", 0)) > 0
            )
            rank = (
                1 if useful else 0,
                1 if record.get("status") == "stale" else 0,
                float(record.get("utility_score", 0)),
                int(record.get("helped_count", 0)),
                int(record.get("evidence_count", 0)),
                float(record.get("confidence", 0)),
            )
            candidates.append((rank, record, useful))
        candidates.sort(key=lambda item: item[0], reverse=True)
        capsule, used = [], 2
        reactivated, verification, dormant = [], [], []
        for _rank, record, useful in candidates:
            if useful:
                record["status"] = "active"
                record["last_confirmed"] = instant_text
                reactivated.append(record["id"])
                continue
            if len(capsule) >= max_records:
                break
            cost = len(json.dumps(record, ensure_ascii=False)) + 1
            if used + cost > max_chars:
                continue
            record["last_selected"] = instant_text
            record["selection_count"] += 1
            capsule.append(json.loads(json.dumps(record)))
            used += cost
            if record["status"] == "stale":
                verification.append(record["id"])
            else:
                dormant.append(record["id"])
        if reactivated or capsule:
            _atomic_store(directory / "active.json", store)
        return {
            "domain": domain,
            "project_id": project_id,
            "capsule": capsule,
            "reactivated_ids": reactivated,
            "verification_required_ids": verification,
            "dormant_review_ids": dormant,
            "record_count": len(capsule),
            "character_count": used,
            "archive_records_scanned": 0,
        }


def record_verification(home, instance_id, record_id, *, verified,
                        verify_by=None, now=None):
    """Resolve a stale returned memory using explicit verification evidence."""
    if type(verified) is not bool:
        raise MemoryError("verified must be boolean")
    instant = _now_at(now)
    if verify_by is None and verified:
        deadline = _timestamp_value(instant) + dt.timedelta(days=90)
        verify_by = deadline.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    elif verify_by is not None:
        _validate_timestamp(verify_by, "verify_by")
        if _timestamp_value(verify_by) <= _timestamp_value(instant):
            raise MemoryError("verify_by must be after verification time")
    instance_id = _validate_instance_id(instance_id)
    directory = _instance_dir(home, instance_id)
    archived = []
    with FileLock(directory / ".lock"):
        store = _read_store_locked(directory, instance_id)
        record = next((item for item in store["records"]
                       if item.get("id") == record_id
                       and item.get("status") == "stale"), None)
        if record is None:
            raise MemoryError("verification target is unavailable or not stale")
        if record["selection_count"] <= record["application_count"]:
            raise MemoryError("stale memory was not returned for verification")
        record["last_applied"] = instant
        record["application_count"] += 1
        if verified:
            record["status"] = "active"
            record["last_confirmed"] = instant
            record["verify_by"] = verify_by
        else:
            record["status"] = "archived"
            archived.append(record)
            store["records"].remove(record)
            _append_archive(
                directory, archived, {record["id"]: "verification-failed"})
        _atomic_store(directory / "active.json", store)
        return json.loads(json.dumps(record))


def _read_jsonl(path):
    path = _reject_link_ancestors(path, "active JSONL")
    if not path.is_file():
        return []
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise MemoryError(f"cannot stat JSONL {path}: {exc}") from exc
    if size > MAX_OUTBOX_BYTES:
        raise MemoryError(
            f"JSONL {path} exceeds the {MAX_OUTBOX_BYTES}-byte active bound")
    values = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MemoryError(f"invalid JSONL at {path}:{number}: {exc}") from exc
        if not isinstance(value, dict):
            raise MemoryError(f"JSONL entry at {path}:{number} must be an object")
        values.append(value)
        if len(values) > MAX_OUTBOX_ENTRIES:
            raise MemoryError(
                f"JSONL {path} exceeds the {MAX_OUTBOX_ENTRIES}-entry active bound")
    return values


def _validate_feedback_entry(entry, instance_id):
    required = {
        "schema_version", "id", "instance_id", "pattern", "action",
        "evidence_count", "created_at",
    }
    if set(entry) != required:
        raise MemoryError("feedback entry has unknown/missing fields")
    if entry.get("schema_version") != SCHEMA_VERSION \
            or entry.get("instance_id") != _validate_instance_id(instance_id):
        raise MemoryError("feedback entry header is invalid or cross-instance")
    try:
        parsed = str(uuid.UUID(str(entry.get("id"))))
    except ValueError as exc:
        raise MemoryError("feedback entry id is invalid") from exc
    if parsed != entry.get("id"):
        raise MemoryError("feedback entry id is not canonical")
    if entry.get("pattern") not in FEEDBACK_PATTERNS \
            or entry.get("action") not in FEEDBACK_ACTIONS:
        raise MemoryError("feedback entry pattern/action is unsupported")
    count = entry.get("evidence_count")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 1_000_000:
        raise MemoryError("feedback evidence_count must be an integer in [1, 1000000]")
    _validate_timestamp(entry.get("created_at"), "feedback created_at")


def _append_jsonl(path, value):
    path = _reject_link_ancestors(path, "active JSONL")
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    _atomic_text(path, existing + json.dumps(
        value, sort_keys=True, ensure_ascii=False) + "\n")


def _append_archive_lines(path, values):
    """Retain a bounded newest archive tail; old inactive detail is garbage-collected."""
    if not values:
        return
    path = _reject_link_ancestors(path, "archive path")
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_link_ancestors(path, "archive path")
    lines = deque(_archive_tail_lines(path), maxlen=MAX_ARCHIVE_ENTRIES)
    for value in values:
        if not isinstance(value, dict):
            raise MemoryError("archive entries must be objects")
        line = (json.dumps(
            value, sort_keys=True, ensure_ascii=False,
            separators=(",", ":")) + "\n").encode("utf-8")
        if len(line) > MAX_ARCHIVE_LINE_BYTES:
            raise MemoryError("archive entry exceeds its byte bound")
        lines.append(line)
    total = sum(len(line) for line in lines)
    while lines and total > MAX_ARCHIVE_BYTES:
        total -= len(lines.popleft())
    _atomic_bytes(path, b"".join(lines))


def _archive_tail_lines(path):
    """Read only the bounded newest complete lines from a possibly legacy-large archive."""
    path = _reject_link_ancestors(path, "archive path")
    if not path.is_file():
        return []
    try:
        size = path.stat().st_size
        scan = min(size, MAX_ARCHIVE_BYTES + MAX_ARCHIVE_LINE_BYTES)
        with path.open("rb") as stream:
            stream.seek(size - scan)
            raw = stream.read(scan)
    except OSError as exc:
        raise MemoryError(f"cannot read archive tail: {exc}") from exc
    if size > scan:
        boundary = raw.find(b"\n")
        raw = b"" if boundary < 0 else raw[boundary + 1:]
    complete = raw.splitlines(keepends=True)
    if complete and not complete[-1].endswith(b"\n"):
        complete.pop()
    kept = deque(maxlen=MAX_ARCHIVE_ENTRIES)
    total = 0
    for line in reversed(complete):
        if len(line) > MAX_ARCHIVE_LINE_BYTES:
            continue
        if total + len(line) > MAX_ARCHIVE_BYTES:
            break
        kept.appendleft(line)
        total += len(line)
        if len(kept) >= MAX_ARCHIVE_ENTRIES:
            break
    return list(kept)


def _read_archive(path):
    values = []
    for number, line in enumerate(_archive_tail_lines(path), 1):
        try:
            value = json.loads(line.decode("utf-8"), object_pairs_hook=_strict_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise MemoryError(f"invalid archive JSONL at retained line {number}: {exc}") \
                from exc
        if not isinstance(value, dict):
            raise MemoryError("archive entry must be an object")
        values.append(value)
    return values


def queue_feedback(home, instance_id, *, pattern, action, evidence_count):
    instance_id = _validate_instance_id(instance_id)
    if pattern not in FEEDBACK_PATTERNS:
        raise MemoryError(f"unsupported generic feedback pattern: {pattern}")
    if action not in FEEDBACK_ACTIONS:
        raise MemoryError(f"unsupported generic feedback action: {action}")
    if isinstance(evidence_count, bool) or not isinstance(evidence_count, int) \
            or not 1 <= evidence_count <= 1_000_000:
        raise MemoryError("feedback evidence_count must be an integer in [1, 1000000]")
    entry = {
        "schema_version": SCHEMA_VERSION,
        "id": str(uuid.uuid4()),
        "instance_id": instance_id,
        "pattern": pattern,
        "action": action,
        "evidence_count": evidence_count,
        "created_at": _now(),
    }
    _validate_feedback_entry(entry, instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        if len(_read_jsonl(directory / "outbox.jsonl")) >= MAX_OUTBOX_ENTRIES:
            raise MemoryError(
                "feedback outbox is full; contribute or discard entries before adding more")
        _append_jsonl(directory / "outbox.jsonl", entry)
    return entry


def drain_feedback(home, instance_id, *, receiver_instance_id):
    instance_id = _validate_instance_id(instance_id)
    receiver = _validate_instance_id(receiver_instance_id)
    if receiver != instance_id:
        raise MemoryError(
            "cross-instance feedback drain refused: receiver does not own this outbox")
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        path = directory / "outbox.jsonl"
        entries = _read_jsonl(path)
        for entry in entries:
            _validate_feedback_entry(entry, instance_id)
        _atomic_text(path, "")
    return entries


def _feedback_compaction_plan(text, instance_id, max_active, keep_resolved):
    matches = list(re.finditer(r"(?m)^###\s+", text))
    if not matches:
        return text, [], {"total_entries": 0, "active": 0, "archived_now": 0}
    header = text[:matches[0].start()].rstrip()
    entries = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.start():end].strip() + "\n"
        entry_id = hashlib.sha256(body.encode("utf-8")).hexdigest()
        resolved = bool(re.search(r"(?mi)^-\s*(?:✔|\*\*Resolution\s*\()", body))
        entries.append({
            "index": index, "entry_id": entry_id,
            "resolved": resolved, "content": body,
        })
    unresolved = [entry for entry in entries if not entry["resolved"]]
    resolved = [entry for entry in entries if entry["resolved"]]
    keep_unresolved = unresolved[-max_active:]
    remaining = max(0, max_active - len(keep_unresolved))
    keep_resolved_count = min(keep_resolved, remaining)
    keep_resolved_entries = resolved[-keep_resolved_count:] \
        if keep_resolved_count else []
    keep_ids = {entry["entry_id"] for entry in
                keep_unresolved + keep_resolved_entries}
    archived = [entry for entry in entries if entry["entry_id"] not in keep_ids]
    archived_at = _now()
    archive_values = [{
        "schema_version": SCHEMA_VERSION,
        "instance_id": instance_id,
        "entry_id": entry["entry_id"],
        "resolved": entry["resolved"],
        "archived_at": archived_at,
        "reason": ("resolved-history" if entry["resolved"] else "active-queue-cap"),
        "content": entry["content"],
    } for entry in archived]
    kept = sorted(
        [entry for entry in entries if entry["entry_id"] in keep_ids],
        key=lambda entry: entry["index"])
    active_text = header + "\n\n" + "\n".join(
        entry["content"].rstrip() for entry in kept) + "\n"
    return active_text, archive_values, {
        "total_entries": len(entries),
        "active": len(kept),
        "archived_now": len(archive_values),
    }


def contribute(home, instance_id, loom_root):
    """Explicitly move controlled patterns to this same instance's FEEDBACK.md."""
    instance_id = _validate_instance_id(instance_id)
    loom_root = _reject_link_ancestors(loom_root, "receiver installation root")
    marker = loom_root / INSTANCE_MARKER
    try:
        marker = _reject_link_ancestors(marker, "receiver instance marker")
        receiver = _validate_instance_id(marker.read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError, MemoryError) as exc:
        raise MemoryError(f"receiver instance marker is unavailable/invalid: {exc}") from exc
    if receiver != instance_id:
        raise MemoryError("cross-instance contribution refused")
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"), FileLock(loom_root / ".loom-feedback.lock"):
        outbox = directory / "outbox.jsonl"
        entries = _read_jsonl(outbox)
        for entry in entries:
            _validate_feedback_entry(entry, instance_id)
        if not entries:
            return 0
        feedback = loom_root / "FEEDBACK.md"
        feedback = _reject_link_ancestors(feedback, "FEEDBACK.md")
        text = (feedback.read_text(encoding="utf-8") if feedback.is_file()
                else "# FEEDBACK\n\n## Queue\n")
        if text and not text.endswith("\n"):
            text += "\n"
        appended = 0
        today = dt.date.today().isoformat()
        for entry in entries:
            marker_text = f"loom-feedback:{entry['id']}"
            if marker_text in text:
                continue
            text += (
                f"\n### {today} — typed-memory — loom-core\n"
                f"- saw: controlled pattern `{entry['pattern']}` "
                f"(evidence_count: {entry['evidence_count']})\n"
                f"- fix: controlled action `{entry['action']}`\n"
                f"<!-- {marker_text} -->\n")
            appended += 1
        active_text, archive_values, _ = _feedback_compaction_plan(
            text, instance_id, MAX_FEEDBACK_ACTIVE, 10)
        archive_path = loom_root / ".loom-private" / "feedback-archive.jsonl"
        _reject_link_ancestors(archive_path, "private feedback archive")
        _append_archive_lines(archive_path, archive_values)
        _atomic_text(feedback, active_text)
        _atomic_text(outbox, "")
    return appended


def _empty_outcome_store(instance_id):
    return {
        "schema_version": SCHEMA_VERSION,
        "instance_id": _validate_instance_id(instance_id),
        "total_count": 0,
        "records": [],
        "partitions": {},
    }


def _validate_outcome_value(outcome, instance_id):
    _require_exact_fields(outcome, OUTCOME_RECORD_FIELDS, "outcome record")
    if type(outcome.get("schema_version")) is not int \
            or outcome.get("schema_version") != SCHEMA_VERSION \
            or outcome.get("instance_id") != instance_id \
            or outcome.get("metric") not in OUTCOME_METRICS:
        raise MemoryError("outcome record header is invalid or cross-instance")
    try:
        if not isinstance(outcome.get("id"), str):
            raise TypeError
        uuid.UUID(outcome["id"])
        if any(type(outcome[field]) not in (int, float)
               for field in ("predicted", "actual", "absolute_error")):
            raise TypeError
        predicted = float(outcome["predicted"])
        actual = float(outcome["actual"])
        error = float(outcome["absolute_error"])
    except (ValueError, TypeError, KeyError) as exc:
        raise MemoryError("outcome record contains invalid numeric/id data") from exc
    if not all(math.isfinite(value) and 0.0 <= value <= 1.0
               for value in (predicted, actual, error)) \
            or not math.isclose(error, abs(predicted - actual), abs_tol=1e-12):
        raise MemoryError("outcome record error does not match predicted/actual")
    domain, project_id = outcome.get("domain"), outcome.get("project_id")
    if not isinstance(domain, str) or not ID_RE.fullmatch(domain) \
            or (project_id is not None
                and (not isinstance(project_id, str)
                     or not PROJECT_ID_RE.fullmatch(project_id))):
        raise MemoryError("outcome record domain/project identifiers are invalid")
    _validate_timestamp(outcome.get("recorded_at"), "recorded_at")


def _read_outcome_store(directory, instance_id):
    path = _reject_link_ancestors(
        Path(directory) / "outcomes.json", "outcome store")
    if not path.is_file():
        return _empty_outcome_store(instance_id)
    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryError(f"cannot read outcome store: {exc}") from exc
    _require_exact_fields(store, OUTCOME_STORE_FIELDS, "outcome store")
    if type(store.get("schema_version")) is not int \
            or store.get("schema_version") != SCHEMA_VERSION \
            or store.get("instance_id") != _validate_instance_id(instance_id) \
            or not isinstance(store.get("records"), list) \
            or not isinstance(store.get("partitions"), dict) \
            or isinstance(store.get("total_count"), bool) \
            or not isinstance(store.get("total_count"), int):
        raise MemoryError("outcome store header is invalid or cross-instance")
    if store["total_count"] < len(store["records"]) \
            or len(store["records"]) > MAX_OUTCOMES_ACTIVE \
            or len(store["partitions"]) > MAX_OUTCOME_PARTITIONS:
        raise MemoryError("outcome store exceeds a bound or has an impossible count")
    for outcome in store["records"]:
        _validate_outcome_value(outcome, instance_id)
    partition_total = 0
    for key, partition in store["partitions"].items():
        _require_exact_fields(partition, OUTCOME_PARTITION_FIELDS,
                              "outcome partition")
        try:
            metric = partition["metric"]
            domain = partition["domain"]
            sample_count = partition["sample_count"]
            total_error = partition["sum_absolute_error"]
            first = partition["first_errors"]
            recent = partition["recent_errors"]
            updated_at = partition["updated_at"]
        except (KeyError, TypeError) as exc:
            raise MemoryError("outcome partition is malformed") from exc
        if isinstance(sample_count, bool) or not isinstance(sample_count, int) \
                or isinstance(total_error, bool) \
                or not isinstance(total_error, (int, float)) \
                or not isinstance(first, list) or not isinstance(recent, list):
            raise MemoryError("outcome partition error windows are invalid")
        errors = first + recent
        if key != _outcome_partition_key(metric, domain) \
                or metric not in OUTCOME_METRICS \
                or not isinstance(domain, str) or not ID_RE.fullmatch(domain) \
                or sample_count < 1 or not math.isfinite(float(total_error)) \
                or not 0 <= float(total_error) <= sample_count \
                or len(first) != min(sample_count, OUTCOME_WINDOW) \
                or len(recent) != min(sample_count, OUTCOME_WINDOW) \
                or not all(not isinstance(value, bool)
                           and isinstance(value, (int, float))
                           and math.isfinite(float(value))
                           and 0 <= float(value) <= 1 for value in errors):
            raise MemoryError("outcome partition is invalid")
        _validate_timestamp(updated_at, "outcome partition updated_at")
        partition_total += sample_count
    if partition_total != store["total_count"]:
        raise MemoryError("outcome partition totals do not match total_count")
    return store


def _outcome_partition_key(metric, domain):
    return f"{metric}:{domain}"


def _update_outcome_store(store, outcome):
    key = _outcome_partition_key(outcome["metric"], outcome["domain"])
    partition = store["partitions"].get(key)
    if partition is None:
        if len(store["partitions"]) >= MAX_OUTCOME_PARTITIONS:
            raise MemoryError(
                "outcome partition limit reached; consolidate domain identifiers first")
        partition = {
            "metric": outcome["metric"],
            "domain": outcome["domain"],
            "sample_count": 0,
            "sum_absolute_error": 0.0,
            "first_errors": [],
            "recent_errors": [],
        }
        store["partitions"][key] = partition
    error = float(outcome["absolute_error"])
    partition["sample_count"] += 1
    partition["sum_absolute_error"] += error
    if len(partition["first_errors"]) < OUTCOME_WINDOW:
        partition["first_errors"].append(error)
    partition["recent_errors"] = (
        partition["recent_errors"] + [error])[-OUTCOME_WINDOW:]
    partition["updated_at"] = outcome["recorded_at"]
    store["total_count"] += 1
    store["records"].append(outcome)
    overflow = store["records"][:-MAX_OUTCOMES_ACTIVE]
    store["records"] = store["records"][-MAX_OUTCOMES_ACTIVE:]
    return overflow


def record_outcome(home, instance_id, *, metric, predicted, actual,
                   domain="general", project_id=None, outcome_id=None):
    instance_id = _validate_instance_id(instance_id)
    if metric not in OUTCOME_METRICS:
        raise MemoryError(f"unsupported outcome metric: {metric}")
    if type(predicted) not in (int, float) or type(actual) not in (int, float):
        raise MemoryError("predicted and actual must be numeric")
    predicted, actual = float(predicted), float(actual)
    if not all(math.isfinite(value) and 0.0 <= value <= 1.0
               for value in (predicted, actual)):
        raise MemoryError("predicted and actual must be finite values in [0, 1]")
    if not isinstance(domain, str) or not ID_RE.fullmatch(domain) \
            or (project_id is not None
                and (not isinstance(project_id, str)
                     or not PROJECT_ID_RE.fullmatch(project_id))):
        raise MemoryError("outcome domain/project identifiers are invalid")
    if outcome_id is None:
        outcome_id = str(uuid.uuid4())
    else:
        try:
            canonical_id = str(uuid.UUID(outcome_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise MemoryError("outcome_id must be a canonical UUID") from exc
        if canonical_id != outcome_id:
            raise MemoryError("outcome_id must be a canonical UUID")
    outcome = {
        "schema_version": SCHEMA_VERSION,
        "id": outcome_id,
        "instance_id": instance_id,
        "metric": metric,
        "predicted": predicted,
        "actual": actual,
        "absolute_error": abs(predicted - actual),
        "domain": domain,
        "project_id": project_id,
        "recorded_at": _now(),
    }
    _validate_outcome_value(outcome, instance_id)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = _read_outcome_store(directory, instance_id)
        existing = next(
            (item for item in store["records"] if item["id"] == outcome_id), None)
        if existing is not None:
            comparable = (
                "instance_id", "metric", "predicted", "actual", "absolute_error",
                "domain", "project_id",
            )
            if any(existing[field] != outcome[field] for field in comparable):
                raise MemoryError("outcome_id is already bound to different evidence")
            return existing
        overflow = _update_outcome_store(store, outcome)
        _append_archive_lines(directory / "outcomes-archive.jsonl", overflow)
        _atomic_json(directory / "outcomes.json", store)
    return outcome


def learning_report(home, instance_id, *, metric, domain="general"):
    instance_id = _validate_instance_id(instance_id)
    if metric not in OUTCOME_METRICS:
        raise MemoryError("learning report requires one controlled metric")
    if not isinstance(domain, str) or not ID_RE.fullmatch(domain):
        raise MemoryError("learning report requires one explicit safe domain")
    directory = _instance_dir(home, instance_id)
    store = _read_outcome_store(directory, instance_id)
    partitions = [item for item in store["partitions"].values()
                  if item.get("metric") == metric
                  and item.get("domain") == domain]
    sample_count = sum(int(item["sample_count"]) for item in partitions)
    active = [item for item in store["records"]
              if item.get("metric") == metric
              and item.get("domain") == domain]

    if sample_count == len(active):
        split = len(active) // 2
        early_errors = [float(item["absolute_error"]) for item in active[:split]]
        recent_errors = [float(item["absolute_error"])
                         for item in (active[-split:] if split else [])]
    else:
        early_errors = [float(value) for item in partitions
                        for value in item["first_errors"]]
        recent_errors = [float(value) for item in partitions
                         for value in item["recent_errors"]]

    def mean_error(errors):
        return (sum(errors) / len(errors)
                if errors else None)

    early_mae, recent_mae = mean_error(early_errors), mean_error(recent_errors)
    return {
        "schema_version": SCHEMA_VERSION,
        "instance_id": instance_id,
        "metric": metric,
        "domain": domain,
        "sample_count": sample_count,
        "active_evidence_count": len(active),
        "early_sample_count": len(early_errors),
        "recent_sample_count": len(recent_errors),
        "early_mae": early_mae,
        "recent_mae": recent_mae,
        "improved": (recent_mae < early_mae
                     if early_mae is not None and recent_mae is not None else None),
    }


def migrate_legacy(home, instance_id):
    """Quarantine unscoped Markdown memory; never guess cross-domain applicability."""
    home = _reject_link_ancestors(home, "Loom home")
    directory = _instance_dir(home, instance_id)
    sources = [
        home / "profile.md", home / "calibration.md", home / "projects.md",
        home / "feedback-outbox.md",
    ]
    with FileLock(directory / ".lock"):
        marker_path = directory / "legacy-migration.json"
        marker = _read_legacy_marker(marker_path)
        quarantined = 0
        for source in sources:
            source = _reject_link_ancestors(
                source, f"legacy source {source.name}")
            if not source.is_file():
                continue
            raw = source.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if marker["sources"].get(source.name) == digest:
                continue
            text = raw.decode("utf-8", errors="strict")
            for number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("- ") or re.fullmatch(r"-+", stripped):
                    continue
                _append_archive_lines(directory / "legacy-quarantine.jsonl", [{
                    "schema_version": SCHEMA_VERSION,
                    "instance_id": _validate_instance_id(instance_id),
                    "source_file": source.name,
                    "source_line": number,
                    "content": stripped,
                    "quarantined_at": _now(),
                    "reason": "legacy entry has no typed scope; manual classification required",
                }])
                quarantined += 1
            marker["sources"][source.name] = digest
        marker["completed_at"] = _now()
        _atomic_json(marker_path, marker)
    return {"quarantined": quarantined, "migrated_active": 0}


def compact_feedback(loom_root, *, max_active=MAX_FEEDBACK_ACTIVE,
                     keep_resolved=10):
    """Move old feedback bodies to a local archive and bound the active queue."""
    loom_root = _reject_link_ancestors(loom_root, "Loom installation root")
    feedback = loom_root / "FEEDBACK.md"
    if not feedback.is_file():
        raise MemoryError("FEEDBACK.md is missing")
    try:
        max_active, keep_resolved = int(max_active), int(keep_resolved)
    except (TypeError, ValueError) as exc:
        raise MemoryError("feedback caps must be integers") from exc
    if not 1 <= max_active <= MAX_FEEDBACK_ACTIVE \
            or not 0 <= keep_resolved <= max_active:
        raise MemoryError(
            f"max_active must be in [1, {MAX_FEEDBACK_ACTIVE}] and "
            "keep_resolved in [0, max_active]")
    try:
        marker = _reject_link_ancestors(
            loom_root / INSTANCE_MARKER, "installation marker")
        instance_id = _validate_instance_id(
            marker.read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError, MemoryError) as exc:
        raise MemoryError(
            f"cannot compact feedback without a valid installation marker: {exc}") from exc
    with FileLock(loom_root / ".loom-feedback.lock"):
        feedback = _reject_link_ancestors(feedback, "FEEDBACK.md")
        text = feedback.read_text(encoding="utf-8")
        archive_path = loom_root / ".loom-private" / "feedback-archive.jsonl"
        _reject_link_ancestors(archive_path, "private feedback archive")
        active_text, archive_values, result = _feedback_compaction_plan(
            text, instance_id, max_active, keep_resolved)
        _append_archive_lines(archive_path, archive_values)
        _atomic_text(feedback, active_text)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scoped, bounded, per-install Loom owner learning")
    parser.add_argument("--home", default=str(Path.home() / ".loom"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--loom-root", required=True)
    project_id_cmd = sub.add_parser("project-id")
    project_id_cmd.add_argument("--instance", required=True)
    project_id_cmd.add_argument("--project-root", required=True)
    add = sub.add_parser("add")
    add.add_argument("--instance", required=True)
    add.add_argument("--scope", choices=sorted(SCOPES), required=True)
    add.add_argument("--category", choices=sorted(CATEGORIES), required=True)
    add.add_argument("--statement", required=True)
    add.add_argument("--provenance", choices=sorted(PROVENANCE), required=True)
    add.add_argument("--evidence-count", type=int, default=1)
    add.add_argument("--domain")
    add.add_argument("--project")
    select_cmd = sub.add_parser("select")
    select_cmd.add_argument("--instance", required=True)
    select_cmd.add_argument("--domain", action="append")
    select_cmd.add_argument("--project")
    select_cmd.add_argument("--max-chars", type=int, default=MAX_SELECT_CHARS)
    pref = sub.add_parser("set-preference")
    pref.add_argument("--instance", required=True)
    pref.add_argument("--domain")
    pref.add_argument("key", choices=sorted(PREFERENCE_KEYS))
    pref.add_argument("value")
    forget_cmd = sub.add_parser("forget")
    forget_cmd.add_argument("--instance", required=True)
    forget_cmd.add_argument("record_id")
    compact_cmd = sub.add_parser("compact")
    compact_cmd.add_argument("--instance", required=True)
    queue = sub.add_parser("queue-feedback")
    queue.add_argument("--instance", required=True)
    queue.add_argument("--pattern", choices=sorted(FEEDBACK_PATTERNS), required=True)
    queue.add_argument("--action", choices=sorted(FEEDBACK_ACTIONS), required=True)
    queue.add_argument("--evidence-count", type=int, required=True)
    contribute_cmd = sub.add_parser("contribute")
    contribute_cmd.add_argument("--instance", required=True)
    contribute_cmd.add_argument("--loom-root", required=True)
    outcome = sub.add_parser("record-outcome")
    outcome.add_argument("--instance", required=True)
    outcome.add_argument("--metric", choices=sorted(OUTCOME_METRICS), required=True)
    outcome.add_argument("--predicted", type=float, required=True)
    outcome.add_argument("--actual", type=float, required=True)
    outcome.add_argument("--domain", default="general")
    outcome.add_argument("--project")
    report = sub.add_parser("report")
    report.add_argument("--instance", required=True)
    report.add_argument("--metric", choices=sorted(OUTCOME_METRICS), required=True)
    report.add_argument("--domain", default="general")
    migrate = sub.add_parser("migrate-legacy")
    migrate.add_argument("--instance", required=True)
    feedback_compact = sub.add_parser("compact-feedback")
    feedback_compact.add_argument("--loom-root", required=True)
    feedback_compact.add_argument("--max-active", type=int, default=MAX_FEEDBACK_ACTIVE)
    feedback_compact.add_argument("--keep-resolved", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = {"instance_id": initialize(args.home, args.loom_root)}
        elif args.command == "project-id":
            result = {"project_id": project_identity(
                args.instance, args.project_root)}
        elif args.command == "add":
            result = add_record(
                args.home, args.instance, scope=args.scope, category=args.category,
                statement=args.statement, provenance=args.provenance,
                evidence_count=args.evidence_count, domain=args.domain,
                project_id=args.project)
        elif args.command == "select":
            result = select(
                args.home, args.instance, domain=args.domain,
                project_id=args.project, max_chars=args.max_chars)
        elif args.command == "set-preference":
            result = set_preference(
                args.home, args.instance, args.key, args.value, domain=args.domain)
        elif args.command == "forget":
            result = {"forgotten": forget(args.home, args.instance, args.record_id)}
        elif args.command == "compact":
            result = compact(args.home, args.instance)
        elif args.command == "queue-feedback":
            result = queue_feedback(
                args.home, args.instance, pattern=args.pattern, action=args.action,
                evidence_count=args.evidence_count)
        elif args.command == "contribute":
            result = {"contributed": contribute(
                args.home, args.instance, args.loom_root)}
        elif args.command == "record-outcome":
            result = record_outcome(
                args.home, args.instance, metric=args.metric,
                predicted=args.predicted, actual=args.actual,
                domain=args.domain, project_id=args.project)
        elif args.command == "report":
            result = learning_report(
                args.home, args.instance, metric=args.metric, domain=args.domain)
        elif args.command == "migrate-legacy":
            result = migrate_legacy(args.home, args.instance)
        else:
            result = compact_feedback(
                args.loom_root, max_active=args.max_active,
                keep_resolved=args.keep_resolved)
    except (MemoryError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "ok", "result": result},
                     sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
