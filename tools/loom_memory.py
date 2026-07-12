#!/usr/bin/env python3
"""loom_memory — scoped, bounded, per-install owner learning (stdlib only)."""

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
import uuid
from pathlib import Path

SCHEMA_VERSION = 1
INSTANCE_MARKER = ".loom-instance-id"
SCOPES = {"global", "domain", "project", "temporary"}
CATEGORIES = {"preference", "calibration", "process", "domain"}
PROVENANCE = {"stated", "observed", "inferred"}
STATUSES = {"active", "retired", "tombstone"}
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
PARTITION_CAPS = {"global": 64, "domain": 48, "project": 48, "temporary": 16}
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


class MemoryError(RuntimeError):
    pass


class FileLock:
    def __init__(self, path, timeout=5.0, stale_after=None):
        self.path = Path(path)
        self.timeout = timeout
        self.fd = None
        self.token = f"{os.getpid()}:{uuid.uuid4().hex}\n"

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        self.path.parent.mkdir(parents=True, exist_ok=True)
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


def _atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
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
    base = Path(home).expanduser().resolve()
    instances = base / "instances"
    directory = instances / _validate_instance_id(instance_id)
    if instances.is_symlink() or directory.is_symlink():
        raise MemoryError("instance storage must not use symlinked partitions")
    try:
        directory.parent.resolve(strict=False).relative_to(base)
    except ValueError as exc:
        raise MemoryError("instance storage escapes the selected Loom home") from exc
    return directory


def project_identity(instance_id, project_root):
    """Return a path-derived identifier namespaced to one Loom installation."""
    namespace = uuid.UUID(_validate_instance_id(instance_id))
    root = os.path.normcase(str(Path(project_root).expanduser().resolve()))
    return "p-" + uuid.uuid5(namespace, root).hex


def initialize(home, loom_root):
    home = Path(home).expanduser().resolve()
    loom_root = Path(loom_root).resolve()
    marker = loom_root / INSTANCE_MARKER
    if marker.is_symlink():
        raise MemoryError("installation marker must not be a symlink")
    with FileLock(loom_root / ".loom-instance-init.lock"):
        if marker.is_file():
            instance_id = _validate_instance_id(
                marker.read_text(encoding="utf-8").strip())
        else:
            instance_id = str(uuid.uuid4())
            _atomic_text(marker, instance_id + "\n")
    directory = _instance_dir(home, instance_id)
    directory.mkdir(parents=True, exist_ok=True)
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
            _atomic_json(store, {
                "schema_version": SCHEMA_VERSION,
                "instance_id": instance_id,
                "records": [],
            })
    # Legacy flat Markdown has no trustworthy scope. Quarantine a local inactive copy on first
    # initialization, but never infer/import any row into active memory.
    migrate_legacy(home, instance_id)
    return instance_id


def read_store(home, instance_id):
    instance_id = _validate_instance_id(instance_id)
    path = _instance_dir(home, instance_id) / "active.json"
    if path.is_symlink():
        raise MemoryError("active memory must not be a symlink")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryError(f"cannot read active memory: {exc}") from exc
    if data.get("schema_version") != SCHEMA_VERSION \
            or data.get("instance_id") != instance_id \
            or not isinstance(data.get("records"), list):
        raise MemoryError("active memory header is invalid or cross-instance")
    if len(data["records"]) > MAX_ACTIVE_RECORDS + 64:
        raise MemoryError("active memory exceeds its hard record bound")
    for record in data["records"]:
        if not isinstance(record, dict):
            raise MemoryError("active memory contains a non-object record")
        _validate_record(record)
    return data


def _read_legacy_marker(path):
    path = Path(path)
    if path.is_symlink():
        raise MemoryError("legacy migration marker must not be a symlink")
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
    home = Path(home).expanduser().resolve()
    instances = home / "instances"
    if instances.is_symlink():
        raise MemoryError("instance storage must not be symlinked")
    result = {}
    if not instances.is_dir():
        return result
    for directory in sorted(path for path in instances.iterdir() if path.is_dir()):
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
    try:
        meta = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        findings.append(f"invalid instance metadata: {exc}")
    else:
        if meta.get("schema_version") != SCHEMA_VERSION \
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
    try:
        uuid.UUID(str(record.get("id")))
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
    try:
        confidence = float(record.get("confidence"))
    except (TypeError, ValueError) as exc:
        raise MemoryError("memory confidence must be numeric") from exc
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise MemoryError("memory confidence must be in [0, 1]")
    _validate_timestamp(record.get("created_at"), "created_at")
    _validate_timestamp(record.get("last_confirmed"), "last_confirmed")
    _validate_timestamp(record.get("expires_at"), "expires_at", nullable=True)
    if not isinstance(record.get("supersedes"), list):
        raise MemoryError("supersedes must be a list")
    for prior_id in record["supersedes"]:
        try:
            uuid.UUID(str(prior_id))
        except ValueError as exc:
            raise MemoryError("supersedes contains an invalid UUID") from exc
    domain, project = record.get("domain"), record.get("project_id")
    if domain is not None and not ID_RE.fullmatch(str(domain)):
        raise MemoryError("domain must be a safe local identifier")
    if project is not None and not PROJECT_ID_RE.fullmatch(str(project)):
        raise MemoryError("project_id must be generated by loom_memory project-id")
    if record["scope"] == "global" and (domain or project):
        raise MemoryError("global memory cannot carry domain/project identity")
    if record["scope"] == "global" and record["category"] != "preference":
        raise MemoryError(
            "global active memory is limited to typed stated preferences; "
            "use record-outcome for transferable calibration")
    if record["scope"] == "domain" and (not domain or project):
        raise MemoryError("domain memory requires domain and forbids project_id")
    if record["scope"] == "project" and (not domain or not project):
        raise MemoryError("project memory requires both domain and project_id")
    if record["scope"] == "temporary" and not domain:
        raise MemoryError("temporary memory requires an explicit domain")
    if record["category"] == "domain" and not domain:
        raise MemoryError("domain-category memory requires an explicit domain")
    if record["status"] == "active" and record["category"] == "preference" \
            and (not record.get("preference_key")
                 or record.get("preference_value") is None):
        raise MemoryError("preference records must use the typed preference API")
    if record["status"] == "active" and record["category"] == "preference" \
            and record["provenance"] != "stated":
        raise MemoryError("active preferences require stated provenance")
    if record["status"] == "active" and record["category"] == "preference":
        key = record["preference_key"]
        if key not in PREFERENCE_KEYS:
            raise MemoryError("preference key is unsupported")
        if key in DOMAIN_PREFERENCE_KEYS and record["scope"] != "domain":
            raise MemoryError("domain preference has the wrong scope")
        if key in GENERAL_PREFERENCE_KEYS and record["scope"] != "global":
            raise MemoryError("general preference has the wrong scope")
    if record["scope"] == "temporary" and not record.get("expires_at"):
        raise MemoryError("temporary memory requires expires_at")
    if not isinstance(record.get("evidence_count"), int) \
            or record["evidence_count"] < 1:
        raise MemoryError("evidence_count must be a positive integer")


def _new_record(*, scope, category, statement, provenance, evidence_count=1,
                domain=None, project_id=None, confidence=0.5, expires_at=None,
                preference_key=None, preference_value=None):
    now = _now()
    if expires_at is None and provenance in {"observed", "inferred"}:
        days = 365 if provenance == "observed" else 90
        expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)) \
            .replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        evidence_count = int(evidence_count)
        confidence = float(confidence)
    except (TypeError, ValueError) as exc:
        raise MemoryError("evidence_count/confidence must be numeric") from exc
    record = {
        "id": str(uuid.uuid4()),
        "scope": scope,
        "category": category,
        "statement": re.sub(r"\s+", " ", str(statement)).strip(),
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
    }
    _validate_record(record)
    return record


def add_record(home, instance_id, *, scope, category, statement, provenance,
               evidence_count=1, domain=None, project_id=None, confidence=0.5,
               expires_at=None, preference_key=None, preference_value=None):
    instance_id = _validate_instance_id(instance_id)
    record = _new_record(
        scope=scope, category=category, statement=statement,
        provenance=provenance, evidence_count=evidence_count, domain=domain,
        project_id=project_id, confidence=confidence, expires_at=expires_at,
        preference_key=preference_key, preference_value=preference_value)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = read_store(home, instance_id)
        store["records"].append(record)
        if len(store["records"]) > MAX_ACTIVE_RECORDS:
            store, _ = _compact_records(directory, store)
        _atomic_json(directory / "active.json", store)
    return record


def set_preference(home, instance_id, key, value, *, provenance="stated", domain=None):
    if key not in PREFERENCE_KEYS:
        raise MemoryError(f"unsupported preference key: {key}")
    value = str(value).strip()
    if not value or len(value) > 200 or "\n" in value or "\r" in value:
        raise MemoryError("preference value must be one non-empty line up to 200 characters")
    if key == "autonomy_default" and value not in {"A0", "A1", "A2", "A3"}:
        raise MemoryError("autonomy_default must be A0, A1, A2, or A3")
    if key in DOMAIN_PREFERENCE_KEYS:
        if not domain or not ID_RE.fullmatch(str(domain)):
            raise MemoryError(f"{key} requires an explicit domain")
        scope = "domain"
    else:
        if domain:
            raise MemoryError(f"{key} is general and cannot carry a domain")
        scope = "global"
    instance_id = _validate_instance_id(instance_id)
    record = _new_record(
        scope=scope, category="preference", statement=f"{key}={value}",
        provenance=provenance, domain=domain, preference_key=key,
        preference_value=value)
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = read_store(home, instance_id)
        if key == "hard_stop":
            active_hard_stops = [
                prior for prior in store["records"]
                if prior.get("status") == "active"
                and prior.get("preference_key") == "hard_stop"
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
                prior["status"] = "retired"
                superseded.append(prior["id"])
        record["supersedes"] = sorted(set(superseded))
        store["records"].append(record)
        store, _ = _compact_records(directory, store)
        _atomic_json(directory / "active.json", store)
    return record


def _normal_statement(value):
    return re.sub(r"\s+", " ", str(value)).strip().casefold()


def _record_rank(record):
    provenance_rank = {"stated": 3, "observed": 2, "inferred": 1}
    return (
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
        if record.get("status") == "retired" \
                or (record.get("expires_at")
                    and _timestamp_value(record["expires_at"]) < now):
            archived.append(record)
            reasons[record["id"]] = "retired-or-expired"
            continue
        if record.get("status") != "active":
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
        if winner is record:
            kept[kept.index(prior)] = record
            by_key[key] = record
        archived.append(loser)
        reasons[loser["id"]] = "deduplicated"
        deduplicated += 1

    active = [record for record in kept if record.get("status") == "active"]
    tombstones = [record for record in kept if record.get("status") == "tombstone"]
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
    tombstones.sort(key=lambda record: record.get("created_at", ""), reverse=True)
    for record in tombstones[64:]:
        archived.append(record)
        reasons[record["id"]] = "old-tombstone"
    store["records"] = survivors + tombstones[:64]
    _append_archive(directory, archived, reasons)
    return store, {
        "active": len(survivors),
        "tombstones": min(len(tombstones), 64),
        "archived": len(archived),
        "deduplicated": deduplicated,
    }


def compact(home, instance_id):
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = read_store(home, instance_id)
        store, result = _compact_records(directory, store)
        _atomic_json(directory / "active.json", store)
    return result


def forget(home, instance_id, record_id):
    directory = _instance_dir(home, instance_id)
    with FileLock(directory / ".lock"):
        store = read_store(home, instance_id)
        target = next((record for record in store["records"]
                       if record.get("id") == record_id
                       and record.get("status") == "active"), None)
        if target is None:
            return False
        target["status"] = "retired"
        now = _now()
        store["records"].append({
            "id": str(uuid.uuid4()), "scope": "global",
            "category": "preference", "statement": "explicit forget tombstone",
            "provenance": "stated", "evidence_count": 1, "confidence": 1.0,
            "domain": None, "project_id": None, "created_at": now,
            "last_confirmed": now, "expires_at": None, "status": "tombstone",
            "supersedes": [record_id], "preference_key": None,
            "preference_value": None,
        })
        store, _ = _compact_records(directory, store)
        _atomic_json(directory / "active.json", store)
    return True


def select(home, instance_id, *, domain=None, project_id=None,
           max_chars=MAX_SELECT_CHARS):
    if domain is None:
        domains = []
    elif isinstance(domain, str):
        domains = [domain]
    elif isinstance(domain, (list, tuple, set)):
        domains = list(domain)
    else:
        raise MemoryError("domain selection must be a string or list of strings")
    domains = list(dict.fromkeys(str(value) for value in domains))
    if any(not ID_RE.fullmatch(value) for value in domains):
        raise MemoryError("domain must be a safe local identifier")
    domain_set = set(domains)
    if project_id and not domain_set:
        raise MemoryError("project selection requires an explicit domain")
    if project_id and not PROJECT_ID_RE.fullmatch(str(project_id)):
        raise MemoryError("project_id must be generated by loom_memory project-id")
    try:
        max_chars = int(max_chars)
    except (TypeError, ValueError) as exc:
        raise MemoryError("max_chars must be an integer") from exc
    if not 1 <= max_chars <= MAX_SELECT_CHARS:
        raise MemoryError(
            f"max_chars must be between 1 and {MAX_SELECT_CHARS}")
    records = []
    now = dt.datetime.now(dt.timezone.utc)
    for record in read_store(home, instance_id)["records"]:
        if record.get("status") != "active":
            continue
        if record.get("expires_at") \
                and _timestamp_value(record["expires_at"]) < now:
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
            records.append(record)
    rank = {"stated": 3, "observed": 2, "inferred": 1}
    records.sort(key=lambda item: (
        rank.get(item["provenance"], 0), item["evidence_count"],
        item["last_confirmed"]), reverse=True)
    selected, used = [], 2
    for record in records:
        cost = len(json.dumps(record, ensure_ascii=False)) + 1
        if selected and used + cost > max_chars:
            break
        if cost > max_chars:
            continue
        selected.append(record)
        used += cost
    return selected


def _read_jsonl(path):
    if Path(path).is_symlink():
        raise MemoryError(f"active JSONL must not be a symlink: {path}")
    if not Path(path).is_file():
        return []
    try:
        size = Path(path).stat().st_size
    except OSError as exc:
        raise MemoryError(f"cannot stat JSONL {path}: {exc}") from exc
    if size > MAX_OUTBOX_BYTES:
        raise MemoryError(
            f"JSONL {path} exceeds the {MAX_OUTBOX_BYTES}-byte active bound")
    values = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
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
    path = Path(path)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    _atomic_text(path, existing + json.dumps(
        value, sort_keys=True, ensure_ascii=False) + "\n")


def _append_archive_lines(path, values):
    """Append inactive history without rereading an ever-growing archive."""
    if not values:
        return
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise MemoryError(f"archive path must not be symlinked: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        for value in values:
            stream.write(json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


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
    loom_root = Path(loom_root).resolve()
    marker = loom_root / INSTANCE_MARKER
    try:
        if marker.is_symlink():
            raise MemoryError("receiver instance marker must not be a symlink")
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
        if feedback.is_symlink():
            raise MemoryError("FEEDBACK.md must not be a symlink")
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
        if archive_path.parent.is_symlink():
            raise MemoryError("private feedback archive directory must not be a symlink")
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
    if outcome.get("schema_version") != SCHEMA_VERSION \
            or outcome.get("instance_id") != instance_id \
            or outcome.get("metric") not in OUTCOME_METRICS:
        raise MemoryError("outcome record header is invalid or cross-instance")
    try:
        uuid.UUID(str(outcome.get("id")))
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
    path = Path(directory) / "outcomes.json"
    if not path.is_file():
        return _empty_outcome_store(instance_id)
    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MemoryError(f"cannot read outcome store: {exc}") from exc
    if store.get("schema_version") != SCHEMA_VERSION \
            or store.get("instance_id") != _validate_instance_id(instance_id) \
            or not isinstance(store.get("records"), list) \
            or not isinstance(store.get("partitions"), dict) \
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
                   domain="general", project_id=None):
    instance_id = _validate_instance_id(instance_id)
    if metric not in OUTCOME_METRICS:
        raise MemoryError(f"unsupported outcome metric: {metric}")
    try:
        predicted, actual = float(predicted), float(actual)
    except (TypeError, ValueError) as exc:
        raise MemoryError("predicted and actual must be numeric") from exc
    if not all(math.isfinite(value) and 0.0 <= value <= 1.0
               for value in (predicted, actual)):
        raise MemoryError("predicted and actual must be finite values in [0, 1]")
    if not ID_RE.fullmatch(domain) \
            or (project_id and not PROJECT_ID_RE.fullmatch(project_id)):
        raise MemoryError("outcome domain/project identifiers are invalid")
    outcome = {
        "schema_version": SCHEMA_VERSION,
        "id": str(uuid.uuid4()),
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
    home = Path(home).expanduser().resolve()
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
            if source.is_symlink():
                raise MemoryError(f"legacy source must not be a symlink: {source.name}")
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
    loom_root = Path(loom_root).resolve()
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
        if (loom_root / INSTANCE_MARKER).is_symlink():
            raise MemoryError("installation marker must not be a symlink")
        instance_id = _validate_instance_id(
            (loom_root / INSTANCE_MARKER).read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError, MemoryError) as exc:
        raise MemoryError(
            f"cannot compact feedback without a valid installation marker: {exc}") from exc
    with FileLock(loom_root / ".loom-feedback.lock"):
        if feedback.is_symlink():
            raise MemoryError("FEEDBACK.md must not be a symlink")
        text = feedback.read_text(encoding="utf-8")
        archive_path = loom_root / ".loom-private" / "feedback-archive.jsonl"
        if archive_path.parent.is_symlink():
            raise MemoryError("private feedback archive directory must not be a symlink")
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
