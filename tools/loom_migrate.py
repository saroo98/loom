#!/usr/bin/env python3
"""Read-only Loom 0.8/1.0 importer into the current owner vault."""

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import uuid
from contextlib import closing
from pathlib import Path

import loom_memory
import loom_vault


MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MIGRATION_NAMESPACE = uuid.UUID("f250566d-4565-4ef4-867d-c08462ab2fb8")


class MigrationError(RuntimeError):
    pass


def _is_redirect(path):
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        if junction and junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except FileNotFoundError:
        return False


def source_inventory(source):
    source = Path(source).resolve()
    if not source.is_dir() or _is_redirect(source):
        raise MigrationError("legacy source is missing or redirected")
    files = []
    total = 0
    for directory, names, filenames in os.walk(source, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            if _is_redirect(directory_path / name):
                raise MigrationError("legacy source contains a redirected directory")
        for name in filenames:
            path = directory_path / name
            if _is_redirect(path) or not path.is_file():
                raise MigrationError("legacy source contains a non-regular file")
            size = path.stat().st_size
            if size > MAX_SOURCE_FILE_BYTES:
                raise MigrationError("legacy source file exceeds migration bound")
            raw = path.read_bytes()
            if len(raw) != size:
                raise MigrationError("legacy source changed while being inventoried")
            total += size
            if total > MAX_SOURCE_BYTES:
                raise MigrationError("legacy source exceeds migration bound")
            files.append({"path": path.relative_to(source).as_posix(), "bytes": size,
                          "sha256": hashlib.sha256(raw).hexdigest()})
    files.sort(key=lambda item: item["path"])
    root = hashlib.sha256(json.dumps(
        files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"files": files, "root_sha256": root, "bytes": total}


def _legacy_fingerprint(record):
    body = {field: record.get(field) for field in (
        "scope", "category", "statement", "domain", "project_id",
        "preference_key", "preference_value")}
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def _transform_record(record):
    required = {"id", "scope", "category", "statement", "provenance", "status",
                "confidence", "evidence_count", "created_at"}
    if not isinstance(record, dict) or not required <= set(record):
        raise MigrationError("legacy memory record is incomplete")
    status = record["status"]
    if status == "retired":
        status = "superseded"
    if record["scope"] == "project" and status == "active":
        status = "dormant"
    return {
        "id": record["id"], "scope": record["scope"],
        "domain": record.get("domain"), "project_id": record.get("project_id"),
        "category": record["category"], "statement": record["statement"],
        "provenance": record["provenance"], "status": status,
        "confidence": record["confidence"], "evidence_count": record["evidence_count"],
        "created_at": record["created_at"],
        "preference_key": record.get("preference_key"),
        "preference_value": record.get("preference_value"),
    }


def import_legacy_record(vault, record, *, source_sequence):
    fingerprint = _legacy_fingerprint(record)
    if vault.is_forgotten(record["id"], legacy_fingerprint=fingerprint):
        return {"id": record["id"], "status": "forgotten"}
    return vault.import_memory(_transform_record(record), source_sequence=source_sequence)


def _read_json(path, default):
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"legacy state is invalid: {path.name}: {exc}") from exc


def _migrate_v1_into(home, install_root, vault, *, expected_instance_id,
                     inventory=None):
    home = Path(home).resolve()
    install_root = Path(install_root).resolve()
    marker = install_root / loom_memory.INSTANCE_MARKER
    try:
        marker_id = marker.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MigrationError(f"legacy installation marker is unavailable: {exc}") from exc
    if marker_id != expected_instance_id:
        raise MigrationError("legacy installation marker does not match expected instance")
    try:
        loom_memory.validate_instance(home, marker_id)
    except loom_memory.MemoryError as exc:
        raise MigrationError(f"legacy instance validation failed: {exc}") from exc
    source = home / "instances" / marker_id
    inventory = inventory or source_inventory(source)
    alias = vault.legacy_alias("legacy-install", marker_id)
    if alias:
        if alias["source_hash"] != inventory["root_sha256"]:
            raise MigrationError("legacy source changed after its completed migration")
        receipt = vault.get_receipt(alias["target_id"])
        if receipt is None:
            raise MigrationError("legacy migration alias has no authenticated receipt")
        return {**receipt, "status": "already-migrated"}

    active = _read_json(source / "active.json", {"records": []})
    tombstones = _read_json(source / "tombstones.json", {"entries": []})
    outcomes = _read_json(source / "outcomes.json", {"records": []})
    records = active.get("records")
    entries = tombstones.get("entries")
    outcome_records = outcomes.get("records")
    if not isinstance(records, list) or not isinstance(entries, list) \
            or not isinstance(outcome_records, list):
        raise MigrationError("legacy semantic stores have invalid collections")
    preferences = sum(record.get("category") == "preference" for record in records)
    before = {"records": len(records), "tombstones": len(entries),
              "outcomes": len(outcome_records), "preferences": preferences}
    migration_id = str(uuid.uuid5(
        MIGRATION_NAMESPACE,
        f"{vault.identity()['owner_vault_id']}:{marker_id}:{inventory['root_sha256']}"))

    reconciliation = []
    for index, entry in enumerate(entries, 1):
        result = vault.import_tombstone(
            record_id=entry["record_id"],
            semantic_fingerprint=entry["semantic_fingerprint"],
            forgotten_at=entry["forgotten_at"], source_sequence=index)
        reconciliation.append({"source_id": entry["record_id"],
                               "target_id": entry["record_id"],
                               "action": "forgotten", "reason": "legacy-tombstone-first"})
    for index, record in enumerate(records, 1):
        result = import_legacy_record(vault, record, source_sequence=index)
        action = "forgotten" if result["status"] == "forgotten" else (
            "dormant" if result["status"] == "dormant" else "preserved")
        reconciliation.append({"source_id": record["id"], "target_id": record["id"],
                               "action": action,
                               "reason": "project-awaits-lineage" if action == "dormant"
                               else "scope-and-provenance-preserved"})
    for index, outcome in enumerate(outcome_records, 1):
        entity_id = str(outcome.get("id") or f"legacy-outcome-{index}")
        vault.put_entity("outcome", entity_id, outcome, source_sequence=index)
    recognized = {
        "learning-events.json": "memory-observation",
        "learning-candidates.json": "learning-candidate",
        "preference-evolution.json": "preference-slot",
        "artifact-utility.json": "artifact-utility",
        "improvement-evidence.json": "policy-evaluation",
        "reversible-actions.json": "reversible-action",
        "usage.json": "usage-observation",
        "performance.json": "performance-observation",
    }
    for name, entity_type in recognized.items():
        path = source / name
        if path.is_file():
            value = _read_json(path, None)
            records_value = []
            if isinstance(value, list):
                records_value = value
            elif isinstance(value, dict):
                for key in ("records", "events", "candidates", "entries", "actions", "samples"):
                    if isinstance(value.get(key), list):
                        records_value = value[key]
                        break
            if records_value:
                for index, item in enumerate(records_value, 1):
                    if entity_type == "performance-observation":
                        item = {"schema_version": 3,
                            "measurement_status": "legacy-ambiguous",
                            "processed_total_tokens": None,
                            "normalization_reason":
                                "legacy performance sample lacks overlap semantics",
                            "legacy_sample": item}
                    entity_id = str(uuid.uuid5(
                        MIGRATION_NAMESPACE, f"{migration_id}:{name}:{index}"))
                    vault.put_entity(entity_type, entity_id, item, source_sequence=index)
                    reconciliation.append({
                        "source_id": f"{name}:{index}", "target_id": entity_id,
                        "action": "preserved-inactive" if entity_type == "learning-candidate"
                        else "typed-import",
                        "reason": f"recognized-{entity_type}",
                    })
            else:
                vault.quarantine_import(name, value)
                reconciliation.append({
                    "source_id": name, "target_id": None, "action": "quarantined",
                    "reason": "recognized-file-with-unknown-shape",
                })

    after = dict(before)
    receipt = {
        "migration_id": migration_id, "source_versions": ["1.0"],
        "source_hashes": [item["sha256"] for item in inventory["files"]],
        "before": before, "after": after, "reconciliation": reconciliation,
        "activated": True,
    }
    vault.put_receipt(migration_id, "legacy-migration", receipt)
    vault.put_legacy_alias(
        "legacy-install", marker_id, migration_id, inventory["root_sha256"])
    return {**receipt, "status": "migrated"}


def migrate_v1(home, install_root, vault, *, expected_instance_id,
               activate=os.replace):
    """Migrate against a private SQLite snapshot, then atomically activate it.

    The live vault is never incrementally mutated. A failed import, integrity check, or pointer
    replacement leaves the complete pre-migration database authoritative.
    """
    home = Path(home).resolve()
    install_root = Path(install_root).resolve()
    marker = install_root / loom_memory.INSTANCE_MARKER
    try:
        marker_id = marker.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise MigrationError(f"legacy installation marker is unavailable: {exc}") from exc
    if marker_id != expected_instance_id:
        raise MigrationError("legacy installation marker does not match expected instance")
    source = home / "instances" / marker_id
    inventory = source_inventory(source)
    alias = vault.legacy_alias("legacy-install", marker_id)
    if alias:
        if alias["source_hash"] != inventory["root_sha256"]:
            raise MigrationError("legacy source changed after its completed migration")
        receipt = vault.get_receipt(alias["target_id"])
        if receipt is None:
            raise MigrationError("legacy migration alias has no authenticated receipt")
        return {**receipt, "status": "already-migrated"}

    vault.path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, staged_name = tempfile.mkstemp(
        prefix=".loom-migration-", suffix=".sqlite3", dir=vault.path.parent)
    os.close(descriptor)
    staged = Path(staged_name)
    staged.unlink()
    try:
        vault.online_backup(staged)
        staged_vault = loom_vault.OwnerVault.open(
            staged, crypto=vault.crypto,
            allow_test_crypto=not getattr(vault.crypto, "production_safe", False))
        receipt = _migrate_v1_into(
            home, install_root, staged_vault,
            expected_instance_id=expected_instance_id, inventory=inventory)
        with closing(sqlite3.connect(staged)) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise MigrationError(f"staged vault integrity check failed: {integrity}")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        activate(staged, vault.path)
        staged = None
        return receipt
    except (OSError, sqlite3.Error, loom_vault.VaultError) as exc:
        raise MigrationError(f"migration activation failed safely: {exc}") from exc
    finally:
        if staged is not None:
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(str(staged) + suffix).unlink()
                except FileNotFoundError:
                    pass
