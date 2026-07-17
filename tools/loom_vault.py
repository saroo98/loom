#!/usr/bin/env python3
"""Encrypted, transactional, owner-scoped state authority for Loom.

The module owns SQLite structure and semantic validation. Cryptographic operations are delegated
to an injected helper implementing the narrow loom-vault protocol; production callers cannot opt
into a test provider accidentally.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import uuid
from contextlib import closing
from pathlib import Path

from loom_reliability import _is_trusted_os_alias


VAULT_SCHEMA_VERSION = 3
PAYLOAD_SCHEMA_VERSION = 3
MAX_ACTIVE_RECORDS = 256
MAX_EVENTS = 10000
MAX_DEVICES = 32
MAX_DEVICE_HISTORY = 256
MAX_QUARANTINE_BYTES = 64 * 1024 * 1024
MAX_STATE_ENTITIES = 1024
MAX_ENTITY_TYPE = 256
MAX_RECENT_EFFECTS = 4096
BUSY_TIMEOUT_MS = 5000
OWNER_NAMESPACE = uuid.UUID("4d137292-4498-4d60-8127-181d9e270c30")
RUNTIME_NAMESPACE = uuid.UUID("1514f49b-d752-4a8a-b108-99ccf09634df")
SCOPES = {"global", "general", "domain", "project", "component", "temporary", "device"}
STATUSES = {
    "candidate", "active", "dormant", "revalidation-required", "archived",
    "superseded", "quarantined", "forgotten", "stale",
}
ATTRIBUTION_STATUSES = {
    "selected-only", "applied-unverified", "verified-helped", "verified-hurt",
    "verified-neutral", "outcome-ambiguous", "rejected-before-use",
}
EVIDENCE_STATES = {
    "no-outcomes", "measurement-started", "associated-only",
    "structural-counterfactual-only", "insufficient-paired-evidence",
    "benefit-uncertain", "benefit-observed-local", "causal-local-evidence",
    "regression-observed", "quarantined-harm", "owner-judgment",
    "requires-independent-attestation",
}


class VaultError(RuntimeError):
    pass


class _ClosingConnection(sqlite3.Connection):
    """Make `with` close SQLite handles as well as commit or roll back."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stamp():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _event_rank(device_counter, device_id, event_id):
    """Return a stable SQLite rank; accepted events are collision-checked separately."""
    if type(device_counter) is not int or device_counter < 1:
        raise VaultError("event rank counter is invalid")
    device_id = _uuid(device_id, "device_id")
    event_id = _uuid(event_id, "event_id")
    tie_breaker = int.from_bytes(hashlib.sha256(
        f"{device_id}:{event_id}".encode("ascii")).digest()[:4], "big")
    rank = (device_counter << 32) | tie_breaker
    if rank > 0x7FFF_FFFF_FFFF_FFFF:
        raise VaultError("event rank exceeds SQLite integer bounds")
    return rank


def _collision_checked_event_rank(connection, device_counter, device_id, event_id):
    candidate = _event_rank(device_counter, device_id, event_id)
    rows = connection.execute(
        "SELECT event_id,device_id,device_counter FROM events WHERE device_counter=?",
        (device_counter,)).fetchall()
    for row in rows:
        if row["event_id"] != event_id and _event_rank(
                row["device_counter"], row["device_id"], row["event_id"]) == candidate:
            raise VaultError("event total-order rank collision; refusing ambiguous materialization")
    return candidate


def _uuid(value, label):
    try:
        parsed = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise VaultError(f"{label} must be a canonical UUID") from exc
    if parsed != str(value):
        raise VaultError(f"{label} must be a canonical UUID")
    return parsed


def _is_redirect(path):
    path = Path(path)
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
    except OSError as exc:
        raise VaultError(f"cannot inspect vault path {path}: {exc}") from exc


def _safe_path(path, label):
    try:
        absolute = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise VaultError(f"{label} is invalid: {exc}") from exc
    for component in [*reversed(absolute.parents), absolute]:
        if _is_redirect(component) and not _is_trusted_os_alias(component):
            raise VaultError(f"{label} must not traverse a symlink or junction: {component}")
    return absolute


def runtime_install_id(version, payload_sha256):
    if not isinstance(version, str) or not version.strip() \
            or not isinstance(payload_sha256, str) \
            or len(payload_sha256) != 64 \
            or any(character not in "0123456789abcdef" for character in payload_sha256):
        raise VaultError("runtime identity inputs are invalid")
    return str(uuid.uuid5(RUNTIME_NAMESPACE, f"{version}:{payload_sha256}"))


def project_identity(owner_vault_id, lineage):
    owner = uuid.UUID(_uuid(owner_vault_id, "owner_vault_id"))
    if not isinstance(lineage, dict) or not lineage:
        raise VaultError("project lineage must be a non-empty mapping")
    return "p-" + uuid.uuid5(owner, _canonical(lineage).decode("utf-8")).hex


SCHEMA = """
CREATE TABLE metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL CHECK(counter >= 0),
  status TEXT NOT NULL CHECK(status IN ('active','dormant','revoked')),
  last_seen TEXT NOT NULL
) STRICT;
CREATE TABLE legacy_aliases (
  alias_type TEXT NOT NULL,
  alias_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  PRIMARY KEY(alias_type, alias_id)
) STRICT;
CREATE TABLE memory_records (
  record_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK(scope IN ('global','general','domain','project','component','temporary','device')),
  domain_tag TEXT,
  project_tag TEXT,
  component_tag TEXT,
  device_tag TEXT,
  semantic_tag TEXT NOT NULL,
  status TEXT NOT NULL,
  source_sequence INTEGER NOT NULL CHECK(source_sequence >= 0),
  source_event_id TEXT NOT NULL DEFAULT 'unmaterialized',
  source_device_id TEXT NOT NULL DEFAULT 'unmaterialized',
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX memory_scope_index ON memory_records(
  scope, domain_tag, project_tag, component_tag, device_tag, status
);
CREATE TABLE memory_utility (
  record_id TEXT PRIMARY KEY,
  selection_count INTEGER NOT NULL DEFAULT 0 CHECK(selection_count >= 0),
  helped_count INTEGER NOT NULL DEFAULT 0 CHECK(helped_count >= 0),
  hurt_count INTEGER NOT NULL DEFAULT 0 CHECK(hurt_count >= 0),
  application_count INTEGER NOT NULL DEFAULT 0 CHECK(application_count >= 0),
  verified_neutral_count INTEGER NOT NULL DEFAULT 0 CHECK(verified_neutral_count >= 0),
  ambiguous_count INTEGER NOT NULL DEFAULT 0 CHECK(ambiguous_count >= 0),
  last_selected TEXT,
  last_applied TEXT,
  last_helped TEXT,
  last_hurt TEXT,
  FOREIGN KEY(record_id) REFERENCES memory_records(record_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE tombstones (
  record_id TEXT PRIMARY KEY,
  semantic_tag TEXT NOT NULL UNIQUE,
  source_sequence INTEGER NOT NULL CHECK(source_sequence >= 0),
  source_event_id TEXT NOT NULL DEFAULT 'unmaterialized',
  source_device_id TEXT NOT NULL DEFAULT 'unmaterialized',
  ciphertext BLOB NOT NULL,
  forgotten_at TEXT NOT NULL
) STRICT;
CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  device_counter INTEGER NOT NULL CHECK(device_counter >= 1),
  scope TEXT NOT NULL,
  domain_tag TEXT,
  project_tag TEXT,
  payload_schema_version INTEGER NOT NULL,
  prior_event_hash TEXT,
  ciphertext BLOB NOT NULL,
  signature BLOB NOT NULL,
  event_hash TEXT NOT NULL UNIQUE,
  recorded_at TEXT NOT NULL,
  UNIQUE(device_id, device_counter),
  FOREIGN KEY(device_id) REFERENCES devices(device_id)
) STRICT;
CREATE TABLE checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  event_count INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  root_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE checkpoint_acks (
  checkpoint_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  acknowledged_at TEXT NOT NULL,
  PRIMARY KEY(checkpoint_id, device_id),
  FOREIGN KEY(checkpoint_id) REFERENCES checkpoints(checkpoint_id),
  FOREIGN KEY(device_id) REFERENCES devices(device_id)
) STRICT;
CREATE TABLE quarantine (
  item_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  reason TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK(bytes >= 0),
  ciphertext BLOB NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE receipts (
  receipt_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE state_entities (
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  source_sequence INTEGER NOT NULL CHECK(source_sequence >= 0),
  source_event_id TEXT NOT NULL DEFAULT 'unmaterialized',
  source_device_id TEXT NOT NULL DEFAULT 'unmaterialized',
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(entity_type, entity_id)
) STRICT;
CREATE TABLE memory_observations (
  observation_id TEXT PRIMARY KEY,
  memory_id TEXT,
  scope TEXT NOT NULL,
  domain_tag TEXT,
  project_tag TEXT,
  component_tag TEXT,
  decision_target TEXT NOT NULL,
  evidence_id TEXT NOT NULL UNIQUE,
  source_event_id TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  observed_at TEXT NOT NULL
) STRICT;
CREATE INDEX observation_scope_index ON memory_observations(
  scope,domain_tag,project_tag,component_tag,decision_target
);
CREATE TABLE memory_effects (
  effect_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  attribution_status TEXT NOT NULL,
  evidence_id TEXT,
  source_event_id TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  recorded_at TEXT NOT NULL,
  UNIQUE(memory_id,operation_id)
) STRICT;
CREATE INDEX memory_effect_status_index ON memory_effects(memory_id,attribution_status);
CREATE TABLE preference_slots (
  slot_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  domain_tag TEXT,
  project_tag TEXT,
  component_tag TEXT,
  preference_key TEXT NOT NULL,
  status TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX preference_scope_index ON preference_slots(
  scope,domain_tag,project_tag,component_tag,preference_key,status
);
CREATE TABLE derivation_edges (
  parent_id TEXT NOT NULL,
  child_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  PRIMARY KEY(parent_id,child_id,relation)
) STRICT;
CREATE INDEX derivation_child_index ON derivation_edges(child_id);
CREATE TABLE deletion_commitments (
  commitment_id TEXT PRIMARY KEY,
  record_id TEXT NOT NULL,
  semantic_tag TEXT NOT NULL,
  deletion_epoch INTEGER NOT NULL CHECK(deletion_epoch >= 1),
  checkpoint_id TEXT,
  status TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX deletion_floor_index ON deletion_commitments(deletion_epoch,status);
CREATE TABLE policy_evaluations (
  evaluation_id TEXT PRIMARY KEY,
  partition_key TEXT NOT NULL,
  evidence_state TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;
CREATE INDEX policy_partition_index ON policy_evaluations(partition_key,evidence_state);
CREATE TABLE scope_aliases (
  alias_type TEXT NOT NULL,
  alias_tag TEXT NOT NULL,
  target_tag TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  PRIMARY KEY(alias_type,alias_tag)
) STRICT;
"""


class OwnerVault:
    def __init__(self, path, crypto, *, allow_test_crypto=False):
        self.path = _safe_path(path, "owner vault")
        self.crypto = crypto
        safe = getattr(crypto, "production_safe", False) is True
        if not safe and not allow_test_crypto:
            raise VaultError("production vault requires the signed loom-vault crypto helper")
        for method in ("seal", "open", "sign", "verify", "blind_index", "public_key"):
            if not callable(getattr(crypto, method, None)):
                raise VaultError(f"crypto helper does not implement {method}")

    @classmethod
    def create(cls, path, *, crypto, owner_vault_id=None, device_id=None,
               allow_test_crypto=False):
        vault = cls(path, crypto, allow_test_crypto=allow_test_crypto)
        if vault.path.exists():
            raise VaultError("owner vault already exists")
        vault.path.parent.mkdir(parents=True, exist_ok=True)
        _safe_path(vault.path.parent, "owner vault directory")
        owner_vault_id = _uuid(
            owner_vault_id or str(uuid.uuid4()), "owner_vault_id")
        device_id = _uuid(device_id or str(uuid.uuid4()), "device_id")
        try:
            with vault._connect() as connection:
                connection.executescript(SCHEMA)
                stamp = _stamp()
                values = {
                    "owner_vault_id": owner_vault_id,
                    "device_id": device_id,
                    "key_slot_id": owner_vault_id,
                    "schema_version": str(VAULT_SCHEMA_VERSION),
                    "generation": "1",
                    "created_at": stamp,
                    "last_release_sequence": "0",
                    "deletion_epoch": "0",
                }
                connection.executemany(
                    "INSERT INTO metadata(key,value) VALUES(?,?)", values.items())
                connection.execute(
                    "INSERT INTO devices(device_id,public_key,counter,status,last_seen) "
                    "VALUES(?,?,?,?,?)",
                    (device_id, crypto.public_key(), 0, "active", stamp))
                connection.commit()
            try:
                os.chmod(vault.path, 0o600)
            except OSError:
                pass
        except BaseException:
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(str(vault.path) + suffix).unlink()
                except FileNotFoundError:
                    pass
            raise
        return vault

    @classmethod
    def open(cls, path, *, crypto, allow_test_crypto=False):
        vault = cls(path, crypto, allow_test_crypto=allow_test_crypto)
        if not vault.path.is_file():
            raise VaultError("owner vault does not exist")
        vault._migrate_schema()
        identity = vault.identity()
        if identity["schema_version"] != VAULT_SCHEMA_VERSION:
            raise VaultError("owner vault schema requires migration")
        return vault

    def _migrate_schema(self):
        try:
            with closing(sqlite3.connect(self.path)) as source:
                row = source.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'").fetchone()
                version = int(row[0]) if row else 0
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise VaultError(f"owner vault schema is unreadable: {exc}") from exc
        if version == VAULT_SCHEMA_VERSION:
            return {"status": "current", "from": version, "to": version}
        if version not in {1, 2}:
            raise VaultError("owner vault schema requires an unavailable migration")
        descriptor, staged_name = tempfile.mkstemp(
            prefix=".loom-schema-v3-", suffix=".sqlite3", dir=self.path.parent)
        os.close(descriptor)
        staged = Path(staged_name)
        staged.unlink()
        rollback = self.path.with_name(self.path.name + f".schema-v{version}.rollback")
        if rollback.exists():
            raise VaultError("schema migration rollback snapshot is ambiguous")
        try:
            with closing(sqlite3.connect(self.path)) as source, \
                    closing(sqlite3.connect(staged)) as target:
                source.backup(target)
                target.execute("BEGIN IMMEDIATE")
                if version == 1:
                    for table in ("memory_records", "tombstones", "state_entities"):
                        columns = {row[1] for row in target.execute(f"PRAGMA table_info({table})")}
                        if "source_event_id" not in columns:
                            target.execute(
                                f"ALTER TABLE {table} ADD COLUMN source_event_id TEXT "
                                "NOT NULL DEFAULT 'legacy-v1'")
                        if "source_device_id" not in columns:
                            target.execute(
                                f"ALTER TABLE {table} ADD COLUMN source_device_id TEXT "
                                "NOT NULL DEFAULT 'legacy-v1'")
                    v1_receipt = {"schema_version": 1, "from": 1, "to": 2,
                                  "tables": ["memory_records", "state_entities", "tombstones"],
                                  "status": "migrated"}
                    target.execute(
                        "INSERT INTO metadata(key,value) VALUES('schema_migration_v1_v2',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (_canonical(v1_receipt).decode("utf-8"),))
                utility_columns = {
                    row[1] for row in target.execute("PRAGMA table_info(memory_utility)")}
                for name in ("application_count", "verified_neutral_count", "ambiguous_count"):
                    if name not in utility_columns:
                        target.execute(
                            f"ALTER TABLE memory_utility ADD COLUMN {name} INTEGER NOT NULL "
                            "DEFAULT 0 CHECK(" + name + ">=0)")
                if "last_applied" not in utility_columns:
                    target.execute("ALTER TABLE memory_utility ADD COLUMN last_applied TEXT")
                memory_columns = {
                    row[1] for row in target.execute("PRAGMA table_info(memory_records)")}
                for name in ("component_tag", "device_tag"):
                    if name not in memory_columns:
                        target.execute(f"ALTER TABLE memory_records ADD COLUMN {name} TEXT")
                v3_tables = [
                    "memory_observations", "memory_effects", "preference_slots",
                    "derivation_edges", "deletion_commitments", "policy_evaluations",
                    "scope_aliases",
                ]
                target.execute("DROP INDEX IF EXISTS memory_scope_index")
                target.execute("""
                    CREATE TABLE memory_records_v3 (
                      record_id TEXT PRIMARY KEY,
                      scope TEXT NOT NULL CHECK(scope IN (
                        'global','general','domain','project','component','temporary','device')),
                      domain_tag TEXT,
                      project_tag TEXT,
                      component_tag TEXT,
                      device_tag TEXT,
                      semantic_tag TEXT NOT NULL,
                      status TEXT NOT NULL,
                      source_sequence INTEGER NOT NULL CHECK(source_sequence >= 0),
                      source_event_id TEXT NOT NULL DEFAULT 'unmaterialized',
                      source_device_id TEXT NOT NULL DEFAULT 'unmaterialized',
                      ciphertext BLOB NOT NULL,
                      updated_at TEXT NOT NULL
                    ) STRICT
                """)
                target.execute(
                    "INSERT INTO memory_records_v3 SELECT record_id,scope,domain_tag,project_tag,"
                    "component_tag,device_tag,semantic_tag,status,source_sequence,source_event_id,"
                    "source_device_id,ciphertext,updated_at FROM memory_records")
                target.execute("DROP TABLE memory_records")
                target.execute("ALTER TABLE memory_records_v3 RENAME TO memory_records")
                target.execute(
                    "CREATE INDEX memory_scope_index ON memory_records("
                    "scope,domain_tag,project_tag,component_tag,device_tag,status)")
                schema_tail = SCHEMA[SCHEMA.index("CREATE TABLE memory_observations"):]
                schema_tail = schema_tail.replace(
                    "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ").replace(
                    "CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ")
                target.executescript(schema_tail)
                receipt = {"schema_version": 1, "from": version, "to": 3,
                           "tables": v3_tables, "status": "migrated"}
                target.execute(
                    "UPDATE metadata SET value=? WHERE key='schema_version'",
                    (str(VAULT_SCHEMA_VERSION),))
                target.execute(
                    "INSERT INTO metadata(key,value) VALUES('schema_migration_v2_v3',?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (_canonical(receipt).decode("utf-8"),))
                target.execute(f"PRAGMA user_version={VAULT_SCHEMA_VERSION}")
                target.commit()
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok" \
                        or target.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise VaultError("staged schema migration failed database validation")
            os.replace(self.path, rollback)
            try:
                os.replace(staged, self.path)
            except BaseException:
                os.replace(rollback, self.path)
                raise
            return receipt
        except (OSError, sqlite3.Error) as exc:
            raise VaultError(f"schema migration failed safely: {exc}") from exc
        finally:
            staged.unlink(missing_ok=True)

    def schema_migration_receipt(self):
        with self._connect() as connection:
            metadata = self._metadata(connection)
            value = metadata.get("schema_migration_v2_v3") \
                or metadata.get("schema_migration_v1_v2")
        return json.loads(value) if value else None

    def _connect(self):
        connection = sqlite3.connect(
            self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None,
            factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @staticmethod
    def _metadata(connection):
        return {row["key"]: row["value"] for row in connection.execute(
            "SELECT key,value FROM metadata")}

    def identity(self):
        try:
            with self._connect() as connection:
                metadata = self._metadata(connection)
                required = {"owner_vault_id", "device_id", "schema_version", "generation"}
                if not required <= set(metadata):
                    raise VaultError("owner vault identity is incomplete")
                return {
                    "owner_vault_id": _uuid(metadata["owner_vault_id"], "owner_vault_id"),
                    "device_id": _uuid(metadata["device_id"], "device_id"),
                    "schema_version": int(metadata["schema_version"]),
                    "generation": int(metadata["generation"]),
                }
        except (sqlite3.Error, ValueError) as exc:
            raise VaultError(f"owner vault identity is invalid: {exc}") from exc

    def deletion_epoch(self):
        with self._connect() as connection:
            value = self._metadata(connection).get("deletion_epoch", "0")
        try:
            epoch = int(value)
        except (TypeError, ValueError) as exc:
            raise VaultError("owner vault deletion epoch is invalid") from exc
        if epoch < 0:
            raise VaultError("owner vault deletion epoch is invalid")
        return epoch

    @staticmethod
    def _advance_deletion_epoch(connection):
        connection.execute(
            "INSERT INTO metadata(key,value) VALUES('deletion_epoch','1') "
            "ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")

    def authorize_device(self, device_id, public_key):
        device_id = _uuid(device_id, "device_id")
        if not isinstance(public_key, str):
            raise VaultError("device public key is invalid")
        try:
            if len(base64.b64decode(public_key, validate=True)) != 32:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise VaultError("device public key is invalid") from exc

        def write(connection):
            existing = connection.execute(
                "SELECT public_key,status FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if existing:
                if existing["public_key"] != public_key:
                    raise VaultError("device identity already has another signing key")
                if existing["status"] == "revoked":
                    raise VaultError("revoked device requires a new device identity")
                return {"device_id": device_id, "status": existing["status"],
                        "idempotent": True}
            if connection.execute(
                    "SELECT COUNT(*) FROM devices WHERE status!='revoked'").fetchone()[0] \
                    >= MAX_DEVICES:
                raise VaultError("active paired-device bound reached")
            if connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] \
                    >= MAX_DEVICE_HISTORY:
                raise VaultError("paired-device history bound reached")
            connection.execute(
                "INSERT INTO devices(device_id,public_key,counter,status,last_seen) "
                "VALUES(?,?,?,?,?)", (device_id, public_key, 0, "active", _stamp()))
            return {"device_id": device_id, "status": "active", "idempotent": False}

        return self.run_transaction(write)

    def assign_key_slot(self, key_slot_id):
        """Bind this vault copy to a separately staged secure-key slot."""
        key_slot_id = _uuid(key_slot_id, "key slot id")

        def write(connection):
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('key_slot_id',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key_slot_id,))
            return {"key_slot_id": key_slot_id}

        return self.run_transaction(write)

    def maintain_devices(self, *, now=None):
        instant = now or dt.datetime.now(dt.timezone.utc)
        if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
            raise VaultError("device lifecycle time must be timezone-aware")
        instant = instant.astimezone(dt.timezone.utc)
        local = self.identity()["device_id"]

        def write(connection):
            dormant = []
            for row in connection.execute(
                    "SELECT device_id,last_seen FROM devices WHERE status='active' "
                    "AND device_id!=?", (local,)).fetchall():
                try:
                    seen = dt.datetime.fromisoformat(row["last_seen"].replace("Z", "+00:00"))
                except ValueError as exc:
                    raise VaultError("device last-seen timestamp is invalid") from exc
                if (instant - seen.astimezone(dt.timezone.utc)).days >= 90:
                    connection.execute(
                        "UPDATE devices SET status='dormant' WHERE device_id=?",
                        (row["device_id"],))
                    dormant.append(row["device_id"])
            return {"dormant": len(dormant), "device_ids": sorted(dormant)}

        return self.run_transaction(write)

    def revoke_device(self, device_id):
        device_id = _uuid(device_id, "device_id")
        if device_id == self.identity()["device_id"]:
            raise VaultError("the active local device cannot revoke itself")

        def write(connection):
            changed = connection.execute(
                "UPDATE devices SET status='revoked',last_seen=? "
                "WHERE device_id=? AND status!='revoked'", (_stamp(), device_id)).rowcount
            if not changed and not connection.execute(
                    "SELECT 1 FROM devices WHERE device_id=? AND status='revoked'",
                    (device_id,)).fetchone():
                raise VaultError("device is not paired")
            return {"device_id": device_id, "status": "revoked",
                    "idempotent": not bool(changed)}

        return self.run_transaction(write)

    def adopt_local_device(self, device_id, public_key):
        """Switch a restored checkpoint to an already authorized new local device."""
        device_id = _uuid(device_id, "device_id")
        if not isinstance(public_key, str):
            raise VaultError("device public key is invalid")

        def write(connection):
            row = connection.execute(
                "SELECT public_key,status FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if row is None or row["public_key"] != public_key or row["status"] != "active":
                raise VaultError("restored local device was not authorized by the source vault")
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='device_id'", (device_id,))
            return {"device_id": device_id, "status": "adopted"}

        return self.run_transaction(write)

    def device_identity(self, device_id):
        device_id = _uuid(device_id, "device_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT public_key,status FROM devices WHERE device_id=?", (device_id,)).fetchone()
        return None if row is None else {"device_id": device_id,
                                         "public_key": row["public_key"],
                                         "status": row["status"]}

    def run_transaction(self, operation):
        if not callable(operation):
            raise VaultError("transaction operation must be callable")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            result = operation(connection)
            connection.execute(
                "UPDATE metadata SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
            connection.commit()
            return result
        except BaseException as exc:
            try:
                connection.rollback()
            finally:
                connection.close()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(exc, VaultError):
                raise
            raise VaultError(str(exc)) from exc
        finally:
            try:
                connection.close()
            except sqlite3.Error:
                pass

    def _tags(self, record):
        scope = record["scope"]
        domain = record.get("domain")
        project = record.get("project_id")
        component = record.get("component_id")
        device = record.get("device_id")
        return (
            self.crypto.blind_index("domain", domain) if domain else None,
            self.crypto.blind_index("project", project) if project else None,
            self.crypto.blind_index("component", component) if component else None,
            self.crypto.blind_index("device", device) if device else None,
        )

    def _validate_record(self, record):
        required = {
            "id", "scope", "domain", "project_id", "category", "statement",
            "provenance", "status", "confidence", "evidence_count", "created_at",
            "preference_key", "preference_value",
        }
        optional = {"component_id", "device_id", "expires_at", "verify_by"}
        if not isinstance(record, dict) or not required <= set(record) \
                or set(record) - required - optional:
            raise VaultError("memory record has unknown or missing fields")
        _uuid(record["id"], "memory id")
        if record["scope"] not in SCOPES or record["status"] not in STATUSES:
            raise VaultError("memory scope or status is invalid")
        if record["scope"] in {"global", "general"} and (record["domain"] is not None
                                               or record["project_id"] is not None):
            raise VaultError("general memory cannot carry domain or project identity")
        if record["scope"] == "domain" and (
                not isinstance(record["domain"], str) or record["project_id"] is not None):
            raise VaultError("domain memory requires exactly one domain")
        if record["scope"] == "project" and (
                not isinstance(record["domain"], str)
                or not isinstance(record["project_id"], str)
                or not record["project_id"].startswith("p-")):
            raise VaultError("project memory requires exact domain and project lineage")
        if record["scope"] == "component" and (
                not isinstance(record["domain"], str)
                or not isinstance(record["project_id"], str)
                or not record["project_id"].startswith("p-")
                or not isinstance(record.get("component_id"), str)
                or not record["component_id"].startswith("c-")):
            raise VaultError("component memory requires exact domain and project lineage")
        if record["scope"] == "device" and (
                record["domain"] is not None or record["project_id"] is not None
                or not isinstance(record.get("device_id"), str)):
            raise VaultError("device memory requires exact device identity only")
        if record["scope"] != "component" and record.get("component_id") is not None:
            raise VaultError("only component memory may carry component identity")
        if record["scope"] != "device" and record.get("device_id") is not None:
            raise VaultError("only device memory may carry device identity")
        if record["scope"] == "temporary" and not isinstance(record.get("expires_at"), str):
            raise VaultError("temporary memory requires an expiry")
        if record["category"] == "technical-fact" and not isinstance(
                record.get("verify_by"), str):
            raise VaultError("technical facts require a currentness deadline")
        if not isinstance(record["statement"], str) or not 1 <= len(record["statement"]) <= 1000:
            raise VaultError("memory statement is invalid or oversized")
        if record["category"] == "preference":
            if record["provenance"] != "stated" \
                    or not isinstance(record["preference_key"], str) \
                    or not isinstance(record["preference_value"], str):
                raise VaultError("active preference must be explicit and keyed")
        elif record["preference_key"] is not None or record["preference_value"] is not None:
            raise VaultError("non-preference memory cannot carry preference values")
        return json.loads(json.dumps(record))

    def _semantic_tag(self, record):
        body = {key: record.get(key) for key in (
            "scope", "domain", "project_id", "category", "statement",
            "component_id", "device_id", "preference_key", "preference_value")}
        return self.crypto.blind_index(
            "memory-semantic", _canonical(body).decode("utf-8"))

    def _next_event(self, connection, *, kind, payload, scope, domain_tag, project_tag):
        metadata = self._metadata(connection)
        device_id = metadata["device_id"]
        row = connection.execute(
            "SELECT counter,status FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if row is None or row["status"] != "active":
            raise VaultError("local device is not authorized")
        counter = row["counter"] + 1
        prior = connection.execute(
            "SELECT event_hash FROM events WHERE device_id=? ORDER BY device_counter DESC LIMIT 1",
            (device_id,)).fetchone()
        prior_hash = prior["event_hash"] if prior else None
        event_id = str(uuid.uuid4())
        recorded_at = _stamp()
        header = {
            "event_id": event_id, "owner_vault_id": metadata["owner_vault_id"],
            "device_id": device_id, "device_counter": counter,
            "causal_parents": [prior_hash] if prior_hash else [],
            "payload_schema_version": PAYLOAD_SCHEMA_VERSION,
            "scope": scope, "domain": domain_tag, "project_id": project_tag,
            "prior_event_hash": prior_hash,
        }
        aad = _canonical(header)
        ciphertext = self.crypto.seal(_canonical({"kind": kind, "payload": payload}), aad)
        signature = self.crypto.sign(aad + b"\x00" + ciphertext)
        event_hash = hashlib.sha256(aad + b"\x00" + ciphertext + b"\x00" + signature).hexdigest()
        event_rank = _collision_checked_event_rank(
            connection, counter, device_id, event_id)
        connection.execute(
            "INSERT INTO events(event_id,device_id,device_counter,scope,domain_tag,project_tag,"
            "payload_schema_version,prior_event_hash,ciphertext,signature,event_hash,recorded_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, device_id, counter, scope, domain_tag, project_tag,
             PAYLOAD_SCHEMA_VERSION, prior_hash, ciphertext, signature, event_hash, recorded_at))
        connection.execute(
            "UPDATE devices SET counter=?,last_seen=? WHERE device_id=?",
            (counter, recorded_at, device_id))
        if connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] > MAX_EVENTS:
            raise VaultError("event bound reached before an acknowledged checkpoint")
        return {
            "event_id": event_id,
            "device_id": device_id,
            "device_counter": counter,
            "causal_parents": header["causal_parents"],
            "rank": event_rank,
        }

    def put_memory(self, record, *, source_sequence=0):
        record = self._validate_record(record)
        if type(source_sequence) is not int or source_sequence < 0:
            raise VaultError("source sequence is invalid")
        domain_tag, project_tag, component_tag, device_tag = self._tags(record)

        def write(connection):
            count = connection.execute("SELECT COUNT(*) FROM memory_records").fetchone()[0]
            exists = connection.execute(
                "SELECT 1 FROM memory_records WHERE record_id=?", (record["id"],)).fetchone()
            if not exists and count >= MAX_ACTIVE_RECORDS:
                raise VaultError("active memory record bound reached")
            event = self._next_event(
                connection, kind="memory-upsert", payload=record, scope=record["scope"],
                domain_tag=domain_tag, project_tag=project_tag)
            event.update({"scope": record["scope"], "domain": domain_tag,
                          "project_id": project_tag})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "memory-upsert", "payload": record}, receipt=receipt)
            if receipt["deduplicated"] and connection.execute(
                    "SELECT 1 FROM tombstones WHERE record_id=?", (record["id"],)).fetchone():
                return {"id": record["id"], "status": "forgotten"}
            return json.loads(json.dumps(record))

        return self.run_transaction(write)

    def import_memory(self, record, *, source_sequence):
        return self.put_memory(record, source_sequence=source_sequence)

    def is_forgotten(self, record_id, *, legacy_fingerprint=None):
        record_id = _uuid(record_id, "memory id")
        tags = []
        if legacy_fingerprint is not None:
            if not isinstance(legacy_fingerprint, str) or len(legacy_fingerprint) != 64:
                raise VaultError("legacy semantic fingerprint is invalid")
            tags.append(self.crypto.blind_index("legacy-fingerprint", legacy_fingerprint))
        with self._connect() as connection:
            if connection.execute(
                    "SELECT 1 FROM tombstones WHERE record_id=?", (record_id,)).fetchone():
                return True
            return any(connection.execute(
                "SELECT 1 FROM tombstones WHERE semantic_tag=?", (tag,)).fetchone()
                       for tag in tags)

    def import_tombstone(self, *, record_id, semantic_fingerprint, forgotten_at,
                         source_sequence=0):
        record_id = _uuid(record_id, "memory id")
        if not isinstance(semantic_fingerprint, str) or len(semantic_fingerprint) != 64 \
                or any(character not in "0123456789abcdef" for character in semantic_fingerprint):
            raise VaultError("legacy semantic fingerprint is invalid")
        if type(source_sequence) is not int or source_sequence < 0:
            raise VaultError("source sequence is invalid")
        tag = self.crypto.blind_index("legacy-fingerprint", semantic_fingerprint)
        payload = {"record_id": record_id, "reason": "legacy-import",
                   "semantic_tag": tag, "forgotten_at": forgotten_at}

        def write(connection):
            existing = connection.execute(
                "SELECT source_sequence FROM tombstones WHERE record_id=? OR semantic_tag=?",
                (record_id, tag)).fetchone()
            if existing and existing["source_sequence"] >= source_sequence:
                return {"id": record_id, "status": "forgotten", "idempotent": True}
            event = self._next_event(
                connection, kind="memory-forgotten", payload=payload,
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "memory-forgotten", "payload": payload}, receipt=receipt)
            return {"id": record_id, "status": "forgotten", "idempotent": False}

        return self.run_transaction(write)

    def put_entity(self, entity_type, entity_id, payload, *, source_sequence=0):
        if not isinstance(entity_type, str) or not entity_type \
                or not isinstance(entity_id, str) or not entity_id \
                or type(source_sequence) is not int or source_sequence < 0:
            raise VaultError("state entity identity is invalid")
        if len(entity_type) > 64 or len(entity_id) > 128:
            raise VaultError("state entity identity exceeds bound")
        if len(_canonical(payload)) > 1024 * 1024:
            raise VaultError("state entity exceeds bound")

        def write(connection):
            body = {"kind": "state-entity-upsert", "payload": {
                "entity_type": entity_type, "entity_id": entity_id, "value": payload}}
            event = self._next_event(
                connection, kind=body["kind"], payload=body["payload"],
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(connection, event=event, body=body, receipt=receipt)
            return {"entity_type": entity_type, "entity_id": entity_id}

        return self.run_transaction(write)

    def quarantine_import(self, kind, payload):
        if not isinstance(kind, str) or not kind or len(kind) > 64 \
                or len(_canonical(payload)) > 1024 * 1024:
            raise VaultError("legacy quarantine payload is invalid")

        def write(connection):
            body = {"kind": f"legacy-unknown:{kind}", "payload": payload}
            event = self._next_event(
                connection, kind=body["kind"], payload=payload,
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(connection, event=event, body=body, receipt=receipt)
            return {"kind": kind, "status": "quarantined", "receipt": receipt}

        return self.run_transaction(write)

    def list_entities(self, entity_type, *, limit=256):
        if not isinstance(entity_type, str) or not entity_type \
                or type(limit) is not int or not 1 <= limit <= 512:
            raise VaultError("entity listing inputs are invalid")
        identity = self.identity()["owner_vault_id"]
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM state_entities WHERE entity_type=? "
                "ORDER BY updated_at DESC,entity_id LIMIT ?", (entity_type, limit)).fetchall()
        result = []
        for row in rows:
            aad = f"entity:{identity}:{entity_type}:{row['entity_id']}".encode()
            try:
                value = json.loads(self.crypto.open(row["ciphertext"], aad).decode("utf-8"))
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                raise VaultError(f"state entity authentication failed: {exc}") from exc
            result.append({"id": row["entity_id"], "value": value,
                           "source_sequence": row["source_sequence"],
                           "updated_at": row["updated_at"]})
        return result

    def legacy_alias(self, alias_type, alias_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT target_id,source_hash FROM legacy_aliases "
                "WHERE alias_type=? AND alias_id=?", (alias_type, alias_id)).fetchone()
        return dict(row) if row else None

    def put_legacy_alias(self, alias_type, alias_id, target_id, source_hash):
        if not all(isinstance(value, str) and value for value in (
                alias_type, alias_id, target_id, source_hash)):
            raise VaultError("legacy alias is invalid")

        def write(connection):
            existing = connection.execute(
                "SELECT target_id,source_hash FROM legacy_aliases WHERE alias_type=? AND alias_id=?",
                (alias_type, alias_id)).fetchone()
            if existing and (existing["target_id"], existing["source_hash"]) != \
                    (target_id, source_hash):
                raise VaultError("legacy alias conflicts with existing migration")
            connection.execute(
                "INSERT OR IGNORE INTO legacy_aliases(alias_type,alias_id,target_id,source_hash) "
                "VALUES(?,?,?,?)", (alias_type, alias_id, target_id, source_hash))
            return {"alias_type": alias_type, "alias_id": alias_id}

        return self.run_transaction(write)

    def legacy_alias_ids(self, alias_type):
        if not isinstance(alias_type, str) or not alias_type:
            raise VaultError("legacy alias type is invalid")
        with self._connect() as connection:
            return [row[0] for row in connection.execute(
                "SELECT alias_id FROM legacy_aliases WHERE alias_type=? ORDER BY alias_id",
                (alias_type,))]

    def rekey_project_memory(self, legacy_project_id, current_project_id):
        if not isinstance(legacy_project_id, str) or not legacy_project_id.startswith("p-") \
                or not isinstance(current_project_id, str) or not current_project_id.startswith("p-"):
            raise VaultError("project rekey identities are invalid")
        old_tag = self.crypto.blind_index("project", legacy_project_id)
        new_tag = self.crypto.blind_index("project", current_project_id)
        owner = self.identity()["owner_vault_id"]

        def write(connection):
            rows = connection.execute(
                "SELECT * FROM memory_records WHERE scope='project' AND project_tag=?",
                (old_tag,)).fetchall()
            changed = 0
            for row in rows:
                record = self._decrypt_record(row)
                if record.get("project_id") != legacy_project_id:
                    raise VaultError("legacy project blind index does not match encrypted identity")
                record["project_id"] = current_project_id
                if record["status"] == "dormant":
                    record["status"] = "active"
                semantic_tag = self._semantic_tag(record)
                if connection.execute(
                        "SELECT 1 FROM tombstones WHERE record_id=? OR semantic_tag=?",
                        (record["id"], semantic_tag)).fetchone():
                    continue
                aad = f"memory:{owner}:{record['id']}".encode()
                ciphertext = self.crypto.seal(_canonical(record), aad)
                self._next_event(
                    connection, kind="memory-upsert", payload=record,
                    scope="project", domain_tag=row["domain_tag"], project_tag=new_tag)
                connection.execute(
                    "UPDATE memory_records SET project_tag=?,semantic_tag=?,status=?,"
                    "ciphertext=?,updated_at=? WHERE record_id=?",
                    (new_tag, semantic_tag, record["status"], ciphertext, _stamp(), record["id"]))
                changed += 1
            return {"legacy_project_id": legacy_project_id,
                    "current_project_id": current_project_id, "rekeyed": changed}

        return self.run_transaction(write)

    def put_receipt(self, receipt_id, kind, receipt):
        receipt_id = _uuid(receipt_id, "receipt id")
        if not isinstance(kind, str) or not kind:
            raise VaultError("receipt kind is invalid")
        owner = self.identity()["owner_vault_id"]
        aad = f"receipt:{owner}:{receipt_id}".encode()
        ciphertext = self.crypto.seal(_canonical(receipt), aad)

        def write(connection):
            connection.execute(
                "INSERT OR IGNORE INTO receipts(receipt_id,kind,ciphertext,created_at) "
                "VALUES(?,?,?,?)", (receipt_id, kind, ciphertext, _stamp()))
            return receipt

        return self.run_transaction(write)

    def get_receipt(self, receipt_id):
        receipt_id = _uuid(receipt_id, "receipt id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT ciphertext FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        if row is None:
            return None
        owner = self.identity()["owner_vault_id"]
        aad = f"receipt:{owner}:{receipt_id}".encode()
        try:
            return json.loads(self.crypto.open(row["ciphertext"], aad).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise VaultError("receipt authentication failed") from exc

    def _decrypt_record(self, row):
        owner = self.identity()["owner_vault_id"]
        aad = f"memory:{owner}:{row['record_id']}".encode()
        try:
            value = json.loads(self.crypto.open(row["ciphertext"], aad).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise VaultError(f"memory authentication failed: {exc}") from exc
        return self._validate_record(value)

    def _quarantine_connection(self, connection, *, item_id, kind, reason, payload):
        raw = _canonical(payload)
        current = connection.execute(
            "SELECT COALESCE(SUM(bytes),0) FROM quarantine").fetchone()[0]
        if current + len(raw) > MAX_QUARANTINE_BYTES:
            raise VaultError("quarantine byte bound reached")
        owner = self._metadata(connection)["owner_vault_id"]
        aad = f"quarantine:{owner}:{item_id}".encode()
        ciphertext = self.crypto.seal(raw, aad)
        connection.execute(
            "INSERT OR IGNORE INTO quarantine(item_id,kind,reason,bytes,ciphertext,created_at) "
            "VALUES(?,?,?,?,?,?)", (item_id, kind, reason, len(raw), ciphertext, _stamp()))

    def _apply_event(self, connection, *, event, body, receipt):
        """Apply one authenticated event to bounded materialized state.

        Local writes and remote merges must use this function.  The event row itself is
        intentionally persisted by the caller only after this function succeeds.
        """
        if not isinstance(body, dict) or set(body) != {"kind", "payload"}:
            raise VaultError("event payload is invalid")
        kind, payload = body["kind"], body["payload"]
        metadata = self._metadata(connection)
        event_rank = event["rank"]

        if kind == "memory-upsert":
            record = self._validate_record(payload)
            domain_tag, project_tag, component_tag, device_tag = self._tags(record)
            if (record["scope"], domain_tag, project_tag) != (
                    event["scope"], event["domain"], event["project_id"]):
                raise VaultError("memory scope does not match signed envelope")
            semantic_tag = self._semantic_tag(record)
            if connection.execute(
                    "SELECT 1 FROM tombstones WHERE record_id=? OR semantic_tag=?",
                    (record["id"], semantic_tag)).fetchone():
                receipt["deduplicated"] += 1
                return

            conflicts = []
            sequential = []
            if record["category"] == "preference" and record["status"] == "active":
                candidates = connection.execute(
                    "SELECT * FROM memory_records WHERE status='active' AND scope=? "
                    "AND COALESCE(domain_tag,'')=COALESCE(?, '') "
                    "AND COALESCE(project_tag,'')=COALESCE(?, '') AND record_id!=?",
                    (record["scope"], domain_tag, project_tag, record["id"])).fetchall()
                for candidate in candidates:
                    existing = self._decrypt_record(candidate)
                    if existing["category"] != "preference" \
                            or existing["preference_key"] != record["preference_key"] \
                            or existing["preference_value"] == record["preference_value"]:
                        continue
                    if candidate["source_device_id"] == event["device_id"] \
                            and candidate["source_sequence"] < event_rank:
                        sequential.append((candidate, existing))
                    else:
                        conflicts.append((candidate, existing))
            for candidate, existing in sequential:
                existing["status"] = "superseded"
                candidate_aad = (f"memory:{metadata['owner_vault_id']}:"
                                 f"{candidate['record_id']}").encode()
                connection.execute(
                    "UPDATE memory_records SET status='superseded',ciphertext=?,updated_at=? "
                    "WHERE record_id=?",
                    (self.crypto.seal(_canonical(existing), candidate_aad),
                     _stamp(), candidate["record_id"]))
            if conflicts:
                record["status"] = "dormant"
                conflict_ids = [record["id"]]
                for candidate, existing in conflicts:
                    existing["status"] = "dormant"
                    candidate_aad = (f"memory:{metadata['owner_vault_id']}:"
                                     f"{candidate['record_id']}").encode()
                    connection.execute(
                        "UPDATE memory_records SET status='dormant',ciphertext=?,updated_at=? "
                        "WHERE record_id=?",
                        (self.crypto.seal(_canonical(existing), candidate_aad),
                         _stamp(), candidate["record_id"]))
                    conflict_ids.append(candidate["record_id"])
                item_id = str(uuid.uuid5(
                    OWNER_NAMESPACE, "preference-conflict:" + ":".join(sorted(conflict_ids))))
                self._quarantine_connection(
                    connection, item_id=item_id, kind="preference-conflict",
                    reason="owner-choice-required", payload={
                        "record_ids": sorted(conflict_ids),
                        "preference_key": record["preference_key"]})
                receipt["quarantined"] += 1

            record_aad = f"memory:{metadata['owner_vault_id']}:{record['id']}".encode()
            existing = connection.execute(
                "SELECT source_sequence FROM memory_records WHERE record_id=?",
                (record["id"],)).fetchone()
            changed = connection.execute(
                "INSERT INTO memory_records(record_id,scope,domain_tag,project_tag,component_tag,"
                "device_tag,semantic_tag,"
                "status,source_sequence,source_event_id,source_device_id,ciphertext,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET "
                "scope=excluded.scope,domain_tag=excluded.domain_tag,"
                "project_tag=excluded.project_tag,component_tag=excluded.component_tag,"
                "device_tag=excluded.device_tag,semantic_tag=excluded.semantic_tag,"
                "status=excluded.status,source_sequence=excluded.source_sequence,"
                "source_event_id=excluded.source_event_id,source_device_id=excluded.source_device_id,"
                "ciphertext=excluded.ciphertext,updated_at=excluded.updated_at "
                "WHERE excluded.source_sequence > memory_records.source_sequence",
                (record["id"], record["scope"], domain_tag, project_tag, component_tag,
                 device_tag, semantic_tag,
                 record["status"], event_rank, event["event_id"], event["device_id"],
                 self.crypto.seal(_canonical(record), record_aad), _stamp())).rowcount
            connection.execute(
                "INSERT OR IGNORE INTO memory_utility(record_id) VALUES(?)", (record["id"],))
            if record["category"] == "preference":
                slot = {
                    "slot_id": record["id"], "key": record["preference_key"],
                    "value": record["preference_value"], "scope": record["scope"],
                    "domain": record["domain"], "project_id": record["project_id"],
                    "component_id": record.get("component_id"),
                    "source": "owner-stated" if record["provenance"] == "stated"
                    else "inferred",
                    "status": record["status"] if record["status"] in {
                        "active", "candidate", "superseded", "quarantined", "forgotten"}
                    else "candidate",
                    "evidence_projects": [record["project_id"]]
                    if record["project_id"] else [],
                    "evidence_domains": [record["domain"]] if record["domain"] else [],
                }
                slot_aad = (
                    f"preference-slot:{metadata['owner_vault_id']}:{record['id']}").encode()
                connection.execute(
                    "INSERT INTO preference_slots(slot_id,scope,domain_tag,project_tag,"
                    "component_tag,preference_key,status,source_event_id,ciphertext,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(slot_id) DO UPDATE SET "
                    "scope=excluded.scope,domain_tag=excluded.domain_tag,"
                    "project_tag=excluded.project_tag,component_tag=excluded.component_tag,"
                    "preference_key=excluded.preference_key,status=excluded.status,"
                    "source_event_id=excluded.source_event_id,ciphertext=excluded.ciphertext,"
                    "updated_at=excluded.updated_at",
                    (record["id"], record["scope"], domain_tag, project_tag, component_tag,
                     record["preference_key"], slot["status"], event["event_id"],
                     self.crypto.seal(_canonical(slot), slot_aad), _stamp()))
            receipt["added" if changed and existing is None else
                    "updated" if changed else "deduplicated"] += 1
            return

        if kind in {"memory-forgotten", "memory-expired", "memory-superseded-expired"}:
            if not isinstance(payload, dict) or set(payload) != {
                    "record_id", "reason", "semantic_tag", "forgotten_at"}:
                raise VaultError("forget event payload is invalid")
            record_id = _uuid(payload["record_id"], "memory id")
            semantic_tag = payload["semantic_tag"]
            if not isinstance(semantic_tag, str) or len(semantic_tag) != 64:
                raise VaultError("forget event semantic tag is invalid")
            aad = f"tombstone:{metadata['owner_vault_id']}:{record_id}".encode()
            existed = connection.execute(
                "SELECT 1 FROM tombstones WHERE record_id=? OR semantic_tag=?",
                (record_id, semantic_tag)).fetchone()
            connection.execute(
                "INSERT INTO tombstones(record_id,semantic_tag,source_sequence,source_event_id,"
                "source_device_id,ciphertext,forgotten_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(record_id) DO UPDATE SET semantic_tag=excluded.semantic_tag,"
                "source_sequence=excluded.source_sequence,source_event_id=excluded.source_event_id,"
                "source_device_id=excluded.source_device_id,ciphertext=excluded.ciphertext,"
                "forgotten_at=excluded.forgotten_at "
                "WHERE excluded.source_sequence > tombstones.source_sequence",
                (record_id, semantic_tag, event_rank, event["event_id"], event["device_id"],
                 self.crypto.seal(_canonical(payload), aad), payload["forgotten_at"]))
            descendants = set()
            frontier = [record_id]
            while frontier:
                parent = frontier.pop()
                children = [row[0] for row in connection.execute(
                    "SELECT child_id FROM derivation_edges WHERE parent_id=?", (parent,))]
                for child in children:
                    if child not in descendants:
                        descendants.add(child)
                        frontier.append(child)
                if len(descendants) > 1024:
                    raise VaultError("forget derivation traversal exceeds bound")
            targets = {record_id, *descendants}
            placeholders = ",".join("?" for _ in targets)
            connection.execute(
                f"DELETE FROM memory_records WHERE record_id IN ({placeholders}) OR semantic_tag=?",
                (*sorted(targets), semantic_tag))
            connection.execute(
                f"DELETE FROM state_entities WHERE entity_id IN ({placeholders})",
                tuple(sorted(targets)))
            connection.execute(
                f"DELETE FROM preference_slots WHERE slot_id IN ({placeholders})",
                tuple(sorted(targets)))
            connection.execute(
                f"DELETE FROM policy_evaluations WHERE evaluation_id IN ({placeholders})",
                tuple(sorted(targets)))
            connection.execute(
                f"DELETE FROM derivation_edges WHERE parent_id IN ({placeholders}) "
                f"OR child_id IN ({placeholders})", (*sorted(targets), *sorted(targets)))
            self._advance_deletion_epoch(connection)
            deletion_epoch = int(self._metadata(connection)["deletion_epoch"])
            commitment_id = str(uuid.uuid5(
                OWNER_NAMESPACE, f"deletion:{record_id}:{deletion_epoch}"))
            commitment = {
                "commitment_id": commitment_id, "record_id": record_id,
                "deletion_epoch": deletion_epoch, "status": "pending-checkpoint",
                "checkpoint_id": None, "pending_devices": [], "created_at": _stamp(),
                "derived_removed": len(descendants),
            }
            commitment_aad = (
                f"deletion-commitment:{metadata['owner_vault_id']}:{commitment_id}").encode()
            connection.execute(
                "INSERT OR REPLACE INTO deletion_commitments(commitment_id,record_id,semantic_tag,"
                "deletion_epoch,checkpoint_id,status,source_event_id,ciphertext,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (commitment_id, record_id, semantic_tag, deletion_epoch, None,
                 "pending-checkpoint", event["event_id"],
                 self.crypto.seal(_canonical(commitment), commitment_aad),
                 commitment["created_at"]))
            receipt["deduplicated" if existed else "forgotten"] += 1
            return

        if kind == "memory-outcome":
            if not isinstance(payload, dict) or set(payload) != {
                    "selected_ids", "helped_ids", "hurt_ids"}:
                raise VaultError("memory outcome event payload is invalid")
            selected = payload["selected_ids"]
            helped, hurt = set(payload["helped_ids"]), set(payload["hurt_ids"])
            if not isinstance(selected, list) or not all(isinstance(item, str) for item in selected) \
                    or not helped <= set(selected) or not hurt <= set(selected) or helped & hurt:
                raise VaultError("memory outcome event IDs are invalid")
            stamp = _stamp()
            for record_id in selected:
                connection.execute(
                    "UPDATE memory_utility SET helped_count=helped_count+?,"
                    "hurt_count=hurt_count+?,last_helped=CASE WHEN ? THEN ? ELSE last_helped END,"
                    "last_hurt=CASE WHEN ? THEN ? ELSE last_hurt END WHERE record_id=?",
                    (int(record_id in helped), int(record_id in hurt),
                     int(record_id in helped), stamp, int(record_id in hurt), stamp, record_id))
            receipt["recomputed"] += 1
            return

        if kind == "memory-effect":
            required = {
                "effect_id", "memory_id", "operation_id", "status", "decision_target",
                "intended_effect", "evidence_id", "serious_harm",
            }
            if not isinstance(payload, dict) or set(payload) != required:
                raise VaultError("memory effect payload is invalid")
            effect_id = _uuid(payload["effect_id"], "memory effect id")
            memory_id = _uuid(payload["memory_id"], "memory id")
            status = payload["status"]
            if status not in ATTRIBUTION_STATUSES \
                    or not isinstance(payload["operation_id"], str) \
                    or not 1 <= len(payload["operation_id"]) <= 128 \
                    or not isinstance(payload["decision_target"], str) \
                    or not 1 <= len(payload["decision_target"]) <= 128 \
                    or not isinstance(payload["intended_effect"], str) \
                    or not 1 <= len(payload["intended_effect"]) <= 240 \
                    or type(payload["serious_harm"]) is not bool:
                raise VaultError("memory effect fields are invalid")
            evidence_required = status in {
                "verified-helped", "verified-hurt", "verified-neutral"}
            if evidence_required != isinstance(payload["evidence_id"], str):
                raise VaultError("verified memory effects require exactly one evidence id")
            if payload["serious_harm"] and status != "verified-hurt":
                raise VaultError("serious harm must be verified hurt")
            row = connection.execute(
                "SELECT * FROM memory_records WHERE record_id=?", (memory_id,)).fetchone()
            if row is None:
                raise VaultError("memory effect references an unavailable record")
            aad = f"memory-effect:{metadata['owner_vault_id']}:{effect_id}".encode()
            changed = connection.execute(
                "INSERT OR IGNORE INTO memory_effects(effect_id,memory_id,operation_id,"
                "attribution_status,evidence_id,source_event_id,ciphertext,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (effect_id, memory_id, payload["operation_id"], status,
                 payload["evidence_id"], event["event_id"],
                 self.crypto.seal(_canonical(payload), aad), _stamp())).rowcount
            if not changed:
                receipt["deduplicated"] += 1
                return
            applied = status not in {"selected-only", "rejected-before-use"}
            stamp = _stamp()
            connection.execute(
                "UPDATE memory_utility SET application_count=application_count+?,"
                "helped_count=helped_count+?,hurt_count=hurt_count+?,"
                "verified_neutral_count=verified_neutral_count+?,"
                "ambiguous_count=ambiguous_count+?,"
                "last_applied=CASE WHEN ? THEN ? ELSE last_applied END,"
                "last_helped=CASE WHEN ? THEN ? ELSE last_helped END,"
                "last_hurt=CASE WHEN ? THEN ? ELSE last_hurt END WHERE record_id=?",
                (int(applied), int(status == "verified-helped"),
                 int(status == "verified-hurt"), int(status == "verified-neutral"),
                 int(status == "outcome-ambiguous"), int(applied), stamp,
                 int(status == "verified-helped"), stamp,
                 int(status == "verified-hurt"), stamp, memory_id))
            if payload["serious_harm"]:
                record = self._decrypt_record(row)
                record["status"] = "quarantined"
                record_aad = f"memory:{metadata['owner_vault_id']}:{memory_id}".encode()
                connection.execute(
                    "UPDATE memory_records SET status='quarantined',ciphertext=?,updated_at=? "
                    "WHERE record_id=?",
                    (self.crypto.seal(_canonical(record), record_aad), stamp, memory_id))
            excess = connection.execute(
                "SELECT COUNT(*) FROM memory_effects").fetchone()[0] - MAX_RECENT_EFFECTS
            if excess > 0:
                compacted = [dict(row) for row in connection.execute(
                    "SELECT effect_id,memory_id,operation_id,attribution_status,evidence_id,"
                    "source_event_id FROM memory_effects ORDER BY recorded_at,effect_id LIMIT ?",
                    (excess,))]
                commitment = {
                    "count": len(compacted),
                    "root_sha256": hashlib.sha256(_canonical(compacted)).hexdigest(),
                    "compacted_at": stamp,
                }
                compact_id = str(uuid.uuid4())
                compact_aad = (
                    f"receipt:{metadata['owner_vault_id']}:{compact_id}").encode()
                connection.execute(
                    "INSERT INTO receipts(receipt_id,kind,ciphertext,created_at) VALUES(?,?,?,?)",
                    (compact_id, "memory-effect-compaction",
                     self.crypto.seal(_canonical(commitment), compact_aad), stamp))
                ids = [item["effect_id"] for item in compacted]
                connection.execute(
                    f"DELETE FROM memory_effects WHERE effect_id IN "
                    f"({','.join('?' for _ in ids)})", ids)
            receipt["recomputed"] += 1
            return

        if kind == "memory-observation":
            required = {
                "observation_id", "memory_id", "scope", "domain", "project_id",
                "component_id", "decision_target", "evidence_id", "observed_at", "value",
            }
            if not isinstance(payload, dict) or set(payload) != required:
                raise VaultError("memory observation payload is invalid")
            observation_id = _uuid(payload["observation_id"], "observation id")
            if payload["memory_id"] is not None:
                _uuid(payload["memory_id"], "memory id")
            if payload["scope"] not in SCOPES \
                    or not isinstance(payload["decision_target"], str) \
                    or not 1 <= len(payload["decision_target"]) <= 128 \
                    or not isinstance(payload["evidence_id"], str) \
                    or not 8 <= len(payload["evidence_id"]) <= 256:
                raise VaultError("memory observation fields are invalid")
            domain_tag = self.crypto.blind_index(
                "domain", payload["domain"]) if payload["domain"] else None
            project_tag = self.crypto.blind_index(
                "project", payload["project_id"]) if payload["project_id"] else None
            component_tag = self.crypto.blind_index(
                "component", payload["component_id"]) if payload["component_id"] else None
            aad = f"memory-observation:{metadata['owner_vault_id']}:{observation_id}".encode()
            changed = connection.execute(
                "INSERT OR IGNORE INTO memory_observations(observation_id,memory_id,scope,"
                "domain_tag,project_tag,component_tag,decision_target,evidence_id,source_event_id,"
                "ciphertext,observed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (observation_id, payload["memory_id"], payload["scope"], domain_tag,
                 project_tag, component_tag, payload["decision_target"], payload["evidence_id"],
                 event["event_id"], self.crypto.seal(_canonical(payload), aad),
                 payload["observed_at"])).rowcount
            receipt["added" if changed else "deduplicated"] += 1
            return

        if kind == "preference-slot":
            required = {
                "slot_id", "key", "value", "scope", "domain", "project_id",
                "component_id", "source", "status", "evidence_projects",
                "evidence_domains",
            }
            if not isinstance(payload, dict) or set(payload) != required:
                raise VaultError("preference slot payload is invalid")
            slot_id = _uuid(payload["slot_id"], "preference slot id")
            if payload["scope"] not in SCOPES or payload["status"] not in {
                    "active", "candidate", "superseded", "quarantined", "forgotten"} \
                    or payload["source"] not in {
                        "owner-stated", "confirmed-inference", "inferred", "default"} \
                    or not isinstance(payload["key"], str) \
                    or not 1 <= len(payload["key"]) <= 128 \
                    or not isinstance(payload["value"], str) \
                    or not 1 <= len(payload["value"]) <= 240 \
                    or not isinstance(payload["evidence_projects"], list) \
                    or len(payload["evidence_projects"]) > 64 \
                    or not isinstance(payload["evidence_domains"], list) \
                    or len(payload["evidence_domains"]) > 16:
                raise VaultError("preference slot fields are invalid")
            domain_tag = self.crypto.blind_index(
                "domain", payload["domain"]) if payload["domain"] else None
            project_tag = self.crypto.blind_index(
                "project", payload["project_id"]) if payload["project_id"] else None
            component_tag = self.crypto.blind_index(
                "component", payload["component_id"]) if payload["component_id"] else None
            aad = f"preference-slot:{metadata['owner_vault_id']}:{slot_id}".encode()
            changed = connection.execute(
                "INSERT INTO preference_slots(slot_id,scope,domain_tag,project_tag,component_tag,"
                "preference_key,status,source_event_id,ciphertext,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(slot_id) DO UPDATE SET "
                "scope=excluded.scope,domain_tag=excluded.domain_tag,"
                "project_tag=excluded.project_tag,component_tag=excluded.component_tag,"
                "preference_key=excluded.preference_key,status=excluded.status,"
                "source_event_id=excluded.source_event_id,ciphertext=excluded.ciphertext,"
                "updated_at=excluded.updated_at",
                (slot_id, payload["scope"], domain_tag, project_tag, component_tag,
                 payload["key"], payload["status"], event["event_id"],
                 self.crypto.seal(_canonical(payload), aad), _stamp())).rowcount
            receipt["updated" if changed else "deduplicated"] += 1
            return

        if kind == "policy-evaluation":
            required = {
                "evaluation_id", "partition", "evidence_state", "policy_version",
                "sample_count", "effect_lower", "effect_upper", "harm_upper",
                "token_cost", "elapsed_seconds",
            }
            if not isinstance(payload, dict) or set(payload) != required:
                raise VaultError("policy evaluation payload is invalid")
            evaluation_id = _uuid(payload["evaluation_id"], "policy evaluation id")
            if not isinstance(payload["partition"], str) \
                    or not 1 <= len(payload["partition"]) <= 256 \
                    or not isinstance(payload["evidence_state"], str) \
                    or not isinstance(payload["policy_version"], str) \
                    or not 1 <= len(payload["policy_version"]) <= 64 \
                    or type(payload["sample_count"]) is not int \
                    or payload["sample_count"] < 0 \
                    or type(payload["token_cost"]) is not int \
                    or payload["token_cost"] < 0 \
                    or type(payload["elapsed_seconds"]) not in (int, float) \
                    or payload["elapsed_seconds"] < 0 \
                    or any(value is not None and type(value) not in (int, float)
                           for value in (payload["effect_lower"], payload["effect_upper"],
                                         payload["harm_upper"])):
                raise VaultError("policy evaluation fields are invalid")
            partition_key = self.crypto.blind_index("policy-partition", payload["partition"])
            aad = f"policy-evaluation:{metadata['owner_vault_id']}:{evaluation_id}".encode()
            changed = connection.execute(
                "INSERT INTO policy_evaluations(evaluation_id,partition_key,evidence_state,"
                "policy_version,source_event_id,ciphertext,updated_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(evaluation_id) DO UPDATE SET partition_key=excluded.partition_key,"
                "evidence_state=excluded.evidence_state,policy_version=excluded.policy_version,"
                "source_event_id=excluded.source_event_id,ciphertext=excluded.ciphertext,"
                "updated_at=excluded.updated_at",
                (evaluation_id, partition_key, payload["evidence_state"],
                 payload["policy_version"], event["event_id"],
                 self.crypto.seal(_canonical(payload), aad), _stamp())).rowcount
            receipt["updated" if changed else "deduplicated"] += 1
            return

        if kind == "derivation-edge":
            if not isinstance(payload, dict) or set(payload) != {
                    "parent_id", "child_id", "relation"}:
                raise VaultError("derivation edge payload is invalid")
            if any(not isinstance(payload[key], str) or not 1 <= len(payload[key]) <= 128
                   for key in ("parent_id", "child_id")) \
                    or payload["parent_id"] == payload["child_id"] \
                    or payload["relation"] not in {
                        "derived-from", "summarizes", "evaluates", "supersedes"}:
                raise VaultError("derivation edge fields are invalid")
            connection.execute(
                "INSERT OR IGNORE INTO derivation_edges(parent_id,child_id,relation,source_event_id) "
                "VALUES(?,?,?,?)", (payload["parent_id"], payload["child_id"],
                                     payload["relation"], event["event_id"]))
            receipt["recomputed"] += 1
            return

        if kind == "state-entity-upsert":
            if not isinstance(payload, dict) or set(payload) != {
                    "entity_type", "entity_id", "value"}:
                raise VaultError("state entity event payload is invalid")
            entity_type, entity_id = payload["entity_type"], payload["entity_id"]
            if not isinstance(entity_type, str) or not entity_type \
                    or not isinstance(entity_id, str) or not entity_id \
                    or len(entity_type) > 64 or len(entity_id) > 128 \
                    or len(_canonical(payload["value"])) > 1024 * 1024:
                raise VaultError("state entity event exceeds its contract bounds")
            aad = (f"entity:{metadata['owner_vault_id']}:{entity_type}:{entity_id}").encode()
            existing = connection.execute(
                "SELECT source_sequence FROM state_entities WHERE entity_type=? AND entity_id=?",
                (entity_type, entity_id)).fetchone()
            changed = connection.execute(
                "INSERT INTO state_entities(entity_type,entity_id,source_sequence,source_event_id,"
                "source_device_id,ciphertext,updated_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(entity_type,entity_id) DO UPDATE SET "
                "source_sequence=excluded.source_sequence,source_event_id=excluded.source_event_id,"
                "source_device_id=excluded.source_device_id,ciphertext=excluded.ciphertext,"
                "updated_at=excluded.updated_at "
                "WHERE excluded.source_sequence > state_entities.source_sequence",
                (entity_type, entity_id, event_rank, event["event_id"], event["device_id"],
                 self.crypto.seal(_canonical(payload["value"]), aad), _stamp())).rowcount
            connection.execute(
                "DELETE FROM state_entities WHERE entity_type=? AND entity_id IN ("
                "SELECT entity_id FROM state_entities WHERE entity_type=? "
                "ORDER BY source_sequence DESC,entity_id LIMIT -1 OFFSET ?)",
                (entity_type, entity_type, MAX_ENTITY_TYPE))
            connection.execute(
                "DELETE FROM state_entities WHERE (entity_type,entity_id) IN ("
                "SELECT entity_type,entity_id FROM state_entities "
                "ORDER BY source_sequence DESC,entity_type,entity_id LIMIT -1 OFFSET ?)",
                (MAX_STATE_ENTITIES,))
            receipt["added" if changed and existing is None else
                    "updated" if changed else "deduplicated"] += 1
            return

        self._quarantine_connection(
            connection, item_id=event["event_id"], kind="unknown-event-kind",
            reason="inactive-unknown-kind", payload=body)
        receipt["quarantined"] += 1

    def merge_events(self, events):
        if not isinstance(events, list) or len(events) > 500:
            raise VaultError("merge bundle is invalid or exceeds 500 events")
        required = {
            "event_id", "owner_vault_id", "device_id", "device_counter",
            "causal_parents", "payload_schema_version", "scope", "domain",
            "project_id", "ciphertext", "prior_event_hash", "signature", "event_hash",
        }
        normalized = []
        for event in events:
            if not isinstance(event, dict) or set(event) != required:
                raise VaultError("merge event has unknown or missing fields")
            _uuid(event["event_id"], "event_id")
            _uuid(event["owner_vault_id"], "owner_vault_id")
            _uuid(event["device_id"], "device_id")
            if type(event["device_counter"]) is not int or event["device_counter"] < 1:
                raise VaultError("merge event counter is invalid")
            normalized.append(dict(event))
        normalized.sort(key=lambda item: (item["device_id"], item["device_counter"], item["event_id"]))

        def merge(connection):
            metadata = self._metadata(connection)
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            for event in normalized:
                if event["owner_vault_id"] != metadata["owner_vault_id"]:
                    raise VaultError("merge event belongs to another owner vault")
                duplicate = connection.execute(
                    "SELECT 1 FROM events WHERE event_id=? OR event_hash=?",
                    (event["event_id"], event["event_hash"])).fetchone()
                if duplicate:
                    receipt["deduplicated"] += 1
                    continue
                device = connection.execute(
                    "SELECT public_key,counter,status FROM devices WHERE device_id=?",
                    (event["device_id"],)).fetchone()
                if device is None:
                    raise VaultError("merge event device is not paired")
                if device["status"] == "revoked":
                    raise VaultError("merge event device is revoked")
                if device["status"] == "dormant":
                    raise VaultError(
                        "dormant device requires a complete current checkpoint before merging")
                if event["device_counter"] != device["counter"] + 1:
                    raise VaultError("merge event counter is replayed or has a gap")
                expected_prior = connection.execute(
                    "SELECT event_hash FROM events WHERE device_id=? "
                    "ORDER BY device_counter DESC LIMIT 1", (event["device_id"],)).fetchone()
                expected_prior = expected_prior["event_hash"] if expected_prior else None
                if event["prior_event_hash"] != expected_prior \
                        or event["causal_parents"] != ([expected_prior] if expected_prior else []):
                    raise VaultError("merge event signature chain is broken")
                header = {key: event[key] for key in (
                    "event_id", "owner_vault_id", "device_id", "device_counter",
                    "causal_parents", "payload_schema_version", "scope", "domain",
                    "project_id", "prior_event_hash")}
                aad = _canonical(header)
                try:
                    ciphertext = event["ciphertext"].encode("ascii")
                    signature = event["signature"].encode("ascii")
                except (AttributeError, UnicodeEncodeError) as exc:
                    raise VaultError("merge event encoding is invalid") from exc
                if not self.crypto.verify(
                        aad + b"\x00" + ciphertext, signature, device["public_key"]):
                    raise VaultError("merge event signature is invalid")
                observed_hash = hashlib.sha256(
                    aad + b"\x00" + ciphertext + b"\x00" + signature).hexdigest()
                if observed_hash != event["event_hash"]:
                    raise VaultError("merge event hash is invalid")
                event_rank = _collision_checked_event_rank(
                    connection,
                    event["device_counter"], event["device_id"], event["event_id"])
                if event["payload_schema_version"] != PAYLOAD_SCHEMA_VERSION:
                    self._quarantine_connection(
                        connection, item_id=event["event_id"], kind="unknown-event-schema",
                        reason="inactive-unknown-schema", payload=event)
                    receipt["quarantined"] += 1
                else:
                    try:
                        body = json.loads(self.crypto.open(ciphertext, aad).decode("utf-8"))
                    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                        raise VaultError("merge event payload authentication failed") from exc
                    if not isinstance(body, dict) or set(body) != {"kind", "payload"}:
                        raise VaultError("merge event payload is invalid")
                    self._apply_event(
                        connection,
                        event={**event, "rank": event_rank},
                        body=body,
                        receipt=receipt)
                connection.execute(
                    "INSERT INTO events(event_id,device_id,device_counter,scope,domain_tag,project_tag,"
                    "payload_schema_version,prior_event_hash,ciphertext,signature,event_hash,recorded_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (event["event_id"], event["device_id"], event["device_counter"],
                     event["scope"], event["domain"], event["project_id"],
                     event["payload_schema_version"], event["prior_event_hash"], ciphertext,
                     signature, event["event_hash"], _stamp()))
                connection.execute(
                    "UPDATE devices SET counter=?,last_seen=? WHERE device_id=?",
                    (event["device_counter"], _stamp(), event["device_id"]))
            return receipt

        return self.run_transaction(merge)

    def select_memory(self, *, domain, project_id, component_id=None,
                      max_records=4, max_chars=4096):
        if not isinstance(domain, str) or not domain or type(max_records) is not int \
                or type(max_chars) is not int or not 1 <= max_records <= 4 \
                or not 256 <= max_chars <= 4096:
            raise VaultError("memory selection inputs are invalid")
        domain_tag = self.crypto.blind_index("domain", domain)
        project_tag = self.crypto.blind_index("project", project_id) if project_id else None
        component_tag = self.crypto.blind_index(
            "component", component_id) if component_id else None
        device_tag = self.crypto.blind_index("device", self.identity()["device_id"])
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM memory_records WHERE status='active' AND (scope IN ('global','general') "
                "OR (scope='domain' AND domain_tag=?) "
                "OR (scope IN ('project','temporary') AND domain_tag=? AND project_tag=?) "
                "OR (scope='component' AND domain_tag=? AND project_tag=? AND component_tag=?) "
                "OR (scope='device' AND device_tag=?)) "
                "ORDER BY updated_at DESC,record_id",
                (domain_tag, domain_tag, project_tag, domain_tag, project_tag,
                 component_tag, device_tag)).fetchall()
        selected = []
        used = 0
        for row in rows:
            record = self._decrypt_record(row)
            cost = len(_canonical(record)) + 1
            if len(selected) >= max_records or used + cost > max_chars:
                continue
            selected.append(record)
            used += cost
        if selected:
            ids = [record["id"] for record in selected]
            placeholders = ",".join("?" for _ in ids)

            def mark(connection):
                connection.execute(
                    f"UPDATE memory_utility SET selection_count=selection_count+1," 
                    f"last_selected=? WHERE record_id IN ({placeholders})",
                    (_stamp(), *ids))
                return len(ids)

            self.run_transaction(mark)
        return selected

    def list_memory(self, *, statuses=None, limit=32):
        statuses = statuses or {"active"}
        if not isinstance(statuses, set) or not statuses or not statuses <= STATUSES \
                or type(limit) is not int or not 1 <= limit <= 64:
            raise VaultError("memory listing bounds are invalid")
        placeholders = ",".join("?" for _ in statuses)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM memory_records WHERE status IN ({placeholders}) "
                "ORDER BY updated_at DESC,record_id LIMIT ?", (*sorted(statuses), limit)).fetchall()
        return [self._decrypt_record(row) for row in rows]

    def get_memory(self, record_id):
        record_id = _uuid(record_id, "memory id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM memory_records WHERE record_id=?", (record_id,)).fetchone()
        return self._decrypt_record(row) if row is not None else None

    def improvement_summary(self):
        with self._connect() as connection:
            utility = connection.execute(
                "SELECT COALESCE(SUM(selection_count),0),COALESCE(SUM(helped_count),0),"
                "COALESCE(SUM(hurt_count),0),COALESCE(SUM(application_count),0),"
                "COALESCE(SUM(verified_neutral_count),0),COALESCE(SUM(ambiguous_count),0) "
                "FROM memory_utility").fetchone()
            outcomes = connection.execute(
                "SELECT COUNT(*) FROM state_entities WHERE entity_type='session-outcome'").fetchone()[0]
        selected, helped, hurt, applied, neutral, ambiguous = map(int, utility)
        if hurt:
            evidence_state = "regression-observed"
        elif outcomes == 0:
            evidence_state = "no-outcomes"
        elif outcomes == 1:
            evidence_state = "measurement-started"
        elif helped or neutral or applied:
            evidence_state = "associated-only"
        else:
            evidence_state = "benefit-uncertain"
        return {"outcome_count": outcomes, "memory_selection_count": selected,
                "memory_helped_count": helped, "memory_hurt_count": hurt,
                "memory_application_count": applied,
                "memory_neutral_count": neutral,
                "memory_ambiguous_count": ambiguous,
                "evidence_state": evidence_state}

    def semantic_inventory(self):
        """Hash identities and lifecycle semantics without exposing encrypted bodies."""
        with self._connect() as connection:
            memory = [dict(row) for row in connection.execute(
                "SELECT record_id,scope,domain_tag,project_tag,semantic_tag,status,"
                "source_sequence FROM memory_records ORDER BY record_id")]
            tombstones = [dict(row) for row in connection.execute(
                "SELECT record_id,semantic_tag,source_sequence FROM tombstones ORDER BY record_id")]
            devices = [dict(row) for row in connection.execute(
                "SELECT device_id,status,counter FROM devices ORDER BY device_id")]
            aliases = [dict(row) for row in connection.execute(
                "SELECT alias_type,alias_id,target_id,source_hash FROM legacy_aliases "
                "ORDER BY alias_type,alias_id")]
        body = {"memory": memory, "tombstones": tombstones,
                "devices": devices, "legacy_aliases": aliases}
        return {"sha256": hashlib.sha256(_canonical(body)).hexdigest(),
                "memory": len(memory), "tombstones": len(tombstones),
                "devices": len(devices), "legacy_aliases": len(aliases)}

    def checkpoint_if_due(self, *, now=None, force=False):
        instant = now or dt.datetime.now(dt.timezone.utc)
        if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
            raise VaultError("checkpoint time must be timezone-aware")
        instant = instant.astimezone(dt.timezone.utc)

        def write(connection):
            count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            latest = connection.execute(
                "SELECT * FROM checkpoints ORDER BY created_at DESC LIMIT 1").fetchone()
            since = count if latest is None else connection.execute(
                "SELECT COUNT(*) FROM events WHERE recorded_at>?", (latest["created_at"],)
            ).fetchone()[0]
            due_by_count = since >= 500
            due_by_age = latest is None or (
                instant - dt.datetime.fromisoformat(
                    latest["created_at"].replace("Z", "+00:00"))).days >= 7
            if not force and not due_by_count and not due_by_age:
                return {"status": "not-due", "event_count": count}
            hashes = [row[0] for row in connection.execute(
                "SELECT event_hash FROM events ORDER BY device_id,device_counter")]
            checkpoint_id = str(uuid.uuid4())
            root_hash = hashlib.sha256(_canonical(hashes)).hexdigest()
            generation = int(self._metadata(connection)["generation"])
            created_at = instant.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            connection.execute(
                "INSERT INTO checkpoints(checkpoint_id,event_count,generation,root_hash,created_at) "
                "VALUES(?,?,?,?,?)", (checkpoint_id, count, generation, root_hash, created_at))
            device_id = self._metadata(connection)["device_id"]
            connection.execute(
                "INSERT INTO checkpoint_acks(checkpoint_id,device_id,acknowledged_at) VALUES(?,?,?)",
                (checkpoint_id, device_id, created_at))
            return {"status": "created", "checkpoint_id": checkpoint_id,
                    "event_count": count, "root_hash": root_hash}

        return self.run_transaction(write)

    def acknowledge_checkpoint(self, checkpoint_id, device_id):
        checkpoint_id = _uuid(checkpoint_id, "checkpoint id")
        device_id = _uuid(device_id, "device id")

        def write(connection):
            if connection.execute(
                    "SELECT 1 FROM checkpoints WHERE checkpoint_id=?", (checkpoint_id,)
            ).fetchone() is None:
                raise VaultError("checkpoint does not exist")
            device = connection.execute(
                "SELECT status FROM devices WHERE device_id=?", (device_id,)).fetchone()
            if device is None or device["status"] != "active":
                raise VaultError("only an active authorized device may acknowledge")
            connection.execute(
                "INSERT OR IGNORE INTO checkpoint_acks(checkpoint_id,device_id,acknowledged_at) "
                "VALUES(?,?,?)", (checkpoint_id, device_id, _stamp()))
            active = {row[0] for row in connection.execute(
                "SELECT device_id FROM devices WHERE status='active'")}
            acknowledged = {row[0] for row in connection.execute(
                "SELECT device_id FROM checkpoint_acks WHERE checkpoint_id=?", (checkpoint_id,))}
            completed = 0
            if active <= acknowledged:
                owner = self._metadata(connection)["owner_vault_id"]
                for row in connection.execute(
                        "SELECT * FROM deletion_commitments WHERE checkpoint_id=? "
                        "AND status='pending-devices'", (checkpoint_id,)).fetchall():
                    payload = {
                        "commitment_id": row["commitment_id"], "record_id": row["record_id"],
                        "deletion_epoch": row["deletion_epoch"], "status": "complete",
                        "checkpoint_id": checkpoint_id, "pending_devices": [],
                        "created_at": row["created_at"],
                    }
                    aad = (f"deletion-commitment:{owner}:"
                           f"{row['commitment_id']}").encode()
                    connection.execute(
                        "UPDATE deletion_commitments SET status='complete',ciphertext=? "
                        "WHERE commitment_id=?",
                        (self.crypto.seal(_canonical(payload), aad), row["commitment_id"]))
                    completed += 1
            return {"checkpoint_id": checkpoint_id, "device_id": device_id,
                    "status": "acknowledged", "deletion_commitments_completed": completed}

        return self.run_transaction(write)

    def compact_acknowledged(self):
        """Drop portable history only after every currently active device acknowledged it."""
        def write(connection):
            checkpoint = connection.execute(
                "SELECT * FROM checkpoints ORDER BY created_at DESC LIMIT 1").fetchone()
            if checkpoint is None:
                return {"status": "no-checkpoint", "events_removed": 0}
            active = {row[0] for row in connection.execute(
                "SELECT device_id FROM devices WHERE status='active'")}
            acknowledged = {row[0] for row in connection.execute(
                "SELECT device_id FROM checkpoint_acks WHERE checkpoint_id=?",
                (checkpoint["checkpoint_id"],))}
            if not active <= acknowledged:
                return {"status": "awaiting-active-devices", "events_removed": 0,
                        "unacknowledged": len(active - acknowledged)}
            before = connection.total_changes
            # event_count is the exact insertion frontier committed by the checkpoint. Wall clock
            # time is descriptive and can be later than a caller-supplied checkpoint timestamp.
            connection.execute(
                "DELETE FROM events WHERE rowid IN (SELECT rowid FROM events "
                "ORDER BY rowid LIMIT ?)", (checkpoint["event_count"],))
            removed = connection.total_changes - before
            receipt_id = str(uuid.uuid4())
            payload = {"checkpoint_id": checkpoint["checkpoint_id"],
                       "root_hash": checkpoint["root_hash"], "events_removed": removed,
                       "compacted_at": _stamp()}
            aad = f"receipt:{self.identity()['owner_vault_id']}:{receipt_id}".encode()
            connection.execute(
                "INSERT INTO receipts(receipt_id,kind,ciphertext,created_at) VALUES(?,?,?,?)",
                (receipt_id, "event-compaction", self.crypto.seal(_canonical(payload), aad),
                 payload["compacted_at"]))
            return {"status": "compacted", "events_removed": removed,
                    "checkpoint_id": checkpoint["checkpoint_id"]}

        return self.run_transaction(write)

    def record_memory_outcome(self, selected_ids, *, helped_ids=(), hurt_ids=()):
        """Compatibility facade for already content-attributed legacy callers.

        It never infers help from session success. Callers must name the exact records whose
        effect was verified. New production callers use ``record_memory_effects``.
        """
        selected = [_uuid(value, "selected memory id") for value in selected_ids]
        helped = {_uuid(value, "helpful memory id") for value in helped_ids}
        hurt = {_uuid(value, "hurtful memory id") for value in hurt_ids}
        if len(selected) != len(set(selected)) or not helped <= set(selected) \
                or not hurt <= set(selected) or helped & hurt:
            raise VaultError("memory outcome IDs are inconsistent")

        def write(connection):
            rows = connection.execute(
                f"SELECT record_id FROM memory_records WHERE record_id IN "
                f"({','.join('?' for _ in selected)})", selected).fetchall() if selected else []
            if {row["record_id"] for row in rows} != set(selected):
                raise VaultError("memory outcome references an unavailable record")
            body = {"kind": "memory-outcome", "payload": {
                "selected_ids": selected, "helped_ids": sorted(helped),
                "hurt_ids": sorted(hurt)}}
            event = self._next_event(
                connection, kind=body["kind"], payload=body["payload"],
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(connection, event=event, body=body, receipt=receipt)
            return {"selected": len(selected), "helped": len(helped), "hurt": len(hurt)}

        return self.run_transaction(write)

    def record_memory_effects(self, operation_id, effects):
        if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 128 \
                or not isinstance(effects, list) or len(effects) > 16:
            raise VaultError("memory effect batch is invalid")
        normalized = []
        seen = set()
        for index, item in enumerate(effects):
            if not isinstance(item, dict):
                raise VaultError("memory effect must be an object")
            required = {
                "memory_id", "status", "decision_target", "intended_effect",
                "evidence_id", "serious_harm",
            }
            if set(item) != required:
                raise VaultError("memory effect fields are unknown or missing")
            memory_id = _uuid(item["memory_id"], "memory id")
            if memory_id in seen:
                raise VaultError("one operation may record only one effect per memory")
            seen.add(memory_id)
            normalized.append({
                **item,
                "memory_id": memory_id,
                "effect_id": str(uuid.uuid5(
                    uuid.UUID(self.identity()["owner_vault_id"]),
                    f"memory-effect:{operation_id}:{index}:{memory_id}")),
                "operation_id": operation_id,
            })

        def write(connection):
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            for payload in normalized:
                event = self._next_event(
                    connection, kind="memory-effect", payload=payload,
                    scope="vault", domain_tag=None, project_tag=None)
                event.update({"scope": "vault", "domain": None, "project_id": None})
                self._apply_event(
                    connection, event=event,
                    body={"kind": "memory-effect", "payload": payload}, receipt=receipt)
            return {"operation_id": operation_id, "effects": len(normalized),
                    "quarantined": sum(bool(item["serious_harm"]) for item in normalized),
                    "receipt": receipt}

        return self.run_transaction(write)

    def record_observation(self, observation):
        if not isinstance(observation, dict):
            raise VaultError("memory observation must be an object")
        value = dict(observation)
        value.setdefault("observation_id", str(uuid.uuid4()))
        value.setdefault("memory_id", None)
        value.setdefault("component_id", None)
        value.setdefault("observed_at", _stamp())
        required = {
            "observation_id", "memory_id", "scope", "domain", "project_id",
            "component_id", "decision_target", "evidence_id", "observed_at", "value",
        }
        if set(value) != required:
            raise VaultError("memory observation fields are unknown or missing")

        def write(connection):
            event = self._next_event(
                connection, kind="memory-observation", payload=value,
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "memory-observation", "payload": value}, receipt=receipt)
            return {"observation_id": value["observation_id"], "receipt": receipt}

        return self.run_transaction(write)

    def put_preference_slot(self, slot):
        if not isinstance(slot, dict):
            raise VaultError("preference slot must be an object")
        value = dict(slot)
        value.setdefault("slot_id", str(uuid.uuid4()))

        def write(connection):
            event = self._next_event(
                connection, kind="preference-slot", payload=value,
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "preference-slot", "payload": value}, receipt=receipt)
            return {"slot_id": value["slot_id"], "receipt": receipt}

        return self.run_transaction(write)

    def record_policy_evaluation(self, evaluation):
        if not isinstance(evaluation, dict):
            raise VaultError("policy evaluation must be an object")
        value = dict(evaluation)
        value.setdefault("evaluation_id", str(uuid.uuid4()))

        def write(connection):
            event = self._next_event(
                connection, kind="policy-evaluation", payload=value,
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "policy-evaluation", "payload": value}, receipt=receipt)
            return {"evaluation_id": value["evaluation_id"], "receipt": receipt}

        return self.run_transaction(write)

    def list_memory_effects(self, *, memory_id=None, limit=64):
        if memory_id is not None:
            memory_id = _uuid(memory_id, "memory id")
        if type(limit) is not int or not 1 <= limit <= 256:
            raise VaultError("memory effect listing bound is invalid")
        query = "SELECT * FROM memory_effects"
        parameters = []
        if memory_id:
            query += " WHERE memory_id=?"
            parameters.append(memory_id)
        query += " ORDER BY recorded_at DESC,effect_id LIMIT ?"
        parameters.append(limit)
        owner = self.identity()["owner_vault_id"]
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        values = []
        for row in rows:
            aad = f"memory-effect:{owner}:{row['effect_id']}".encode()
            try:
                values.append(json.loads(self.crypto.open(
                    row["ciphertext"], aad).decode("utf-8")))
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                raise VaultError("memory effect authentication failed") from exc
        return values

    def add_derivation(self, parent_id, child_id, *, relation="derived-from"):
        payload = {"parent_id": parent_id, "child_id": child_id, "relation": relation}

        def write(connection):
            event = self._next_event(
                connection, kind="derivation-edge", payload=payload,
                scope="vault", domain_tag=None, project_tag=None)
            event.update({"scope": "vault", "domain": None, "project_id": None})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "derivation-edge", "payload": payload}, receipt=receipt)
            return payload

        return self.run_transaction(write)

    def maintain_memory_lifecycle(self, *, now=None):
        instant = now or dt.datetime.now(dt.timezone.utc)
        if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
            raise VaultError("memory lifecycle time must be timezone-aware")
        instant = instant.astimezone(dt.timezone.utc)

        def age_days(value):
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (AttributeError, ValueError) as exc:
                raise VaultError("memory lifecycle timestamp is invalid") from exc
            return (instant - parsed.astimezone(dt.timezone.utc)).days

        def write(connection):
            rows = connection.execute(
                "SELECT m.*,u.selection_count,u.helped_count,u.hurt_count,u.last_selected,"
                "u.last_applied,u.last_helped,u.last_hurt "
                "FROM memory_records m JOIN memory_utility u USING(record_id)").fetchall()
            receipt = {"dormant": 0, "revalidation-required": 0,
                       "archived": 0, "expired": 0, "retained": 0}
            for row in rows:
                record = self._decrypt_record(row)
                reference = row["last_applied"] or row["last_helped"] \
                    or row["last_hurt"] or record["created_at"]
                age = age_days(reference)
                status = row["status"]
                explicit = record["provenance"] == "stated"
                next_status = None
                if record["scope"] == "temporary" and record.get("expires_at") \
                        and age_days(record["expires_at"]) >= 0:
                    payload = {"record_id": row["record_id"], "reason": "temporary-expired",
                               "semantic_tag": row["semantic_tag"], "forgotten_at": _stamp()}
                    event = self._next_event(
                        connection, kind="memory-expired", payload=payload,
                        scope=row["scope"], domain_tag=row["domain_tag"],
                        project_tag=row["project_tag"])
                    event.update({"scope": row["scope"], "domain": row["domain_tag"],
                                  "project_id": row["project_tag"]})
                    effects = {"added": 0, "updated": 0, "deduplicated": 0,
                               "forgotten": 0, "recomputed": 0, "quarantined": 0}
                    self._apply_event(connection, event=event,
                                      body={"kind": "memory-expired", "payload": payload},
                                      receipt=effects)
                    receipt["expired"] += 1
                    continue
                if record["category"] == "technical-fact" \
                        and record.get("verify_by") \
                        and age_days(record["verify_by"]) >= 0 \
                        and status == "active":
                    next_status = "revalidation-required"
                if status == "superseded" and age_days(row["updated_at"]) >= 90:
                    payload = {"record_id": row["record_id"],
                               "reason": "superseded-retention-expired",
                               "semantic_tag": row["semantic_tag"], "forgotten_at": _stamp()}
                    event = self._next_event(
                        connection, kind="memory-superseded-expired", payload=payload,
                        scope=row["scope"], domain_tag=row["domain_tag"],
                        project_tag=row["project_tag"])
                    event.update({"scope": row["scope"], "domain": row["domain_tag"],
                                  "project_id": row["project_tag"]})
                    effects = {"added": 0, "updated": 0, "deduplicated": 0,
                               "forgotten": 0, "recomputed": 0, "quarantined": 0}
                    self._apply_event(
                        connection, event=event,
                        body={"kind": "memory-superseded-expired", "payload": payload},
                        receipt=effects)
                    receipt["expired"] += 1
                    continue
                if next_status is None and not explicit and status == "active" and age >= 30 \
                        and row["helped_count"] == 0:
                    next_status = "dormant"
                elif not explicit and status in {"dormant", "stale", "revalidation-required"} and age >= 90 \
                        and row["helped_count"] == 0:
                    next_status = "archived"
                elif not explicit and status == "archived" and age >= 365 \
                        and row["helped_count"] == 0:
                    payload = {"record_id": row["record_id"], "reason": "automatic-expiry",
                               "semantic_tag": row["semantic_tag"],
                               "forgotten_at": _stamp()}
                    event = self._next_event(
                        connection, kind="memory-expired", payload=payload,
                        scope=row["scope"], domain_tag=row["domain_tag"],
                        project_tag=row["project_tag"])
                    event.update({"scope": row["scope"], "domain": row["domain_tag"],
                                  "project_id": row["project_tag"]})
                    effects = {"added": 0, "updated": 0, "deduplicated": 0,
                               "forgotten": 0, "recomputed": 0, "quarantined": 0}
                    self._apply_event(
                        connection, event=event,
                        body={"kind": "memory-expired", "payload": payload},
                        receipt=effects)
                    receipt["expired"] += 1
                    continue
                if next_status:
                    record["status"] = next_status
                    aad = (f"memory:{self._metadata(connection)['owner_vault_id']}:"
                           f"{row['record_id']}").encode()
                    connection.execute(
                        "UPDATE memory_records SET status=?,ciphertext=?,updated_at=? "
                        "WHERE record_id=?",
                        (next_status, self.crypto.seal(_canonical(record), aad),
                         _stamp(), row["record_id"]))
                    receipt[next_status] += 1
                else:
                    receipt["retained"] += 1
            return receipt

        return self.run_transaction(write)

    def forget_memory(self, record_id, *, reason):
        record_id = _uuid(record_id, "memory id")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 128:
            raise VaultError("forget reason is invalid")

        def write(connection):
            row = connection.execute(
                "SELECT * FROM memory_records WHERE record_id=?", (record_id,)).fetchone()
            if row is None:
                existing = connection.execute(
                    "SELECT 1 FROM tombstones WHERE record_id=?", (record_id,)).fetchone()
                if existing:
                    return {"id": record_id, "status": "forgotten"}
                raise VaultError("memory record does not exist")
            payload = {"record_id": record_id, "reason": reason,
                       "semantic_tag": row["semantic_tag"], "forgotten_at": _stamp()}
            event = self._next_event(
                connection, kind="memory-forgotten", payload=payload, scope=row["scope"],
                domain_tag=row["domain_tag"], project_tag=row["project_tag"])
            event.update({"scope": row["scope"], "domain": row["domain_tag"],
                          "project_id": row["project_tag"]})
            receipt = {"added": 0, "updated": 0, "deduplicated": 0, "forgotten": 0,
                       "recomputed": 0, "quarantined": 0}
            self._apply_event(
                connection, event=event,
                body={"kind": "memory-forgotten", "payload": payload}, receipt=receipt)
            commitment = connection.execute(
                "SELECT commitment_id,deletion_epoch FROM deletion_commitments "
                "WHERE record_id=? ORDER BY deletion_epoch DESC LIMIT 1", (record_id,)).fetchone()
            return {"id": record_id, "status": "pending-checkpoint",
                    "commitment_id": commitment["commitment_id"],
                    "deletion_epoch": commitment["deletion_epoch"]}

        result = self.run_transaction(write)
        if result.get("status") == "forgotten":
            return result
        checkpoint = self.checkpoint_if_due(force=True)

        def finalize(connection):
            active = {row[0] for row in connection.execute(
                "SELECT device_id FROM devices WHERE status='active'")}
            acknowledged = {row[0] for row in connection.execute(
                "SELECT device_id FROM checkpoint_acks WHERE checkpoint_id=?",
                (checkpoint["checkpoint_id"],))}
            pending = sorted(active - acknowledged)
            status = "complete" if not pending else "pending-devices"
            row = connection.execute(
                "SELECT * FROM deletion_commitments WHERE commitment_id=?",
                (result["commitment_id"],)).fetchone()
            payload = {
                "commitment_id": result["commitment_id"], "record_id": record_id,
                "deletion_epoch": result["deletion_epoch"], "status": status,
                "checkpoint_id": checkpoint["checkpoint_id"],
                "pending_devices": pending, "created_at": row["created_at"],
            }
            aad = (f"deletion-commitment:{self._metadata(connection)['owner_vault_id']}:"
                   f"{result['commitment_id']}").encode()
            connection.execute(
                "UPDATE deletion_commitments SET checkpoint_id=?,status=?,ciphertext=? "
                "WHERE commitment_id=?",
                (checkpoint["checkpoint_id"], status,
                 self.crypto.seal(_canonical(payload), aad), result["commitment_id"]))
            return payload

        return self.run_transaction(finalize)

    def count(self, table):
        if table not in {"memory_records", "memory_utility", "events", "tombstones", "quarantine", "devices",
                         "state_entities", "receipts", "legacy_aliases", "checkpoints",
                         "checkpoint_acks", "memory_observations", "memory_effects",
                         "preference_slots", "derivation_edges", "deletion_commitments",
                         "policy_evaluations", "scope_aliases"}:
            raise VaultError("count table is not allowed")
        with self._connect() as connection:
            return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def export_events(self):
        identity = self.identity()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY device_id,device_counter").fetchall()
        result = []
        for row in rows:
            result.append({
                "event_id": row["event_id"],
                "owner_vault_id": identity["owner_vault_id"],
                "device_id": row["device_id"],
                "device_counter": row["device_counter"],
                "causal_parents": [row["prior_event_hash"]] if row["prior_event_hash"] else [],
                "payload_schema_version": row["payload_schema_version"],
                "scope": row["scope"], "domain": row["domain_tag"],
                "project_id": row["project_tag"],
                "ciphertext": bytes(row["ciphertext"]).decode("ascii"),
                "prior_event_hash": row["prior_event_hash"],
                "signature": bytes(row["signature"]).decode("ascii"),
                "event_hash": row["event_hash"],
            })
        return result

    def online_backup(self, destination):
        destination = _safe_path(destination, "checkpoint destination")
        if destination.exists():
            raise VaultError("checkpoint destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        _safe_path(destination.parent, "checkpoint destination directory")
        try:
            with self._connect() as source, sqlite3.connect(
                    destination, factory=_ClosingConnection) as target:
                source.backup(target)
                integrity = target.execute("PRAGMA integrity_check").fetchone()[0]
                records = target.execute("SELECT COUNT(*) FROM memory_records").fetchone()[0]
                events = target.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if integrity != "ok":
                raise VaultError("checkpoint integrity check failed")
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            return {"path": str(destination), "sha256": digest,
                    "records": records, "events": events}
        except BaseException:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            raise

    def stage_key_rotation(self, destination, *, new_crypto, key_slot_id,
                           revoked_device_id, local_device_keys):
        """Create a complete rotated vault copy; the authoritative vault is untouched."""
        key_slot_id = _uuid(key_slot_id, "key slot id")
        revoked_device_id = _uuid(revoked_device_id, "revoked device id")
        required_keys = {"signing_public", "exchange_public"}
        if not isinstance(local_device_keys, dict) or set(local_device_keys) != required_keys:
            raise VaultError("rotated local device keys are invalid")
        destination = _safe_path(destination, "rotated vault destination")
        self.online_backup(destination)
        allow_test = getattr(self.crypto, "production_safe", False) is not True
        staged = OwnerVault.open(
            destination, crypto=self.crypto, allow_test_crypto=allow_test)

        def rotate(connection):
            metadata = staged._metadata(connection)
            owner = metadata["owner_vault_id"]
            local = metadata["device_id"]
            if revoked_device_id == local:
                raise VaultError("the active local device cannot revoke itself")
            row = connection.execute(
                "SELECT status FROM devices WHERE device_id=?", (revoked_device_id,)).fetchone()
            if row is None:
                raise VaultError("device is not paired")
            if row["status"] == "revoked":
                raise VaultError("device is already revoked")
            event_hashes = [item[0] for item in connection.execute(
                "SELECT event_hash FROM events ORDER BY device_id,device_counter")]
            commitment = hashlib.sha256(_canonical(event_hashes)).hexdigest()

            for row in connection.execute("SELECT * FROM memory_records").fetchall():
                aad = f"memory:{owner}:{row['record_id']}".encode()
                plaintext = staged.crypto.open(row["ciphertext"], aad)
                record = staged._validate_record(json.loads(plaintext.decode("utf-8")))
                if staged._semantic_tag(record) != row["semantic_tag"]:
                    raise VaultError("key rotation would change semantic forgetting commitments")
                connection.execute(
                    "UPDATE memory_records SET ciphertext=? WHERE record_id=?",
                    (new_crypto.seal(plaintext, aad), row["record_id"]))
            for row in connection.execute("SELECT * FROM tombstones").fetchall():
                aad = f"tombstone:{owner}:{row['record_id']}".encode()
                plaintext = staged.crypto.open(row["ciphertext"], aad)
                connection.execute(
                    "UPDATE tombstones SET ciphertext=? WHERE record_id=?",
                    (new_crypto.seal(plaintext, aad), row["record_id"]))
            for row in connection.execute("SELECT * FROM state_entities").fetchall():
                aad = f"entity:{owner}:{row['entity_type']}:{row['entity_id']}".encode()
                plaintext = staged.crypto.open(row["ciphertext"], aad)
                connection.execute(
                    "UPDATE state_entities SET ciphertext=? WHERE entity_type=? AND entity_id=?",
                    (new_crypto.seal(plaintext, aad), row["entity_type"], row["entity_id"]))
            for row in connection.execute("SELECT * FROM receipts").fetchall():
                aad = f"receipt:{owner}:{row['receipt_id']}".encode()
                plaintext = staged.crypto.open(row["ciphertext"], aad)
                connection.execute(
                    "UPDATE receipts SET ciphertext=? WHERE receipt_id=?",
                    (new_crypto.seal(plaintext, aad), row["receipt_id"]))
            for row in connection.execute("SELECT * FROM quarantine").fetchall():
                aad = f"quarantine:{owner}:{row['item_id']}".encode()
                plaintext = staged.crypto.open(row["ciphertext"], aad)
                connection.execute(
                    "UPDATE quarantine SET ciphertext=? WHERE item_id=?",
                    (new_crypto.seal(plaintext, aad), row["item_id"]))
            encrypted_v3_tables = (
                ("memory_observations", "observation_id", "memory-observation"),
                ("memory_effects", "effect_id", "memory-effect"),
                ("preference_slots", "slot_id", "preference-slot"),
                ("deletion_commitments", "commitment_id", "deletion-commitment"),
                ("policy_evaluations", "evaluation_id", "policy-evaluation"),
            )
            for table, identity_column, aad_prefix in encrypted_v3_tables:
                for row in connection.execute(f"SELECT * FROM {table}").fetchall():
                    identity = row[identity_column]
                    aad = f"{aad_prefix}:{owner}:{identity}".encode()
                    plaintext = staged.crypto.open(row["ciphertext"], aad)
                    connection.execute(
                        f"UPDATE {table} SET ciphertext=? WHERE {identity_column}=?",
                        (new_crypto.seal(plaintext, aad), identity))

            connection.execute(
                "UPDATE devices SET status='revoked',last_seen=? WHERE device_id=?",
                (_stamp(), revoked_device_id))
            reauthorize = [item[0] for item in connection.execute(
                "SELECT device_id FROM devices WHERE status='active' AND device_id NOT IN (?,?)",
                (local, revoked_device_id))]
            connection.execute(
                "UPDATE devices SET status='dormant' WHERE status='active' AND device_id!=?",
                (local,))
            connection.execute(
                "UPDATE devices SET public_key=?,last_seen=? WHERE device_id=?",
                (local_device_keys["signing_public"], _stamp(), local))
            receipt_id = str(uuid.uuid4())
            entity_id = local
            aad = f"entity:{owner}:device-key:{entity_id}".encode()
            connection.execute(
                "INSERT INTO state_entities(entity_type,entity_id,source_sequence,source_event_id,"
                "source_device_id,ciphertext,updated_at) VALUES('device-key',?,?,?,?,?,?) "
                "ON CONFLICT(entity_type,entity_id) DO UPDATE SET "
                "source_event_id=excluded.source_event_id,"
                "source_device_id=excluded.source_device_id,"
                "ciphertext=excluded.ciphertext,updated_at=excluded.updated_at",
                (entity_id, 0, receipt_id, local,
                 new_crypto.seal(_canonical(local_device_keys), aad), _stamp()))
            connection.execute("DELETE FROM checkpoint_acks")
            connection.execute("DELETE FROM checkpoints")
            connection.execute("DELETE FROM events")
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='generation'",
                (str(int(metadata["generation"]) + 1),))
            connection.execute(
                "INSERT INTO metadata(key,value) VALUES('key_slot_id',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key_slot_id,))
            receipt = {
                "revoked_device_id": revoked_device_id,
                "prior_event_commitment": commitment,
                "prior_event_count": len(event_hashes),
                "reauthorization_required": sorted(reauthorize),
                "rotated_at": _stamp(),
            }
            receipt_aad = f"receipt:{owner}:{receipt_id}".encode()
            connection.execute(
                "INSERT INTO receipts(receipt_id,kind,ciphertext,created_at) VALUES(?,?,?,?)",
                (receipt_id, "device-revocation-key-rotation",
                 new_crypto.seal(_canonical(receipt), receipt_aad), receipt["rotated_at"]))
            return {**receipt, "receipt_id": receipt_id, "key_slot_id": key_slot_id}

        try:
            result = staged.run_transaction(rotate)
            staged.crypto = new_crypto
            # Authenticate every encrypted semantic collection under the new key before activation.
            with staged._connect() as connection:
                memory_rows = connection.execute("SELECT * FROM memory_records").fetchall()
                tombstone_rows = connection.execute("SELECT * FROM tombstones").fetchall()
                receipt_rows = connection.execute("SELECT receipt_id FROM receipts").fetchall()
                quarantine_rows = connection.execute("SELECT * FROM quarantine").fetchall()
                encrypted_v3_rows = {
                    (table, identity_column, aad_prefix): connection.execute(
                        f"SELECT {identity_column},ciphertext FROM {table}").fetchall()
                    for table, identity_column, aad_prefix in (
                        ("memory_observations", "observation_id", "memory-observation"),
                        ("memory_effects", "effect_id", "memory-effect"),
                        ("preference_slots", "slot_id", "preference-slot"),
                        ("deletion_commitments", "commitment_id", "deletion-commitment"),
                        ("policy_evaluations", "evaluation_id", "policy-evaluation"),
                    )
                }
                entity_types = {row[0] for row in connection.execute(
                    "SELECT DISTINCT entity_type FROM state_entities").fetchall()}
            for row in memory_rows:
                staged._decrypt_record(row)
            for row in tombstone_rows:
                aad = f"tombstone:{staged.identity()['owner_vault_id']}:{row['record_id']}".encode()
                staged.crypto.open(row["ciphertext"], aad)
            for row in receipt_rows:
                staged.get_receipt(row["receipt_id"])
            for row in quarantine_rows:
                aad = f"quarantine:{staged.identity()['owner_vault_id']}:{row['item_id']}".encode()
                staged.crypto.open(row["ciphertext"], aad)
            for (_table, identity_column, aad_prefix), rows in encrypted_v3_rows.items():
                for row in rows:
                    aad = (f"{aad_prefix}:{staged.identity()['owner_vault_id']}:"
                           f"{row[identity_column]}").encode()
                    staged.crypto.open(row["ciphertext"], aad)
            for entity_type in entity_types:
                staged.list_entities(entity_type, limit=1)
            with staged._connect() as connection:
                # Rewriting the file removes free pages that could still contain ciphertext
                # encrypted under the revoked generation's data key.
                connection.execute("VACUUM")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise VaultError("rotated vault failed integrity validation")
            return result
        except BaseException:
            for suffix in ("", "-wal", "-shm"):
                Path(str(destination) + suffix).unlink(missing_ok=True)
            raise
