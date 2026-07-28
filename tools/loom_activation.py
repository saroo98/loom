#!/usr/bin/env python3
"""Immutable runtime/state activation-set construction and verification."""

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

import loom_reliability
import loom_subject_identity


VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
POINTER_BASE_FIELDS = {
    "version", "path", "payload_sha256", "release_sequence", "previous",
}
POINTER_V1_FIELDS = POINTER_BASE_FIELDS | {
    "activation_set_id", "activation_receipt_sha256", "state",
    "previous_activation_set_id",
}


class ActivationError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stamp():
    return dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def _uuid(value, label):
    try:
        canonical = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ActivationError(f"{label} is invalid") from exc
    if canonical != value:
        raise ActivationError(f"{label} is not canonical")
    return canonical


def runtime_identity(pointer):
    if not isinstance(pointer, dict) or not POINTER_BASE_FIELDS <= set(pointer):
        raise ActivationError("runtime pointer identity is incomplete")
    value = {key: pointer[key] for key in (
        "version", "path", "payload_sha256", "release_sequence")}
    if not VERSION_RE.fullmatch(str(value["version"])) \
            or value["path"] != value["version"] \
            or not HEX64.fullmatch(str(value["payload_sha256"])) \
            or type(value["release_sequence"]) is not int \
            or value["release_sequence"] < 1:
        raise ActivationError("runtime pointer identity is invalid")
    return value


def installed_runtime_subject(pointer, *, install_receipt_sha256):
    """Return a path-free typed runtime subject for external comparison."""
    value = runtime_identity(pointer)
    activation_receipt = pointer.get("activation_receipt_sha256")
    if not HEX64.fullmatch(str(install_receipt_sha256)) \
            or not HEX64.fullmatch(str(activation_receipt)):
        raise ActivationError("installed runtime receipt binding is incomplete")
    try:
        return loom_subject_identity.installed_runtime(
            version=value["version"],
            release_sequence=value["release_sequence"],
            payload_sha256=value["payload_sha256"],
            install_receipt_sha256=install_receipt_sha256,
            activation_receipt_sha256=activation_receipt)
    except loom_subject_identity.SubjectIdentityError as exc:
        raise ActivationError(str(exc)) from exc


def _redirect(path):
    try:
        if path.is_symlink():
            return True
        junction = getattr(path, "is_junction", None)
        return bool(junction and junction())
    except OSError:
        return True


def state_inventory(path):
    path = loom_reliability._absolute(
        path, "owner-state generation", must_exist=True)
    if not path.is_file() or _redirect(path):
        raise ActivationError("owner-state generation is missing or redirected")
    try:
        connection = sqlite3.connect(
            "file:" + path.as_posix() + "?mode=ro", uri=True, timeout=2)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            metadata = dict(connection.execute(
                "SELECT key,value FROM metadata WHERE key IN "
                "('owner_vault_id','generation','schema_version','deletion_epoch')"))
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            projections = {}
            for table, columns in (
                    ("memory_records", "record_id,semantic_tag,status,source_sequence"),
                    ("tombstones", "record_id,semantic_tag,source_sequence"),
                    ("events", "event_id,device_id,device_counter,event_hash"),
                    ("deletion_commitments",
                     "commitment_id,record_id,deletion_epoch,status,source_event_id")):
                if table in tables:
                    projections[table] = [
                        list(row) for row in connection.execute(
                            f"SELECT {columns} FROM {table} ORDER BY 1")]
                else:
                    projections[table] = []
        finally:
            connection.close()
        owner = str(uuid.UUID(metadata["owner_vault_id"]))
        generation = int(metadata["generation"])
        schema = int(metadata["schema_version"])
        deletion_epoch = int(metadata.get("deletion_epoch", "0"))
    except (sqlite3.Error, OSError, KeyError, TypeError, ValueError) as exc:
        raise ActivationError(
            f"owner-state generation cannot be inventoried: {exc}") from exc
    if integrity != ("ok",) or owner != metadata["owner_vault_id"] \
            or generation < 1 or schema < 1 or deletion_epoch < 0:
        raise ActivationError("owner-state generation integrity or identity is invalid")
    body = {
        "owner_vault_id": owner,
        "generation": generation,
        "schema_version": schema,
        "deletion_epoch": deletion_epoch,
        "projections": projections,
    }
    return {
        "owner_vault_id": owner,
        "generation": generation,
        "schema_version": schema,
        "deletion_epoch": deletion_epoch,
        "inventory_sha256": _sha(body),
    }


def _consistent_backup(source, destination):
    source = loom_reliability._absolute(
        source, "active owner state", must_exist=True)
    destination = loom_reliability._absolute(
        destination, "candidate owner state")
    if destination.exists() or not source.is_file() or _redirect(source):
        raise ActivationError("owner-state clone inputs are unsafe")
    destination.parent.mkdir(parents=True, exist_ok=False)
    try:
        with closing(sqlite3.connect(
                "file:" + source.as_posix() + "?mode=ro", uri=True, timeout=2
        )) as source_connection, closing(sqlite3.connect(destination)) as target:
            source_connection.backup(target)
            target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            if target.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ActivationError("candidate owner state failed integrity validation")
        # Windows refuses fsync on a read-only CRT descriptor. Open the completed
        # candidate read/write without changing bytes so durability is portable.
        with destination.open("r+b") as stream:
            os.fsync(stream.fileno())
        loom_reliability._sync_parent(destination)
    except BaseException:
        for suffix in ("", "-wal", "-shm"):
            Path(str(destination) + suffix).unlink(missing_ok=True)
        try:
            destination.parent.rmdir()
        except OSError:
            pass
        raise


class ActivationStore:
    def __init__(self, home):
        self.home = loom_reliability._absolute(home, "Loom home")
        self.runtime = self.home / "runtime"
        self.receipts = self.runtime / "activation-sets"
        self.generations = self.home / "vault" / "generations"
        self.receipts.mkdir(parents=True, exist_ok=True)
        self.generations.mkdir(parents=True, exist_ok=True)

    def _receipt_path(self, activation_set_id):
        return self.receipts / f"{_uuid(activation_set_id, 'activation set id')}.json"

    def read_receipt(self, activation_set_id):
        path = self._receipt_path(activation_set_id)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ActivationError(f"activation-set receipt is unreadable: {exc}") from exc
        return self._validate_receipt(value)

    def _validate_receipt(self, value):
        fields = {
            "schema_version", "activation_set_id", "purpose", "runtime", "state",
            "schema_range", "previous_activation_set_id", "created_at",
            "receipt_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields \
                or value["schema_version"] != 1 \
                or value["purpose"] not in {
                    "baseline-adoption", "release-activation",
                    "rollback-forward-state", "reactivation"}:
            raise ActivationError("activation-set receipt contract is invalid")
        _uuid(value["activation_set_id"], "activation set id")
        runtime_identity({**value["runtime"], "previous": None})
        schema_range = value["schema_range"]
        if not isinstance(schema_range, dict) \
                or set(schema_range) != {"minimum", "maximum"} \
                or type(schema_range["minimum"]) is not int \
                or type(schema_range["maximum"]) is not int \
                or not 0 <= schema_range["minimum"] <= schema_range["maximum"]:
            raise ActivationError("activation-set schema range is invalid")
        if value["previous_activation_set_id"] is not None:
            _uuid(value["previous_activation_set_id"], "previous activation set id")
        try:
            instant = dt.datetime.fromisoformat(
                value["created_at"].replace("Z", "+00:00"))
            if instant.tzinfo is None:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise ActivationError("activation-set timestamp is invalid") from exc
        state = value["state"]
        if state is not None:
            required = {
                "state_set_id", "path", "owner_vault_id", "generation",
                "schema_version", "deletion_epoch", "inventory_sha256",
                "baseline_sha256",
            }
            if not isinstance(state, dict) or set(state) != required:
                raise ActivationError("activation-set state identity is invalid")
            _uuid(state["state_set_id"], "state set id")
            _uuid(state["owner_vault_id"], "owner vault id")
            expected = (
                f"vault/generations/{state['state_set_id']}/owner.sqlite3")
            if state["path"] != expected \
                    or type(state["generation"]) is not int \
                    or type(state["schema_version"]) is not int \
                    or type(state["deletion_epoch"]) is not int \
                    or state["generation"] < 1 or state["schema_version"] < 1 \
                    or state["deletion_epoch"] < 0 \
                    or not HEX64.fullmatch(str(state["inventory_sha256"])) \
                    or not HEX64.fullmatch(str(state["baseline_sha256"])) \
                    or not schema_range["minimum"] <= state["schema_version"] \
                    <= schema_range["maximum"]:
                raise ActivationError(
                    "activation-set state identity or compatibility is invalid")
        body = {key: value[key] for key in fields if key != "receipt_sha256"}
        if value["receipt_sha256"] != _sha(body):
            raise ActivationError("activation-set receipt digest is invalid")
        return value

    def _state_from_source(self, source):
        if source is None:
            return None
        state_set_id = str(uuid.uuid4())
        destination = (
            self.generations / state_set_id / "owner.sqlite3")
        _consistent_backup(source, destination)
        inventory = state_inventory(destination)
        raw_sha = hashlib.sha256(destination.read_bytes()).hexdigest()
        state = {
            "state_set_id": state_set_id,
            "path": destination.relative_to(self.home).as_posix(),
            **inventory,
            "baseline_sha256": raw_sha,
        }
        receipt = {
            "schema_version": 1,
            **state,
            "created_at": _stamp(),
        }
        receipt["receipt_sha256"] = _sha(receipt)
        loom_reliability.atomic_write_json(
            destination.parent / ".state-receipt.json", receipt)
        return state

    def create(self, runtime_pointer, *, state_source, schema_range,
               previous_activation_set_id=None, purpose):
        runtime = runtime_identity(runtime_pointer)
        if purpose not in {
                "baseline-adoption", "release-activation",
                "rollback-forward-state", "reactivation"}:
            raise ActivationError("activation-set purpose is invalid")
        previous_receipt = None
        if previous_activation_set_id is not None:
            previous_receipt = self.read_receipt(previous_activation_set_id)
        state = self._state_from_source(state_source)
        if previous_receipt is not None:
            previous_state = previous_receipt["state"]
            if previous_state is not None and state is None:
                raise ActivationError(
                    "a new activation set cannot discard owner state")
            if previous_state is not None and (
                    state["owner_vault_id"] != previous_state["owner_vault_id"]
                    or state["generation"] < previous_state["generation"]
                    or state["deletion_epoch"] < previous_state["deletion_epoch"]):
                raise ActivationError(
                    "candidate owner state moves behind or crosses owner identity")
        activation_set_id = str(uuid.uuid4())
        value = {
            "schema_version": 1,
            "activation_set_id": activation_set_id,
            "purpose": purpose,
            "runtime": runtime,
            "state": state,
            "schema_range": dict(schema_range),
            "previous_activation_set_id": previous_activation_set_id,
            "created_at": _stamp(),
        }
        value["receipt_sha256"] = _sha(value)
        self._validate_receipt(value)
        loom_reliability.atomic_write_json(
            self._receipt_path(activation_set_id), value)
        previous = runtime_pointer.get("previous")
        return {
            **runtime,
            "previous": previous,
            "activation_set_id": activation_set_id,
            "activation_receipt_sha256": value["receipt_sha256"],
            "state": state,
            "previous_activation_set_id": previous_activation_set_id,
        }

    def validate_pointer(self, pointer):
        if not isinstance(pointer, dict):
            raise ActivationError("activation pointer is invalid")
        if set(pointer) == POINTER_BASE_FIELDS:
            runtime_identity(pointer)
            return pointer
        if set(pointer) != POINTER_V1_FIELDS:
            raise ActivationError("activation pointer fields are unknown or missing")
        runtime = runtime_identity(pointer)
        receipt = self.read_receipt(pointer["activation_set_id"])
        if receipt["receipt_sha256"] != pointer["activation_receipt_sha256"] \
                or receipt["runtime"] != runtime \
                or receipt["state"] != pointer["state"] \
                or receipt["previous_activation_set_id"] \
                != pointer["previous_activation_set_id"]:
            raise ActivationError("activation pointer does not match its receipt")
        if pointer["state"] is not None:
            state_path = self.home.joinpath(*Path(pointer["state"]["path"]).parts)
            root = self.generations.resolve()
            if not state_path.resolve().is_relative_to(root) \
                    or _redirect(state_path) or not state_path.is_file():
                raise ActivationError("active state path is unsafe")
            observed = state_inventory(state_path)
            expected = pointer["state"]
            if observed["owner_vault_id"] != expected["owner_vault_id"] \
                    or observed["schema_version"] != expected["schema_version"] \
                    or observed["generation"] < expected["generation"] \
                    or observed["deletion_epoch"] < expected["deletion_epoch"]:
                raise ActivationError(
                    "active state moved behind or outside its activation set")
        return pointer

    def state_path(self, pointer):
        pointer = self.validate_pointer(pointer)
        state = pointer.get("state")
        if state is None:
            legacy = self.home / "vault" / "owner.sqlite3"
            return legacy if legacy.exists() else None
        return self.home.joinpath(*Path(state["path"]).parts)

    def adopt_legacy(self, pointer, *, schema_range=None):
        if set(pointer) != POINTER_BASE_FIELDS:
            return self.validate_pointer(pointer)
        legacy = self.home / "vault" / "owner.sqlite3"
        if legacy.exists():
            inventory = state_inventory(legacy)
            compatible = schema_range or {
                "minimum": inventory["schema_version"],
                "maximum": inventory["schema_version"],
            }
            source = legacy
        else:
            compatible = schema_range or {"minimum": 0, "maximum": 0}
            source = None
        return self.create(
            pointer, state_source=source, schema_range=compatible,
            previous_activation_set_id=None, purpose="baseline-adoption")

    def public_projection(self, pointer):
        pointer = self.validate_pointer(pointer)
        state = pointer.get("state")
        return {
            "activation_set_id": pointer.get("activation_set_id"),
            "runtime_version": pointer["version"],
            "release_sequence": pointer["release_sequence"],
            "state_generation": state["generation"] if state else 0,
            "state_schema": state["schema_version"] if state else 0,
            "deletion_epoch": state["deletion_epoch"] if state else 0,
        }

    def prune_inactive(self, keep_activation_ids):
        """Remove only exact receipt-owned inactive activation/state sets."""
        keep = {
            _uuid(item, "retained activation set id")
            for item in keep_activation_ids if item is not None
        }
        receipts = []
        for path in sorted(self.receipts.glob("*.json")):
            if path.name.endswith(".rollback.json"):
                continue
            if path.is_symlink() or not path.is_file():
                raise ActivationError("activation receipt store contains an unsafe entry")
            receipt = self.read_receipt(path.stem)
            receipts.append((path, receipt))
        referenced_state = {
            receipt["state"]["state_set_id"]
            for _path, receipt in receipts
            if receipt["activation_set_id"] in keep and receipt["state"] is not None
        }
        removed = []
        for path, receipt in receipts:
            activation_id = receipt["activation_set_id"]
            if activation_id in keep:
                continue
            state = receipt["state"]
            if state is not None and state["state_set_id"] not in referenced_state:
                directory = self.generations / state["state_set_id"]
                database = directory / "owner.sqlite3"
                state_receipt = directory / ".state-receipt.json"
                try:
                    entries = {item.name for item in directory.iterdir()}
                except OSError as exc:
                    raise ActivationError(
                        f"inactive state ownership is unreadable: {exc}") from exc
                if _redirect(directory) or entries - {
                        "owner.sqlite3", ".state-receipt.json"} \
                        or not database.is_file() or database.is_symlink() \
                        or not state_receipt.is_file() or state_receipt.is_symlink():
                    raise ActivationError(
                        "inactive state contains unowned or redirected bytes")
                state_inventory(database)
                database.unlink()
                state_receipt.unlink()
                directory.rmdir()
            rollback = path.with_name(path.stem + ".rollback.json")
            if rollback.exists():
                if rollback.is_symlink() or not rollback.is_file():
                    raise ActivationError("rollback receipt is unsafe")
                rollback.unlink()
            path.unlink()
            removed.append(activation_id)
        return {"status": "pruned", "removed_activation_sets": removed}
