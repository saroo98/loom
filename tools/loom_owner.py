#!/usr/bin/env python3
"""Fail-closed owner-vault bootstrap and body-free private health reporting."""

import base64
import datetime as dt
import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
from pathlib import Path

import loom_adapters
import loom_crypto
import loom_reliability
import loom_transfer
import loom_vault


LEGACY_KEY_BYTES = 96
KEY_BYTES = 128


class OwnerError(RuntimeError):
    pass


class NativeKeyStore:
    def __init__(self, helper):
        self.helper = helper

    def set(self, owner_vault_id, secret):
        loom_crypto.key_store_set(self.helper, owner_vault_id, secret)

    def get(self, owner_vault_id):
        return loom_crypto.key_store_get(self.helper, owner_vault_id)

    def delete(self, owner_vault_id):
        loom_crypto.key_store_delete(self.helper, owner_vault_id)


def _pack_keys(keys):
    names = ("master_key", "signing_key", "exchange_secret")
    try:
        raw = b"".join(base64.b64decode(keys[name], validate=True) for name in names)
    except (KeyError, ValueError, TypeError) as exc:
        raise OwnerError("generated vault key material is invalid") from exc
    if len(raw) != LEGACY_KEY_BYTES:
        raise OwnerError("generated vault key material has the wrong size")
    # The fourth key is a stable blind-index key. It survives data-key rotation so
    # scopes and forgetting commitments remain comparable without retaining the old data key.
    return raw + raw[:32]


def _unpack_keys(raw):
    if not isinstance(raw, bytes) or len(raw) not in {LEGACY_KEY_BYTES, KEY_BYTES}:
        raise OwnerError("stored vault key material is invalid")
    index = raw[96:128] if len(raw) == KEY_BYTES else raw[:32]
    return raw[:32], raw[32:64], raw[64:96], index


def peek_owner_vault_id(path):
    path = loom_reliability._absolute(path, "owner vault", must_exist=True)
    if not path.is_file() or path.is_symlink():
        raise OwnerError("owner vault is missing or unsafe")
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='owner_vault_id'").fetchone()
        finally:
            connection.close()
        owner = str(uuid.UUID(row[0])) if row else None
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise OwnerError(f"owner vault identity cannot be read safely: {exc}") from exc
    if owner != row[0]:
        raise OwnerError("owner vault identity is not canonical")
    return owner


def peek_key_slot_id(path):
    path = loom_reliability._absolute(path, "owner vault", must_exist=True)
    owner = peek_owner_vault_id(path)
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key='key_slot_id'").fetchone()
        finally:
            connection.close()
        return str(uuid.UUID(row[0])) if row else owner
    except (sqlite3.Error, ValueError, TypeError) as exc:
        raise OwnerError(f"owner vault key slot cannot be read safely: {exc}") from exc


def open_owner_vault(home, helper, *, key_store=None):
    home = loom_reliability._absolute(home, "Loom home")
    path = home / "vault" / "owner.sqlite3"
    owner = peek_owner_vault_id(path)
    key_slot = peek_key_slot_id(path)
    store = key_store or NativeKeyStore(helper)
    master, signing, _exchange, index = _unpack_keys(store.get(key_slot))
    crypto = loom_crypto.HelperCrypto(
        helper, master_key=master, signing_key=signing, index_key=index)
    return loom_vault.OwnerVault.open(path, crypto=crypto), crypto


def initialize_owner_vault(home, helper, *, key_store=None, owner_vault_id=None,
                           device_id=None):
    """Create or reopen one vault; no unwrapped key is ever persisted to a file."""
    home = loom_reliability._absolute(home, "Loom home")
    path = home / "vault" / "owner.sqlite3"
    if path.exists():
        vault, crypto = open_owner_vault(home, helper, key_store=key_store)
        return {"status": "opened", "vault": vault, "crypto": crypto}
    owner = owner_vault_id or str(uuid.uuid4())
    device = device_id or str(uuid.uuid4())
    store = key_store or NativeKeyStore(helper)
    keys = loom_crypto.generate_keys(helper)
    secret = _pack_keys(keys)
    crypto = loom_crypto.HelperCrypto(
        helper, master_key=secret[:32], signing_key=secret[32:64],
        index_key=secret[96:128])
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=".owner-vault-", suffix=".sqlite3", dir=path.parent)
    os.close(descriptor)
    staged = Path(name)
    staged.unlink()
    stored = False
    try:
        staged_vault = loom_vault.OwnerVault.create(
            staged, crypto=crypto, owner_vault_id=owner, device_id=device)
        staged_vault.put_entity("device-key", device, {
            "exchange_public": keys["exchange_public"],
            "signing_public": keys["signing_public"],
        })
        store.set(owner, secret)
        stored = True
        os.replace(staged, path)
        staged = None
        vault = loom_vault.OwnerVault.open(path, crypto=crypto)
        return {"status": "initialized", "vault": vault, "crypto": crypto}
    except BaseException as exc:
        if stored:
            try:
                store.delete(owner)
            except BaseException as cleanup:
                raise OwnerError(
                    "vault activation failed and secure-key rollback also failed") from cleanup
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, OwnerError):
            raise
        raise OwnerError(f"owner vault initialization failed safely: {exc}") from exc
    finally:
        if staged is not None:
            for suffix in ("", "-wal", "-shm"):
                try:
                    Path(str(staged) + suffix).unlink()
                except FileNotFoundError:
                    pass


def revoke_device_and_rotate(home, helper, revoked_device_id, *, key_store=None):
    """Revoke one device and atomically activate a newly encrypted vault generation."""
    home = loom_reliability._absolute(home, "Loom home")
    path = home / "vault" / "owner.sqlite3"
    store = key_store or NativeKeyStore(helper)
    old_slot = peek_key_slot_id(path)
    old_secret = store.get(old_slot)
    _old_master, _old_signing, _old_exchange, index_key = _unpack_keys(old_secret)
    vault, _old_crypto = open_owner_vault(home, helper, key_store=store)
    before = vault.semantic_inventory()
    generated = loom_crypto.generate_keys(helper)
    try:
        master = base64.b64decode(generated["master_key"], validate=True)
        signing = base64.b64decode(generated["signing_key"], validate=True)
        exchange = base64.b64decode(generated["exchange_secret"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise OwnerError("rotated vault key material is invalid") from exc
    new_secret = master + signing + exchange + index_key
    if len(new_secret) != KEY_BYTES:
        raise OwnerError("rotated vault key material has the wrong size")
    new_crypto = loom_crypto.HelperCrypto(
        helper, master_key=master, signing_key=signing, index_key=index_key)
    new_slot = str(uuid.uuid4())
    checkpoints = home / "vault" / "checkpoints"
    checkpoints.mkdir(parents=True, exist_ok=True)
    rollback = checkpoints / (
        f"pre-revocation-g{vault.identity()['generation']:08d}-{old_slot}.sqlite3")
    if rollback.exists():
        raise OwnerError("a rollback checkpoint already exists for this vault generation")
    vault.online_backup(rollback)
    descriptor, name = tempfile.mkstemp(
        prefix=".owner-rotation-", suffix=".sqlite3", dir=path.parent)
    os.close(descriptor)
    staged = Path(name)
    staged.unlink()
    stored = False
    activated = False
    try:
        receipt = vault.stage_key_rotation(
            staged, new_crypto=new_crypto, key_slot_id=new_slot,
            revoked_device_id=revoked_device_id,
            local_device_keys={
                "signing_public": generated["signing_public"],
                "exchange_public": generated["exchange_public"],
            })
        rotated = loom_vault.OwnerVault.open(staged, crypto=new_crypto)
        after = rotated.semantic_inventory()
        if before["memory"] != after["memory"] \
                or before["tombstones"] != after["tombstones"] \
                or before["legacy_aliases"] != after["legacy_aliases"]:
            raise OwnerError("key rotation changed owner-memory semantic counts")
        store.set(new_slot, new_secret)
        stored = True
        with vault._connect() as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        Path(str(path) + "-wal").unlink(missing_ok=True)
        Path(str(path) + "-shm").unlink(missing_ok=True)
        os.replace(staged, path)
        staged = None
        activated = True
        reopened, crypto = open_owner_vault(home, helper, key_store=store)
        return {"status": "rotated", "vault": reopened, "crypto": crypto,
                "rollback_checkpoint": str(rollback), **receipt}
    except BaseException as exc:
        if activated:
            try:
                Path(str(path) + "-wal").unlink(missing_ok=True)
                Path(str(path) + "-shm").unlink(missing_ok=True)
                os.replace(rollback, path)
                activated = False
            except BaseException as restore:
                raise OwnerError(
                    "rotated vault activation failed and rollback could not be restored") from restore
        if stored:
            try:
                store.delete(new_slot)
            except BaseException as cleanup:
                raise OwnerError(
                    "key rotation failed and secure-key rollback also failed") from cleanup
        rollback.unlink(missing_ok=True)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, OwnerError):
            raise
        raise OwnerError(f"device revocation and key rotation failed safely: {exc}") from exc
    finally:
        if staged is not None:
            for suffix in ("", "-wal", "-shm"):
                Path(str(staged) + suffix).unlink(missing_ok=True)


def _safe_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def health_summary(home, vault):
    """Return operational metadata only; never decrypt or return owner-memory bodies."""
    home = loom_reliability._absolute(home, "Loom home")
    pointer = _safe_json(home / "runtime" / "current.json")
    backup = _safe_json(home / "backups" / loom_transfer.BACKUP_INDEX)
    receipts = home / "adapters" / "receipts"
    connected = sorted(path.stem for path in receipts.glob("*.json")
                       if path.is_file() and not path.is_symlink()) if receipts.is_dir() else []
    with vault._connect() as connection:
        devices = {row["status"]: row["count"] for row in connection.execute(
            "SELECT status,COUNT(*) AS count FROM devices GROUP BY status")}
        quarantine = connection.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]
        migration = connection.execute(
            "SELECT created_at FROM receipts WHERE kind='legacy-migration' "
            "ORDER BY created_at DESC LIMIT 1").fetchone()
    backup_entries = backup.get("entries", []) if isinstance(backup, dict) else []
    last_backup = max((item.get("created_at", "") for item in backup_entries), default=None)
    identity = vault.identity()
    return {
        "runtime_version": pointer.get("version") if isinstance(pointer, dict) else None,
        "state_schema": identity["schema_version"],
        "last_verified_backup": last_backup,
        "connected_agents": connected,
        "paired_devices": devices.get("active", 0),
        "dormant_devices": devices.get("dormant", 0),
        "last_successful_migration": migration["created_at"] if migration else None,
        "quarantined_conflicts": quarantine,
        "update_delivery": "codex-marketplace-controlled",
        "telemetry": False,
    }
