#!/usr/bin/env python3
"""Receiver-bound pairing and phrase-unlocked encrypted recovery for Loom vaults."""

import base64
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from pathlib import Path

import loom_crypto
import loom_reliability
import loom_vault


MAX_VAULT_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_BYTES = 700 * 1024 * 1024
CHUNK_BYTES = 512 * 1024
MAX_CHUNKS = 1024
MAX_PAIR_RECEIPTS = 4096
PAIR_TTL_SECONDS = 300
BACKUP_INDEX = ".loom-backup-index.json"
RECOVERY_ANCHOR = ".loom-recovery-anchor.json"
ROLLING_BACKUPS = 3
WEEKLY_BACKUPS = 4
MONTHLY_BACKUPS = 12
BACKUP_NAME_RE = re.compile(r"^loom-[0-9]{8}T[0-9]{6}Z-[0-9]{8}\.loom-backup$")


class TransferError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_bundle(path):
    path = loom_reliability._absolute(path, "transfer bundle", must_exist=True)
    if not path.is_file() or path.stat().st_size > MAX_BUNDLE_BYTES:
        raise TransferError("transfer bundle is missing, non-regular, or oversized")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferError(f"transfer bundle is invalid: {exc}") from exc


def _checkpoint(vault):
    with tempfile.TemporaryDirectory(prefix="loom-vault-checkpoint-") as temporary:
        path = Path(temporary) / "checkpoint.sqlite3"
        vault.online_backup(path)
        raw = path.read_bytes()
    if len(raw) > MAX_VAULT_BYTES:
        raise TransferError("owner vault exceeds the 512 MiB recovery bound")
    return raw


def _write_checkpoint(destination, raw):
    destination = loom_reliability._absolute(destination, "restored owner vault")
    if destination.exists() or len(raw) > MAX_VAULT_BYTES:
        raise TransferError("restore destination exists or checkpoint exceeds its bound")
    destination.parent.mkdir(parents=True, exist_ok=True)
    loom_reliability.atomic_write_bytes(destination, raw)
    connection = sqlite3.connect(destination)
    try:
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise TransferError("restored checkpoint failed SQLite integrity validation")
    finally:
        connection.close()
    return destination


def _remove_checkpoint(path):
    """Remove only the exact failed restore and its SQLite sidecars."""
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def _chunks(raw):
    count = max(1, (len(raw) + CHUNK_BYTES - 1) // CHUNK_BYTES)
    if count > MAX_CHUNKS:
        raise TransferError("checkpoint exceeds the encrypted chunk bound")
    return [raw[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
            for index in range(count)]


def _chunk_aad(header, index, count, digest):
    return _canonical({**header, "chunk_index": index, "chunk_count": count,
                       "chunk_sha256": digest})


def _instant(value=None):
    instant = value or dt.datetime.now(dt.timezone.utc)
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise TransferError("pairing time must be timezone-aware")
    return instant.astimezone(dt.timezone.utc)


def _parse_instant(value, label):
    try:
        instant = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransferError(f"{label} is invalid") from exc
    if instant.tzinfo is None:
        raise TransferError(f"{label} is invalid")
    return instant.astimezone(dt.timezone.utc)


def _pair_receipts(path):
    if not path.is_file():
        return {"schema_version": 1, "receipts": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferError(f"pair replay receipt store is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "receipts"} \
            or value["schema_version"] != 1 or not isinstance(value["receipts"], list) \
            or len(value["receipts"]) > MAX_PAIR_RECEIPTS:
        raise TransferError("pair replay receipt store contract is invalid")
    return value


def new_device(helper, *, now=None):
    keys = loom_crypto.generate_keys(helper)
    device_id = str(uuid.uuid4())
    public = {
        "device_id": device_id,
        "exchange_public": keys["exchange_public"],
        "signing_public": keys["signing_public"],
    }
    fingerprint = hashlib.sha256(_canonical(public)).hexdigest()
    issued = _instant(now)
    expires = issued + dt.timedelta(seconds=PAIR_TTL_SECONDS)
    request = {
        "kind": "loom-pair-request-v2", **public,
        "challenge": base64.b64encode(os.urandom(32)).decode("ascii"),
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
    }
    request_sha256 = hashlib.sha256(_canonical(request)).hexdigest()
    return {
        "pairing_payload": {**request, "request_sha256": request_sha256,
                            "fingerprint": fingerprint},
        "private_material": {
            "device_id": device_id, "exchange_secret": keys["exchange_secret"],
            "exchange_public": keys["exchange_public"],
            "signing_key": keys["signing_key"], "signing_public": keys["signing_public"],
            "fingerprint": fingerprint, "challenge": request["challenge"],
            "request_sha256": request_sha256, "expires_at": request["expires_at"],
        },
    }


def create_pair_bundle(vault, crypto, pairing_payload, destination, *, owner_authorized, now=None):
    required = {"kind", "device_id", "exchange_public", "signing_public", "fingerprint",
                "challenge", "issued_at", "expires_at", "request_sha256"}
    if not isinstance(pairing_payload, dict) or set(pairing_payload) != required:
        raise TransferError("pairing payload is invalid")
    if owner_authorized is not True:
        raise TransferError("pairing requires explicit owner authorization of the receiver")
    request = {key: pairing_payload[key] for key in required - {"fingerprint", "request_sha256"}}
    if pairing_payload["kind"] != "loom-pair-request-v2" \
            or pairing_payload["request_sha256"] != hashlib.sha256(_canonical(request)).hexdigest() \
            or _parse_instant(pairing_payload["expires_at"], "pairing expiry") <= _instant(now) \
            or len(base64.b64decode(pairing_payload["challenge"], validate=True)) != 32:
        raise TransferError("pairing request is invalid or expired")
    public = {key: pairing_payload[key] for key in (
        "device_id", "exchange_public", "signing_public")}
    if pairing_payload["fingerprint"] != hashlib.sha256(_canonical(public)).hexdigest():
        raise TransferError("pairing payload fingerprint does not match")
    vault.authorize_device(pairing_payload["device_id"], pairing_payload["signing_public"])
    vault.put_entity("device-key", pairing_payload["device_id"], {
        "exchange_public": pairing_payload["exchange_public"],
        "signing_public": pairing_payload["signing_public"],
    })
    raw = _checkpoint(vault)
    identity = vault.identity()
    bundle_id = str(uuid.uuid4())
    checkpoint_sha = hashlib.sha256(raw).hexdigest()
    owner_commitment = hashlib.sha256(_canonical({
        "owner_vault_id": identity["owner_vault_id"],
        "sender_device_id": identity["device_id"],
        "sequence": identity["generation"],
        "deletion_epoch": vault.deletion_epoch(),
    })).hexdigest()
    header = {
        "kind": "loom-pair-v2", "bundle_id": bundle_id,
        "owner_vault_id": identity["owner_vault_id"],
        "sender_device_id": identity["device_id"],
        "receiver_device_id": pairing_payload["device_id"],
        "sequence": identity["generation"], "deletion_epoch": vault.deletion_epoch(),
        "checkpoint_sha256": checkpoint_sha,
        "request_sha256": pairing_payload["request_sha256"],
        "receiver_challenge": pairing_payload["challenge"],
        "expires_at": pairing_payload["expires_at"],
        "owner_vault_commitment": owner_commitment,
    }
    try:
        envelope = crypto.pair_seal(
            pairing_payload["exchange_public"], {
                "owner_vault_id": identity["owner_vault_id"],
                "receiver_device_id": pairing_payload["device_id"],
                "checkpoint_sha256": checkpoint_sha,
                "deletion_epoch": vault.deletion_epoch(),
                "request_sha256": pairing_payload["request_sha256"],
                "owner_vault_commitment": owner_commitment,
            }, _canonical(header))
        pieces = _chunks(raw)
        encrypted = []
        for index, piece in enumerate(pieces):
            digest = hashlib.sha256(piece).hexdigest()
            encrypted.append({
                "index": index, "sha256": digest,
                **crypto.pair_seal_bytes(
                    pairing_payload["exchange_public"], piece,
                    _chunk_aad(header, index, len(pieces), digest)),
            })
    except loom_crypto.CryptoError as exc:
        raise TransferError(f"pairing encryption failed: {exc}") from exc
    bundle = {**header, "envelope": envelope, "chunks": encrypted}
    sender_fingerprint = hashlib.sha256(_canonical({
        "owner_vault_id": identity["owner_vault_id"],
        "sender_device_id": identity["device_id"],
        "sender_signing_public": envelope["sender_signing_public"],
    })).hexdigest()
    sas = hashlib.sha256(_canonical({
        "bundle_id": bundle_id, "request_sha256": pairing_payload["request_sha256"],
        "sender_fingerprint": sender_fingerprint,
        "owner_vault_commitment": owner_commitment,
    })).hexdigest()[:12]
    sas = "-".join(sas[index:index + 4] for index in range(0, 12, 4))
    destination = loom_reliability._absolute(destination, "pair bundle destination")
    if destination.exists():
        raise TransferError("pair bundle destination already exists")
    loom_reliability.atomic_write_json(destination, bundle)
    return {"status": "created", "bundle_id": bundle_id,
            "receiver_device_id": pairing_payload["device_id"],
            "sender_fingerprint": sender_fingerprint,
            "sas": sas, "expires_at": pairing_payload["expires_at"],
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


def accept_pair_bundle(helper, bundle_path, private_material, destination, *,
                       expected_sender_fingerprint, expected_sas, key_store=None,
                       receipt_store=None, now=None):
    bundle = _read_bundle(bundle_path)
    required = {"kind", "bundle_id", "owner_vault_id", "sender_device_id",
                "receiver_device_id", "sequence", "deletion_epoch", "checkpoint_sha256", "request_sha256",
                "receiver_challenge", "expires_at", "owner_vault_commitment", "envelope",
                "chunks"}
    if not isinstance(bundle, dict) or set(bundle) != required or bundle["kind"] != "loom-pair-v2":
        raise TransferError("pair bundle contract is invalid")
    private_required = {"device_id", "exchange_secret", "signing_key",
                        "exchange_public", "signing_public", "fingerprint", "challenge",
                        "request_sha256", "expires_at"}
    if not isinstance(private_material, dict) or set(private_material) != private_required \
            or private_material["device_id"] != bundle["receiver_device_id"] \
            or private_material["challenge"] != bundle["receiver_challenge"] \
            or private_material["request_sha256"] != bundle["request_sha256"] \
            or private_material["expires_at"] != bundle["expires_at"] \
            or _parse_instant(bundle["expires_at"], "pair bundle expiry") <= _instant(now):
        raise TransferError("pair bundle is not addressed to this device")
    destination = loom_reliability._absolute(destination, "restored owner vault")
    receipt_path = loom_reliability._absolute(
        receipt_store or destination.parent / ".loom-pair-receipts.json",
        "pair replay receipt store")
    replay_state = _pair_receipts(receipt_path)
    bundle_digest = hashlib.sha256(Path(bundle_path).read_bytes()).hexdigest()
    if any(item.get("bundle_id") == bundle["bundle_id"] or item.get("sha256") == bundle_digest
           for item in replay_state["receipts"] if isinstance(item, dict)):
        raise TransferError("pair bundle replay was already accepted")
    header = {key: bundle[key] for key in (
        "kind", "bundle_id", "owner_vault_id", "sender_device_id",
        "receiver_device_id", "sequence", "deletion_epoch", "checkpoint_sha256", "request_sha256",
        "receiver_challenge", "expires_at", "owner_vault_commitment")}
    try:
        envelope = bundle["envelope"]
        if not isinstance(envelope, dict) or set(envelope) != {
                "ciphertext", "sender_exchange_public", "sender_signing_public", "signature"}:
            raise TransferError("pair envelope contract is invalid")
        observed_sender = hashlib.sha256(_canonical({
            "owner_vault_id": bundle["owner_vault_id"],
            "sender_device_id": bundle["sender_device_id"],
            "sender_signing_public": envelope["sender_signing_public"],
        })).hexdigest()
        if not isinstance(expected_sender_fingerprint, str) \
                or not re.fullmatch(r"[0-9a-f]{64}", expected_sender_fingerprint) \
                or observed_sender != expected_sender_fingerprint:
            raise TransferError("pair sender does not match the owner-authorized fingerprint")
        observed_commitment = hashlib.sha256(_canonical({
            "owner_vault_id": bundle["owner_vault_id"],
            "sender_device_id": bundle["sender_device_id"],
            "sequence": bundle["sequence"],
            "deletion_epoch": bundle["deletion_epoch"],
        })).hexdigest()
        observed_sas = hashlib.sha256(_canonical({
            "bundle_id": bundle["bundle_id"], "request_sha256": bundle["request_sha256"],
            "sender_fingerprint": observed_sender,
            "owner_vault_commitment": observed_commitment,
        })).hexdigest()[:12]
        observed_sas = "-".join(
            observed_sas[index:index + 4] for index in range(0, 12, 4))
        if observed_commitment != bundle["owner_vault_commitment"] \
                or not isinstance(expected_sas, str) or observed_sas != expected_sas:
            raise TransferError("pairing SAS or owner-vault commitment does not match")
        plaintext = loom_crypto.pair_open(
            helper, receiver_secret=base64.b64decode(private_material["exchange_secret"]),
            sender_exchange_public=envelope["sender_exchange_public"],
            sender_signing_public=envelope["sender_signing_public"],
            ciphertext=envelope["ciphertext"], signature=envelope["signature"],
            aad=_canonical(header))
        payload = json.loads(plaintext.decode("utf-8"))
    except (loom_crypto.CryptoError, ValueError, UnicodeError, json.JSONDecodeError,
            TransferError) as exc:
        raise TransferError(f"pair bundle authentication failed: {exc}") from exc
    expected = {"owner_vault_id", "receiver_device_id", "checkpoint_sha256",
                "request_sha256", "owner_vault_commitment", "deletion_epoch",
                "master_key", "index_key"}
    if not isinstance(payload, dict) or set(payload) != expected \
            or payload["owner_vault_id"] != bundle["owner_vault_id"] \
            or payload["receiver_device_id"] != bundle["receiver_device_id"] \
            or payload["request_sha256"] != bundle["request_sha256"] \
            or payload["deletion_epoch"] != bundle["deletion_epoch"] \
            or payload["owner_vault_commitment"] != bundle["owner_vault_commitment"]:
        raise TransferError("pair bundle decrypted contract is invalid")
    chunks = bundle["chunks"]
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= MAX_CHUNKS:
        raise TransferError("pair chunk collection is invalid")
    raw_parts = []
    chunk_fields = {"index", "sha256", "ciphertext", "sender_exchange_public",
                    "sender_signing_public", "signature"}
    for index, item in enumerate(chunks):
        if not isinstance(item, dict) or set(item) != chunk_fields or item["index"] != index:
            raise TransferError("pair chunk order or contract is invalid")
        if item["sender_signing_public"] != envelope["sender_signing_public"]:
            raise TransferError("pair chunk sender changed within the bundle")
        piece = loom_crypto.pair_open(
            helper, receiver_secret=base64.b64decode(private_material["exchange_secret"]),
            sender_exchange_public=item["sender_exchange_public"],
            sender_signing_public=item["sender_signing_public"],
            ciphertext=item["ciphertext"], signature=item["signature"],
            aad=_chunk_aad(header, index, len(chunks), item["sha256"]))
        if hashlib.sha256(piece).hexdigest() != item["sha256"]:
            raise TransferError("pair chunk hash is invalid")
        raw_parts.append(piece)
    raw = b"".join(raw_parts)
    if hashlib.sha256(raw).hexdigest() != bundle["checkpoint_sha256"] \
            or payload["checkpoint_sha256"] != bundle["checkpoint_sha256"]:
        raise TransferError("pair bundle checkpoint hash is invalid")
    destination = _write_checkpoint(destination, raw)
    crypto = loom_crypto.HelperCrypto(
        helper, master_key=base64.b64decode(payload["master_key"], validate=True),
        signing_key=base64.b64decode(private_material["signing_key"], validate=True),
        index_key=base64.b64decode(payload["index_key"], validate=True))
    try:
        vault = loom_vault.OwnerVault.open(destination, crypto=crypto)
        if vault.deletion_epoch() != bundle["deletion_epoch"]:
            raise TransferError("pair bundle deletion floor does not match its checkpoint")
        sender = vault.device_identity(bundle["sender_device_id"])
        if sender is None or sender["status"] != "active" \
                or sender["public_key"] != envelope["sender_signing_public"]:
            raise TransferError("pairing sender is not an active checkpoint member")
        vault.adopt_local_device(private_material["device_id"],
                                 private_material["signing_public"])
        key_slot_id = str(uuid.uuid4())
        vault.assign_key_slot(key_slot_id)
        if key_store is not None:
            activation_secret = (
                base64.b64decode(payload["master_key"], validate=True)
                + base64.b64decode(private_material["signing_key"], validate=True)
                + base64.b64decode(private_material["exchange_secret"], validate=True)
                + base64.b64decode(payload["index_key"], validate=True))
            key_store.set(key_slot_id, activation_secret)
    except BaseException:
        _remove_checkpoint(destination)
        raise
    replay_state["receipts"].append({
        "bundle_id": bundle["bundle_id"], "sha256": bundle_digest,
        "accepted_at": _instant(now).isoformat().replace("+00:00", "Z")})
    replay_state["receipts"] = replay_state["receipts"][-MAX_PAIR_RECEIPTS:]
    loom_reliability.atomic_write_json(receipt_path, replay_state)
    return {"status": ("accepted" if key_store is not None else "validated-not-activated"),
            "crypto": crypto,
            "owner_vault_id": vault.identity()["owner_vault_id"],
            "key_slot_id": key_slot_id,
            "key_stored": key_store is not None}


def generate_recovery(helper):
    try:
        result = loom_crypto.generate_recovery(helper)
    except loom_crypto.CryptoError as exc:
        raise TransferError(f"recovery generation failed: {exc}") from exc
    secret = base64.b64decode(result["secret"], validate=True)
    return {"phrase": result["phrase"],
            "recovery_key_id": hashlib.sha256(secret).hexdigest(),
            "instruction": "The phrase unlocks an encrypted backup; it cannot reconstruct data alone."}


def _read_recovery_anchor(helper, path):
    value = _read_bundle(path)
    if not isinstance(value, dict) or set(value) != {"body", "signature"} \
            or not isinstance(value["body"], dict) \
            or set(value["body"]) != {
                "kind", "owner_vault_id", "deletion_epoch", "signing_public", "created_at"}:
        raise TransferError("recovery anchor contract is invalid")
    body = value["body"]
    try:
        owner = str(uuid.UUID(body["owner_vault_id"]))
        created = dt.datetime.fromisoformat(body["created_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise TransferError("recovery anchor identity is invalid") from exc
    if body["kind"] != "loom-recovery-anchor-v1" or owner != body["owner_vault_id"] \
            or type(body["deletion_epoch"]) is not int or body["deletion_epoch"] < 0 \
            or created.tzinfo is None \
            or not loom_crypto.verify_signature(
                helper, _canonical(body), value["signature"], body["signing_public"]):
        raise TransferError("recovery anchor authentication failed")
    return body


def write_recovery_anchor(vault, crypto, destination):
    destination = loom_reliability._absolute(destination, "recovery anchor destination")
    identity = vault.identity()
    body = {
        "kind": "loom-recovery-anchor-v1",
        "owner_vault_id": identity["owner_vault_id"],
        "deletion_epoch": vault.deletion_epoch(),
        "signing_public": crypto.public_key(),
        "created_at": dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if destination.exists():
        prior = _read_recovery_anchor(crypto.helper, destination)
        if prior["owner_vault_id"] != body["owner_vault_id"] \
                or prior["deletion_epoch"] > body["deletion_epoch"]:
            raise TransferError("recovery anchor would cross owners or roll back")
    signature = crypto.sign(_canonical(body)).decode("ascii")
    loom_reliability.atomic_write_json(
        destination, {"body": body, "signature": signature})
    return {"path": str(destination), "deletion_epoch": body["deletion_epoch"]}


def _decode_recovery_bundle(helper, bundle, phrase, *, minimum_sequence=None):
    required = {"kind", "backup_id", "owner_vault_id", "sequence", "deletion_epoch",
                "checkpoint_sha256", "envelope", "chunks"}
    if not isinstance(bundle, dict) or set(bundle) != required \
            or bundle["kind"] != "loom-recovery-v2" \
            or type(bundle["deletion_epoch"]) is not int or bundle["deletion_epoch"] < 0:
        raise TransferError("recovery backup contract is invalid")
    if minimum_sequence is not None and (
            type(minimum_sequence) is not int or bundle["sequence"] < minimum_sequence):
        raise TransferError("recovery backup is older than the required deletion epoch")
    header = {key: bundle[key] for key in (
        "kind", "backup_id", "owner_vault_id", "sequence", "deletion_epoch",
        "checkpoint_sha256")}
    try:
        plaintext = loom_crypto.recovery_open(
            helper, phrase=phrase, ciphertext=bundle["envelope"], aad=_canonical(header))
        payload = json.loads(plaintext.decode("utf-8"))
    except (loom_crypto.CryptoError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferError(f"recovery phrase or backup authentication failed: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {
            "owner_vault_id", "checkpoint_sha256", "master_key", "index_key"} \
            or payload["owner_vault_id"] != bundle["owner_vault_id"]:
        raise TransferError("recovery backup decrypted contract is invalid")
    chunks = bundle["chunks"]
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= MAX_CHUNKS:
        raise TransferError("recovery chunk collection is invalid")
    raw_parts = []
    for index, item in enumerate(chunks):
        if not isinstance(item, dict) or set(item) != {"index", "sha256", "ciphertext"} \
                or item["index"] != index:
            raise TransferError("recovery chunk order or contract is invalid")
        piece = loom_crypto.recovery_open(
            helper, phrase=phrase, ciphertext=item["ciphertext"],
            aad=_chunk_aad(header, index, len(chunks), item["sha256"]))
        if hashlib.sha256(piece).hexdigest() != item["sha256"]:
            raise TransferError("recovery chunk hash is invalid")
        raw_parts.append(piece)
    raw = b"".join(raw_parts)
    if hashlib.sha256(raw).hexdigest() != bundle["checkpoint_sha256"] \
            or payload["checkpoint_sha256"] != bundle["checkpoint_sha256"]:
        raise TransferError("recovery checkpoint hash is invalid")
    return raw, payload


def create_recovery_backup(vault, crypto, phrase, destination, *, sequence,
                           recovery_anchor):
    if type(sequence) is not int or sequence < 1:
        raise TransferError("recovery backup sequence is invalid")
    raw = _checkpoint(vault)
    identity = vault.identity()
    backup_id = str(uuid.uuid4())
    checkpoint_sha = hashlib.sha256(raw).hexdigest()
    deletion_epoch = vault.deletion_epoch()
    header = {"kind": "loom-recovery-v2", "backup_id": backup_id,
              "owner_vault_id": identity["owner_vault_id"], "sequence": sequence,
              "deletion_epoch": deletion_epoch,
              "checkpoint_sha256": checkpoint_sha}
    try:
        envelope = crypto.recovery_wrap(phrase, {
            "owner_vault_id": identity["owner_vault_id"],
            "checkpoint_sha256": checkpoint_sha}, _canonical(header))
        pieces = _chunks(raw)
        encrypted = []
        for index, piece in enumerate(pieces):
            digest = hashlib.sha256(piece).hexdigest()
            encrypted.append({"index": index, "sha256": digest,
                              "ciphertext": crypto.recovery_wrap_bytes(
                                  phrase, piece,
                                  _chunk_aad(header, index, len(pieces), digest))})
    except loom_crypto.CryptoError as exc:
        raise TransferError(f"recovery backup encryption failed: {exc}") from exc
    destination = loom_reliability._absolute(destination, "recovery backup destination")
    if destination.exists():
        raise TransferError("recovery backup destination already exists")
    loom_reliability.atomic_write_json(
        destination, {**header, "envelope": envelope, "chunks": encrypted})
    # A backup is not accepted until every chunk decrypts, the reconstructed database passes
    # SQLite integrity, and its semantic inventory matches the live source vault.
    try:
        verified_raw, _payload = _decode_recovery_bundle(
            crypto.helper, _read_bundle(destination), phrase)
        with tempfile.TemporaryDirectory(prefix="loom-backup-self-test-") as temporary:
            probe_path = Path(temporary) / "owner.sqlite3"
            _write_checkpoint(probe_path, verified_raw)
            reopened = loom_vault.OwnerVault.open(probe_path, crypto=crypto)
            if reopened.semantic_inventory()["sha256"] \
                    != vault.semantic_inventory()["sha256"]:
                raise TransferError("recovery backup semantic inventory changed")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    anchor = write_recovery_anchor(vault, crypto, recovery_anchor)
    return {"status": "created", "backup_id": backup_id, "sequence": sequence,
            "deletion_epoch": deletion_epoch, "recovery_anchor": anchor["path"],
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


def restore_recovery_backup(helper, backup_path, phrase, destination, *, minimum_sequence=None,
                            recovery_anchor=None, key_store=None):
    path = Path(backup_path)
    if not path.is_file():
        raise TransferError("an encrypted backup is required; a recovery phrase alone has no data")
    bundle = _read_bundle(path)
    if recovery_anchor is None:
        raise TransferError(
            "a current recovery anchor is required; forgetting freshness is unknown")
    anchor = _read_recovery_anchor(helper, recovery_anchor)
    if anchor["owner_vault_id"] != bundle.get("owner_vault_id") \
            or bundle.get("deletion_epoch", -1) < anchor["deletion_epoch"]:
        raise TransferError("recovery backup is older than the current deletion epoch")
    raw, payload = _decode_recovery_bundle(
        helper, bundle, phrase, minimum_sequence=minimum_sequence)
    keys = loom_crypto.generate_keys(helper)
    crypto = loom_crypto.HelperCrypto(
        helper, master_key=base64.b64decode(payload["master_key"], validate=True),
        signing_key=base64.b64decode(keys["signing_key"], validate=True),
        index_key=base64.b64decode(payload["index_key"], validate=True))
    destination = _write_checkpoint(destination, raw)
    try:
        vault = loom_vault.OwnerVault.open(destination, crypto=crypto)
        new_device_id = str(uuid.uuid4())
        vault.authorize_device(new_device_id, keys["signing_public"])
        vault.adopt_local_device(new_device_id, keys["signing_public"])
        vault.put_entity("device-key", new_device_id, {
            "exchange_public": keys["exchange_public"],
            "signing_public": keys["signing_public"],
        })
        key_slot_id = str(uuid.uuid4())
        vault.assign_key_slot(key_slot_id)
        if key_store is not None:
            activation_secret = (
                base64.b64decode(payload["master_key"], validate=True)
                + base64.b64decode(keys["signing_key"], validate=True)
                + base64.b64decode(keys["exchange_secret"], validate=True)
                + base64.b64decode(payload["index_key"], validate=True))
            key_store.set(key_slot_id, activation_secret)
    except BaseException:
        _remove_checkpoint(destination)
        raise
    return {"status": ("restored" if key_store is not None else "validated-not-activated"),
            "crypto": crypto,
            "owner_vault_id": vault.identity()["owner_vault_id"],
            "key_slot_id": key_slot_id,
            "device_id": vault.identity()["device_id"],
            "key_stored": key_store is not None}


def _backup_stamp(value=None):
    instant = value or dt.datetime.now(dt.timezone.utc)
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise TransferError("backup time must be timezone-aware")
    return instant.astimezone(dt.timezone.utc).replace(microsecond=0)


def _read_backup_index(directory):
    path = directory / BACKUP_INDEX
    if not path.exists():
        return {"schema_version": 1, "entries": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferError(f"backup ownership index is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "entries"} \
            or value["schema_version"] != 1 or not isinstance(value["entries"], list):
        raise TransferError("backup ownership index contract is invalid")
    required = {"name", "sha256", "created_at", "sequence", "owner_vault_id",
                "deletion_epoch"}
    if any(not isinstance(item, dict) or set(item) != required for item in value["entries"]):
        raise TransferError("backup ownership entry is invalid")
    names = []
    for item in value["entries"]:
        try:
            owner = str(uuid.UUID(item["owner_vault_id"]))
            created = dt.datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
        except (ValueError, TypeError, AttributeError) as exc:
            raise TransferError("backup ownership entry identity is invalid") from exc
        if not BACKUP_NAME_RE.fullmatch(str(item["name"])) \
                or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])) \
                or type(item["sequence"]) is not int or item["sequence"] < 1 \
                or type(item["deletion_epoch"]) is not int or item["deletion_epoch"] < 0 \
                or owner != item["owner_vault_id"] or created.tzinfo is None:
            raise TransferError("backup ownership entry values are invalid")
        names.append(item["name"])
    if len(names) != len(set(names)):
        raise TransferError("backup ownership index contains duplicate paths")
    return value


def _retained_backup_names(entries):
    ordered = sorted(entries, key=lambda item: (item["created_at"], item["sequence"]),
                     reverse=True)
    keep = {item["name"] for item in ordered[:ROLLING_BACKUPS]}
    weekly = set()
    monthly = set()
    for item in ordered:
        instant = dt.datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
        week = instant.isocalendar()[:2]
        month = (instant.year, instant.month)
        if week not in weekly and len(weekly) < WEEKLY_BACKUPS:
            weekly.add(week)
            keep.add(item["name"])
        if month not in monthly and len(monthly) < MONTHLY_BACKUPS:
            monthly.add(month)
            keep.add(item["name"])
    return keep


def create_managed_recovery_backup(vault, crypto, phrase, directory, *, sequence,
                                   now=None):
    """Create, self-test, index, and safely prune an owner-selected backup directory."""
    directory = loom_reliability._absolute(directory, "recovery backup directory")
    directory.mkdir(parents=True, exist_ok=True)
    index = _read_backup_index(directory)
    owner = vault.identity()["owner_vault_id"]
    if any(item["owner_vault_id"] != owner for item in index["entries"]):
        raise TransferError("backup directory belongs to another owner vault")
    instant = _backup_stamp(now)
    name = f"loom-{instant.strftime('%Y%m%dT%H%M%SZ')}-{sequence:08d}.loom-backup"
    destination = directory / name
    receipt = create_recovery_backup(
        vault, crypto, phrase, destination, sequence=sequence,
        recovery_anchor=directory / RECOVERY_ANCHOR)
    entry = {
        "name": name, "sha256": receipt["sha256"],
        "created_at": instant.isoformat().replace("+00:00", "Z"),
        "sequence": sequence,
        "deletion_epoch": receipt["deletion_epoch"],
        "owner_vault_id": owner,
    }
    entries = [item for item in index["entries"] if item["name"] != name] + [entry]
    keep = _retained_backup_names(entries)
    retained = []
    removed = []
    for item in entries:
        path = directory / item["name"]
        if item["name"] in keep:
            retained.append(item)
            continue
        if not path.is_file() or path.is_symlink() \
                or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            destination.unlink(missing_ok=True)
            raise TransferError(
                f"backup cleanup refused changed or missing owned file: {item['name']}")
        path.unlink()
        removed.append(item["name"])
    next_index = {"schema_version": 1,
                  "entries": sorted(retained, key=lambda item: item["created_at"])}
    loom_reliability.atomic_write_json(directory / BACKUP_INDEX, next_index)
    total = sum((directory / item["name"]).stat().st_size for item in retained)
    return {**receipt, "path": str(destination), "retained": len(retained),
            "removed": removed, "retained_bytes": total}
