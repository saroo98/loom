#!/usr/bin/env python3
"""Strict stdin-only client for the signed Rust loom-vault helper."""

import base64
import json
import os
import stat
import subprocess
from pathlib import Path


MAX_HELPER_BYTES = 128 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class CryptoError(RuntimeError):
    pass


def _helper_path(path):
    value = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    for component in [*reversed(value.parents), value]:
        try:
            redirected = component.is_symlink()
            junction = getattr(component, "is_junction", None)
            redirected = redirected or bool(junction and junction())
            attributes = getattr(component.lstat(), "st_file_attributes", 0)
            redirected = redirected or bool(
                attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
        except FileNotFoundError:
            redirected = False
        if redirected:
            raise CryptoError(f"crypto helper path is redirected: {component}")
    if not value.is_file() or value.stat().st_size > MAX_HELPER_BYTES:
        raise CryptoError("crypto helper is missing, non-regular, or oversized")
    return value


def _b64(value):
    if not isinstance(value, (bytes, bytearray)):
        raise CryptoError("crypto input must be bytes")
    return base64.b64encode(bytes(value)).decode("ascii")


def _invoke(helper, payload, *, runner=subprocess.run):
    path = _helper_path(helper)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise CryptoError("crypto request exceeds bound")
    try:
        result = runner(
            [str(path)], input=encoded, capture_output=True, text=True,
            timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CryptoError(f"crypto helper could not run: {exc}") from exc
    if len(result.stdout.encode("utf-8", errors="replace")) > MAX_RESPONSE_BYTES:
        raise CryptoError("crypto helper response exceeds bound")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CryptoError("crypto helper returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("ok") is not True:
        message = value.get("error", "operation refused") if isinstance(value, dict) \
            else "operation refused"
        raise CryptoError(f"crypto helper refused operation: {message}")
    return {key: item for key, item in value.items() if key != "ok"}


def generate_keys(helper, *, runner=subprocess.run):
    result = _invoke(helper, {"op": "generate-keys"}, runner=runner)
    expected = {"master_key", "signing_key", "signing_public",
                "exchange_secret", "exchange_public"}
    if set(result) != expected:
        raise CryptoError("crypto helper key response is invalid")
    for key in expected:
        try:
            raw = base64.b64decode(result[key], validate=True)
        except (ValueError, TypeError) as exc:
            raise CryptoError("crypto helper key response is invalid") from exc
        if len(raw) != 32:
            raise CryptoError("crypto helper key response has wrong size")
    return result


def generate_recovery(helper, *, runner=subprocess.run):
    result = _invoke(helper, {"op": "generate-recovery"}, runner=runner)
    if set(result) != {"phrase", "secret"} or not isinstance(result["phrase"], str) \
            or len(result["phrase"].split()) != 24:
        raise CryptoError("recovery response is invalid")
    if len(base64.b64decode(result["secret"], validate=True)) != 32:
        raise CryptoError("recovery secret has wrong size")
    return result


def key_store_set(helper, owner_vault_id, secret, *, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "key-store-set", "owner_vault_id": owner_vault_id,
        "secret": _b64(secret)}, runner=runner)
    if result != {"stored": True}:
        raise CryptoError("secure key store response is invalid")


def key_store_get(helper, owner_vault_id, *, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "key-store-get", "owner_vault_id": owner_vault_id}, runner=runner)
    if set(result) != {"secret"}:
        raise CryptoError("secure key store response is invalid")
    try:
        secret = base64.b64decode(result["secret"], validate=True)
    except (ValueError, TypeError) as exc:
        raise CryptoError("secure key store returned invalid key material") from exc
    if not 64 <= len(secret) <= 4096:
        raise CryptoError("secure key store returned invalid key material")
    return secret


def key_store_delete(helper, owner_vault_id, *, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "key-store-delete", "owner_vault_id": owner_vault_id}, runner=runner)
    if result != {"deleted": True}:
        raise CryptoError("secure key store response is invalid")


def pair_open(helper, *, receiver_secret, sender_exchange_public,
              sender_signing_public, ciphertext, signature, aad,
              runner=subprocess.run):
    result = _invoke(helper, {
        "op": "pair-open", "receiver_secret": _b64(receiver_secret),
        "sender_exchange_public": sender_exchange_public,
        "sender_signing_public": sender_signing_public,
        "ciphertext": ciphertext, "signature": signature, "aad": _b64(aad)}, runner=runner)
    if set(result) != {"plaintext"}:
        raise CryptoError("pair-open response is invalid")
    return base64.b64decode(result["plaintext"], validate=True)


def recovery_open(helper, *, phrase, ciphertext, aad, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "recovery-open", "phrase": phrase, "ciphertext": ciphertext,
        "aad": _b64(aad)}, runner=runner)
    if set(result) != {"plaintext"}:
        raise CryptoError("recovery-open response is invalid")
    return base64.b64decode(result["plaintext"], validate=True)


def passphrase_wrap(helper, *, passphrase, plaintext, aad, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "passphrase-wrap", "passphrase": passphrase,
        "plaintext": _b64(plaintext), "aad": _b64(aad)}, runner=runner)
    if set(result) != {"salt", "ciphertext"}:
        raise CryptoError("passphrase-wrap response is invalid")
    return result


def passphrase_open(helper, *, passphrase, salt, ciphertext, aad,
                    runner=subprocess.run):
    result = _invoke(helper, {
        "op": "passphrase-open", "passphrase": passphrase, "salt": salt,
        "ciphertext": ciphertext, "aad": _b64(aad)}, runner=runner)
    if set(result) != {"plaintext"}:
        raise CryptoError("passphrase-open response is invalid")
    return base64.b64decode(result["plaintext"], validate=True)


def verify_signature(helper, message, signature, public_key, *, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "verify", "public_key": public_key,
        "message": _b64(message), "signature": signature}, runner=runner)
    if set(result) != {"valid"} or type(result["valid"]) is not bool:
        raise CryptoError("signature verification response is invalid")
    return result["valid"]


def sign_message(helper, message, signing_key, *, runner=subprocess.run):
    result = _invoke(helper, {
        "op": "sign", "signing_key": _b64(signing_key),
        "message": _b64(message)}, runner=runner)
    if set(result) != {"signature"}:
        raise CryptoError("signature response is invalid")
    return result["signature"]


class HelperCrypto:
    production_safe = True

    def __init__(self, helper, *, master_key, signing_key, index_key=None,
                 runner=subprocess.run):
        self.helper = _helper_path(helper)
        index_key = master_key if index_key is None else index_key
        if len(master_key) != 32 or len(signing_key) != 32 or len(index_key) != 32:
            raise CryptoError("vault and signing keys must contain 32 bytes")
        self._master_key = bytes(master_key)
        self._signing_key = bytes(signing_key)
        self._index_key = bytes(index_key)
        self._runner = runner
        self._public_key = None

    def _call(self, payload):
        return _invoke(self.helper, payload, runner=self._runner)

    def seal(self, plaintext, aad):
        result = self._call({
            "op": "seal", "key": _b64(self._master_key),
            "plaintext": _b64(plaintext), "aad": _b64(aad)})
        if set(result) != {"ciphertext"}:
            raise CryptoError("seal response is invalid")
        base64.b64decode(result["ciphertext"], validate=True)
        return result["ciphertext"].encode("ascii")

    def open(self, ciphertext, aad):
        if isinstance(ciphertext, bytes):
            ciphertext = ciphertext.decode("ascii")
        result = self._call({
            "op": "open", "key": _b64(self._master_key),
            "ciphertext": ciphertext, "aad": _b64(aad)})
        if set(result) != {"plaintext"}:
            raise CryptoError("open response is invalid")
        return base64.b64decode(result["plaintext"], validate=True)

    def sign(self, message):
        result = self._call({
            "op": "sign", "signing_key": _b64(self._signing_key),
            "message": _b64(message)})
        if set(result) != {"signature"}:
            raise CryptoError("sign response is invalid")
        return result["signature"].encode("ascii")

    def verify(self, message, signature, public_key=None):
        if isinstance(signature, bytes):
            signature = signature.decode("ascii")
        result = self._call({
            "op": "verify", "public_key": public_key or self.public_key(),
            "message": _b64(message), "signature": signature})
        if set(result) != {"valid"} or type(result["valid"]) is not bool:
            raise CryptoError("verify response is invalid")
        return result["valid"]

    def blind_index(self, label, value):
        if not isinstance(label, str) or not isinstance(value, str):
            raise CryptoError("blind-index label and value must be strings")
        result = self._call({
            "op": "blind-index", "key": _b64(self._index_key),
            "label": label, "value": value})
        tag = result.get("tag")
        if set(result) != {"tag"} or not isinstance(tag, str) or len(tag) != 64:
            raise CryptoError("blind-index response is invalid")
        return tag

    def public_key(self):
        if self._public_key is None:
            result = self._call({
                "op": "public-key", "signing_key": _b64(self._signing_key)})
            if set(result) != {"public_key"}:
                raise CryptoError("public-key response is invalid")
            if len(base64.b64decode(result["public_key"], validate=True)) != 32:
                raise CryptoError("public-key response has wrong size")
            self._public_key = result["public_key"]
        return self._public_key

    def pair_seal(self, receiver_public, payload, aad):
        if not isinstance(payload, dict):
            raise CryptoError("pairing payload must be a mapping")
        body = {**payload, "master_key": _b64(self._master_key),
                "index_key": _b64(self._index_key)}
        return self.pair_seal_bytes(receiver_public, json.dumps(
            body, sort_keys=True, separators=(",", ":")).encode("utf-8"), aad)

    def pair_seal_bytes(self, receiver_public, plaintext, aad):
        result = self._call({
            "op": "pair-seal", "receiver_public": receiver_public,
            "signing_key": _b64(self._signing_key),
            "plaintext": _b64(plaintext),
            "aad": _b64(aad)})
        expected = {"ciphertext", "sender_exchange_public",
                    "sender_signing_public", "signature"}
        if set(result) != expected:
            raise CryptoError("pair-seal response is invalid")
        return result

    def recovery_wrap(self, phrase, payload, aad):
        if not isinstance(payload, dict):
            raise CryptoError("recovery payload must be a mapping")
        body = {**payload, "master_key": _b64(self._master_key),
                "index_key": _b64(self._index_key)}
        return self.recovery_wrap_bytes(phrase, json.dumps(
            body, sort_keys=True, separators=(",", ":")).encode("utf-8"), aad)

    def recovery_wrap_bytes(self, phrase, plaintext, aad):
        result = self._call({
            "op": "recovery-wrap", "phrase": phrase,
            "plaintext": _b64(plaintext),
            "aad": _b64(aad)})
        if set(result) != {"ciphertext"}:
            raise CryptoError("recovery-wrap response is invalid")
        return result["ciphertext"]
