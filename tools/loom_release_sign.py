#!/usr/bin/env python3
"""Offline 2-of-3 release authority for Loom TUF-style metadata."""

import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

import loom_crypto
import loom_reliability
import loom_privacy


KEY_AAD = b"loom-offline-root-key-v1"
LEGACY_KDF = {
    "algorithm": "argon2id", "version": 19, "memory_kib": 19 * 1024,
    "iterations": 2, "parallelism": 1, "output_bytes": 32,
}


class SigningError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _stamp(value):
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise SigningError("release time must be timezone-aware")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def create_root_authority(helper, directory, passphrases, *, expires):
    """Create encrypted private keys outside source control and a public root policy."""
    directory = loom_reliability._absolute(directory, "offline key directory")
    if directory.exists() or not isinstance(passphrases, (list, tuple)) \
            or len(passphrases) != 3 or len(set(passphrases)) != 3:
        raise SigningError("root ceremony requires a new directory and three distinct passphrases")
    directory.mkdir(parents=True)
    keys = {}
    created = []
    try:
        for _index, passphrase in enumerate(passphrases, 1):
            generated = loom_crypto.generate_keys(helper)
            public = generated["signing_public"]
            key_id = hashlib.sha256(base64.b64decode(public, validate=True)).hexdigest()[:24]
            secret = base64.b64decode(generated["signing_key"], validate=True)
            wrapped = loom_crypto.passphrase_wrap(
                helper, passphrase=passphrase, plaintext=secret,
                aad=KEY_AAD + b":" + key_id.encode("ascii"))
            value = {"schema_version": 2, "key_id": key_id, "public_key": public,
                     **wrapped}
            path = directory / f"{key_id}.loom-root-key"
            loom_reliability.atomic_write_json(path, value)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            created.append(path)
            keys[key_id] = public
        root = {"version": 1, "threshold": 2, "keys": keys, "expires": _stamp(expires)}
        loom_reliability.atomic_write_json(directory / "root.json", root)
        return {"root": root, "private_key_paths": [str(path) for path in created]}
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        (directory / "root.json").unlink(missing_ok=True)
        try:
            directory.rmdir()
        except OSError:
            pass
        raise


def _unlock(helper, path, passphrase):
    path = loom_reliability._absolute(path, "offline signing key", must_exist=True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SigningError(f"offline signing key is invalid: {exc}") from exc
    v1 = {"schema_version", "key_id", "public_key", "salt", "ciphertext"}
    v2 = v1 | {"kdf"}
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2} \
            or set(value) != (v1 if value.get("schema_version") == 1 else v2):
        raise SigningError("offline signing key contract is invalid")
    kdf = LEGACY_KDF if value["schema_version"] == 1 else value["kdf"]
    try:
        secret = loom_crypto.passphrase_open(
            helper, passphrase=passphrase, salt=value["salt"],
            ciphertext=value["ciphertext"], kdf=kdf,
            aad=KEY_AAD + b":" + value["key_id"].encode("ascii"))
        crypto = loom_crypto.HelperCrypto(
            helper, master_key=b"\0" * 32, signing_key=secret)
    except loom_crypto.CryptoError as exc:
        raise SigningError(f"offline signing key could not be unlocked: {exc}") from exc
    if crypto.public_key() != value["public_key"]:
        raise SigningError("offline signing key public identity does not match")
    return value["key_id"], secret, value["public_key"]


def sign_release(helper, root, manifest, authorities, *, expires, output=None):
    if not isinstance(root, dict) or set(root) != {"version", "threshold", "keys", "expires"} \
            or root["threshold"] != 2 or len(root["keys"]) != 3:
        raise SigningError("trusted root policy is invalid")
    if not isinstance(manifest, dict) or manifest.get("package") != "loom" \
            or type(manifest.get("release_sequence")) is not int:
        raise SigningError("release manifest is invalid")
    if not isinstance(authorities, (list, tuple)) or len(authorities) < 2:
        raise SigningError("at least two offline authorities must sign")
    unlocked = []
    for path, passphrase in authorities:
        key_id, secret, public = _unlock(helper, path, passphrase)
        if root["keys"].get(key_id) != public or key_id in {item[0] for item in unlocked}:
            raise SigningError("signing authority is duplicated or not trusted")
        unlocked.append((key_id, secret))
    sequence = manifest["release_sequence"]
    targets = {"version": sequence, "manifest": manifest}
    snapshot = {"version": sequence,
                "targets_sha256": hashlib.sha256(_canonical(targets)).hexdigest()}
    timestamp = {"version": sequence,
                 "snapshot_sha256": hashlib.sha256(_canonical(snapshot)).hexdigest(),
                 "expires": _stamp(expires)}

    def envelope(value):
        return {"signed": value, "signatures": [
            {"key_id": key_id,
             "signature": loom_crypto.sign_message(helper, _canonical(value), secret)}
            for key_id, secret in unlocked]}

    bundle = {"root": envelope(root), "targets": envelope(targets),
              "snapshot": envelope(snapshot), "timestamp": envelope(timestamp)}
    if output is not None:
        output = loom_reliability._absolute(output, "release metadata output")
        if output.exists():
            raise SigningError("release metadata output already exists")
        loom_reliability.atomic_write_json(output, bundle)
    return bundle


def sign_root_transition(helper, old_root, new_root, old_authorities, new_authorities,
                         *, output=None):
    """Create one sequential root envelope authorized by both trust generations."""
    required = {"version", "threshold", "keys", "expires"}
    for label, root in (("old", old_root), ("new", new_root)):
        if not isinstance(root, dict) or set(root) != required \
                or root.get("threshold") != 2 or len(root.get("keys", {})) != 3:
            raise SigningError(f"{label} root policy is invalid")
    if new_root["version"] != old_root["version"] + 1:
        raise SigningError("root transition must advance exactly one version")

    unlocked = []
    for label, root, authorities in (
            ("old", old_root, old_authorities), ("new", new_root, new_authorities)):
        if not isinstance(authorities, (list, tuple)) or len(authorities) < root["threshold"]:
            raise SigningError(f"{label} root transition lacks authorities")
        accepted = set()
        for path, passphrase in authorities:
            key_id, secret, public = _unlock(helper, path, passphrase)
            if root["keys"].get(key_id) != public or key_id in accepted:
                raise SigningError(f"{label} root authority is duplicated or not trusted")
            accepted.add(key_id)
            unlocked.append((key_id, secret))
        if len(accepted) < root["threshold"]:
            raise SigningError(f"{label} root transition lacks threshold authority")

    message = _canonical(new_root)
    envelope_value = {"signed": new_root, "signatures": [
        {"key_id": key_id,
         "signature": loom_crypto.sign_message(helper, message, secret)}
        for key_id, secret in unlocked]}
    if output is not None:
        output = loom_reliability._absolute(output, "root transition output")
        if output.exists():
            raise SigningError("root transition output already exists")
        loom_reliability.atomic_write_json(output, envelope_value)
    return envelope_value


def finalize_package(helper, package, root, authorities, *, expires,
                     forbidden_tokens=()):
    """Threshold-sign one already-built package and firewall the exact final bytes."""
    package = loom_reliability._absolute(package, "plugin package", must_exist=True)
    release = package / "release"
    if not package.is_dir() or (release / "metadata.json").exists() \
            or (release / "trusted-root.json").exists():
        raise SigningError("plugin package is unavailable or already finalized")
    try:
        manifest = json.loads((release / "unsigned-manifest.json").read_text(encoding="utf-8"))
        build = json.loads((package / "PLUGIN-BUILD-MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SigningError(f"plugin package manifest is invalid: {exc}") from exc
    bundle = sign_release(helper, root, manifest, authorities, expires=expires)
    loom_reliability.atomic_write_json(release / "metadata.json", bundle)
    loom_reliability.atomic_write_json(release / "trusted-root.json", root)
    (release / "unsigned-manifest.json").unlink()
    opaque = {item["sha256"] for item in manifest["targets"]}
    for receipt in build.get("helper_provenance", {}).values():
        opaque.add(receipt["binary_sha256"])
    files = [{"path": path.relative_to(package).as_posix(),
              "bytes": path.stat().st_size,
              "sha256": loom_reliability.file_sha256(path)}
             for path in loom_reliability._regular_files(package)]
    receipt = {"schema_version": 1, "version": manifest["version"],
               "release_sequence": manifest["release_sequence"], "files": files}
    loom_reliability.atomic_write_json(package / "FINAL-PACKAGE-RECEIPT.json", receipt)
    firewall = loom_privacy.scan_publication(
        package, forbidden_tokens=tuple(forbidden_tokens),
        verified_opaque_hashes=opaque)
    if not firewall["clean"]:
        (release / "metadata.json").unlink(missing_ok=True)
        (release / "trusted-root.json").unlink(missing_ok=True)
        (package / "FINAL-PACKAGE-RECEIPT.json").unlink(missing_ok=True)
        raise SigningError(f"final signed package firewall failed: {firewall['findings'][:3]}")
    return {"status": "finalized", "firewall": firewall, "receipt": receipt}
