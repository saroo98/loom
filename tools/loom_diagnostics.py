#!/usr/bin/env python3
"""Private, body-free Loom health and explicitly encrypted support receipts."""

import argparse
import getpass
import hashlib
import json
import re
import sqlite3
import uuid
from pathlib import Path

import loom_crypto
import loom_reliability


MAX_BUNDLE_PLAINTEXT = 256 * 1024


class DiagnosticError(RuntimeError):
    pass


def _safe_json(path):
    if not path.exists():
        return None
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise DiagnosticError("diagnostic state file is unsafe")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DiagnosticError(f"diagnostic state file is invalid: {exc}") from exc


def _vault_health(home):
    database = home / "vault" / "owner.sqlite3"
    if not database.exists():
        return {"present": False, "integrity": "not-initialized", "schema": 0,
                "generation": 0, "events": 0, "quarantine": 0}
    if not database.is_file() or database.is_symlink():
        raise DiagnosticError("owner vault is redirected or not a regular file")
    try:
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=2)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            metadata = dict(connection.execute(
                "SELECT key,value FROM metadata WHERE key IN ('schema_version','generation')"))
            events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            quarantine = connection.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]
        finally:
            connection.close()
    except (sqlite3.Error, OSError, KeyError, TypeError, ValueError) as exc:
        raise DiagnosticError(f"owner vault cannot be verified: {exc}") from exc
    return {"present": True, "integrity": "ok" if integrity == ("ok",) else "failed",
            "schema": int(metadata["schema_version"]),
            "generation": int(metadata["generation"]),
            "events": int(events), "quarantine": int(quarantine)}


def _adapter_health(home):
    root = home / "adapters" / "receipts"
    if not root.exists():
        return {"connected": 0, "owned": 0, "changed": 0, "hosts": []}
    if not root.is_dir() or root.is_symlink():
        raise DiagnosticError("adapter receipt directory is unsafe")
    connected = owned = changed = 0
    hosts = []
    for receipt_path in sorted(root.glob("*.json")):
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise DiagnosticError("adapter receipt entry is unsafe")
        receipt = _safe_json(receipt_path)
        host = receipt_path.stem
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", host) \
                or not isinstance(receipt, dict) or receipt.get("agent") != host:
            raise DiagnosticError("adapter receipt identity is invalid")
        connected += 1
        hosts.append(host)
        target = Path(str(receipt.get("path", "")))
        try:
            unchanged = target.is_file() and not target.is_symlink() \
                and hashlib.sha256(target.read_bytes()).hexdigest() == receipt.get("sha256")
        except OSError:
            unchanged = False
        if unchanged:
            owned += 1
        else:
            changed += 1
    return {"connected": connected, "owned": owned, "changed": changed,
            "hosts": hosts}


def doctor(home):
    home = loom_reliability._absolute(home, "Loom home")
    pointer = _safe_json(home / "runtime" / "current.json")
    pending = _safe_json(home / "runtime" / "pending.json")
    update = _safe_json(home / "runtime" / "update-state.json")
    generation = _safe_json(home / "adapters" / "generation.json")
    sessions_root = home / "runtime" / "sessions"
    sessions = (sum(path.is_file() and not path.is_symlink()
                    for path in sessions_root.glob("*.json"))
                if sessions_root.is_dir() and not sessions_root.is_symlink() else 0)
    vault = _vault_health(home)
    adapters = _adapter_health(home)
    problems = []
    if pointer is None:
        problems.append("RUNTIME_POINTER_MISSING")
    if vault["integrity"] == "failed":
        problems.append("VAULT_INTEGRITY_FAILED")
    if adapters["changed"]:
        problems.append("ADAPTER_OWNERSHIP_CONFLICT")
    if update and pointer and update.get("version") != pointer.get("version") \
            and update.get("state") not in {"pending", "quarantined"}:
        problems.append("UPDATE_STATE_SPLIT_BRAIN")
    return {
        "schema_version": 1,
        "status": "healthy" if not problems else "blocked",
        "runtime": {
            "version": pointer.get("version") if isinstance(pointer, dict) else None,
            "release_sequence": pointer.get("release_sequence") if isinstance(pointer, dict) else None,
            "previous_available": bool(isinstance(pointer, dict) and pointer.get("previous")),
            "pending_version": pending.get("version") if isinstance(pending, dict) else None,
            "update_state": update.get("state") if isinstance(update, dict) else None,
            "active_sessions": sessions,
        },
        "state": vault,
        "adapters": adapters,
        "adapter_generation": (generation.get("generation")
                               if isinstance(generation, dict) else 0),
        "problems": problems,
        "privacy": {"memory_bodies": False, "prompts": False,
                    "absolute_paths": False, "stable_owner_ids": False,
                    "telemetry": False},
    }


def export_encrypted(home, helper, output, *, passphrase):
    output = loom_reliability._absolute(output, "support bundle output")
    if output.exists() or not isinstance(passphrase, str) or len(passphrase) < 12:
        raise DiagnosticError("support bundle output or passphrase is invalid")
    report = doctor(home)
    plaintext = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(plaintext) > MAX_BUNDLE_PLAINTEXT:
        raise DiagnosticError("support bundle exceeds its plaintext bound")
    aad = b"loom-private-support-bundle-v1"
    try:
        wrapped = loom_crypto.passphrase_wrap(
            helper, passphrase=passphrase, plaintext=plaintext, aad=aad)
    except loom_crypto.CryptoError as exc:
        raise DiagnosticError(f"support bundle encryption failed: {exc}") from exc
    value = {"schema_version": 1, "bundle_id": str(uuid.uuid4()),
             "encryption": "xchacha20-poly1305", "aad": aad.decode("ascii"),
             "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
             "plaintext_bytes": len(plaintext), "upload": False, **wrapped}
    loom_reliability.atomic_write_json(output, value)
    return {"status": "encrypted", "bytes": output.stat().st_size,
            "upload": False, "output_exists": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    health = sub.add_parser("doctor")
    health.add_argument("--home", required=True)
    bundle = sub.add_parser("support-bundle")
    bundle.add_argument("--home", required=True)
    bundle.add_argument("--helper", required=True)
    bundle.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor(args.home)
        else:
            first = getpass.getpass("Support bundle passphrase: ")
            second = getpass.getpass("Confirm passphrase: ")
            if first != second:
                raise DiagnosticError("support bundle passphrases do not match")
            result = export_encrypted(
                args.home, args.helper, args.output, passphrase=first)
    except (DiagnosticError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") in {"healthy", "encrypted"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
