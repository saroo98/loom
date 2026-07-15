#!/usr/bin/env python3
"""Crash-safe local writes, reversible migrations, and proven-ownership removal."""

import base64
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_MIGRATION_FILES = 256


class ReliabilityError(RuntimeError):
    pass


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
        raise ReliabilityError(f"cannot inspect path: {path}: {exc}") from exc


def _is_trusted_os_alias(path):
    """Allow only Apple's documented root aliases while retaining redirect checks.

    macOS exposes ``/var`` and ``/tmp`` as symlinks into ``/private``.  They are
    OS-owned aliases, not user-controlled project redirects, and hosted runners
    routinely place temporary directories beneath them.  We still verify the
    exact target so a modified alias fails closed.
    """
    if sys.platform != "darwin":
        return False
    expected = {
        Path("/var"): Path("/private/var"),
        Path("/tmp"): Path("/private/tmp"),
    }.get(Path(path))
    if expected is None:
        return False
    try:
        return Path(path).resolve(strict=False) == expected
    except OSError as exc:
        raise ReliabilityError(f"cannot resolve operating-system alias: {path}: {exc}") from exc


def _absolute(path, label, *, must_exist=False):
    try:
        value = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise ReliabilityError(f"{label} is invalid: {exc}") from exc
    if must_exist and not value.exists():
        raise ReliabilityError(f"{label} does not exist: {value}")
    for component in [*reversed(value.parents), value]:
        if _is_redirect(component) and not _is_trusted_os_alias(component):
            raise ReliabilityError(f"{label} traverses a symlink or reparse point: {component}")
    return value


def _safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReliabilityError("owned/migration paths must be non-empty POSIX-relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReliabilityError("owned/migration path escapes its root")
    return path.as_posix()


def _target(root, relative):
    root = _absolute(root, "state root", must_exist=True)
    relative = _safe_relative(relative)
    target = _absolute(root.joinpath(*PurePosixPath(relative).parts), "state target")
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ReliabilityError("state target escapes its root") from exc
    return target


def _sync_parent(path):
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path, content):
    """Durably replace one regular file; the old file survives every pre-replace failure."""
    if not isinstance(content, bytes) or len(content) > MAX_FILE_BYTES:
        raise ReliabilityError("atomic content must be bounded bytes")
    path = _absolute(path, "atomic target")
    path.parent.mkdir(parents=True, exist_ok=True)
    _absolute(path.parent, "atomic target parent", must_exist=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("atomic write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        _sync_parent(path)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path, text):
    if not isinstance(text, str):
        raise ReliabilityError("atomic text must be a string")
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path, value):
    atomic_write_text(path, json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _content_hash(content):
    return None if content is None else hashlib.sha256(content).hexdigest()


def _canonical_hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def plan_migration(root, changes):
    """Return a deterministic dry-run plan. This function never writes."""
    root = _absolute(root, "migration root", must_exist=True)
    if not isinstance(changes, dict) or not 1 <= len(changes) <= MAX_MIGRATION_FILES:
        raise ReliabilityError("migration changes must be a bounded non-empty mapping")
    entries = []
    for relative in sorted(changes):
        relative = _safe_relative(relative)
        after = changes[relative]
        if not isinstance(after, bytes) or len(after) > MAX_FILE_BYTES:
            raise ReliabilityError("migration content must be bounded bytes")
        target = _target(root, relative)
        if target.exists() and not target.is_file():
            raise ReliabilityError(f"migration target is not a regular file: {relative}")
        before = target.read_bytes() if target.exists() else None
        entries.append({
            "path": relative,
            "before_sha256": _content_hash(before),
            "after_sha256": _content_hash(after),
            "before_base64": (base64.b64encode(before).decode("ascii")
                              if before is not None else None),
            "after_base64": base64.b64encode(after).decode("ascii"),
        })
    body = {"schema_version": 1, "kind": "loom-migration-plan", "changes": entries}
    return {**body, "plan_id": _canonical_hash(body)}


def _validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {
            "schema_version", "kind", "changes", "plan_id"} \
            or plan.get("schema_version") != 1 \
            or plan.get("kind") != "loom-migration-plan" \
            or not isinstance(plan.get("changes"), list) \
            or not 1 <= len(plan["changes"]) <= MAX_MIGRATION_FILES:
        raise ReliabilityError("migration plan contract is invalid")
    body = {key: value for key, value in plan.items() if key != "plan_id"}
    if plan["plan_id"] != _canonical_hash(body):
        raise ReliabilityError("migration plan hash is invalid")
    seen = set()
    for entry in plan["changes"]:
        if not isinstance(entry, dict) or set(entry) != {
                "path", "before_sha256", "after_sha256", "before_base64", "after_base64"}:
            raise ReliabilityError("migration change contract is invalid")
        relative = _safe_relative(entry["path"])
        if relative in seen or not DIGEST.fullmatch(str(entry["after_sha256"])):
            raise ReliabilityError("migration change identity is invalid")
        seen.add(relative)
        try:
            before = (base64.b64decode(entry["before_base64"], validate=True)
                      if entry["before_base64"] is not None else None)
            after = base64.b64decode(entry["after_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ReliabilityError("migration content encoding is invalid") from exc
        if _content_hash(before) != entry["before_sha256"] \
                or _content_hash(after) != entry["after_sha256"]:
            raise ReliabilityError("migration content hash is invalid")
    return plan


def _recovery_path(root, recovery_root, plan_id):
    root = _absolute(root, "migration root", must_exist=True)
    recovery = _absolute(recovery_root, "recovery root", must_exist=True)
    if recovery == root or recovery.is_relative_to(root):
        raise ReliabilityError("recovery storage must be outside the project tree")
    return recovery / f"{plan_id}.json"


def _read_journal(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReliabilityError(f"migration recovery journal is corrupt: {exc}") from exc


def apply_migration(root, plan, recovery_root):
    plan = _validate_plan(plan)
    journal_path = _recovery_path(root, recovery_root, plan["plan_id"])
    if journal_path.exists():
        journal = _read_journal(journal_path)
        if journal.get("plan") != plan or journal.get("status") == "rolled-back":
            raise ReliabilityError("migration journal conflicts with the requested plan")
        if journal.get("status") == "applied":
            return {"status": "applied", "plan_id": plan["plan_id"],
                    "idempotent": True, "files": len(plan["changes"])}
    else:
        journal = {"schema_version": 1, "status": "prepared", "plan": plan,
                   "applied_paths": []}
        atomic_write_json(journal_path, journal)
    for entry in plan["changes"]:
        target = _target(root, entry["path"])
        current = file_sha256(target) if target.exists() else None
        if current == entry["after_sha256"]:
            pass
        elif current == entry["before_sha256"]:
            atomic_write_bytes(target, base64.b64decode(entry["after_base64"], validate=True))
        else:
            raise ReliabilityError(
                f"migration target changed outside the journal: {entry['path']}")
        if entry["path"] not in journal["applied_paths"]:
            journal["applied_paths"].append(entry["path"])
            atomic_write_json(journal_path, journal)
    journal["status"] = "applied"
    atomic_write_json(journal_path, journal)
    return {"status": "applied", "plan_id": plan["plan_id"],
            "idempotent": False, "files": len(plan["changes"])}


def rollback_migration(root, plan_id, recovery_root):
    if not isinstance(plan_id, str) or not DIGEST.fullmatch(plan_id):
        raise ReliabilityError("migration plan id is invalid")
    journal_path = _recovery_path(root, recovery_root, plan_id)
    if not journal_path.is_file():
        raise ReliabilityError("migration recovery journal is missing")
    journal = _read_journal(journal_path)
    plan = _validate_plan(journal.get("plan"))
    if plan["plan_id"] != plan_id:
        raise ReliabilityError("migration journal identity is invalid")
    if journal.get("status") == "rolled-back":
        return {"status": "rolled-back", "plan_id": plan_id, "idempotent": True}
    for entry in reversed(plan["changes"]):
        target = _target(root, entry["path"])
        current = file_sha256(target) if target.exists() else None
        if current == entry["before_sha256"]:
            continue
        if current != entry["after_sha256"]:
            raise ReliabilityError(
                f"rollback target changed outside the journal: {entry['path']}")
        if entry["before_base64"] is None:
            target.unlink()
            _sync_parent(target)
        else:
            atomic_write_bytes(
                target, base64.b64decode(entry["before_base64"], validate=True))
    journal["status"] = "rolled-back"
    atomic_write_json(journal_path, journal)
    return {"status": "rolled-back", "plan_id": plan_id, "idempotent": False}


def quarantine_corrupt(path, quarantine_root, *, reason):
    """Copy corrupt bytes outside the project; do not delete or silently replace the source."""
    source = _absolute(path, "corrupt source", must_exist=True)
    if not source.is_file() or not isinstance(reason, str) or not SAFE_ID.fullmatch(reason):
        raise ReliabilityError("corruption quarantine inputs are invalid")
    quarantine = _absolute(quarantine_root, "quarantine root")
    quarantine.mkdir(parents=True, exist_ok=True)
    quarantine = _absolute(quarantine, "quarantine root", must_exist=True)
    if quarantine == source.parent or quarantine.is_relative_to(source.parent):
        raise ReliabilityError("corruption quarantine must be outside the source tree")
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    destination = quarantine / f"{source.name}.{digest}.corrupt"
    atomic_write_bytes(destination, raw)
    receipt = {"schema_version": 1, "source_name": source.name, "reason": reason,
               "sha256": digest, "quarantine_path": str(destination),
               "source_preserved": True}
    atomic_write_json(quarantine / f"{source.name}.{digest}.receipt.json", receipt)
    return receipt


def _regular_files(root):
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in sorted(os.scandir(directory), key=lambda item: item.name.casefold()):
            path = Path(entry.path)
            if entry.name == ".git" and entry.is_dir(follow_symlinks=False):
                continue
            if entry.is_symlink() or _is_redirect(path):
                raise ReliabilityError(f"tree contains a redirected entry: {path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False):
                yield path
            else:
                raise ReliabilityError(f"tree contains a non-regular entry: {path}")


def deterministic_manifest(root):
    root = _absolute(root, "manifest root", must_exist=True)
    files = []
    for path in _regular_files(root):
        raw = path.read_bytes()
        files.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    files.sort(key=lambda item: item["path"])
    body = {"schema_version": 1, "files": files}
    return {**body, "root_sha256": _canonical_hash(body)}


def installation_receipt(root, owned_paths, *, install_id):
    root = _absolute(root, "installation root", must_exist=True)
    if not isinstance(install_id, str) or not SAFE_ID.fullmatch(install_id) \
            or not isinstance(owned_paths, (list, tuple)) or not owned_paths:
        raise ReliabilityError("installation receipt inputs are invalid")
    files = []
    for relative in sorted(set(owned_paths)):
        target = _target(root, relative)
        if not target.is_file():
            raise ReliabilityError(f"owned installation file is missing: {relative}")
        files.append({"path": _safe_relative(relative), "sha256": file_sha256(target)})
    body = {"schema_version": 1, "install_id": install_id, "files": files}
    return {**body, "receipt_hash": _canonical_hash(body)}


def uninstall_owned_files(root, receipt, *, confirmation):
    if not isinstance(receipt, dict) or set(receipt) != {
            "schema_version", "install_id", "files", "receipt_hash"}:
        raise ReliabilityError("installation receipt is invalid")
    body = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    if receipt["receipt_hash"] != _canonical_hash(body) \
            or confirmation != receipt.get("install_id"):
        raise ReliabilityError("uninstall confirmation or ownership receipt is invalid")
    targets = []
    for item in receipt.get("files", []):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"} \
                or not DIGEST.fullmatch(str(item.get("sha256", ""))):
            raise ReliabilityError("owned file receipt is invalid")
        target = _target(root, item["path"])
        if not target.is_file() or file_sha256(target) != item["sha256"]:
            raise ReliabilityError(f"owned file changed or is missing: {item['path']}")
        targets.append(target)
    for target in targets:
        target.unlink()
        _sync_parent(target)
    return {"install_id": receipt["install_id"], "removed_files": len(targets),
            "scope": "receipt-proven-files-only"}
