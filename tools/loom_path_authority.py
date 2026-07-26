#!/usr/bin/env python3
"""Closed operation-class authority for sensitive filesystem effects."""

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path


OPERATION_CLASSES = {
    "archive", "staging", "release-package", "install-update",
    "transfer-recovery", "vault-state", "adapter-config",
}
EXPECTED_TYPES = {"file", "directory", "absent"}
REPLACEMENT_POLICIES = {"forbid", "owned-exact", "atomic-no-replace"}
CLEANUP_DISPOSITIONS = {
    "preserve", "remove-if-owned", "quarantine-if-uncertain",
}
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class PathAuthorityError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _absolute(value, label):
    path = Path(value)
    if not path.is_absolute():
        raise PathAuthorityError(f"{label} must be absolute")
    return Path(os.path.abspath(path))


def _is_redirected(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise PathAuthorityError(f"cannot inspect path component: {exc}") from exc
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _parent_chain(path, root):
    path = _absolute(path, "authorized path")
    root = _absolute(root, "authority root")
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise PathAuthorityError("authorized path escapes its authority root") from exc
    chain = []
    cursor = path.parent
    while True:
        if not cursor.exists() or not cursor.is_dir() or _is_redirected(cursor):
            raise PathAuthorityError("path parent chain is missing or redirected")
        chain.append({
            "path": str(cursor),
            "device": int(cursor.stat().st_dev),
            "identity": int(getattr(cursor.stat(), "st_ino", 0)),
        })
        if cursor == root:
            break
        if cursor.parent == cursor:
            raise PathAuthorityError("path parent chain did not reach its root")
        cursor = cursor.parent
    return path, root, chain


def _observed_type(path):
    if not path.exists():
        return "absent"
    if _is_redirected(path):
        raise PathAuthorityError("authorized path is redirected")
    if path.is_file():
        return "file"
    if path.is_dir():
        return "directory"
    raise PathAuthorityError("authorized path has an unsupported type")


def create_ownership_receipt(*, path, root, operation_id, expected_type):
    path, root, chain = _parent_chain(path, root)
    try:
        canonical_operation = str(uuid.UUID(str(operation_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise PathAuthorityError("ownership operation identity is invalid") from exc
    if canonical_operation != str(operation_id) or expected_type not in {"file", "directory"} \
            or _observed_type(path) != expected_type:
        raise PathAuthorityError("ownership receipt subject is invalid")
    body = {
        "schema_version": 1,
        "operation_id": canonical_operation,
        "path": str(path),
        "root": str(root),
        "expected_type": expected_type,
        "volume": int(path.stat().st_dev),
        "object_identity": int(getattr(path.stat(), "st_ino", 0)),
        "parent_chain_sha256": _hash(chain),
    }
    body["receipt_sha256"] = _hash(body)
    return body


def validate_ownership_receipt(value, *, path, root):
    fields = {
        "schema_version", "operation_id", "path", "root", "expected_type",
        "volume", "object_identity", "parent_chain_sha256", "receipt_sha256",
    }
    path, root, chain = _parent_chain(path, root)
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("receipt_sha256") != _hash({
                key: item for key, item in value.items() if key != "receipt_sha256"}) \
            or value.get("path") != str(path) or value.get("root") != str(root) \
            or value.get("expected_type") != _observed_type(path) \
            or value.get("volume") != int(path.stat().st_dev) \
            or value.get("object_identity") != int(getattr(path.stat(), "st_ino", 0)) \
            or value.get("parent_chain_sha256") != _hash(chain):
        raise PathAuthorityError("ownership receipt does not match the current path")
    return value


def authorize(*, operation_class, path, root, expected_type,
              replacement_policy, cleanup_disposition,
              ownership_receipt=None, peer_path=None, require_same_volume=None):
    if operation_class not in OPERATION_CLASSES \
            or expected_type not in EXPECTED_TYPES \
            or replacement_policy not in REPLACEMENT_POLICIES \
            or cleanup_disposition not in CLEANUP_DISPOSITIONS \
            or require_same_volume not in {None, True, False}:
        raise PathAuthorityError("path authority contract is invalid")
    path, root, chain = _parent_chain(path, root)
    observed = _observed_type(path)
    if observed != expected_type:
        raise PathAuthorityError(
            f"path type mismatch: expected {expected_type}, observed {observed}")
    if ownership_receipt is not None:
        validate_ownership_receipt(ownership_receipt, path=path, root=root)
    elif replacement_policy == "owned-exact" \
            or cleanup_disposition == "remove-if-owned":
        raise PathAuthorityError("owned filesystem effect lacks an ownership receipt")
    peer = None
    same_volume = None
    if peer_path is not None:
        peer, _peer_root, peer_chain = _parent_chain(peer_path, root)
        peer_type = _observed_type(peer)
        peer_device = int(
            peer.stat().st_dev if peer_type != "absent" else peer.parent.stat().st_dev)
        path_device = int(
            path.stat().st_dev if observed != "absent" else path.parent.stat().st_dev)
        same_volume = path_device == peer_device
        if require_same_volume is not None and same_volume is not require_same_volume:
            raise PathAuthorityError("filesystem volume relation is not authorized")
    body = {
        "schema_version": 1,
        "operation_class": operation_class,
        "path": str(path),
        "root": str(root),
        "parent_chain_sha256": _hash(chain),
        "observed_type": observed,
        "replacement_policy": replacement_policy,
        "cleanup_disposition": cleanup_disposition,
        "ownership_receipt_sha256": (
            ownership_receipt["receipt_sha256"] if ownership_receipt else None),
        "peer_path": str(peer) if peer is not None else None,
        "same_volume": same_volume,
        "failure_precedence": "primary-effect-before-cleanup",
    }
    body["authority_sha256"] = _hash(body)
    return body


def remove_owned_tree(path, *, root, ownership_receipt):
    import shutil
    path = _absolute(path, "owned cleanup path")
    validate_ownership_receipt(ownership_receipt, path=path, root=root)
    authorize(
        operation_class="staging", path=path, root=root,
        expected_type="directory", replacement_policy="owned-exact",
        cleanup_disposition="remove-if-owned",
        ownership_receipt=ownership_receipt)
    shutil.rmtree(path)
    return not path.exists()
