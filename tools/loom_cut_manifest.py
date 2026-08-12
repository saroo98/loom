#!/usr/bin/env python3
"""Closed public-cut manifest verification shared by release and workers."""

import hashlib
import json
import re
from pathlib import Path

import loom_reliability


MANIFEST = "BUILD-MANIFEST.json"


class CutManifestError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _canonical_hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


def verify(root):
    root = Path(root).resolve()
    manifest_path = root / MANIFEST
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CutManifestError(f"public cut manifest is unreadable: {exc}") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema_version", "files", "root_sha256"} \
            or manifest.get("schema_version") != 1 \
            or not isinstance(manifest.get("files"), list) \
            or not isinstance(manifest.get("root_sha256"), str):
        raise CutManifestError("public cut manifest shape is invalid")
    observed_files = []
    try:
        for path in loom_reliability._regular_files(root):
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST:
                continue
            raw = path.read_bytes()
            observed_files.append({
                "path": relative, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
    except (OSError, loom_reliability.ReliabilityError) as exc:
        raise CutManifestError(f"public cut traversal failed: {exc}") from exc
    observed_files.sort(key=lambda item: item["path"])
    for item in manifest["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} \
                or not isinstance(item["path"], str) \
                or type(item["bytes"]) is not int or item["bytes"] < 0 \
                or not isinstance(item["sha256"], str) \
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise CutManifestError("public cut manifest file entry is invalid")
        try:
            target = loom_reliability._target(root, item["path"])
        except loom_reliability.ReliabilityError as exc:
            raise CutManifestError(
                f"public cut manifest path is invalid: {exc}") from exc
        if target.relative_to(root).as_posix() != item["path"]:
            raise CutManifestError("public cut manifest path is not canonical")
    if manifest["files"] != observed_files:
        raise CutManifestError(
            "public cut files do not exactly match the sealed manifest")
    body = {"schema_version": 1, "files": manifest["files"]}
    if manifest["root_sha256"] != _canonical_hash(body):
        raise CutManifestError("public cut manifest root hash is invalid")
    return manifest
