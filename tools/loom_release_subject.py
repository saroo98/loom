#!/usr/bin/env python3
"""Bind every exact release surface to one deterministic subject digest."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

import loom_reliability


MAX_FILES = 8192
MAX_FILE_BYTES = 512 * 1024 * 1024


class ReleaseSubjectError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _artifact(path):
    try:
        path = loom_reliability._absolute(
            path, "release subject artifact", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise ReleaseSubjectError(str(exc)) from exc
    if not path.is_file() or path.stat().st_size < 1 \
            or path.stat().st_size > MAX_FILE_BYTES:
        raise ReleaseSubjectError(f"release subject artifact is unsafe: {path}")
    raw = path.read_bytes()
    if len(raw) != path.stat().st_size:
        raise ReleaseSubjectError("release subject artifact changed while hashing")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _tree(root):
    try:
        root = loom_reliability._absolute(
            root, "release subject tree", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise ReleaseSubjectError(str(exc)) from exc
    if not root.is_dir():
        raise ReleaseSubjectError("release subject tree is unsafe")
    rows = []
    pending = [root]
    ignored_directories = {".git", "__pycache__", "target"}
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise ReleaseSubjectError(
                f"release subject tree cannot be inspected: {directory}: {exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            try:
                redirected = loom_reliability._is_redirect(path)
            except loom_reliability.ReliabilityError as exc:
                raise ReleaseSubjectError(str(exc)) from exc
            if redirected:
                raise ReleaseSubjectError("release subject tree contains a redirected entry")
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in ignored_directories:
                    pending.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ReleaseSubjectError("release subject tree contains a non-regular entry")
            raw = path.read_bytes()
            if len(raw) > MAX_FILE_BYTES:
                raise ReleaseSubjectError("release subject tree contains an oversized file")
            rows.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()})
            if len(rows) > MAX_FILES:
                raise ReleaseSubjectError("release subject tree exceeds its file bound")
    if not rows:
        raise ReleaseSubjectError("release subject tree is empty")
    raw = _canonical(rows)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": sum(
        row["bytes"] for row in rows)}


def _named_artifacts(values, label):
    if not isinstance(values, dict) or not values or len(values) > 32 \
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", key)
                   for key in values):
        raise ReleaseSubjectError(f"{label} inventory is invalid")
    return {key: _artifact(path) for key, path in sorted(values.items())}


def create(*, source, public_cut, plugin, helpers, sboms, workflows,
           schemas, docs, registry, provenance, commit, tag, release_sequence,
           previous_subject=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) \
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) \
            or type(release_sequence) is not int or release_sequence < 1 \
            or previous_subject is not None \
            and not re.fullmatch(r"[0-9a-f]{64}", str(previous_subject)):
        raise ReleaseSubjectError("release identity is invalid")
    body = {
        "schema_version": 2, "repository": "https://github.com/saroo98/loom",
        "commit": commit, "tag": tag, "release_sequence": release_sequence,
        "previous_subject_sha256": previous_subject,
        "source_tree": _tree(source), "public_cut": _tree(public_cut),
        "canonical_plugin": _artifact(plugin),
        "helpers": _named_artifacts(helpers, "helper"),
        "sboms": _named_artifacts(sboms, "SBOM"),
        "workflows": _named_artifacts(workflows, "workflow"),
        "schemas": _tree(schemas), "documentation": _tree(docs),
        "capability_registry": _artifact(registry),
        "provenance": _named_artifacts(provenance, "provenance"),
    }
    return {**body, "subject_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


def _mapping(values):
    result = {}
    for value in values:
        if "=" not in value:
            raise ReleaseSubjectError("named artifact must use NAME=PATH")
        name, path = value.split("=", 1)
        if name in result:
            raise ReleaseSubjectError("named artifact is duplicated")
        result[name] = path
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--public-cut", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--helper", action="append", default=[])
    parser.add_argument("--sbom", action="append", default=[])
    parser.add_argument("--workflow", action="append", default=[])
    parser.add_argument("--schemas", required=True)
    parser.add_argument("--docs", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--provenance", action="append", default=[])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-sequence", required=True, type=int)
    parser.add_argument("--previous-subject")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = create(
            source=args.source, public_cut=args.public_cut, plugin=args.plugin,
            helpers=_mapping(args.helper), sboms=_mapping(args.sbom),
            workflows=_mapping(args.workflow), schemas=args.schemas, docs=args.docs,
            registry=args.registry, provenance=_mapping(args.provenance),
            commit=args.commit, tag=args.tag, release_sequence=args.release_sequence,
            previous_subject=args.previous_subject)
    except ReleaseSubjectError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    try:
        output = loom_reliability._absolute(args.output, "release subject output")
        if output.exists():
            raise ReleaseSubjectError("release subject output already exists")
        loom_reliability.atomic_write_json(output, result)
    except (ReleaseSubjectError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "created", "subject_sha256": result["subject_sha256"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
