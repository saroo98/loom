#!/usr/bin/env python3
"""Create typed v3 release bundles; retain v2 construction for compatibility tests."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

import loom_reliability
import loom_subject_identity


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
    """Create a historical v2 aggregate for compatibility fixtures only."""
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


def create_typed(*, subjects, release_sequence, previous_bundle_sha256=None):
    """Create a v3 bundle relation without collapsing component identities."""
    if type(release_sequence) is not int or release_sequence < 1 \
            or previous_bundle_sha256 is not None \
            and not re.fullmatch(r"[0-9a-f]{64}", str(previous_bundle_sha256)):
        raise ReleaseSubjectError("typed release bundle identity is invalid")
    try:
        mapped = loom_subject_identity.subject_map(subjects)
    except loom_subject_identity.SubjectIdentityError as exc:
        raise ReleaseSubjectError(str(exc)) from exc
    required = {"main-source", "candidate-source", "release-tag", "plugin-zip"}
    kinds = {kind for kind, _subject_id in mapped}
    if not required <= kinds or "native-helper" not in kinds \
            or "installed-runtime" in kinds:
        raise ReleaseSubjectError(
            "typed release bundle component subjects are incomplete or invalid")
    normalized = sorted(
        mapped.values(), key=lambda item: (
            item["kind"], item["subject_id"], item["subject_digest"]))
    relations = [{
        "relation": "component",
        "subject_kind": item["kind"],
        "subject_id": item["subject_id"],
        "subject_digest": item["subject_digest"],
    } for item in normalized]
    body = {
        "schema_version": 3,
        "repository": loom_subject_identity.REPOSITORY,
        "release_sequence": release_sequence,
        "previous_bundle_sha256": previous_bundle_sha256,
        "subjects": normalized,
        "relations": relations,
    }
    return {
        **body,
        "bundle_sha256": hashlib.sha256(_canonical(body)).hexdigest(),
    }


def create_evidence_v4(*, subjects, release_sequence,
                       reproducibility_receipt_sha256,
                       matrix_certificate_sha256, promotion_policy_sha256,
                       previous_bundle_sha256=None):
    """Create a v4 bundle with exact public-cut, plugin, and native relations."""
    digests = (reproducibility_receipt_sha256, matrix_certificate_sha256,
               promotion_policy_sha256)
    if type(release_sequence) is not int or release_sequence < 1 \
            or any(not re.fullmatch(r"[0-9a-f]{64}", str(value)) for value in digests) \
            or previous_bundle_sha256 is not None \
            and not re.fullmatch(r"[0-9a-f]{64}", str(previous_bundle_sha256)):
        raise ReleaseSubjectError("v4 release evidence identity is invalid")
    try:
        mapped = loom_subject_identity.subject_map(subjects)
    except loom_subject_identity.SubjectIdentityError as exc:
        raise ReleaseSubjectError(str(exc)) from exc
    by_kind = {}
    for (kind, _subject_id), subject in mapped.items():
        by_kind.setdefault(kind, []).append(subject)
    expected_kinds = {
        "main-source", "candidate-source", "release-tag", "plugin-zip",
        "public-cut", "native-helper",
    }
    if set(by_kind) != expected_kinds or len(mapped) != 11 \
            or any(len(by_kind.get(kind, [])) != 1 for kind in (
            "main-source", "candidate-source", "release-tag", "plugin-zip",
            "public-cut")) \
            or {item["platform"] for item in by_kind.get("native-helper", [])} \
            != loom_subject_identity.PLATFORMS \
            or len(by_kind.get("native-helper", [])) != 6:
        raise ReleaseSubjectError(
            "v4 release evidence subjects are incomplete or invalid")
    normalized = sorted(mapped.values(), key=lambda item: (
        item["kind"], item["subject_id"], item["subject_digest"]))
    plugin = by_kind["plugin-zip"][0]
    public_cut = by_kind["public-cut"][0]
    relations = [{
        "relation": "component", "subject_kind": item["kind"],
        "subject_id": item["subject_id"], "subject_digest": item["subject_digest"],
    } for item in normalized]
    relations.append({
        "relation": "embeds-public-cut",
        "plugin_subject_digest": plugin["subject_digest"],
        "public_cut_subject_digest": public_cut["subject_digest"],
    })
    relations.extend({
        "relation": "contains-native-helper",
        "plugin_subject_digest": plugin["subject_digest"],
        "platform": helper["platform"],
        "native_subject_digest": helper["subject_digest"],
    } for helper in sorted(by_kind["native-helper"], key=lambda item: item["platform"]))
    body = {
        "schema_version": 4, "repository": loom_subject_identity.REPOSITORY,
        "release_sequence": release_sequence,
        "previous_bundle_sha256": previous_bundle_sha256,
        "subjects": normalized, "relations": relations,
        "reproducibility_receipt_sha256": reproducibility_receipt_sha256,
        "matrix_certificate_sha256": matrix_certificate_sha256,
        "promotion_policy_sha256": promotion_policy_sha256,
    }
    return {**body, "bundle_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


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
    parser.add_argument("--subjects", required=True)
    parser.add_argument("--release-sequence", required=True, type=int)
    parser.add_argument("--previous-bundle")
    parser.add_argument("--reproducibility-receipt-sha256")
    parser.add_argument("--matrix-certificate-sha256")
    parser.add_argument("--promotion-policy-sha256")
    parser.add_argument("--legacy-v3", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        subject_set = json.loads(
            Path(args.subjects).read_text(encoding="utf-8"))
        subjects = (subject_set.get("subjects")
                    if isinstance(subject_set, dict) else None)
        if args.legacy_v3:
            result = create_typed(
                subjects=subjects, release_sequence=args.release_sequence,
                previous_bundle_sha256=args.previous_bundle)
        else:
            result = create_evidence_v4(
                subjects=subjects, release_sequence=args.release_sequence,
                previous_bundle_sha256=args.previous_bundle,
                reproducibility_receipt_sha256=(
                    args.reproducibility_receipt_sha256),
                matrix_certificate_sha256=args.matrix_certificate_sha256,
                promotion_policy_sha256=args.promotion_policy_sha256)
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            ReleaseSubjectError) as exc:
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
    print(json.dumps({"status": "created", "bundle_sha256": result["bundle_sha256"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
