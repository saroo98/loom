#!/usr/bin/env python3
"""Independently verify a frozen Loom release subject and canonical plugin bytes."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_release_subject
import loom_reliability
import loom_subject_identity


class SubjectVerificationError(RuntimeError):
    pass


V2_FIELDS = {
    "schema_version", "repository", "commit", "tag", "release_sequence",
    "previous_subject_sha256", "source_tree", "public_cut", "canonical_plugin",
    "helpers", "sboms", "workflows", "schemas", "documentation",
    "capability_registry", "provenance", "subject_sha256",
}
V3_FIELDS = {
    "schema_version", "repository", "release_sequence",
    "previous_bundle_sha256", "subjects", "relations", "bundle_sha256",
}


def _verify_v2(value, plugin, *, commit=None, tag=None):
    if not isinstance(value, dict) or set(value) != V2_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("repository") != "https://github.com/saroo98/loom" \
            or not re.fullmatch(r"[0-9a-f]{40}", str(value.get("commit", ""))) \
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(value.get("tag", ""))) \
            or commit is not None and value["commit"] != commit \
            or tag is not None and value["tag"] != tag:
        raise SubjectVerificationError("release subject identity is invalid")
    body = {key: item for key, item in value.items() if key != "subject_sha256"}
    observed = hashlib.sha256(loom_release_subject._canonical(body)).hexdigest()
    if observed != value.get("subject_sha256"):
        raise SubjectVerificationError("release subject digest is invalid")
    try:
        plugin = loom_reliability._absolute(
            plugin, "canonical plugin", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise SubjectVerificationError(str(exc)) from exc
    if not plugin.is_file():
        raise SubjectVerificationError("canonical plugin is missing or redirected")
    raw = plugin.read_bytes()
    expected = value["canonical_plugin"]
    if expected != {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}:
        raise SubjectVerificationError("canonical plugin bytes do not match the release subject")
    return {"status": "verified", "subject_sha256": observed,
            "plugin_sha256": expected["sha256"],
            "release_sequence": value["release_sequence"]}


def _verify_v3(value, plugin, *, commit=None, tag=None):
    if not isinstance(value, dict) or set(value) != V3_FIELDS \
            or value.get("schema_version") != 3 \
            or value.get("repository") != loom_subject_identity.REPOSITORY:
        raise SubjectVerificationError("typed release bundle identity is invalid")
    body = {key: item for key, item in value.items() if key != "bundle_sha256"}
    observed_bundle = hashlib.sha256(
        loom_release_subject._canonical(body)).hexdigest()
    if observed_bundle != value.get("bundle_sha256"):
        raise SubjectVerificationError("typed release bundle digest is invalid")
    try:
        subjects = loom_subject_identity.subject_map(value["subjects"])
    except loom_subject_identity.SubjectIdentityError as exc:
        raise SubjectVerificationError(str(exc)) from exc
    expected_relations = [{
        "relation": "component", "subject_kind": subject["kind"],
        "subject_id": subject["subject_id"],
        "subject_digest": subject["subject_digest"],
    } for subject in sorted(
        subjects.values(), key=lambda item: (
            item["kind"], item["subject_id"], item["subject_digest"]))]
    if value["relations"] != expected_relations:
        raise SubjectVerificationError(
            "typed release bundle relations do not match its components")
    tags = [
        item for (kind, _subject_id), item in subjects.items()
        if kind == "release-tag"]
    candidates = [
        item for (kind, _subject_id), item in subjects.items()
        if kind == "candidate-source"]
    plugins = [
        item for (kind, _subject_id), item in subjects.items()
        if kind == "plugin-zip"]
    if len(tags) != 1 or len(candidates) != 1 or len(plugins) != 1 \
            or tag is not None and tags[0]["tag"] != tag \
            or commit is not None and candidates[0]["commit"] != commit:
        raise SubjectVerificationError(
            "typed release bundle component identity is invalid")
    try:
        plugin = loom_reliability._absolute(
            plugin, "canonical plugin", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise SubjectVerificationError(str(exc)) from exc
    if not plugin.is_file():
        raise SubjectVerificationError(
            "canonical plugin is missing or redirected")
    raw = plugin.read_bytes()
    expected = plugins[0]
    if expected["bytes"] != len(raw) \
            or expected["sha256"] != hashlib.sha256(raw).hexdigest():
        raise SubjectVerificationError(
            "canonical plugin bytes do not match the typed subject")
    return {
        "status": "verified",
        "bundle_sha256": observed_bundle,
        "plugin_subject_digest": expected["subject_digest"],
        "plugin_sha256": expected["sha256"],
        "release_sequence": value["release_sequence"],
    }


def verify(value, plugin, *, commit=None, tag=None):
    if isinstance(value, dict) and value.get("schema_version") == 3:
        return _verify_v3(value, plugin, commit=commit, tag=tag)
    return _verify_v2(value, plugin, commit=commit, tag=tag)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("subject")
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--commit")
    parser.add_argument("--tag")
    args = parser.parse_args(argv)
    try:
        value = json.loads(Path(args.subject).read_text(encoding="utf-8"))
        result = verify(value, args.plugin, commit=args.commit, tag=args.tag)
    except (OSError, UnicodeError, json.JSONDecodeError, SubjectVerificationError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
