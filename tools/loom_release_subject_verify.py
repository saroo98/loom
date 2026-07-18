#!/usr/bin/env python3
"""Independently verify a frozen Loom release subject and canonical plugin bytes."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_release_subject
import loom_reliability


class SubjectVerificationError(RuntimeError):
    pass


FIELDS = {
    "schema_version", "repository", "commit", "tag", "release_sequence",
    "previous_subject_sha256", "source_tree", "public_cut", "canonical_plugin",
    "helpers", "sboms", "workflows", "schemas", "documentation",
    "capability_registry", "provenance", "subject_sha256",
}


def verify(value, plugin, *, commit=None, tag=None):
    if not isinstance(value, dict) or set(value) != FIELDS \
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
