#!/usr/bin/env python3
"""Independently verify a frozen Loom release subject and canonical plugin bytes."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_release_subject
import loom_release_candidate
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
V4_FIELDS = {
    "schema_version", "repository", "release_sequence",
    "previous_bundle_sha256", "subjects", "relations",
    "reproducibility_receipt_sha256", "matrix_certificate_sha256",
    "promotion_policy_sha256", "bundle_sha256",
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


def _verify_v4(value, plugin, *, commit=None, tag=None):
    if not isinstance(value, dict) or set(value) != V4_FIELDS \
            or value.get("schema_version") != 4:
        raise SubjectVerificationError("v4 release bundle identity is invalid")
    try:
        regenerated = loom_release_subject.create_evidence_v4(
            subjects=value["subjects"], release_sequence=value["release_sequence"],
            reproducibility_receipt_sha256=value["reproducibility_receipt_sha256"],
            matrix_certificate_sha256=value["matrix_certificate_sha256"],
            promotion_policy_sha256=value["promotion_policy_sha256"],
            previous_bundle_sha256=value["previous_bundle_sha256"])
    except (KeyError, loom_release_subject.ReleaseSubjectError) as exc:
        raise SubjectVerificationError(str(exc)) from exc
    if regenerated != value:
        raise SubjectVerificationError("v4 release bundle digest or relations are invalid")
    subjects = loom_subject_identity.subject_map(value["subjects"])
    candidates = [item for (kind, _), item in subjects.items()
                  if kind == "candidate-source"]
    tags = [item for (kind, _), item in subjects.items() if kind == "release-tag"]
    plugins = [item for (kind, _), item in subjects.items() if kind == "plugin-zip"]
    if commit is not None and candidates[0]["commit"] != commit \
            or tag is not None and tags[0]["tag"] != tag:
        raise SubjectVerificationError("v4 release component identity is invalid")
    try:
        plugin = loom_reliability._absolute(plugin, "canonical plugin", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise SubjectVerificationError(str(exc)) from exc
    raw = plugin.read_bytes()
    if plugins[0]["bytes"] != len(raw) \
            or plugins[0]["sha256"] != hashlib.sha256(raw).hexdigest():
        raise SubjectVerificationError("canonical plugin bytes do not match the v4 subject")
    public_cuts = [item for (kind, _), item in subjects.items()
                   if kind == "public-cut"]
    native_helpers = {item["platform"]: item for (kind, _), item in subjects.items()
                      if kind == "native-helper"}
    try:
        archive = loom_release_candidate._archive_subject(plugin)
    except loom_release_candidate.CandidateError as exc:
        raise SubjectVerificationError(str(exc)) from exc
    declared_cut = public_cuts[0]
    if archive["public_cut"] != {
            "root_sha256": declared_cut["root_sha256"],
            "manifest_sha256": declared_cut["manifest_sha256"],
            "file_count": declared_cut["file_count"]}:
        raise SubjectVerificationError(
            "canonical plugin embeds the wrong v4 public-cut subject")
    if {platform: item["sha256"] for platform, item in native_helpers.items()} \
            != archive["native_binaries"]:
        raise SubjectVerificationError(
            "canonical plugin embeds the wrong v4 native-helper subjects")
    return {"status": "verified", "bundle_sha256": value["bundle_sha256"],
            "plugin_subject_digest": plugins[0]["subject_digest"],
            "plugin_sha256": plugins[0]["sha256"],
            "release_sequence": value["release_sequence"]}


def verify(value, plugin, *, commit=None, tag=None):
    if isinstance(value, dict) and value.get("schema_version") == 4:
        return _verify_v4(value, plugin, commit=commit, tag=tag)
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
