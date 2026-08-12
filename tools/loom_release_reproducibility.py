#!/usr/bin/env python3
"""Validate sealed A/B release reproducibility evidence without building."""

import hashlib
import json
import re


NATIVE_PLATFORMS = {
    "windows-x64": "loom-vault.exe", "windows-arm64": "loom-vault.exe",
    "macos-x64": "loom-vault", "macos-arm64": "loom-vault",
    "linux-x64": "loom-vault", "linux-arm64": "loom-vault",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReproducibilityError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def seal(body):
    return {
        **body,
        "receipt_sha256": hashlib.sha256(_canonical(body)).hexdigest(),
    }


def verify_receipt(value):
    """Validate one closed, byte-identical A/B release receipt."""
    fields = {
        "schema_version", "status", "candidate_a", "candidate_b",
        "canonical_candidate", "public_cut", "native_subjects",
        "receipt_sha256",
    }
    body = ({key: item for key, item in value.items()
             if key != "receipt_sha256"} if isinstance(value, dict) else None)
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("status") != "reproduced" \
            or value.get("canonical_candidate") != "A" \
            or value.get("receipt_sha256") != seal(body)["receipt_sha256"]:
        raise ReproducibilityError(
            "reproducibility receipt identity is invalid")
    candidate_fields = {
        "sha256", "bytes", "files", "extracted_tree_sha256",
        "installed_tree_sha256", "archive_metadata_sha256", "public_cut",
        "native_binaries",
    }
    cut_fields = {"root_sha256", "manifest_sha256", "file_count"}
    candidates = (value.get("candidate_a"), value.get("candidate_b"))
    for candidate in candidates:
        public_cut = (candidate.get("public_cut")
                      if isinstance(candidate, dict) else None)
        binaries = (candidate.get("native_binaries")
                    if isinstance(candidate, dict) else None)
        if not isinstance(candidate, dict) \
                or set(candidate) != candidate_fields \
                or any(HEX64.fullmatch(str(candidate.get(field, ""))) is None
                       for field in (
                           "sha256", "extracted_tree_sha256",
                           "installed_tree_sha256",
                           "archive_metadata_sha256")) \
                or any(type(candidate.get(field)) is not int
                       or candidate[field] < 1 for field in ("bytes", "files")) \
                or not isinstance(public_cut, dict) \
                or set(public_cut) != cut_fields \
                or any(HEX64.fullmatch(str(public_cut.get(field, ""))) is None
                       for field in ("root_sha256", "manifest_sha256")) \
                or type(public_cut.get("file_count")) is not int \
                or public_cut["file_count"] < 1 \
                or not isinstance(binaries, dict) \
                or set(binaries) != set(NATIVE_PLATFORMS) \
                or any(HEX64.fullmatch(str(digest)) is None
                       for digest in binaries.values()):
            raise ReproducibilityError(
                "reproducibility candidate identity is invalid")
    if candidates[0] != candidates[1] \
            or value.get("public_cut") != candidates[0]["public_cut"]:
        raise ReproducibilityError(
            "reproducibility candidates or public cut disagree")
    natives = value.get("native_subjects")
    native_fields = {
        "platform", "binary_sha256", "sbom_sha256", "provenance_sha256"}
    if not isinstance(natives, list) \
            or len(natives) != len(NATIVE_PLATFORMS) \
            or any(not isinstance(row, dict) for row in natives) \
            or natives != sorted(natives, key=lambda row: row.get("platform", "")) \
            or {row.get("platform") for row in natives} != set(NATIVE_PLATFORMS):
        raise ReproducibilityError(
            "reproducibility native subjects are invalid")
    for row in natives:
        if set(row) != native_fields \
                or any(HEX64.fullmatch(str(row.get(field, ""))) is None
                       for field in (
                           "binary_sha256", "sbom_sha256",
                           "provenance_sha256")) \
                or candidates[0]["native_binaries"].get(row.get("platform")) \
                != row.get("binary_sha256"):
            raise ReproducibilityError(
                "reproducibility native subjects are invalid")
    return value
