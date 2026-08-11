#!/usr/bin/env python3
"""Compile exact current-candidate release evidence separately from qualification."""

import hashlib
import json
from pathlib import Path
import re

import loom_qualification_v2
import loom_release_promotion
import loom_release_reproducibility
import loom_release_rollback


class ReleaseCertificateError(RuntimeError):
    pass


DOMAIN = b"loom.release-certificate.v2\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
MAX_RELEASE_BYTES = 8 * 1024 * 1024
TAG_FIELDS = {
    "schema_version", "tag", "commit", "tag_object_sha256",
    "signature_sha256", "signer_identity_sha256", "attestation_sha256",
    "signature_verified", "receipt_sha256",
}
RELEASE_FIELDS = {
    "schema_version", "status", "evidence_domain", "source_commit",
    "repository_source_tree_sha256", "public_root_sha256",
    "public_manifest_sha256", "public_file_count",
    "candidate_admission_sha256", "authority_mode",
    "authority_policy_sha256", "mechanism_manifest_sha256",
    "mechanism_qualification_sha256", "tag", "tag_receipt_sha256",
    "reproducibility", "reproducibility_receipt_sha256", "rollback",
    "rollback_receipt_sha256", "promotion", "promotion_receipt_sha256",
    "archive", "native_subjects", "release_certificate_sha256",
}


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def _digest(body):
    return hashlib.sha256(DOMAIN + _canonical(body)).hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or not 0 < path.stat().st_size <= MAX_RELEASE_BYTES:
        raise ReleaseCertificateError("release certificate input is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseCertificateError(
            "release certificate input is invalid") from exc


def _tag(value, source_commit):
    if not isinstance(value, dict) or set(value) != TAG_FIELDS:
        raise ReleaseCertificateError("release tag evidence is invalid")
    matched = TAG.fullmatch(str(value.get("tag", "")))
    body = {key: item for key, item in value.items()
            if key != "receipt_sha256"}
    if matched is None or tuple(map(int, matched.groups())) <= (1, 8, 30) \
            or value.get("schema_version") != 1 \
            or value.get("commit") != source_commit \
            or HEX40.fullmatch(str(value.get("commit", ""))) is None \
            or value.get("signature_verified") is not True \
            or any(HEX64.fullmatch(str(value.get(field, ""))) is None
                   for field in (
                       "tag_object_sha256", "signature_sha256",
                       "signer_identity_sha256", "attestation_sha256")) \
            or value.get("receipt_sha256") != hashlib.sha256(
                _canonical(body)).hexdigest():
        raise ReleaseCertificateError("release tag evidence is invalid")
    return dict(value)


def _candidate(value):
    try:
        return loom_qualification_v2._candidate_seal(value)
    except loom_qualification_v2.QualificationV2Error as exc:
        raise ReleaseCertificateError(
            "exact candidate admission is invalid") from exc


def _reproducibility(value):
    try:
        return loom_release_reproducibility.verify_receipt(value)
    except loom_release_reproducibility.ReproducibilityError as exc:
        raise ReleaseCertificateError(str(exc)) from exc


def _rollback(value, candidate):
    try:
        return loom_release_rollback.verify_receipt(
            value, expected_commit=candidate["source_commit"],
            expected_public_root_sha256=candidate["public_root_sha256"])
    except loom_release_rollback.RollbackEvidenceError as exc:
        raise ReleaseCertificateError(str(exc)) from exc


def _promotion(value, archive):
    if value is None:
        return None, "release-ready"
    try:
        value = loom_release_promotion.verify_receipt(
            value, expected_sha256=archive["sha256"],
            expected_bytes=archive["bytes"])
    except loom_release_promotion.PromotionError as exc:
        raise ReleaseCertificateError(str(exc)) from exc
    if value["status"] == "verified-draft":
        return value, "draft-verified"
    installed = archive["installed_tree_sha256"]
    if value.get("installed_subject_sha256") != installed \
            or installed not in value.get("represented_installed_subjects", []) \
            or value.get("behavior_rerun_required") is not False:
        raise ReleaseCertificateError(
            "public installation does not match the reproduced subject")
    return value, "public-verified"


def compile_release(candidate_admission, reproducibility, rollback, *, tag,
                    promotion=None):
    """Compile exact release evidence without reusing old candidate subjects."""
    candidate = _candidate(candidate_admission)
    reproducibility = _reproducibility(reproducibility)
    rollback = _rollback(rollback, candidate)
    tag = _tag(tag, candidate["source_commit"])
    archive = reproducibility["candidate_a"]
    expected_cut = {
        "root_sha256": candidate["public_root_sha256"],
        "manifest_sha256": candidate["public_manifest_sha256"],
        "file_count": candidate["public_file_count"],
    }
    candidate_natives = [{
        key: row[key] for key in (
            "platform", "binary_sha256", "sbom_sha256",
            "provenance_sha256")
    } for row in candidate["native_subjects"]]
    candidate_natives.sort(key=lambda row: row["platform"])
    if reproducibility["public_cut"] != expected_cut \
            or archive["public_cut"] != expected_cut \
            or reproducibility["native_subjects"] != candidate_natives:
        raise ReleaseCertificateError(
            "release archive does not match the exact admitted candidate")
    promotion, status = _promotion(promotion, archive)
    body = {
        "schema_version": 2, "status": status,
        "evidence_domain": "release-certificate-v2",
        "source_commit": candidate["source_commit"],
        "repository_source_tree_sha256": candidate[
            "repository_source_tree_sha256"],
        "public_root_sha256": candidate["public_root_sha256"],
        "public_manifest_sha256": candidate["public_manifest_sha256"],
        "public_file_count": candidate["public_file_count"],
        "candidate_admission_sha256": candidate[
            "candidate_admission_sha256"],
        "authority_mode": candidate["authority_mode"],
        "authority_policy_sha256": candidate["authority_policy_sha256"],
        "mechanism_manifest_sha256": candidate[
            "mechanism_manifest_sha256"],
        "mechanism_qualification_sha256": candidate[
            "mechanism_qualification_sha256"],
        "tag": tag, "tag_receipt_sha256": tag["receipt_sha256"],
        "reproducibility": reproducibility,
        "reproducibility_receipt_sha256": reproducibility[
            "receipt_sha256"],
        "rollback": rollback,
        "rollback_receipt_sha256": rollback["result_sha256"],
        "promotion": promotion,
        "promotion_receipt_sha256": (
            None if promotion is None else promotion["receipt_sha256"]),
        "archive": archive, "native_subjects": candidate_natives,
    }
    return {**body, "release_certificate_sha256": _digest(body)}


def verify_release(value, *, candidate_admission, expected_tag,
                   expected_asset=None):
    if not isinstance(value, dict) or set(value) != RELEASE_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("status") not in {
                "release-ready", "draft-verified", "public-verified"} \
            or value.get("evidence_domain") != "release-certificate-v2":
        raise ReleaseCertificateError("release certificate fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "release_certificate_sha256"}
    if value.get("release_certificate_sha256") != _digest(body) \
            or value.get("tag", {}).get("tag") != expected_tag:
        raise ReleaseCertificateError("release certificate identity is invalid")
    expected = compile_release(
        candidate_admission, value.get("reproducibility"),
        value.get("rollback"), tag=value.get("tag"),
        promotion=value.get("promotion"))
    if expected != value:
        raise ReleaseCertificateError("release certificate is inconsistent")
    if expected_asset is None:
        if value["status"] != "release-ready":
            raise ReleaseCertificateError(
                "verified release lacks an expected asset subject")
    elif not isinstance(expected_asset, dict) \
            or set(expected_asset) != {"sha256", "bytes"} \
            or value["archive"]["sha256"] != expected_asset.get("sha256") \
            or value["archive"]["bytes"] != expected_asset.get("bytes"):
        raise ReleaseCertificateError("release asset subject is wrong")
    return value


def load_release(path, *, candidate_admission, expected_tag,
                 expected_asset=None):
    return verify_release(
        _load(path), candidate_admission=candidate_admission,
        expected_tag=expected_tag, expected_asset=expected_asset)
