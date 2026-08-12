#!/usr/bin/env python3
"""Compose narrow candidate and release authority without product execution."""

import argparse
import hashlib
import json
from pathlib import Path

import loom_qualification_manifest
import loom_qualification_v2
import loom_qualification_workload
import loom_release_certificate
import loom_reliability
import loom_suite_plan


class ReleaseAuthorityError(RuntimeError):
    pass


CANDIDATE_SUITE_FIELDS = {
    "schema_version", "status", "mode", "subject",
    "authority_policy_sha256", "mechanism_manifest_sha256",
    "mechanism_qualification_sha256", "candidate_admission_sha256",
    "matrices", "suite_certificate_sha256",
}
RELEASE_AUTHORITY_FIELDS = {
    "schema_version", "status", "mode", "release_status", "subject",
    "authority_policy_sha256", "mechanism_manifest_sha256",
    "mechanism_qualification_sha256", "candidate_admission_sha256",
    "candidate_suite_certificate_sha256", "release_certificate_sha256",
    "tag", "archive_sha256", "release_authority_sha256",
}


def certify_candidate_admission(admission, *, mechanism, authority_policy,
                                manifest, workload, expected_commit,
                                expected_tree, expected_root):
    try:
        admission = loom_qualification_v2.verify_candidate(
            admission, expected_commit=expected_commit,
            expected_tree=expected_tree,
            expected_public_root=expected_root, mechanism=mechanism,
            policy=authority_policy, manifest=manifest, workload=workload)
        authority_policy = loom_suite_plan.validate_authority_policy(
            authority_policy)
    except (loom_qualification_v2.QualificationV2Error,
            loom_suite_plan.SuitePlanError) as exc:
        raise ReleaseAuthorityError(
            f"candidate admission is invalid: {exc}") from exc
    body = {
        "schema_version": 3, "status": "certified",
        "mode": authority_policy["authority_mode"],
        "subject": {
            "source_commit": admission["source_commit"],
            "source_tree_sha256": admission[
                "repository_source_tree_sha256"],
            "public_root_sha256": admission["public_root_sha256"],
        },
        "authority_policy_sha256": authority_policy["policy_sha256"],
        "mechanism_manifest_sha256": admission[
            "mechanism_manifest_sha256"],
        "mechanism_qualification_sha256": admission[
            "mechanism_qualification_sha256"],
        "candidate_admission_sha256": admission[
            "candidate_admission_sha256"],
        "matrices": admission["matrix_certificates"],
    }
    return {**body, "suite_certificate_sha256":
            loom_suite_plan.digest(body)}


def verify_candidate_admission(value, *, admission, mechanism,
                               authority_policy, manifest, workload,
                               expected_commit, expected_tree, expected_root):
    if not isinstance(value, dict) or set(value) != CANDIDATE_SUITE_FIELDS:
        raise ReleaseAuthorityError(
            "candidate suite certificate is not closed")
    body = {key: item for key, item in value.items()
            if key != "suite_certificate_sha256"}
    if value.get("schema_version") != 3 \
            or value.get("status") != "certified" \
            or value.get("suite_certificate_sha256") != \
            loom_suite_plan.digest(body):
        raise ReleaseAuthorityError("candidate suite certificate is invalid")
    expected = certify_candidate_admission(
        admission, mechanism=mechanism, authority_policy=authority_policy,
        manifest=manifest, workload=workload,
        expected_commit=expected_commit, expected_tree=expected_tree,
        expected_root=expected_root)
    if expected != value:
        raise ReleaseAuthorityError(
            "candidate suite certificate is inconsistent")
    return value


def certify_release_authority(candidate_suite, release_certificate, *,
                              candidate_admission, expected_tag,
                              expected_asset=None):
    if not isinstance(candidate_suite, dict) \
            or set(candidate_suite) != CANDIDATE_SUITE_FIELDS:
        raise ReleaseAuthorityError(
            "candidate suite certificate is not closed")
    candidate_body = {
        key: item for key, item in candidate_suite.items()
        if key != "suite_certificate_sha256"
    }
    if candidate_suite.get("schema_version") != 3 \
            or candidate_suite.get("status") != "certified" \
            or candidate_suite.get("suite_certificate_sha256") != \
            loom_suite_plan.digest(candidate_body):
        raise ReleaseAuthorityError("candidate suite certificate is invalid")
    try:
        release_certificate = loom_release_certificate.verify_release(
            release_certificate, candidate_admission=candidate_admission,
            expected_tag=expected_tag, expected_asset=expected_asset)
    except loom_release_certificate.ReleaseCertificateError as exc:
        raise ReleaseAuthorityError(
            f"release certificate is invalid: {exc}") from exc
    subject = candidate_suite.get("subject")
    expected_subject = {
        "source_commit": release_certificate["source_commit"],
        "source_tree_sha256": release_certificate[
            "repository_source_tree_sha256"],
        "public_root_sha256": release_certificate["public_root_sha256"],
    }
    if subject != expected_subject \
            or candidate_suite.get("mode") != release_certificate[
                "authority_mode"] \
            or candidate_suite.get("authority_policy_sha256") != \
            release_certificate["authority_policy_sha256"] \
            or candidate_suite.get("mechanism_manifest_sha256") != \
            release_certificate["mechanism_manifest_sha256"] \
            or candidate_suite.get("mechanism_qualification_sha256") != \
            release_certificate["mechanism_qualification_sha256"] \
            or candidate_suite.get("candidate_admission_sha256") != \
            release_certificate["candidate_admission_sha256"]:
        raise ReleaseAuthorityError(
            "candidate and release certificates name different authority")
    body = {
        "schema_version": 4, "status": "authorized",
        "mode": candidate_suite["mode"],
        "release_status": release_certificate["status"],
        "subject": expected_subject,
        "authority_policy_sha256": candidate_suite[
            "authority_policy_sha256"],
        "mechanism_manifest_sha256": candidate_suite[
            "mechanism_manifest_sha256"],
        "mechanism_qualification_sha256": candidate_suite[
            "mechanism_qualification_sha256"],
        "candidate_admission_sha256": candidate_suite[
            "candidate_admission_sha256"],
        "candidate_suite_certificate_sha256": candidate_suite[
            "suite_certificate_sha256"],
        "release_certificate_sha256": release_certificate[
            "release_certificate_sha256"],
        "tag": release_certificate["tag"]["tag"],
        "archive_sha256": release_certificate["archive"]["sha256"],
    }
    return {**body, "release_authority_sha256":
            loom_suite_plan.digest(body)}


def verify_release_authority(value, *, candidate_suite, release_certificate,
                             candidate_admission, expected_tag,
                             expected_asset=None):
    if not isinstance(value, dict) or set(value) != RELEASE_AUTHORITY_FIELDS:
        raise ReleaseAuthorityError("release authority receipt is not closed")
    body = {key: item for key, item in value.items()
            if key != "release_authority_sha256"}
    if value.get("schema_version") != 4 \
            or value.get("status") != "authorized" \
            or value.get("release_authority_sha256") != \
            loom_suite_plan.digest(body):
        raise ReleaseAuthorityError("release authority receipt is invalid")
    expected = certify_release_authority(
        candidate_suite, release_certificate,
        candidate_admission=candidate_admission, expected_tag=expected_tag,
        expected_asset=expected_asset)
    if expected != value:
        raise ReleaseAuthorityError(
            "release authority receipt is inconsistent")
    return value


def _write(path, value):
    path = Path(path).resolve()
    if path.exists() or not path.parent.is_dir():
        raise ReleaseAuthorityError("release authority output is unsafe")
    loom_reliability.atomic_write_json(path, value)


def _expected_asset(path):
    if path is None:
        return None
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ReleaseAuthorityError("release authority asset is unsafe")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReleaseAuthorityError(
            "release authority asset is unreadable") from exc
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _common(parser):
    parser.add_argument("--root", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-public-root", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--mechanism")


def _inputs(args):
    _root, manifest, workload = loom_qualification_v2._repository_inputs(
        args.root)
    policy = loom_suite_plan.load_authority_policy(args.policy)
    mechanism = (loom_qualification_v2._load_json(
        args.mechanism, loom_qualification_v2.MAX_MECHANISM_BYTES)
        if args.mechanism else None)
    qualification_workload = (
        workload if policy["authority_mode"] == "certificate" else None)
    admission = loom_qualification_v2.load_candidate(
        args.candidate, expected_commit=args.expected_commit,
        expected_tree=args.expected_tree,
        expected_public_root=args.expected_public_root,
        mechanism=mechanism, policy=policy, manifest=manifest,
        workload=qualification_workload)
    return admission, mechanism, policy, manifest, qualification_workload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    candidate = subparsers.add_parser("candidate-suite")
    _common(candidate)
    candidate.add_argument("--output", required=True)
    release = subparsers.add_parser("release-authority")
    _common(release)
    release.add_argument("--candidate-suite", required=True)
    release.add_argument("--release-certificate", required=True)
    release.add_argument("--expected-tag", required=True)
    release.add_argument("--asset")
    release.add_argument("--output", required=True)
    verify = subparsers.add_parser("verify")
    _common(verify)
    verify.add_argument("--candidate-suite", required=True)
    verify.add_argument("--release-certificate", required=True)
    verify.add_argument("--release-authority", required=True)
    verify.add_argument("--expected-tag", required=True)
    verify.add_argument("--asset")
    args = parser.parse_args(argv)
    try:
        admission, mechanism, policy, manifest, workload = _inputs(args)
        if args.command == "candidate-suite":
            value = certify_candidate_admission(
                admission, mechanism=mechanism, authority_policy=policy,
                manifest=manifest, workload=workload,
                expected_commit=args.expected_commit,
                expected_tree=args.expected_tree,
                expected_root=args.expected_public_root)
            _write(args.output, value)
            result = {
                "status": value["status"],
                "suite_certificate_sha256": value[
                    "suite_certificate_sha256"],
            }
        else:
            candidate_suite = loom_qualification_v2._load_json(
                args.candidate_suite,
                loom_qualification_v2.MAX_OBSERVATION_BYTES)
            candidate_suite = verify_candidate_admission(
                candidate_suite, admission=admission, mechanism=mechanism,
                authority_policy=policy, manifest=manifest,
                workload=workload, expected_commit=args.expected_commit,
                expected_tree=args.expected_tree,
                expected_root=args.expected_public_root)
            release_certificate = loom_release_certificate._load(
                args.release_certificate)
            asset = _expected_asset(args.asset)
            value = certify_release_authority(
                candidate_suite, release_certificate,
                candidate_admission=admission,
                expected_tag=args.expected_tag, expected_asset=asset)
            if args.command == "release-authority":
                _write(args.output, value)
            else:
                value = verify_release_authority(
                    loom_qualification_v2._load_json(
                        args.release_authority,
                        loom_qualification_v2.MAX_OBSERVATION_BYTES),
                    candidate_suite=candidate_suite,
                    release_certificate=release_certificate,
                    candidate_admission=admission,
                    expected_tag=args.expected_tag, expected_asset=asset)
            result = {
                "status": value["status"],
                "release_authority_sha256": value[
                    "release_authority_sha256"],
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ReleaseAuthorityError,
            loom_qualification_v2.QualificationV2Error,
            loom_qualification_manifest.ManifestError,
            loom_qualification_workload.WorkloadError,
            loom_release_certificate.ReleaseCertificateError,
            loom_reliability.ReliabilityError,
            loom_suite_plan.SuitePlanError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
