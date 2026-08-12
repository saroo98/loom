#!/usr/bin/env python3
"""Certify one release-host suite only through exact bound matrix evidence."""

import argparse
import json
import re
from pathlib import Path

import loom_capability
import loom_exact_cut_ci
import loom_qualification_v2
import loom_release_certificate
import loom_reliability
import loom_test
import loom_suite_certificate
import loom_suite_plan


class ReleaseSuiteError(RuntimeError):
    pass


MAX_QUALIFICATION_BYTES = 95_000_000
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


def load_v2_policies(*, authority_path, candidate_path):
    """Load v2 authority and legacy candidate-sharding policy independently."""
    try:
        return {
            "authority": loom_suite_plan.load_authority_policy(authority_path),
            "candidate": loom_suite_plan.load_candidate_policy(candidate_path),
        }
    except loom_suite_plan.SuitePlanError as exc:
        raise ReleaseSuiteError(f"release policy is invalid: {exc}") from exc


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json(path, label, *, max_bytes=4 * 1024 * 1024):
    try:
        path = Path(path)
        if not path.is_file() or path.is_symlink() \
                or type(max_bytes) is not int or max_bytes < 1 \
                or path.stat().st_size > max_bytes:
            raise ReleaseSuiteError(f"{label} is not a bounded regular file")
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError,
            RecursionError) as exc:
        raise ReleaseSuiteError(f"{label} is invalid: {exc}") from exc


def _read_qualification(path, *, max_bytes=MAX_QUALIFICATION_BYTES):
    return _read_json(
        path, "suite qualification", max_bytes=max_bytes)


def _read_reports(paths):
    return [_read_json(path, "matrix report") for path in paths]


def _validate_serial_report(report, *, expected_commit, expected_root):
    binding = report.get("binding") if isinstance(report, dict) else None
    timings = report.get("timings") if isinstance(report, dict) else None
    skips = report.get("skip_receipts") if isinstance(report, dict) else None
    environment = binding.get("environment") if isinstance(binding, dict) else None
    raw_passed = (report.get("failures") == 0
                  and report.get("errors") == 0
                  and report.get("within_budget") is True)
    normalized_passed = (report.get("passed") is True
                         and report.get("failure_count") == 0
                         and report.get("error_count") == 0
                         and report.get("returncode") in {0, 1}
                         and report.get("capability_status") in {
                             "complete", "requires-matrix"})
    environment_body = ({key: item for key, item in environment.items()
                         if key != "environment_sha256"}
                        if isinstance(environment, dict) else {})
    if not (raw_passed or normalized_passed) \
            or not isinstance(timings, list) or not timings \
            or not isinstance(skips, list) \
            or not isinstance(binding, dict) or set(binding) != {
                "source_commit", "public_root_sha256", "platform", "architecture",
                "python", "runner", "environment"} \
            or binding.get("source_commit") != expected_commit \
            or binding.get("public_root_sha256") != expected_root \
            or not isinstance(environment, dict) \
            or set(environment) != loom_exact_cut_ci.ENVIRONMENT_FIELDS \
            or environment.get("environment_sha256") != binding.get("runner") \
            or binding.get("platform") != (
                str(environment.get("image_os")) + ":" +
                str(environment.get("image_version"))) \
            or binding.get("architecture") != environment.get("architecture") \
            or binding.get("python") != environment.get("python_version") \
            or environment.get("environment_sha256") != loom_suite_plan.digest(
                environment_body) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(
                environment.get("environment_sha256", ""))):
        raise ReleaseSuiteError("serial evidence names an invalid exact cell")
    outcomes = {}
    for item in timings:
        if not isinstance(item, dict):
            raise ReleaseSuiteError("serial evidence inventory is invalid")
        duration_fields = ({"seconds"} if "seconds" in item
                           else {"duration_microseconds"})
        duration = (item.get("seconds") if "seconds" in duration_fields
                    else item.get("duration_microseconds"))
        if set(item) != {"test", "status"} | duration_fields \
                or not isinstance(item.get("test"), str) or not item["test"] \
                or item.get("status") not in {"passed", "skipped"} \
                or not isinstance(duration, (int, float)) \
                or isinstance(duration, bool) or duration < 0 \
                or item["test"] in outcomes:
            raise ReleaseSuiteError("serial evidence inventory is invalid")
        outcomes[item["test"]] = item["status"]
    skip_map = {}
    for item in skips:
        raw_reason = isinstance(item, dict) and "reason" in item
        reason_fields = ({"reason"} if raw_reason
                         else {"reason_code", "reason_sha256"})
        reason_code = (loom_test.skip_reason_code(item.get("reason", ""))
                       if isinstance(item, dict) and raw_reason
                       else item.get("reason_code") if isinstance(item, dict) else None)
        if not isinstance(item, dict) or set(item) != {"test"} | reason_fields \
                or not isinstance(item.get("test"), str) \
                or (raw_reason and (
                    not isinstance(item.get("reason"), str) or not item["reason"]
                    or len(item["reason"]) > 4096)) \
                or (not raw_reason and re.fullmatch(
                    r"[0-9a-f]{64}", str(item.get("reason_sha256", ""))) is None) \
                or reason_code not in loom_test.AUTHORIZED_SKIP_REASON_CODES \
                or item["test"] in skip_map:
            raise ReleaseSuiteError("serial skip receipt is invalid")
        skip_map[item["test"]] = item.get("reason", item.get("reason_sha256"))
    observed_skips = {test for test, status in outcomes.items()
                      if status == "skipped"}
    if observed_skips != set(skip_map) \
            or type(report.get("tests_run")) is not int \
            or report["tests_run"] != len(outcomes):
        raise ReleaseSuiteError("serial skip or inventory counts are inconsistent")
    if raw_passed and (report.get("skipped") != len(observed_skips) \
            or report.get("capability_complete") is not (not observed_skips) \
            or report.get("successful") is not (not observed_skips) \
            or report.get("status") != (
                "passed" if not observed_skips else "passed-with-capability-skips")):
        raise ReleaseSuiteError("raw serial result fields are inconsistent")
    if normalized_passed and (report.get("capability_complete") is not (
            not observed_skips) \
            or report.get("capability_status") != (
                "complete" if not observed_skips else "requires-matrix") \
            or report.get("returncode") != (0 if not observed_skips else 1)):
        raise ReleaseSuiteError("normalized serial result fields are inconsistent")
    return outcomes, environment["environment_sha256"]


def certify_candidate_admission(admission, *, mechanism, authority_policy,
                                manifest, workload, expected_commit,
                                expected_tree, expected_root):
    """Consume one exact v2 admission without rerunning candidate behavior."""
    try:
        admission = loom_qualification_v2.verify_candidate(
            admission, expected_commit=expected_commit,
            expected_tree=expected_tree, expected_public_root=expected_root,
            mechanism=mechanism, policy=authority_policy,
            manifest=manifest, workload=workload)
        authority_policy = loom_suite_plan.validate_authority_policy(
            authority_policy)
    except (loom_qualification_v2.QualificationV2Error,
            loom_suite_plan.SuitePlanError) as exc:
        raise ReleaseSuiteError(
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
        raise ReleaseSuiteError("candidate suite certificate is not closed")
    body = {key: item for key, item in value.items()
            if key != "suite_certificate_sha256"}
    if value.get("schema_version") != 3 \
            or value.get("status") != "certified" \
            or value.get("suite_certificate_sha256") != \
            loom_suite_plan.digest(body):
        raise ReleaseSuiteError("candidate suite certificate is invalid")
    expected = certify_candidate_admission(
        admission, mechanism=mechanism, authority_policy=authority_policy,
        manifest=manifest, workload=workload,
        expected_commit=expected_commit, expected_tree=expected_tree,
        expected_root=expected_root)
    if expected != value:
        raise ReleaseSuiteError("candidate suite certificate is inconsistent")
    return value


def certify_release_authority(candidate_suite, release_certificate, *,
                              candidate_admission, expected_tag,
                              expected_asset=None):
    """Require both exact candidate and release certificates for authority."""
    if not isinstance(candidate_suite, dict) \
            or set(candidate_suite) != CANDIDATE_SUITE_FIELDS:
        raise ReleaseSuiteError("candidate suite certificate is not closed")
    candidate_body = {
        key: item for key, item in candidate_suite.items()
        if key != "suite_certificate_sha256"
    }
    if candidate_suite.get("schema_version") != 3 \
            or candidate_suite.get("status") != "certified" \
            or candidate_suite.get("suite_certificate_sha256") != \
            loom_suite_plan.digest(candidate_body):
        raise ReleaseSuiteError("candidate suite certificate is invalid")
    try:
        release_certificate = loom_release_certificate.verify_release(
            release_certificate, candidate_admission=candidate_admission,
            expected_tag=expected_tag, expected_asset=expected_asset)
    except loom_release_certificate.ReleaseCertificateError as exc:
        raise ReleaseSuiteError(f"release certificate is invalid: {exc}") from exc
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
        raise ReleaseSuiteError(
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
        raise ReleaseSuiteError("release authority receipt is not closed")
    body = {key: item for key, item in value.items()
            if key != "release_authority_sha256"}
    if value.get("schema_version") != 4 \
            or value.get("status") != "authorized" \
            or value.get("release_authority_sha256") != \
            loom_suite_plan.digest(body):
        raise ReleaseSuiteError("release authority receipt is invalid")
    expected = certify_release_authority(
        candidate_suite, release_certificate,
        candidate_admission=candidate_admission, expected_tag=expected_tag,
        expected_asset=expected_asset)
    if expected != value:
        raise ReleaseSuiteError("release authority receipt is inconsistent")
    return value


def certify(local_report, matrix_paths, *, expected_commit, expected_root):
    if not re.fullmatch(r"[0-9a-f]{40}", str(expected_commit)) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected_root)):
        raise ReleaseSuiteError("release suite identity is invalid")
    required = {"tests_run", "failures", "errors", "within_budget",
                "skip_receipts", "timings"}
    if not isinstance(local_report, dict) or not required <= set(local_report) \
            or local_report["failures"] != 0 or local_report["errors"] != 0 \
            or local_report["within_budget"] is not True:
        raise ReleaseSuiteError("local release suite did not pass")
    paths = [Path(path) for path in matrix_paths]
    try:
        matrix = loom_capability.aggregate(paths)
    except loom_capability.CapabilityError as exc:
        raise ReleaseSuiteError(str(exc)) from exc
    if matrix["status"] != "certified" \
            or matrix["subject"] != {
                "source_commit": expected_commit,
                "public_root_sha256": expected_root,
            }:
        raise ReleaseSuiteError("matrix evidence is not certified for this release subject")
    reports = _read_reports(paths)
    passed = {item.get("test") for report in reports
              for item in report.get("timings", [])
              if item.get("status") == "passed" and item.get("test")}
    local_skips = sorted({item.get("test") for item in local_report["skip_receipts"]
                          if item.get("test")})
    uncovered = sorted(set(local_skips) - passed)
    if uncovered:
        raise ReleaseSuiteError(
            "local capability skips lack an exact-matrix pass: " + ", ".join(uncovered))
    return {
        "schema_version": 1,
        "status": "certified",
        "subject": matrix["subject"],
        "local": local_report,
        "matrix": matrix,
        "covered_local_skips": local_skips,
    }


def certify_certificates(matrices, *, qualification, policy, expected_commit,
                         expected_root):
    if not re.fullmatch(r"[0-9a-f]{40}", str(expected_commit)) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected_root)):
        raise ReleaseSuiteError("release suite identity is invalid")
    try:
        policy = loom_suite_plan._validate_seal(
            policy, "policy_sha256", loom_suite_plan.seal_policy)
    except loom_suite_plan.SuitePlanError as exc:
        raise ReleaseSuiteError(f"release suite policy is invalid: {exc}") from exc
    if policy["authority_mode"] != "certificate":
        raise ReleaseSuiteError("certificate authority is disabled by serial policy")
    if not isinstance(matrices, list) or not matrices:
        raise ReleaseSuiteError("release suite matrix certificates are missing")
    try:
        matrices = [loom_suite_certificate.verify_matrix(value)
                    for value in matrices]
    except loom_suite_certificate.CertificateError as exc:
        raise ReleaseSuiteError(str(exc)) from exc
    try:
        qualification = loom_suite_certificate.verify_qualification(
            qualification, matrices, policy=policy)
    except loom_suite_certificate.CertificateError as exc:
        raise ReleaseSuiteError(str(exc)) from exc
    consumers = [value["consumer"] for value in matrices]
    if sorted(consumers) != ["compatibility", "quality"]:
        raise ReleaseSuiteError(
            "release suite requires separate quality and compatibility certificates")
    expected_subject = {
        "source_commit": expected_commit,
        "public_root_sha256": expected_root,
    }
    for matrix in matrices:
        observed = matrix["subject"]
        if observed.get("source_commit") != expected_subject["source_commit"] \
                or observed.get("public_root_sha256") != expected_subject[
                    "public_root_sha256"]:
            raise ReleaseSuiteError(
                "matrix certificate is not certified for this release subject")
    rows = [{
        "consumer": matrix["consumer"],
        "matrix_certificate_sha256": matrix["matrix_certificate_sha256"],
    } for matrix in sorted(matrices, key=lambda item: item["consumer"])]
    body = {
        "schema_version": 2, "status": "certified", "mode": "certificate",
        "subject": expected_subject, "policy_sha256": policy["policy_sha256"],
        "qualification_sha256": qualification["qualification_sha256"],
        "matrices": rows,
    }
    return {**body, "suite_certificate_sha256": loom_suite_plan.digest(body)}


def certify_serial_evidence(quality_paths, compatibility_paths, *, policy,
                            expected_commit, expected_root, required_cells=15,
                            enforce_release_topology=True):
    """Compile already-executed authoritative serial cells without rerunning tests."""
    if not re.fullmatch(r"[0-9a-f]{40}", str(expected_commit)) \
            or not re.fullmatch(r"[0-9a-f]{64}", str(expected_root)) \
            or type(required_cells) is not int or required_cells < 1:
        raise ReleaseSuiteError("serial release evidence identity is invalid")
    try:
        policy = loom_suite_plan._validate_seal(
            policy, "policy_sha256", loom_suite_plan.seal_policy)
    except loom_suite_plan.SuitePlanError as exc:
        raise ReleaseSuiteError(f"release suite policy is invalid: {exc}") from exc
    if policy["authority_mode"] != "serial":
        raise ReleaseSuiteError("serial evidence compilation is disabled by policy")
    rows = []
    for consumer, paths in (("quality", quality_paths),
                            ("compatibility", compatibility_paths)):
        paths = [Path(path) for path in paths]
        if len(paths) != required_cells:
            raise ReleaseSuiteError(
                f"{consumer} serial evidence has incomplete cell coverage")
        reports = _read_reports(paths)
        inventories = []
        environments = []
        environment_values = []
        passed_by = {}
        skipped = set()
        for report in reports:
            try:
                outcomes, environment_sha256 = _validate_serial_report(
                    report, expected_commit=expected_commit,
                    expected_root=expected_root)
            except ReleaseSuiteError as exc:
                raise ReleaseSuiteError(f"{consumer} {exc}") from exc
            inventories.append(sorted(outcomes))
            environments.append(environment_sha256)
            environment_values.append(report["binding"]["environment"])
            for test, status in outcomes.items():
                if status == "passed":
                    passed_by.setdefault(test, set()).add(environment_sha256)
                else:
                    skipped.add((test, environment_sha256))
        if any(value != inventories[0] for value in inventories[1:]) \
                or len(environments) != len(set(environments)):
            raise ReleaseSuiteError(
                f"{consumer} serial evidence coverage is inconsistent")
        if enforce_release_topology:
            loom_suite_certificate._require_release_topology(
                [{"environment": value} for value in environment_values], consumer)
        uncovered = sorted({test for test, environment in skipped
                            if not any(other != environment for other in
                                       passed_by.get(test, set()))})
        if uncovered:
            raise ReleaseSuiteError(
                f"{consumer} serial evidence has uncovered skips: "
                + ", ".join(uncovered))
        report_digests = sorted(
            loom_reliability.file_sha256(path) for path in paths)
        rows.append({"consumer": consumer, "cells": len(paths),
                     "matrix_sha256": loom_suite_plan.digest({
                         "consumer": consumer, "reports": report_digests,
                         "subject": {"source_commit": expected_commit,
                                     "public_root_sha256": expected_root}})})
    body = {"schema_version": 2, "status": "certified",
            "mode": "serial-evidence",
            "subject": {"source_commit": expected_commit,
                        "public_root_sha256": expected_root},
            "policy_sha256": policy["policy_sha256"], "matrices": rows}
    return {**body, "suite_certificate_sha256": loom_suite_plan.digest(body)}


def verify_compiled(value, *, policy, expected_commit, expected_root):
    """Verify one closed compiled release-suite certificate without rerunning tests."""
    try:
        policy = loom_suite_plan._validate_seal(
            policy, "policy_sha256", loom_suite_plan.seal_policy)
    except loom_suite_plan.SuitePlanError as exc:
        raise ReleaseSuiteError(f"release suite policy is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "status", "mode", "subject", "policy_sha256",
            "matrices", "suite_certificate_sha256"} | (
                {"qualification_sha256"}
                if isinstance(value, dict) and value.get("mode") == "certificate"
                else set()):
        raise ReleaseSuiteError("compiled release suite is not closed")
    body = {key: item for key, item in value.items()
            if key != "suite_certificate_sha256"}
    if value.get("schema_version") != 2 or value.get("status") != "certified" \
            or value.get("mode") not in {"serial-evidence", "certificate"} \
            or value.get("subject") != {
                "source_commit": expected_commit,
                "public_root_sha256": expected_root} \
            or value.get("policy_sha256") != policy["policy_sha256"] \
            or value.get("suite_certificate_sha256") != loom_suite_plan.digest(body):
        raise ReleaseSuiteError("compiled release suite identity is invalid")
    expected_mode = ("certificate" if policy["authority_mode"] == "certificate"
                     else "serial-evidence")
    if value["mode"] != expected_mode:
        raise ReleaseSuiteError("compiled release suite disagrees with authority policy")
    rows = value.get("matrices")
    if not isinstance(rows, list) or len(rows) != 2 \
            or sorted(row.get("consumer") for row in rows
                      if isinstance(row, dict)) != ["compatibility", "quality"]:
        raise ReleaseSuiteError("compiled release suite matrix coverage is incomplete")
    expected_fields = ({"consumer", "matrix_certificate_sha256"}
                       if value["mode"] == "certificate"
                       else {"consumer", "cells", "matrix_sha256"})
    for row in rows:
        digest_field = ("matrix_certificate_sha256" if value["mode"] == "certificate"
                        else "matrix_sha256")
        if not isinstance(row, dict) or set(row) != expected_fields \
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get(digest_field, ""))) \
                or value["mode"] == "serial-evidence" and row.get("cells") != 15:
            raise ReleaseSuiteError("compiled release suite matrix row is invalid")
    if value["mode"] == "certificate" and not re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("qualification_sha256", ""))):
        raise ReleaseSuiteError("compiled release suite qualification is invalid")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-report", action="append")
    parser.add_argument("--matrix-certificate", action="append")
    parser.add_argument("--quality-report", action="append")
    parser.add_argument("--compatibility-report", action="append")
    parser.add_argument("--serial-evidence-only", action="store_true")
    parser.add_argument("--verify", metavar="SUITE_CERTIFICATE")
    parser.add_argument("--policy")
    parser.add_argument("--qualification")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--public-root", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        policy = (_read_json(args.policy, "release suite policy")
                  if args.policy else None)
        certificate_mode = isinstance(policy, dict) \
            and policy.get("authority_mode") == "certificate"
        if args.verify:
            if args.matrix_report or args.matrix_certificate or args.quality_report \
                    or args.compatibility_report or args.serial_evidence_only \
                    or not args.policy:
                raise ReleaseSuiteError(
                    "verification mode accepts only policy and exact subject inputs")
            result = verify_compiled(
                _read_json(args.verify, "compiled release suite"), policy=policy,
                expected_commit=args.commit, expected_root=args.public_root)
            local = None
        elif args.serial_evidence_only:
            if certificate_mode or not args.quality_report or not args.compatibility_report \
                    or args.matrix_report or args.matrix_certificate:
                raise ReleaseSuiteError(
                    "serial evidence mode requires separate quality and compatibility reports")
            result = certify_serial_evidence(
                args.quality_report, args.compatibility_report, policy=policy,
                expected_commit=args.commit, expected_root=args.public_root)
            local = None
        elif certificate_mode:
            if not args.matrix_certificate or not args.qualification or args.matrix_report:
                raise ReleaseSuiteError(
                    "certificate mode requires matrix certificates and qualification")
            result = certify_certificates(
                _read_reports(args.matrix_certificate),
                qualification=_read_qualification(args.qualification),
                policy=policy,
                expected_commit=args.commit, expected_root=args.public_root)
            local = None
        else:
            if not args.matrix_report or args.matrix_certificate:
                raise ReleaseSuiteError(
                    "serial mode requires only historical matrix reports")
            local = loom_test.run("full")
            result = certify(
                local, args.matrix_report,
                expected_commit=args.commit, expected_root=args.public_root)
        if args.verify:
            if args.output:
                raise ReleaseSuiteError("verification mode does not write output")
        else:
            if not args.output:
                raise ReleaseSuiteError("release suite output is required")
            output = loom_reliability._absolute(args.output, "release suite output")
            if output.exists():
                raise ReleaseSuiteError("release suite output already exists")
            loom_reliability.atomic_write_json(output, result)
    except (ReleaseSuiteError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    printable = {"status": result["status"]}
    if local is None:
        printable.update({"mode": result["mode"], "matrices": len(result["matrices"])})
    else:
        printable.update({
            "tests_run": local["tests_run"],
            "local_skips": len(result["covered_local_skips"]),
            "matrix_reports": result["matrix"]["reports"],
        })
    print(json.dumps(printable, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
