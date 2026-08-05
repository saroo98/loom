#!/usr/bin/env python3
"""Always emit a bounded exact-cut CI receipt, including on verifier failure."""

import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path

import loom_release
import loom_release_subject
import loom_reliability
import loom_operation_envelope
import loom_platform_probe
import loom_test


HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
RECEIPT_FIELDS = {
    "schema_version", "status", "platform", "architecture", "python",
    "source_commit", "build_root_sha256", "verified_root_sha256",
    "public_manifest_sha256", "public_file_count", "suite", "error_type",
    "error_sha256", "operation_id", "environment", "receipt_sha256",
}
SUITE_FIELDS = {
    "schema_version", "passed", "capability_complete", "capability_status",
    "returncode", "primary_failure_sha256", "operation_receipt_sha256",
    "elapsed_microseconds", "tests_run", "failure_count", "error_count",
    "failed_tests", "skip_receipts", "timings", "binding",
}
ENVIRONMENT_FIELDS = {
    "evidence_class", "requested_label", "image_os", "image_version", "os",
    "os_release", "os_version", "architecture", "python_implementation",
    "python_version", "workflow_path", "workflow_digest",
    "action_manifest_digest", "event_name", "run_id", "run_attempt",
    "environment_sha256",
}
BINDING_FIELDS = {
    "source_commit", "public_root_sha256", "environment", "platform",
    "architecture", "python", "runner",
}


def _seal(receipt):
    body = {key: value for key, value in receipt.items()
            if key != "receipt_sha256"}
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")).hexdigest()}


def _microseconds(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return None
    return max(0, int(round(value * 1_000_000)))


def _public_suite(value, *, binding=None):
    """Project verifier output onto the closed public evidence allowlist."""
    value = value if isinstance(value, dict) else {}
    skips = []
    for row in value.get("skip_receipts", []):
        if not isinstance(row, dict) or not isinstance(row.get("test"), str):
            continue
        reason = str(row.get("reason", ""))
        skips.append({
            "test": row["test"],
            "reason_code": loom_test.skip_reason_code(reason),
            "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
        })
    timings = []
    for row in value.get("timings", []):
        if not isinstance(row, dict) or not isinstance(row.get("test"), str) \
                or row.get("status") not in {"passed", "failed", "error", "skipped"}:
            continue
        duration = _microseconds(row.get("seconds"))
        if duration is None:
            continue
        timings.append({"test": row["test"], "status": row["status"],
                        "duration_microseconds": duration})
    failures = []
    for row in value.get("failed_tests", []):
        if isinstance(row, dict) and isinstance(row.get("test"), str) \
                and row.get("status") in {"failed", "error"}:
            failures.append({"test": row["test"], "status": row["status"]})
    skip_only_incomplete = value.get("passed") is True \
        and value.get("capability_complete") is False \
        and value.get("capability_status") == "requires-matrix" \
        and value.get("returncode") == 1 \
        and value.get("failure_count") == 0 \
        and value.get("error_count") == 0 \
        and value.get("failed_tests") == [] \
        and bool(skips)
    primary = None if skip_only_incomplete else value.get("primary_failure")
    body = {
        "schema_version": 2,
        "passed": value.get("passed") is True,
        "capability_complete": value.get("capability_complete") is True,
        "capability_status": value.get("capability_status") if value.get(
            "capability_status") in {"complete", "requires-matrix"} else "failed",
        "returncode": (value.get("returncode")
                       if type(value.get("returncode")) is int else None),
        "primary_failure_sha256": (
            hashlib.sha256(str(primary).encode("utf-8")).hexdigest()
            if primary is not None else None),
        "operation_receipt_sha256": (
            value.get("operation_receipt_sha256")
            if isinstance(value.get("operation_receipt_sha256"), str) else None),
        "elapsed_microseconds": _microseconds(value.get("elapsed_seconds")),
        "tests_run": (value.get("tests_run")
                      if type(value.get("tests_run")) is int else None),
        "failure_count": (value.get("failure_count")
                          if type(value.get("failure_count")) is int else None),
        "error_count": (value.get("error_count")
                        if type(value.get("error_count")) is int else None),
        "failed_tests": sorted(failures, key=lambda row: (row["test"], row["status"])),
        "skip_receipts": sorted(skips, key=lambda row: row["test"]),
        "timings": sorted(timings, key=lambda row: row["test"]),
        "binding": binding,
    }
    return body


def verify_receipt(value, *, require_static=None):
    """Validate one successful closed v2 receipt before evidence reuse."""
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS \
            or value.get("schema_version") != 2 or value.get("status") != "verified" \
            or value.get("error_type") is not None \
            or value.get("error_sha256") is not None \
            or HEX40.fullmatch(str(value.get("source_commit", ""))) is None \
            or any(HEX64.fullmatch(str(value.get(field, ""))) is None for field in (
                "build_root_sha256", "verified_root_sha256",
                "public_manifest_sha256", "receipt_sha256")) \
            or value.get("build_root_sha256") != value.get("verified_root_sha256") \
            or type(value.get("public_file_count")) is not int \
            or value["public_file_count"] < 1 \
            or value["receipt_sha256"] != _seal(value)["receipt_sha256"]:
        raise ValueError("exact-cut receipt identity is invalid")
    environment = value.get("environment")
    if not isinstance(environment, dict) or set(environment) != ENVIRONMENT_FIELDS \
            or environment.get("environment_sha256") != hashlib.sha256(json.dumps(
                {key: item for key, item in environment.items()
                 if key != "environment_sha256"}, sort_keys=True,
                separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest():
        raise ValueError("exact-cut receipt environment is invalid")
    suite = value.get("suite")
    if require_static is True and suite is not None \
            or require_static is False and suite is None:
        raise ValueError("exact-cut receipt execution mode is invalid")
    if suite is None:
        return value
    binding = suite.get("binding") if isinstance(suite, dict) else None
    timings = suite.get("timings") if isinstance(suite, dict) else None
    skips = suite.get("skip_receipts") if isinstance(suite, dict) else None
    if not isinstance(suite, dict) or set(suite) != SUITE_FIELDS \
            or suite.get("schema_version") != 2 \
            or suite.get("passed") is not True \
            or suite.get("failure_count") != 0 or suite.get("error_count") != 0 \
            or type(suite.get("tests_run")) is not int or suite["tests_run"] < 1 \
            or not isinstance(timings, list) or len(timings) != suite["tests_run"] \
            or not isinstance(skips, list) or suite.get("failed_tests") != [] \
            or suite.get("primary_failure_sha256") is not None \
            or HEX64.fullmatch(str(suite.get("operation_receipt_sha256", ""))) is None \
            or type(suite.get("elapsed_microseconds")) is not int \
            or suite["elapsed_microseconds"] < 0 \
            or not isinstance(binding, dict) or set(binding) != BINDING_FIELDS \
            or binding.get("source_commit") != value["source_commit"] \
            or binding.get("public_root_sha256") != value["verified_root_sha256"] \
            or binding.get("environment") != environment \
            or binding.get("runner") != environment.get("environment_sha256"):
        raise ValueError("exact-cut suite receipt is invalid")
    outcomes = {}
    for row in timings:
        if not isinstance(row, dict) or set(row) != {
                "test", "status", "duration_microseconds"} \
                or not isinstance(row.get("test"), str) or not row["test"] \
                or row.get("status") not in {"passed", "skipped"} \
                or type(row.get("duration_microseconds")) is not int \
                or row["duration_microseconds"] < 0 or row["test"] in outcomes:
            raise ValueError("exact-cut suite outcomes are invalid")
        outcomes[row["test"]] = row["status"]
    skip_tests = set()
    for row in skips:
        if not isinstance(row, dict) or set(row) != {
                "test", "reason_code", "reason_sha256"} \
                or row.get("test") in skip_tests \
                or row.get("reason_code") not in loom_test.AUTHORIZED_SKIP_REASON_CODES \
                or HEX64.fullmatch(str(row.get("reason_sha256", ""))) is None:
            raise ValueError("exact-cut suite skips are invalid")
        skip_tests.add(row["test"])
    observed_skips = {test for test, status in outcomes.items()
                      if status == "skipped"}
    if skip_tests != observed_skips \
            or suite.get("capability_complete") is not (not observed_skips) \
            or suite.get("capability_status") != (
                "complete" if not observed_skips else "requires-matrix") \
            or suite.get("returncode") != (0 if not observed_skips else 1):
        raise ValueError("exact-cut suite result fields are inconsistent")
    return value


def run(source, cut, output, *, suite_output=None, forbidden_tokens=(),
        static_only=False):
    source = Path(source).resolve()
    cut = Path(cut).resolve()
    output = Path(output).resolve()
    base = {
        "schema_version": 2,
        "status": "failed",
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python": platform.python_version(),
        "source_commit": os.environ.get("GITHUB_SHA"),
        "build_root_sha256": None,
        "verified_root_sha256": None,
        "public_manifest_sha256": None,
        "public_file_count": None,
        "suite": None,
        "error_type": None,
        "error_sha256": None,
        "operation_id": None,
        "environment": loom_platform_probe.release_environment(),
        "receipt_sha256": None,
    }
    envelope_path = None
    terminal_phase = "failed"
    try:
        try:
            source_subject = loom_release_subject._tree(source)["sha256"]
        except loom_release_subject.ReleaseSubjectError as exc:
            if "tree is empty" not in str(exc):
                raise
            source_subject = hashlib.sha256(
                b"loom-empty-release-subject-v1").hexdigest()
        sidecar_contract = hashlib.sha256(
            ("exact-cut-receipt:" + output.name).encode("utf-8")).hexdigest()
        # The exact-cut verifier must never add its own mutable sidecars to the
        # source tree before the public bytes are selected. The cut is already
        # required to live outside the source, so its parent is the durable,
        # source-independent authority root for this operation.
        envelope_path, envelope = loom_operation_envelope.begin(
            (cut.parent / ".loom-operations").resolve(),
            operation_class="exact-cut",
            subject_digest=source_subject,
            sidecar_type="exact-cut-receipt",
            sidecar_id=output.name,
            sidecar_digest=sidecar_contract)
        base["operation_id"] = envelope["operation_id"]
        loom_operation_envelope.transition(
            envelope_path, phase="started",
            side_effect_boundary="before-public-cut-build",
            state_may_have_changed=False)
        loom_operation_envelope.transition(
            envelope_path, phase="effect",
            side_effect_boundary="public-cut-build-started",
            state_may_have_changed=True)
        build = loom_release.build_public(
            source, cut, forbidden_tokens=list(forbidden_tokens),
            source_classification="public-release")
        base["build_root_sha256"] = build["root_sha256"]
        verified = (loom_release.verify_cut_static(
            cut, forbidden_tokens=list(forbidden_tokens)) if static_only
                    else loom_release.verify_cut(
                        cut, forbidden_tokens=list(forbidden_tokens)))
        suite = None
        if not static_only:
            binding = {
                "source_commit": os.environ.get("GITHUB_SHA") or "0" * 40,
                "public_root_sha256": verified["root_sha256"],
                "environment": base["environment"],
                "platform": (base["environment"]["image_os"] + ":" +
                             base["environment"]["image_version"]),
                "architecture": base["environment"]["architecture"],
                "python": base["environment"]["python_version"],
                "runner": base["environment"]["environment_sha256"],
            }
            suite = _public_suite(verified["suite"], binding=binding)
        base.update({
            "status": "verified",
            "verified_root_sha256": verified["root_sha256"],
            "public_manifest_sha256": verified.get("manifest_sha256"),
            "public_file_count": verified.get("files_verified"),
            "suite": suite,
        })
        terminal_phase = "passed"
    except BaseException as exc:
        message = f"{type(exc).__name__}:{exc}"
        details = getattr(exc, "details", None)
        base.update({
            "error_type": type(exc).__name__,
            "error_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
        })
        if isinstance(details, dict) and isinstance(details.get("suite"), dict):
            base["suite"] = _public_suite(details["suite"])
    finally:
        try:
            base = _seal(base)
            loom_reliability.atomic_write_json(output, base)
            if base["suite"] is not None and suite_output is not None:
                loom_reliability.atomic_write_json(suite_output, base["suite"])
            if envelope_path is not None:
                loom_operation_envelope.transition(
                    envelope_path, phase=terminal_phase,
                    side_effect_boundary="exact-cut-receipt-committed",
                    state_may_have_changed=True,
                    primary_failure=(
                        None if terminal_phase == "passed"
                        else base["error_type"] or "exact-cut-failed"),
                    cleanup_disposition=(
                        "completed" if terminal_phase == "passed" else "preserved"))
        except BaseException as final_exc:
            if base["error_type"] is None:
                message = f"{type(final_exc).__name__}:{final_exc}"
                base.update({
                    "status": "failed",
                    "error_type": type(final_exc).__name__,
                    "error_sha256": hashlib.sha256(
                        message.encode("utf-8")).hexdigest(),
                })
                base = _seal(base)
                loom_reliability.atomic_write_json(output, base)
    return base


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("cut")
    parser.add_argument("--output", required=True)
    parser.add_argument("--suite-output")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--forbidden-token", action="append", default=[])
    args = parser.parse_args(argv)
    result = run(args.source, args.cut, args.output, suite_output=args.suite_output,
                 forbidden_tokens=args.forbidden_token,
                 static_only=args.static_only)
    print(json.dumps({key: result[key] for key in (
        "status", "build_root_sha256", "verified_root_sha256", "error_type")},
        sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
