#!/usr/bin/env python3
"""Validate the closed exact-cut receipt without importing product release code."""

import hashlib
import json
import re

import loom_suite_harness


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


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def seal_receipt(receipt):
    body = {key: value for key, value in receipt.items()
            if key != "receipt_sha256"}
    return {
        **body,
        "receipt_sha256": hashlib.sha256(_canonical(body)).hexdigest(),
    }


def verify_receipt(value, *, require_static=None):
    """Validate one successful closed v2 receipt before evidence reuse."""
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("status") != "verified" \
            or value.get("error_type") is not None \
            or value.get("error_sha256") is not None \
            or HEX40.fullmatch(str(value.get("source_commit", ""))) is None \
            or any(HEX64.fullmatch(str(value.get(field, ""))) is None
                   for field in ("build_root_sha256", "verified_root_sha256",
                                 "public_manifest_sha256", "receipt_sha256")) \
            or value.get("build_root_sha256") != value.get(
                "verified_root_sha256") \
            or type(value.get("public_file_count")) is not int \
            or value["public_file_count"] < 1 \
            or value["receipt_sha256"] != seal_receipt(value)[
                "receipt_sha256"]:
        raise ValueError("exact-cut receipt identity is invalid")
    environment = value.get("environment")
    if not isinstance(environment, dict) \
            or set(environment) != ENVIRONMENT_FIELDS \
            or environment.get("evidence_class") not in {
                "ci-reproduced", "local-unattested"} \
            or environment.get("environment_sha256") != hashlib.sha256(
                _canonical({key: item for key, item in environment.items()
                            if key != "environment_sha256"})).hexdigest():
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
            or suite.get("failure_count") != 0 \
            or suite.get("error_count") != 0 \
            or type(suite.get("tests_run")) is not int \
            or suite["tests_run"] < 1 \
            or not isinstance(timings, list) \
            or len(timings) != suite["tests_run"] \
            or not isinstance(skips, list) \
            or suite.get("failed_tests") != [] \
            or suite.get("primary_failure_sha256") is not None \
            or HEX64.fullmatch(str(suite.get(
                "operation_receipt_sha256", ""))) is None \
            or type(suite.get("elapsed_microseconds")) is not int \
            or suite["elapsed_microseconds"] < 0 \
            or not isinstance(binding, dict) \
            or set(binding) != BINDING_FIELDS \
            or binding.get("source_commit") != value["source_commit"] \
            or binding.get("public_root_sha256") != value[
                "verified_root_sha256"] \
            or binding.get("environment") != environment \
            or binding.get("runner") != environment.get(
                "environment_sha256") \
            or binding.get("platform") != (
                environment.get("image_os", "") + ":" +
                environment.get("image_version", "")) \
            or binding.get("architecture") != environment.get(
                "architecture") \
            or binding.get("python") != environment.get("python_version"):
        raise ValueError("exact-cut suite receipt is invalid")
    outcomes = {}
    for row in timings:
        if not isinstance(row, dict) or set(row) != {
                "test", "status", "duration_microseconds"} \
                or not isinstance(row.get("test"), str) or not row["test"] \
                or row.get("status") not in {"passed", "skipped"} \
                or type(row.get("duration_microseconds")) is not int \
                or row["duration_microseconds"] < 0 \
                or row["test"] in outcomes:
            raise ValueError("exact-cut suite outcomes are invalid")
        outcomes[row["test"]] = row["status"]
    skip_tests = set()
    for row in skips:
        if not isinstance(row, dict) or set(row) != {
                "test", "reason_code", "reason_sha256"} \
                or row.get("test") in skip_tests \
                or row.get("reason_code") not in \
                loom_suite_harness.AUTHORIZED_SKIP_REASON_CODES \
                or HEX64.fullmatch(str(row.get("reason_sha256", ""))) is None:
            raise ValueError("exact-cut suite skips are invalid")
        skip_tests.add(row["test"])
    observed_skips = {
        test for test, status in outcomes.items() if status == "skipped"
    }
    if skip_tests != observed_skips \
            or suite.get("capability_complete") is not (not observed_skips) \
            or suite.get("capability_status") != (
                "complete" if not observed_skips else "requires-matrix") \
            or suite.get("returncode") != (0 if not observed_skips else 1):
        raise ValueError("exact-cut suite result fields are inconsistent")
    return value
