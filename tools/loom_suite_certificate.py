#!/usr/bin/env python3
"""Compile and verify fail-closed exact-subject suite certificates."""

import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import re
from pathlib import Path

import loom_reliability
import loom_exact_cut_ci
import loom_operation_supervisor
import loom_release
import loom_release_candidate
import loom_release_rollback
import loom_suite_certificate_core
import loom_suite_plan
import loom_suite_worker
import loom_test


PRECEDENCE = (
    "UNSAFE_TRANSPORT",
    "SCHEMA",
    "RECEIPT_DIGEST",
    "UNTRUSTED_AUTHORITY",
    "WRONG_SUBJECT",
    "WRONG_ENVIRONMENT",
    "WRONG_POLICY",
    "WORKER_NOT_TERMINAL",
    "CANDIDATE_MUTATION",
    "PRIVACY_FAILURE",
    "INVENTORY_MISMATCH",
    "TEST_FAILURE",
    "UNAUTHORIZED_SKIP",
    "FRESHNESS",
)
RELEASE_MATRIX_LABELS = {
    "quality": ("ubuntu-latest", "macos-latest", "windows-latest"),
    "compatibility": ("ubuntu-24.04", "windows-2025", "macos-15"),
}
RELEASE_MATRIX_PYTHONS = ("3.10", "3.11", "3.12", "3.13", "3.14")
QUALIFICATION_CODE_PATHS = (
    "tools/loom_exact_cut_ci.py", "tools/loom_release_candidate.py",
    "tools/loom_release_rollback.py", "tools/loom_suite_plan.py",
    "tools/loom_suite_worker.py",
    "tools/loom_suite_certificate.py", "tools/loom_release_suite.py",
    "tools/loom_clean_room.py", "schemas/suite-inventory-v1.schema.json",
    "schemas/suite-shard-plan-v1.schema.json",
    "schemas/suite-worker-receipt-v1.schema.json",
    "schemas/suite-cell-certificate-v1.schema.json",
    "schemas/suite-matrix-certificate-v1.schema.json",
    "schemas/suite-qualification-v1.schema.json",
    "schemas/suite-failure-diagnostic-v1.schema.json",
    "schemas/serial-suite-failure-diagnostic-v1.schema.json",
    "schemas/exact-cut-ci-receipt-v2.schema.json",
    "schemas/release-reproducibility-receipt-v1.schema.json",
    "schemas/release-rollback-evidence.schema.json",
)
FAULT_TESTS = {
    "malformed-evidence": "test_release_candidate.ReleaseCandidateTests."
                          "test_public_json_inputs_reject_duplicate_keys_and_non_finite_numbers",
    "corrupt-canonical-receipt": "test_suite_certificate.SuiteCertificateTests."
                                 "test_corrupt_receipt_digest_is_distinct_from_semantic_failure",
    "mixed-runs": "test_suite_certificate.SuiteCertificateTests."
                  "test_fail_closed_precedence_prefers_subject_over_later_test_failure",
    "wrong-subjects": "test_suite_certificate.SuiteCertificateTests."
                      "test_fail_closed_precedence_prefers_subject_over_later_test_failure",
    "candidate-mutation": "test_suite_worker.SuiteWorkerTests."
                          "test_worker_fails_closed_when_the_candidate_copy_changes",
    "privacy-leakage": "test_suite_certificate.SuiteCertificateTests."
                       "test_missing_duplicate_mutated_and_private_receipts_refuse",
    "timeouts": "test_suite_worker.SuiteWorkerTests."
                "test_worker_timeout_is_terminal_and_confirms_no_survivors",
    "survivor-cleanup": "test_suite_worker.SuiteWorkerTests."
                        "test_worker_timeout_is_terminal_and_confirms_no_survivors",
    "missing-tests": "test_suite_certificate.SuiteCertificateTests."
                     "test_missing_duplicate_mutated_and_private_receipts_refuse",
    "unexpected-tests": "test_suite_certificate.SuiteCertificateTests."
                        "test_cell_verifier_refuses_unknown_nested_fields_and_duplicate_tests",
    "unauthorized-skips": "test_suite_worker.SuiteWorkerTests."
                          "test_unclassified_skip_fails_closed_with_a_terminal_receipt",
    "uncovered-skips": "test_suite_certificate.SuiteCertificateTests."
                       "test_cell_records_skips_and_matrix_rejects_uncovered_skip",
    "altered-archives": "test_release_candidate.ReleaseCandidateTests."
                        "test_mismatched_candidate_is_rejected",
    "asset-overwrite": "test_release_candidate.ReleaseCandidateTests."
                       "test_immutable_staging_never_overwrites",
    "malformed-promotion-gate": "test_release_promotion.ReleasePromotionTests."
                                "test_gate_loader_rejects_duplicate_keys",
}
WINDOWS_FAULT_TESTS = {
    "windows-runtime-root-cleanup": "test_suite_worker.SuiteWorkerTests."
                                    "test_windows_external_runtime_root_is_cleaned_if_supervisor_raises",
}
WORKER_FAILURE_CODES = {
    "shard execution lanes are invalid": "WORKER_LANES",
    "shard identity is invalid": "WORKER_SHARD_IDENTITY",
    "shard plan is invalid": "WORKER_PLAN",
    "worker harness subject is invalid": "WORKER_HARNESS_SUBJECT",
    "worker operation receipt is invalid": "WORKER_OPERATION_RECEIPT",
    "worker output already exists": "WORKER_OUTPUT_EXISTS",
    "worker output root is invalid": "WORKER_OUTPUT_ROOT",
    "worker public-cut subject is invalid": "WORKER_PUBLIC_CUT_SUBJECT",
    "worker receipt cannot claim success": "WORKER_SUCCESS_CLAIM",
    "worker receipt contains private evidence": "WORKER_PRIVATE_EVIDENCE",
    "worker receipt digest is invalid": "WORKER_RECEIPT_DIGEST",
    "worker receipt duration is invalid": "WORKER_RECEIPT_DURATION",
    "worker receipt fields are invalid": "WORKER_RECEIPT_FIELDS",
    "worker receipt identity is invalid": "WORKER_RECEIPT_IDENTITY",
    "worker receipt inventory is invalid": "WORKER_RECEIPT_INVENTORY",
    "worker receipt is already sealed": "WORKER_RECEIPT_EXISTS",
    "worker receipt is invalid": "WORKER_RECEIPT_JSON",
    "worker receipt outcome counts are invalid": "WORKER_RECEIPT_COUNTS",
    "worker receipt outcome is invalid": "WORKER_RECEIPT_OUTCOME",
    "worker receipt terminal state is invalid": "WORKER_RECEIPT_TERMINAL",
    "worker request fields are invalid": "WORKER_REQUEST_FIELDS",
    "worker skip authorization state is invalid": "WORKER_SKIP_AUTHORIZATION",
}


class CertificateError(RuntimeError):
    def __init__(self, message, findings, public_details=None):
        unique = sorted(set(findings), key=lambda item: PRECEDENCE.index(item))
        self.findings = unique
        self.primary_reason = unique[0] if unique else "SCHEMA"
        self.public_details = public_details or {
            "failed_tests": [], "missing_tests": [], "unexpected_tests": [],
        }
        if set(self.public_details) != {
                "failed_tests", "missing_tests", "unexpected_tests"} \
                or any(not isinstance(values, list)
                       or values != sorted(set(values))
                       or any(not isinstance(test_id, str)
                              or not 3 <= len(test_id) <= 512
                              for test_id in values)
                       for values in self.public_details.values()) \
                or not loom_suite_worker._privacy_clean(self.public_details):
            raise ValueError("certificate public failure details are invalid")
        super().__init__(f"{message}: {self.primary_reason}")


def _shadow_failure_code(exc):
    """Project an internal exception onto a closed, content-free public code."""
    if isinstance(exc, CertificateError):
        return "CERTIFICATE_" + exc.primary_reason
    if isinstance(exc, loom_suite_worker.SuiteWorkerError):
        message = str(exc)
        if message in WORKER_FAILURE_CODES:
            return WORKER_FAILURE_CODES[message]
        if message.endswith(" is unsafe"):
            return "WORKER_INPUT_UNSAFE"
        if message.endswith(" is unreadable"):
            return "WORKER_INPUT_UNREADABLE"
        return "WORKER_INTERNAL"
    if isinstance(exc, loom_suite_plan.SuitePlanError):
        return "PLAN_VALIDATION"
    return "OS_OPERATION"


def _raise(findings, message="suite certificate refused", public_details=None):
    if findings:
        raise CertificateError(message, findings, public_details)


def _primary(findings):
    ordered = sorted(
        set(findings), key=lambda item: PRECEDENCE.index(item))
    return ordered[0] if ordered else "SCHEMA"


def _require_release_topology(cells, consumer):
    if consumer not in RELEASE_MATRIX_LABELS:
        return
    expected = {(label, python) for label in RELEASE_MATRIX_LABELS[consumer]
                for python in RELEASE_MATRIX_PYTHONS}
    observed = set()
    for cell in cells:
        environment = cell["environment"]
        matched = re.fullmatch(r"([0-9]+\.[0-9]+)\.[0-9]+(?:[-+].*)?",
                               environment["python_version"])
        if matched is None:
            raise CertificateError("matrix Python identity is invalid",
                                   ["WRONG_ENVIRONMENT"])
        observed.add((environment["requested_label"], matched.group(1)))
    if len(cells) != 15 or observed != expected:
        raise CertificateError("release matrix topology is incomplete",
                               ["INVENTORY_MISMATCH"])


def _validated_inputs(inventory, plan, policy):
    inventory = loom_suite_plan._validate_seal(
        inventory, "inventory_sha256", loom_suite_plan.seal_inventory)
    policy = loom_suite_plan._validate_seal(
        policy, "policy_sha256", loom_suite_plan.seal_policy)
    if not isinstance(plan, dict) or plan.get("plan_sha256") != \
            loom_suite_plan.digest({key: value for key, value in plan.items()
                                    if key != "plan_sha256"}) \
            or plan.get("inventory_sha256") != inventory["inventory_sha256"] \
            or plan.get("policy_sha256") != policy["policy_sha256"]:
        raise CertificateError("suite certificate inputs are invalid", ["WRONG_POLICY"])
    return inventory, plan, policy


def _cell_execution_microseconds(workers, *, max_parallel_workers=None):
    exclusive = [
        row["duration_microseconds"] for row in workers
        if row.get("exclusive") is True or row.get("shard_id") == "exclusive"
    ]
    general = [
        row["duration_microseconds"] for row in workers
        if row.get("exclusive") is False
        or (row.get("exclusive") is None
            and row.get("shard_id") != "exclusive")
    ]
    if max_parallel_workers is None or max_parallel_workers <= 1:
        return sum(exclusive) + max(general, default=0)
    return max([*exclusive, *general], default=0)


def compile_cell(inventory, plan, receipts, *, policy):
    inventory, plan, policy = _validated_inputs(inventory, plan, policy)
    if not isinstance(receipts, list) or not receipts:
        raise CertificateError("suite certificate receipts are invalid",
                               ["INVENTORY_MISMATCH"])
    findings = []
    valid_receipts = []
    for receipt in receipts:
        try:
            loom_suite_worker.validate_receipt(receipt)
        except loom_suite_worker.SuiteWorkerError as exc:
            findings.append(
                "RECEIPT_DIGEST" if "digest" in str(exc) else "SCHEMA")
        else:
            valid_receipts.append(receipt)
            findings.extend(receipt["findings"])
    expected_shards = {row["shard_id"]: row for row in plan["shards"]}
    received_ids = [row["shard_id"] for row in valid_receipts]
    if len(received_ids) != len(set(received_ids)) \
            or set(received_ids) != set(expected_shards):
        findings.append("INVENTORY_MISMATCH")
    expected_tests_by_module = {
        row["module"]: row["tests"] for row in inventory["modules"]}
    outcomes = []
    observed_ids = []
    for receipt in valid_receipts:
        shard = expected_shards.get(receipt["shard_id"])
        if receipt["subject"] != inventory["subject"]:
            findings.append("WRONG_SUBJECT")
        if receipt["environment"] != inventory["environment"]:
            findings.append("WRONG_ENVIRONMENT")
        if receipt["inventory_sha256"] != inventory["inventory_sha256"] \
                or receipt["policy_sha256"] != policy["policy_sha256"] \
                or receipt["timing_profile_sha256"] != plan[
                    "timing_profile_sha256"] \
                or receipt["plan_sha256"] != plan["plan_sha256"]:
            findings.append("WRONG_POLICY")
        operation = receipt["operation"]
        operation_terminal = operation.get("survivors_confirmed_zero") is True \
            and operation.get("protected_roots_unchanged") is True \
            and (operation.get("status") == "passed" or (
                operation.get("returncode") == 1
                and operation.get("primary_failure") == "nonzero-exit"
                and "TEST_FAILURE" in receipt["findings"]))
        if not operation_terminal:
            findings.append("WORKER_NOT_TERMINAL")
        if receipt["mutation_clean"] is not True \
                or receipt["pre_manifest_sha256"] != \
                receipt["post_manifest_sha256"]:
            findings.append("CANDIDATE_MUTATION")
        if receipt["privacy_clean"] is not True:
            findings.append("PRIVACY_FAILURE")
        if receipt["runtime_roots_clean"] is not True:
            findings.append("WORKER_NOT_TERMINAL")
        if shard is None:
            findings.append("INVENTORY_MISMATCH")
            continue
        expected_tests = sorted(
            test_id for module in shard["modules"]
            for test_id in expected_tests_by_module[module])
        if receipt["exclusive"] != shard["exclusive"] \
                or receipt["expected_modules"] != shard["modules"] \
                or receipt["expected_tests"] != expected_tests:
            findings.append("INVENTORY_MISMATCH")
        shard_outcomes = receipt["observed_tests"]
        shard_ids = [row.get("test") for row in shard_outcomes]
        if shard_ids != sorted(expected_tests) or len(shard_ids) != len(set(shard_ids)) \
                or receipt["test_count"] != len(shard_outcomes):
            findings.append("INVENTORY_MISMATCH")
        observed_ids.extend(shard_ids)
        outcomes.extend(shard_outcomes)
        if receipt["failure_count"] or receipt["error_count"] \
                or any(row.get("status") in {"failed", "error"}
                       for row in shard_outcomes):
            findings.append("TEST_FAILURE")
    expected_all = sorted(
        test_id for row in inventory["modules"] for test_id in row["tests"])
    if sorted(observed_ids) != expected_all or len(observed_ids) != len(
            set(observed_ids)):
        findings.append("INVENTORY_MISMATCH")
    _raise(findings, public_details={
        "failed_tests": sorted(
            row["test"] for row in outcomes
            if row.get("status") in {"failed", "error"}),
        "missing_tests": sorted(set(expected_all) - set(observed_ids)),
        "unexpected_tests": sorted(set(observed_ids) - set(expected_all)),
    })
    outcomes.sort(key=lambda row: row["test"])
    max_parallel_workers = plan["max_parallel_workers"]
    body = {
        "schema_version": 1, "status": "certified",
        "subject": inventory["subject"],
        "environment": inventory["environment"],
        "environment_sha256": loom_suite_plan.digest(inventory["environment"]),
        "inventory_sha256": inventory["inventory_sha256"],
        "harness_sha256": inventory["harness_sha256"],
        "policy_sha256": policy["policy_sha256"],
        "timing_profile_sha256": plan["timing_profile_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "execution_model": "bounded-parallel-v1",
        "max_parallel_workers": max_parallel_workers,
        "worker_receipts": [{
            "shard_id": receipt["shard_id"],
            "worker_receipt_sha256": receipt["worker_receipt_sha256"],
            "duration_microseconds": receipt["duration_microseconds"],
        } for receipt in sorted(valid_receipts, key=lambda row: row["shard_id"])],
        "execution_microseconds": _cell_execution_microseconds(
            valid_receipts, max_parallel_workers=max_parallel_workers),
        "outcomes": outcomes,
        "outcomes_sha256": loom_suite_plan.digest(outcomes),
        "test_count": len(outcomes),
        "passed_count": sum(row["status"] == "passed" for row in outcomes),
        "failure_count": 0, "error_count": 0,
        "skip_count": sum(row["status"] == "skipped" for row in outcomes),
    }
    return {**body, "cell_certificate_sha256": loom_suite_plan.digest(body)}


def verify_cell(value):
    if not isinstance(value, dict) or "cell_certificate_sha256" not in value:
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    body = {key: item for key, item in value.items()
            if key != "cell_certificate_sha256"}
    if value["cell_certificate_sha256"] != loom_suite_plan.digest(body):
        raise CertificateError("cell certificate is invalid", ["RECEIPT_DIGEST"])
    fields = {
            "schema_version", "status", "subject", "environment",
            "environment_sha256", "inventory_sha256", "harness_sha256",
            "policy_sha256", "timing_profile_sha256", "plan_sha256",
            "worker_receipts", "execution_microseconds", "outcomes",
            "outcomes_sha256", "test_count",
            "passed_count", "failure_count", "error_count", "skip_count"}
    current_fields = fields | {"execution_model", "max_parallel_workers"}
    current = set(body) == current_fields
    if (set(body) != fields and not current) \
            or body.get("schema_version") != 1 \
            or body.get("status") != "certified" \
            or (current and (
                body.get("execution_model") != "bounded-parallel-v1"
                or type(body.get("max_parallel_workers")) is not int
                or not 1 <= body["max_parallel_workers"] <= 8192)):
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    try:
        loom_suite_plan._subject(body.get("subject"))
        loom_suite_plan._environment(body.get("environment"))
    except loom_suite_plan.SuitePlanError as exc:
        raise CertificateError("cell certificate is invalid", ["SCHEMA"]) from exc
    digest_fields = (
        "environment_sha256", "inventory_sha256", "harness_sha256",
        "policy_sha256", "timing_profile_sha256", "plan_sha256",
        "outcomes_sha256",
    )
    if any(loom_suite_plan.HEX64.fullmatch(str(body.get(field, ""))) is None
           for field in digest_fields) \
            or body["environment_sha256"] != loom_suite_plan.digest(
                body["environment"]):
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    workers = body.get("worker_receipts")
    if not isinstance(workers, list) or not workers:
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    worker_ids = []
    worker_digests = []
    for row in workers:
        if not isinstance(row, dict) or set(row) != {
                "shard_id", "worker_receipt_sha256", "duration_microseconds"} \
                or re.fullmatch(r"^(exclusive|general-[0-9]{3})$", str(
                    row.get("shard_id", ""))) is None \
                or loom_suite_plan.HEX64.fullmatch(str(
                    row.get("worker_receipt_sha256", ""))) is None \
                or type(row.get("duration_microseconds")) is not int \
                or row["duration_microseconds"] < 0:
            raise CertificateError("cell certificate is invalid", ["SCHEMA"])
        worker_ids.append(row["shard_id"])
        worker_digests.append(row["worker_receipt_sha256"])
    if worker_ids != sorted(worker_ids) or len(worker_ids) != len(set(worker_ids)) \
            or len(worker_digests) != len(set(worker_digests)):
        raise CertificateError("cell certificate is invalid",
                               ["INVENTORY_MISMATCH"])
    if current and ((body["max_parallel_workers"] > 1
                     and len(workers) > body["max_parallel_workers"])
                    or (body["max_parallel_workers"] == 1
                        and len(workers) > 2)):
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    expected_execution = _cell_execution_microseconds(
        workers, max_parallel_workers=(
            body["max_parallel_workers"] if current else None))
    if type(body.get("execution_microseconds")) is not int \
            or body["execution_microseconds"] != expected_execution:
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    outcomes = body.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    for row in outcomes:
        if not isinstance(row, dict) or row.get("status") not in {
                "passed", "skipped"} or not isinstance(row.get("test"), str) \
                or not 3 <= len(row["test"]) <= 512:
            raise CertificateError("cell certificate is invalid", ["SCHEMA"])
        expected_fields = ({"test", "status", "skip_reason_code",
                            "skip_reason_sha256"}
                           if row["status"] == "skipped" else {"test", "status"})
        if set(row) != expected_fields \
                or (row["status"] == "skipped" and
                    (row.get("skip_reason_code") not in
                     loom_test.AUTHORIZED_SKIP_REASON_CODES
                     or loom_suite_plan.HEX64.fullmatch(str(
                         row.get("skip_reason_sha256", ""))) is None)):
            raise CertificateError("cell certificate is invalid", ["SCHEMA"])
    test_ids = [row["test"] for row in outcomes]
    passed_count = sum(row["status"] == "passed" for row in outcomes)
    skip_count = sum(row["status"] == "skipped" for row in outcomes)
    counts = {
        "test_count": len(outcomes), "passed_count": passed_count,
        "failure_count": 0, "error_count": 0, "skip_count": skip_count,
    }
    if test_ids != sorted(test_ids) or len(test_ids) != len(set(test_ids)) \
            or body["outcomes_sha256"] != loom_suite_plan.digest(outcomes) \
            or any(type(body.get(field)) is not int or body[field] != count
                   for field, count in counts.items()) \
            or passed_count + skip_count != len(outcomes):
        raise CertificateError("cell certificate is invalid",
                               ["INVENTORY_MISMATCH"])
    return value


def compare_shadow(serial_report, certificate):
    verify_cell(certificate)
    if not isinstance(serial_report, dict):
        raise CertificateError("shadow parity report is invalid", ["SCHEMA"])
    skip_hashes = {
        row["test"]: (row["reason_sha256"] if isinstance(
            row.get("reason_sha256"), str) else hashlib.sha256(
                str(row.get("reason", "")).encode("utf-8")).hexdigest())
        for row in serial_report.get("skip_receipts", []) if isinstance(row, dict)
        and isinstance(row.get("test"), str)
    }
    skip_codes = {
        row["test"]: (row.get("reason_code") if row.get("reason_code") in
                      loom_test.AUTHORIZED_SKIP_REASON_CODES else
                      loom_test.skip_reason_code(row.get("reason", "")))
        for row in serial_report.get("skip_receipts", []) if isinstance(row, dict)
        and isinstance(row.get("test"), str)
    }
    outcomes = []
    for row in serial_report.get("timings", []):
        if not isinstance(row, dict) or row.get("status") not in {
                "passed", "failed", "error", "skipped"}:
            raise CertificateError("shadow parity report is invalid", ["SCHEMA"])
        outcome = {"test": row["test"], "status": row["status"]}
        if row["status"] == "skipped":
            outcome["skip_reason_code"] = skip_codes.get(
                row["test"], "unclassified")
            outcome["skip_reason_sha256"] = skip_hashes.get(
                row["test"], hashlib.sha256(b"").hexdigest())
        outcomes.append(outcome)
    outcomes.sort(key=lambda row: row["test"])
    if outcomes != certificate["outcomes"]:
        raise CertificateError("shadow parity mismatch", ["INVENTORY_MISMATCH"])
    serial_microseconds = serial_report.get("elapsed_microseconds")
    if type(serial_microseconds) is not int or serial_microseconds < 0:
        serial_microseconds = 0
        for row in serial_report.get("timings", []):
            duration = row.get("duration_microseconds") if isinstance(row, dict) \
                else None
            if type(duration) is int and duration >= 0:
                serial_microseconds += duration
    body = {
        "schema_version": 2, "status": "matched",
        "subject_sha256": loom_suite_plan.digest(certificate["subject"]),
        "environment_sha256": certificate["environment_sha256"],
        "serial_suite_sha256": loom_suite_plan.digest(serial_report),
        "serial_outcomes_sha256": loom_suite_plan.digest(outcomes),
        "sharded_outcomes_sha256": certificate["outcomes_sha256"],
        "cell_certificate_sha256": certificate["cell_certificate_sha256"],
        "serial_execution_microseconds": serial_microseconds,
        "sharded_execution_microseconds": certificate[
            "execution_microseconds"],
        "test_count": len(outcomes),
    }
    return {**body, "comparison_sha256": loom_suite_plan.digest(body)}


def compile_matrix(certificates, *, consumer, required_environments):
    if consumer not in {"quality", "compatibility", "clean-room", "release"} \
            or not isinstance(certificates, list) or not certificates \
            or not isinstance(required_environments, list):
        raise CertificateError("matrix certificate inputs are invalid", ["SCHEMA"])
    for certificate in certificates:
        verify_cell(certificate)
    environments = [row["environment_sha256"] for row in certificates]
    subjects = [row["subject"] for row in certificates]
    if len(environments) != len(set(environments)) \
            or set(environments) != set(required_environments):
        raise CertificateError("matrix certificate coverage is incomplete",
                               ["INVENTORY_MISMATCH"])
    if any(subject != subjects[0] for subject in subjects[1:]):
        raise CertificateError("matrix certificate subjects differ", ["WRONG_SUBJECT"])
    _require_release_topology(certificates, consumer)
    passed = {
        outcome["test"]
        for certificate in certificates
        for outcome in certificate["outcomes"]
        if outcome["status"] == "passed"
    }
    uncovered = {
        outcome["test"]
        for certificate in certificates
        for outcome in certificate["outcomes"]
        if outcome["status"] == "skipped" and outcome["test"] not in passed
    }
    if uncovered:
        raise CertificateError(
            "matrix certificate contains uncovered skips", ["UNAUTHORIZED_SKIP"])
    test_inventories = [[outcome["test"] for outcome in row["outcomes"]]
                        for row in certificates]
    if any(inventory != test_inventories[0]
           for inventory in test_inventories[1:]):
        raise CertificateError("matrix certificate test inventories differ",
                               ["INVENTORY_MISMATCH"])
    for field in ("harness_sha256", "policy_sha256", "timing_profile_sha256"):
        if any(row[field] != certificates[0][field]
               for row in certificates[1:]):
            raise CertificateError("matrix certificate policies differ",
                                   ["WRONG_POLICY"])
    cells = sorted(certificates, key=lambda item: item["environment_sha256"])
    body = {
        "schema_version": 1, "status": "certified", "consumer": consumer,
        "subject": subjects[0], "cells": cells, "cell_count": len(cells),
    }
    return {**body, "matrix_certificate_sha256": loom_suite_plan.digest(body)}


def verify_matrix(value):
    if not isinstance(value, dict) or "matrix_certificate_sha256" not in value:
        raise CertificateError("matrix certificate is invalid", ["SCHEMA"])
    body = {key: item for key, item in value.items()
            if key != "matrix_certificate_sha256"}
    if value["matrix_certificate_sha256"] != loom_suite_plan.digest(body):
        raise CertificateError("matrix certificate is invalid", ["RECEIPT_DIGEST"])
    if set(body) != {
            "schema_version", "status", "consumer", "subject", "cells",
            "cell_count"} or body.get("schema_version") != 1 \
            or body.get("status") != "certified" \
            or body.get("consumer") not in {
                "quality", "compatibility", "clean-room", "release"} \
            or not isinstance(body.get("cells"), list) or not body["cells"] \
            or body.get("cell_count") != len(body["cells"]):
        raise CertificateError("matrix certificate is invalid", ["SCHEMA"])
    try:
        loom_suite_plan._subject(body.get("subject"))
        cells = [verify_cell(row) for row in body["cells"]]
    except loom_suite_plan.SuitePlanError as exc:
        raise CertificateError("matrix certificate is invalid", ["SCHEMA"]) from exc
    if cells != sorted(cells, key=lambda item: item["environment_sha256"]):
        raise CertificateError("matrix certificate is invalid",
                               ["INVENTORY_MISMATCH"])
    environments = [row["environment_sha256"] for row in cells]
    if len(environments) != len(set(environments)):
        raise CertificateError("matrix certificate is invalid",
                               ["INVENTORY_MISMATCH"])
    if any(row["subject"] != body["subject"] for row in cells):
        raise CertificateError("matrix certificate is invalid", ["WRONG_SUBJECT"])
    _require_release_topology(cells, body["consumer"])
    inventories = [[outcome["test"] for outcome in row["outcomes"]]
                   for row in cells]
    if any(inventory != inventories[0] for inventory in inventories[1:]):
        raise CertificateError("matrix certificate is invalid",
                               ["INVENTORY_MISMATCH"])
    for field in ("harness_sha256", "policy_sha256", "timing_profile_sha256"):
        if any(row[field] != cells[0][field] for row in cells[1:]):
            raise CertificateError("matrix certificate is invalid", ["WRONG_POLICY"])
    passed = {outcome["test"] for cell in cells for outcome in cell["outcomes"]
              if outcome["status"] == "passed"}
    uncovered = {outcome["test"] for cell in cells for outcome in cell["outcomes"]
                 if outcome["status"] == "skipped" and outcome["test"] not in passed}
    if uncovered:
        raise CertificateError("matrix certificate contains uncovered skips",
                               ["UNAUTHORIZED_SKIP"])
    return value


# Preserve the historical public module and CLI while delegating the reusable
# cell, shadow, and matrix semantics to the closed product-independent core.
PRECEDENCE = loom_suite_certificate_core.PRECEDENCE
RELEASE_MATRIX_LABELS = loom_suite_certificate_core.RELEASE_MATRIX_LABELS
RELEASE_MATRIX_PYTHONS = loom_suite_certificate_core.RELEASE_MATRIX_PYTHONS
WORKER_FAILURE_CODES = loom_suite_certificate_core.WORKER_FAILURE_CODES
CertificateError = loom_suite_certificate_core.CertificateError
_shadow_failure_code = loom_suite_certificate_core.shadow_failure_code
_raise = loom_suite_certificate_core._raise
_primary = loom_suite_certificate_core.primary
_require_release_topology = \
    loom_suite_certificate_core._require_release_topology
_validated_inputs = loom_suite_certificate_core._validated_inputs
_cell_execution_microseconds = \
    loom_suite_certificate_core._cell_execution_microseconds
compile_cell = loom_suite_certificate_core.compile_cell
verify_cell = loom_suite_certificate_core.verify_cell
compare_shadow = loom_suite_certificate_core.compare_shadow
compile_matrix = loom_suite_certificate_core.compile_matrix
verify_matrix = loom_suite_certificate_core.verify_matrix


def qualification_code_sha256(root=None):
    root = (Path(__file__).resolve().parents[1] if root is None
            else Path(root).resolve())
    rows = []
    for relative in QUALIFICATION_CODE_PATHS:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise CertificateError("qualification code set is incomplete", ["SCHEMA"])
        rows.append({"path": relative,
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return loom_suite_plan.digest(rows)


def _family(cell, consumer):
    environment = cell["environment"]
    matched = re.fullmatch(r"([0-9]+\.[0-9]+)\.[0-9]+(?:[-+].*)?",
                           environment["python_version"])
    if matched is None:
        raise CertificateError("qualification Python identity is invalid",
                               ["WRONG_ENVIRONMENT"])
    body = {
        "consumer": consumer,
        "requested_label": environment["requested_label"],
        "image_os": environment["image_os"],
        "architecture": environment["architecture"],
        "python_implementation": environment["python_implementation"],
        "python_minor": matched.group(1),
    }
    return {**body, "family_id": loom_suite_plan.digest(body)}


def fault_injection_receipts(matrices):
    """Bind cross-platform fault qualification to exact certified outcomes."""
    matrices = [verify_matrix(value) for value in matrices]
    result = {}
    for platform_id in ("linux", "windows", "macos"):
        required_faults = dict(FAULT_TESTS)
        if platform_id == "windows":
            required_faults.update(WINDOWS_FAULT_TESTS)
        required_tests = set(required_faults.values())

        def normalized_platform(cell):
            system = str(cell["environment"]["os"]).lower()
            return "macos" if system in {"darwin", "macos"} else system

        cells = [
            (matrix["consumer"], cell)
            for matrix in matrices for cell in matrix["cells"]
            if normalized_platform(cell) == platform_id
        ]
        if not cells:
            raise CertificateError("fault qualification platform is missing",
                                   ["INVENTORY_MISMATCH"])
        projection = []
        for consumer, cell in cells:
            outcomes = {row["test"]: row["status"] for row in cell["outcomes"]}
            if any(outcomes.get(test_id) != "passed" for test_id in required_tests):
                raise CertificateError("fault qualification is incomplete",
                                       ["TEST_FAILURE"])
            projection.append({
                "consumer": consumer,
                "cell_certificate_sha256": cell["cell_certificate_sha256"],
                "faults": [{"fault": fault_id, "test": test_id,
                            "status": outcomes[test_id]}
                           for fault_id, test_id in sorted(
                               required_faults.items())],
            })
        result[platform_id] = loom_suite_plan.digest({
            "schema_version": 1,
            "platform": platform_id,
            "cells": sorted(projection, key=lambda item: (
                item["consumer"], item["cell_certificate_sha256"])),
        })
    return result


QUALIFICATION_PAIR_CONTENT_FIELDS = {
    "exact_cut_receipt", "serial_suite", "inventory", "timing_profile",
    "plan", "worker_receipts", "cell_certificate", "shadow_comparison",
}
QUALIFICATION_PAIR_FIELDS = {
    "encoding", "uncompressed_bytes", "payload_sha256", "payload_base64",
    "pair_sha256",
}
MAX_QUALIFICATION_PAIR_BYTES = 16 * 1024 * 1024
MAX_QUALIFICATION_BYTES = 95_000_000
QUALIFICATION_DERIVED_FIELDS = {
    "successful_runs", "resolved_operating_systems", "exact_image_versions",
    "python_patches", "serial_p50_microseconds", "serial_p95_microseconds",
    "sharded_p50_microseconds", "sharded_p95_microseconds",
    "parity_verified", "terminal_receipts_verified", "privacy_clean",
    "mutation_clean", "worker_cleanup_verified",
    "workflow_critical_path_improved",
}
QUALIFICATION_FAMILY_FIELDS = {
    "family_id", "consumer", "requested_label", "image_os", "architecture",
    "python_implementation", "python_minor", "derived", "pairs",
}


def _qualification_policies(policy):
    try:
        policy = loom_suite_plan._validate_seal(
            policy, "policy_sha256", loom_suite_plan.seal_policy)
    except loom_suite_plan.SuitePlanError as exc:
        raise CertificateError(
            "qualification policy is invalid", ["WRONG_POLICY"]) from exc
    if policy["authority_mode"] != "certificate":
        raise CertificateError(
            "qualification record is invalid", ["WRONG_POLICY"])
    serial = loom_suite_plan.seal_policy({
        "schema_version": policy["schema_version"], "authority_mode": "serial",
        "exclusive_modules": policy["exclusive_modules"],
    })
    return policy, serial


def _nearest_rank(values, percentile):
    if not isinstance(values, list) or len(values) != 10 \
            or any(type(value) is not int or value <= 0 for value in values) \
            or percentile not in {50, 95}:
        raise CertificateError(
            "qualification timing evidence is invalid", ["SCHEMA"])
    ordered = sorted(values)
    rank = (percentile * len(ordered) + 99) // 100
    return ordered[rank - 1]


def _strict_qualification_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _qualification_pair_envelope(content):
    if not isinstance(content, dict) \
            or set(content) != QUALIFICATION_PAIR_CONTENT_FIELDS:
        raise CertificateError("qualification pair evidence is invalid", ["SCHEMA"])
    raw = loom_suite_plan.canonical(content)
    if not raw or len(raw) > MAX_QUALIFICATION_PAIR_BYTES:
        raise CertificateError("qualification pair evidence is invalid", ["SCHEMA"])
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    body = {
        "encoding": "gzip-base64-json-v1",
        "uncompressed_bytes": len(raw),
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "payload_base64": base64.b64encode(compressed).decode("ascii"),
    }
    return {**body, "pair_sha256": loom_suite_plan.digest(body)}


def _decode_qualification_pair(value):
    if not isinstance(value, dict) or set(value) != QUALIFICATION_PAIR_FIELDS:
        raise CertificateError("qualification pair evidence is invalid", ["SCHEMA"])
    body = {key: item for key, item in value.items() if key != "pair_sha256"}
    if value.get("encoding") != "gzip-base64-json-v1" \
            or type(value.get("uncompressed_bytes")) is not int \
            or not 1 <= value["uncompressed_bytes"] <= \
            MAX_QUALIFICATION_PAIR_BYTES \
            or loom_suite_plan.HEX64.fullmatch(str(
                value.get("payload_sha256", ""))) is None \
            or not isinstance(value.get("payload_base64"), str) \
            or len(value["payload_base64"]) > MAX_QUALIFICATION_PAIR_BYTES * 2 \
            or value.get("pair_sha256") != loom_suite_plan.digest(body):
        raise CertificateError(
            "qualification pair evidence is invalid", ["RECEIPT_DIGEST"])
    try:
        compressed = base64.b64decode(
            value["payload_base64"].encode("ascii"), validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as archive:
            raw = archive.read(MAX_QUALIFICATION_PAIR_BYTES + 1)
        if len(raw) != value["uncompressed_bytes"] \
                or len(raw) > MAX_QUALIFICATION_PAIR_BYTES \
                or hashlib.sha256(raw).hexdigest() != value["payload_sha256"]:
            raise ValueError("pair payload identity")
        content = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_qualification_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, EOFError, ValueError, UnicodeError, RecursionError,
            json.JSONDecodeError, binascii.Error) as exc:
        raise CertificateError(
            "qualification pair evidence is invalid", ["SCHEMA"]) from exc
    if not isinstance(content, dict) \
            or set(content) != QUALIFICATION_PAIR_CONTENT_FIELDS:
        raise CertificateError("qualification pair evidence is invalid", ["SCHEMA"])
    return content


def _verify_qualification_pair(value, *, serial_policy):
    content = _decode_qualification_pair(value)
    try:
        exact = loom_exact_cut_ci.verify_receipt(
            content["exact_cut_receipt"], require_static=False)
        serial_suite = content["serial_suite"]
        exact_environment = exact["environment"]
        environment = {
            key: exact_environment[key]
            for key in loom_suite_plan.ENVIRONMENT_FIELDS
        }
        if serial_suite != exact["suite"] \
                or exact_environment.get("evidence_class") != "ci-reproduced" \
                or not isinstance(exact.get("platform"), str) \
                or not isinstance(exact_environment.get("os"), str) \
                or exact["platform"].casefold() != exact_environment[
                    "os"].casefold() \
                or not isinstance(exact.get("architecture"), str) \
                or not isinstance(exact_environment.get("architecture"), str) \
                or exact["architecture"].casefold() != exact_environment[
                    "architecture"].casefold() \
                or exact.get("python") != exact_environment.get("python_version"):
            raise CertificateError(
                "qualification serial evidence is invalid", ["WRONG_ENVIRONMENT"])
        inventory = loom_suite_plan._validate_seal(
            content["inventory"], "inventory_sha256",
            loom_suite_plan.seal_inventory)
        timing_profile = loom_suite_plan._validate_seal(
            content["timing_profile"], "profile_sha256",
            loom_suite_plan.seal_timing_profile)
        subject = inventory["subject"]
        expected_subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": exact["source_commit"],
            "source_tree_sha256": subject["source_tree_sha256"],
            "public_root_sha256": exact["verified_root_sha256"],
            "public_manifest_sha256": exact["public_manifest_sha256"],
            "public_file_count": exact["public_file_count"],
        }
        if subject != expected_subject or inventory["environment"] != environment:
            raise CertificateError(
                "qualification pair names the wrong subject",
                ["WRONG_SUBJECT"])
        plan = content["plan"]
        if not isinstance(plan, dict) or set(plan) != {
                "schema_version", "inventory_sha256", "policy_sha256",
                "timing_profile_sha256", "logical_cpu_count",
                "max_parallel_workers", "shards", "plan_sha256"}:
            raise CertificateError(
                "qualification plan evidence is invalid", ["WRONG_POLICY"])
        rebuilt_plan = loom_suite_plan.plan(
            inventory, timing_profile=timing_profile, policy=serial_policy,
            logical_cpus=plan["logical_cpu_count"])
        if plan != rebuilt_plan:
            raise CertificateError(
                "qualification plan evidence is invalid", ["WRONG_POLICY"])
        workers = content["worker_receipts"]
        if not isinstance(workers, list) or not workers:
            raise CertificateError(
                "qualification worker evidence is invalid",
                ["INVENTORY_MISMATCH"])
        compiled = compile_cell(
            inventory, plan, workers, policy=serial_policy)
        if compiled != content["cell_certificate"]:
            raise CertificateError(
                "qualification cell evidence is invalid", ["RECEIPT_DIGEST"])
        expected_comparison = compare_shadow(serial_suite, compiled)
        if expected_comparison != content["shadow_comparison"] \
                or expected_comparison.get("schema_version") != 2 \
                or expected_comparison.get("status") != "matched" \
                or type(serial_suite.get("elapsed_microseconds")) is not int \
                or serial_suite["elapsed_microseconds"] <= 0 \
                or type(compiled.get("execution_microseconds")) is not int \
                or compiled["execution_microseconds"] <= 0:
            raise CertificateError(
                "qualification shadow evidence is invalid",
                ["INVENTORY_MISMATCH"])
    except CertificateError:
        raise
    except (KeyError, TypeError, ValueError, loom_suite_plan.SuitePlanError,
            loom_suite_worker.SuiteWorkerError) as exc:
        raise CertificateError(
            "qualification pair evidence is invalid", ["SCHEMA"]) from exc
    return content


def compile_qualification_pair(value, *, policy):
    """Seal one compressed, self-contained serial/shadow evidence pair."""
    _certificate_policy, serial_policy = _qualification_policies(policy)
    if not isinstance(value, dict) \
            or set(value) != QUALIFICATION_PAIR_CONTENT_FIELDS:
        raise CertificateError("qualification pair evidence is invalid", ["SCHEMA"])
    pair = _qualification_pair_envelope(value)
    _verify_qualification_pair(pair, serial_policy=serial_policy)
    return pair


def _derive_qualification_family(consumer, pairs, *, serial_policy,
                                 compile_unsealed=False):
    if consumer not in {"quality", "compatibility"} \
            or not isinstance(pairs, list) or len(pairs) != 10:
        raise CertificateError(
            "qualification family is invalid", ["INVENTORY_MISMATCH"])
    envelopes = []
    validated = []
    for pair in pairs:
        if compile_unsealed and isinstance(pair, dict) \
                and set(pair) == QUALIFICATION_PAIR_CONTENT_FIELDS:
            pair = _qualification_pair_envelope(pair)
        envelopes.append(pair)
        validated.append(_verify_qualification_pair(
            pair, serial_policy=serial_policy))
    families = [_family(pair["cell_certificate"], consumer)
                for pair in validated]
    if any(family != families[0] for family in families[1:]):
        raise CertificateError(
            "qualification family mixes runner identities",
            ["WRONG_ENVIRONMENT"])
    subjects = [pair["cell_certificate"]["subject"] for pair in validated]
    if any(subject != subjects[0] for subject in subjects[1:]):
        raise CertificateError(
            "qualification family mixes release subjects", ["WRONG_SUBJECT"])
    runs = [{
        "run_id": pair["exact_cut_receipt"]["environment"]["run_id"],
        "run_attempt": pair["exact_cut_receipt"]["environment"]["run_attempt"],
    } for pair in validated]
    run_keys = [(row["run_id"], row["run_attempt"]) for row in runs]
    if any(re.fullmatch(r"[0-9]+", run_id) is None
           or re.fullmatch(r"[0-9]+", run_attempt) is None
           for run_id, run_attempt in run_keys):
        raise CertificateError(
            "qualification run identity is invalid", ["WRONG_ENVIRONMENT"])
    identity_fields = (
        "pair_sha256", "inventory", "plan", "cell_certificate",
        "shadow_comparison", "exact_cut_receipt",
    )
    identities = {
        "pair_sha256": [pair["pair_sha256"] for pair in envelopes],
        "inventory": [pair["inventory"]["inventory_sha256"]
                      for pair in validated],
        "plan": [pair["plan"]["plan_sha256"] for pair in validated],
        "cell_certificate": [pair["cell_certificate"][
            "cell_certificate_sha256"] for pair in validated],
        "shadow_comparison": [pair["shadow_comparison"][
            "comparison_sha256"] for pair in validated],
        "exact_cut_receipt": [pair["exact_cut_receipt"]["receipt_sha256"]
                              for pair in validated],
    }
    if len(run_keys) != len(set(run_keys)) \
            or any(len(identities[field]) != len(set(identities[field]))
                   for field in identity_fields):
        raise CertificateError(
            "qualification family reuses evidence", ["INVENTORY_MISMATCH"])
    environments = [pair["cell_certificate"]["environment"]
                    for pair in validated]
    test_inventories = [[row["test"] for row in pair["cell_certificate"][
        "outcomes"]] for pair in validated]
    if any(tests != test_inventories[0] for tests in test_inventories[1:]):
        raise CertificateError(
            "qualification family test inventory changed",
            ["INVENTORY_MISMATCH"])
    for field in ("harness_sha256", "timing_profile_sha256"):
        values = [pair["cell_certificate"][field] for pair in validated]
        if any(item != values[0] for item in values[1:]):
            raise CertificateError(
                "qualification family inputs changed", ["WRONG_POLICY"])
    for field in ("workflow_path", "workflow_digest", "action_manifest_digest"):
        values = [environment[field] for environment in environments]
        if any(item != values[0] for item in values[1:]):
            raise CertificateError(
                "qualification family workflow changed", ["WRONG_POLICY"])
    serial_times = [pair["serial_suite"]["elapsed_microseconds"]
                    for pair in validated]
    sharded_times = [pair["cell_certificate"]["execution_microseconds"]
                     for pair in validated]
    serial_p50 = _nearest_rank(serial_times, 50)
    serial_p95 = _nearest_rank(serial_times, 95)
    sharded_p50 = _nearest_rank(sharded_times, 50)
    sharded_p95 = _nearest_rank(sharded_times, 95)
    improved = sharded_p50 <= serial_p50 and sharded_p95 <= serial_p95 \
        and (sharded_p50 < serial_p50 or sharded_p95 < serial_p95)
    if not improved:
        raise CertificateError(
            "qualification critical path did not improve", ["SCHEMA"])
    resolved = sorted({(
        environment["os"], environment["os_release"],
        environment["os_version"])
        for environment in environments})
    derived = {
        "successful_runs": [
            {"run_id": run_id, "run_attempt": run_attempt}
            for run_id, run_attempt in sorted(run_keys)],
        "resolved_operating_systems": [
            {"os": os_name, "os_release": release, "os_version": version}
            for os_name, release, version in resolved],
        "exact_image_versions": sorted({
            environment["image_version"] for environment in environments}),
        "python_patches": sorted({
            environment["python_version"] for environment in environments}),
        "serial_p50_microseconds": serial_p50,
        "serial_p95_microseconds": serial_p95,
        "sharded_p50_microseconds": sharded_p50,
        "sharded_p95_microseconds": sharded_p95,
        "parity_verified": True,
        "terminal_receipts_verified": True,
        "privacy_clean": True,
        "mutation_clean": True,
        "worker_cleanup_verified": True,
        "workflow_critical_path_improved": True,
    }
    ordered = sorted(zip(envelopes, validated), key=lambda item: (
        item[1]["exact_cut_receipt"]["environment"]["run_id"],
        item[1]["exact_cut_receipt"]["environment"]["run_attempt"],
        item[0]["pair_sha256"],
    ))
    ordered_pairs = [item[0] for item in ordered]
    ordered_content = [item[1] for item in ordered]
    return {
        **families[0], "derived": derived, "pairs": ordered_pairs,
    }, subjects[0], ordered_content


def _qualification_matrix_families(matrices, *, policy):
    if not isinstance(matrices, list) or len(matrices) != 2:
        raise CertificateError(
            "qualification matrices are incomplete", ["INVENTORY_MISMATCH"])
    matrices = [verify_matrix(matrix) for matrix in matrices]
    if sorted(matrix["consumer"] for matrix in matrices) != [
            "compatibility", "quality"]:
        raise CertificateError(
            "qualification matrices are incomplete", ["INVENTORY_MISMATCH"])
    subjects = [matrix["subject"] for matrix in matrices]
    if subjects[0] != subjects[1]:
        raise CertificateError(
            "qualification matrices mix release subjects", ["WRONG_SUBJECT"])
    cells = {}
    for matrix in matrices:
        for cell in matrix["cells"]:
            family = _family(cell, matrix["consumer"])
            if family["family_id"] in cells \
                    or cell["policy_sha256"] != policy["policy_sha256"]:
                raise CertificateError(
                    "qualification matrix inputs are invalid", ["WRONG_POLICY"])
            cells[family["family_id"]] = cell
    clean_room_cells = [
        cell for matrix in matrices if matrix["consumer"] == "compatibility"
        for cell in matrix["cells"]
        if cell["environment"]["requested_label"] == "ubuntu-24.04"
        and cell["environment"]["python_version"].startswith("3.11.")
    ]
    if len(clean_room_cells) != 1:
        raise CertificateError(
            "clean-room qualification subject is ambiguous",
            ["INVENTORY_MISMATCH"])
    clean_room_family_id = _family(
        clean_room_cells[0], "compatibility")["family_id"]
    fault_injection_receipts(matrices)
    return matrices, cells, clean_room_family_id


def _require_family_matches_matrix(family, current, resolved_pairs):
    # The historical qualification subject is intentionally not compared to
    # the future cutover subject: adding the sealed qualification file changes
    # that commit and public cut.  The full historical subject is instead
    # uniform across every pair and binds reproduction plus rollback below.
    if not isinstance(current, dict) or "environment" not in current:
        raise CertificateError(
            "matrix runner family is not qualified", ["WRONG_ENVIRONMENT"])
    derived = family["derived"]
    environment = current["environment"]
    resolved = {
        (row["os"], row["os_release"], row["os_version"])
        for row in derived["resolved_operating_systems"]
    }
    current_tests = [row["test"] for row in current["outcomes"]]
    if environment["image_version"] not in derived["exact_image_versions"] \
            or environment["python_version"] not in derived["python_patches"] \
            or (environment["os"], environment["os_release"],
                environment["os_version"]) not in resolved:
        raise CertificateError(
            "matrix runner family is not qualified", ["WRONG_ENVIRONMENT"])
    if not isinstance(resolved_pairs, list) or len(resolved_pairs) != 10:
        raise CertificateError(
            "qualification family evidence is incomplete",
            ["INVENTORY_MISMATCH"])
    for pair in resolved_pairs:
        cell = pair["cell_certificate"]
        pair_environment = cell["environment"]
        if cell["harness_sha256"] != current["harness_sha256"] \
                or cell["timing_profile_sha256"] != current[
                    "timing_profile_sha256"] \
                or pair_environment["workflow_path"] != environment[
                    "workflow_path"] \
                or pair_environment["workflow_digest"] != environment[
                    "workflow_digest"] \
                or pair_environment["action_manifest_digest"] != environment[
                    "action_manifest_digest"] \
                or [row["test"] for row in cell["outcomes"]] != current_tests:
            raise CertificateError(
                "matrix inputs differ from qualification", ["WRONG_POLICY"])


def _verify_release_evidence(reproducibility_receipts, rollback_receipt,
                             subject):
    if not isinstance(reproducibility_receipts, list) \
            or len(reproducibility_receipts) != 2:
        raise CertificateError(
            "qualification release evidence is incomplete", ["SCHEMA"])
    verified = []
    try:
        for receipt in reproducibility_receipts:
            verified.append(
                loom_release_candidate.verify_reproducibility_receipt(receipt))
        loom_release_rollback.verify_receipt(
            rollback_receipt, expected_commit=subject["source_commit"],
            expected_public_root_sha256=subject["public_root_sha256"])
    except (loom_release_candidate.CandidateError,
            loom_release_rollback.RollbackEvidenceError) as exc:
        raise CertificateError(
            "qualification release evidence is invalid", ["SCHEMA"]) from exc
    public_cut = {
        "root_sha256": subject["public_root_sha256"],
        "manifest_sha256": subject["public_manifest_sha256"],
        "file_count": subject["public_file_count"],
    }
    digests = [receipt["receipt_sha256"] for receipt in verified]
    candidate_identities = [{
        "candidate_a": receipt["candidate_a"],
        "candidate_b": receipt["candidate_b"],
        "public_cut": receipt["public_cut"],
        "native_binary_subjects": [{
            "platform": row["platform"],
            "binary_sha256": row["binary_sha256"],
        } for row in receipt["native_subjects"]],
    } for receipt in verified]
    if len(digests) != len(set(digests)) \
            or any(receipt["public_cut"] != public_cut for receipt in verified) \
            or any(identity != candidate_identities[0]
                   for identity in candidate_identities[1:]):
        raise CertificateError(
            "qualification release evidence is invalid", ["WRONG_SUBJECT"])


def compile_qualification(families, matrices, *, policy,
                          reproducibility_receipts, rollback_receipt,
                          root=None):
    """Compile ten resolved serial/shadow pairs per runner family."""
    policy, serial_policy = _qualification_policies(policy)
    _matrices, current, clean_room_family_id = _qualification_matrix_families(
        matrices, policy=policy)
    if not isinstance(families, list) or not families:
        raise CertificateError(
            "qualification families are incomplete", ["INVENTORY_MISMATCH"])
    compiled = []
    subjects = []
    resolved_by_family = {}
    for row in families:
        if not isinstance(row, dict) or set(row) != {"consumer", "pairs"}:
            raise CertificateError("qualification family is invalid", ["SCHEMA"])
        family, subject, resolved = _derive_qualification_family(
            row["consumer"], row["pairs"], serial_policy=serial_policy,
            compile_unsealed=True)
        compiled.append(family)
        subjects.append(subject)
        resolved_by_family[family["family_id"]] = resolved
    compiled.sort(key=lambda row: row["family_id"])
    family_ids = [row["family_id"] for row in compiled]
    if len(family_ids) != len(set(family_ids)) or set(family_ids) != set(current):
        raise CertificateError(
            "qualification family coverage is incomplete",
            ["INVENTORY_MISMATCH"])
    if any(subject != subjects[0] for subject in subjects[1:]):
        raise CertificateError(
            "qualification evidence mixes release subjects", ["WRONG_SUBJECT"])
    seen = set()
    for family in compiled:
        resolved = resolved_by_family[family["family_id"]]
        _require_family_matches_matrix(
            family, current[family["family_id"]], resolved)
        for envelope, pair in zip(family["pairs"], resolved):
            identities = (
                envelope["pair_sha256"],
                pair["exact_cut_receipt"]["receipt_sha256"],
                pair["cell_certificate"]["cell_certificate_sha256"],
                pair["shadow_comparison"]["comparison_sha256"],
            )
            if any(identity in seen for identity in identities):
                raise CertificateError(
                    "qualification reuses pair evidence",
                    ["INVENTORY_MISMATCH"])
            seen.update(identities)
    _verify_release_evidence(
        reproducibility_receipts, rollback_receipt, subjects[0])
    body = {
        "schema_version": 1, "status": "qualified",
        "subject": subjects[0],
        "serial_policy_sha256": serial_policy["policy_sha256"],
        "certificate_policy_sha256": policy["policy_sha256"],
        "qualification_code_sha256": qualification_code_sha256(root),
        "clean_room_family_id": clean_room_family_id,
        "families": compiled,
        "reproducibility_receipts": reproducibility_receipts,
        "rollback_receipt": rollback_receipt,
    }
    value = {**body, "qualification_sha256": loom_suite_plan.digest(body)}
    return verify_qualification(value, matrices, policy=policy, root=root)


def verify_qualification(value, matrices, *, policy, root=None):
    """Verify resolved ten-pair evidence before certificate authority."""
    policy, serial_policy = _qualification_policies(policy)
    if not isinstance(value, dict) or "qualification_sha256" not in value:
        raise CertificateError("qualification record is invalid", ["SCHEMA"])
    body = {key: item for key, item in value.items()
            if key != "qualification_sha256"}
    if value["qualification_sha256"] != loom_suite_plan.digest(body):
        raise CertificateError(
            "qualification record is invalid", ["RECEIPT_DIGEST"])
    if set(body) != {
            "schema_version", "status", "subject", "serial_policy_sha256",
            "certificate_policy_sha256", "qualification_code_sha256",
            "clean_room_family_id",
            "families", "reproducibility_receipts", "rollback_receipt"} \
            or body.get("schema_version") != 1 \
            or body.get("status") != "qualified":
        raise CertificateError("qualification record is invalid", ["SCHEMA"])
    try:
        subject = loom_suite_plan._subject(body.get("subject"))
    except loom_suite_plan.SuitePlanError as exc:
        raise CertificateError(
            "qualification subject is invalid", ["WRONG_SUBJECT"]) from exc
    if body.get("serial_policy_sha256") != serial_policy["policy_sha256"] \
            or body.get("certificate_policy_sha256") != policy["policy_sha256"] \
            or body.get("qualification_code_sha256") != \
            qualification_code_sha256(root):
        raise CertificateError(
            "qualification input binding is invalid", ["WRONG_POLICY"])
    _matrices, current, clean_room_family_id = _qualification_matrix_families(
        matrices, policy=policy)
    if body.get("clean_room_family_id") != clean_room_family_id:
        raise CertificateError(
            "clean-room qualification is missing", ["WRONG_ENVIRONMENT"])
    families = body.get("families")
    if not isinstance(families, list) or not families:
        raise CertificateError(
            "qualification families are incomplete", ["INVENTORY_MISMATCH"])
    expected_families = []
    all_identities = []
    for row in families:
        if not isinstance(row, dict) or set(row) != QUALIFICATION_FAMILY_FIELDS \
                or not isinstance(row.get("derived"), dict) \
                or set(row["derived"]) != QUALIFICATION_DERIVED_FIELDS:
            raise CertificateError("qualification family is invalid", ["SCHEMA"])
        expected, pair_subject, resolved = _derive_qualification_family(
            row["consumer"], row["pairs"], serial_policy=serial_policy)
        if row != expected or pair_subject != subject:
            raise CertificateError("qualification family is invalid", ["SCHEMA"])
        expected_families.append(expected)
        _require_family_matches_matrix(
            expected, current.get(row["family_id"], {}), resolved)
        all_identities.extend((
            envelope["pair_sha256"],
            pair["exact_cut_receipt"]["receipt_sha256"],
            pair["cell_certificate"]["cell_certificate_sha256"],
            pair["shadow_comparison"]["comparison_sha256"],
        ) for envelope, pair in zip(row["pairs"], resolved))
    if families != sorted(expected_families, key=lambda row: row["family_id"]) \
            or {row["family_id"] for row in families} != set(current):
        raise CertificateError(
            "qualification family coverage is incomplete",
            ["INVENTORY_MISMATCH"])
    flat_identities = [item for group in all_identities for item in group]
    if len(flat_identities) != len(set(flat_identities)):
        raise CertificateError(
            "qualification reuses pair evidence", ["INVENTORY_MISMATCH"])
    _verify_release_evidence(
        body["reproducibility_receipts"], body["rollback_receipt"], subject)
    return value


def _load(path):
    return loom_suite_worker._load(path, "certificate input")


def _load_qualification(path, *, max_bytes=MAX_QUALIFICATION_BYTES):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or type(max_bytes) is not int or max_bytes < 1 \
            or path.stat().st_size > max_bytes:
        raise loom_suite_worker.SuiteWorkerError(
            "qualification input is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_qualification_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError, RecursionError,
            json.JSONDecodeError) as exc:
        raise loom_suite_worker.SuiteWorkerError(
            "qualification input is unreadable") from exc


def _write(path, value):
    loom_reliability.atomic_write_json(Path(path), value)


def _exact_context(exact_receipt, source_tree_sha256, *, require_static=None):
    try:
        loom_exact_cut_ci.verify_receipt(
            exact_receipt, require_static=require_static)
    except ValueError as exc:
        raise CertificateError(
            "exact-cut receipt is invalid", ["RECEIPT_DIGEST"]) from exc
    if loom_suite_plan.HEX64.fullmatch(str(source_tree_sha256)) is None:
        raise CertificateError("exact-cut receipt is invalid", ["RECEIPT_DIGEST"])
    environment_source = exact_receipt.get("environment")
    if not isinstance(environment_source, dict) \
            or environment_source.get("environment_sha256") != loom_suite_plan.digest({
                key: value for key, value in environment_source.items()
                if key != "environment_sha256"}):
        raise CertificateError("exact-cut environment is invalid", ["WRONG_ENVIRONMENT"])
    environment = {key: environment_source.get(key)
                   for key in loom_suite_plan.ENVIRONMENT_FIELDS}
    try:
        environment = loom_suite_plan._environment(environment)
        subject = loom_suite_plan._subject({
            "repository": "https://github.com/saroo98/loom",
            "source_commit": exact_receipt.get("source_commit"),
            "source_tree_sha256": source_tree_sha256,
            "public_root_sha256": exact_receipt.get("verified_root_sha256"),
            "public_manifest_sha256": exact_receipt.get("public_manifest_sha256"),
            "public_file_count": exact_receipt.get("public_file_count"),
        })
    except loom_suite_plan.SuitePlanError as exc:
        raise CertificateError("exact-cut subject is invalid", ["WRONG_SUBJECT"]) from exc
    return subject, environment


def _execute_cell(cut, test_root, exact_receipt, policy, timing_profile,
                  output_root, *, source_tree_sha256, timeout, required_mode):
    policy = loom_suite_plan._validate_seal(
        policy, "policy_sha256", loom_suite_plan.seal_policy)
    if policy["authority_mode"] != required_mode:
        raise CertificateError("suite cell uses the wrong authority mode",
                               ["WRONG_POLICY"])
    subject, environment = _exact_context(
        exact_receipt, source_tree_sha256,
        require_static=required_mode == "certificate")
    before = loom_release.verify_cut_static(cut, forbidden_tokens=[])
    if before.get("root_sha256") != subject["public_root_sha256"] \
            or before.get("manifest_sha256") != subject["public_manifest_sha256"] \
            or before.get("files_verified") != subject["public_file_count"]:
        raise CertificateError("suite cell public cut differs before behavior",
                               ["WRONG_SUBJECT"])
    harness = Path(test_root).resolve() / "loom_test.py"
    inventory = loom_suite_plan.inventory(
        test_root, subject=subject, environment=environment,
        harness_sha256=hashlib.sha256(harness.read_bytes()).hexdigest(),
        timeout=timeout, protected_roots=[cut], context_root=cut)
    plan = loom_suite_plan.plan(
        inventory, timing_profile=timing_profile, policy=policy)
    _write(output_root / "inventory.json", inventory)
    _write(output_root / "plan.json", plan)
    workers_root = output_root / "workers"
    workers_root.mkdir()
    receipts = loom_suite_worker.run_plan(
        cut, inventory, plan, workers_root, timeout=timeout)
    certificate = compile_cell(inventory, plan, receipts, policy=policy)
    after = loom_release.verify_cut_static(cut, forbidden_tokens=[])
    if after != before:
        raise CertificateError("suite cell changed the public cut",
                               ["CANDIDATE_MUTATION"])
    _write(output_root / "cell-certificate.json", certificate)
    return certificate


def run_certificate_cell(cut, test_root, exact_receipt, policy, timing_profile,
                         output_root, *, source_tree_sha256, timeout=2400):
    """Run one authoritative isolated cell after certificate-mode cutover."""
    output_root = Path(output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    return _execute_cell(
        cut, test_root, exact_receipt, policy, timing_profile, output_root,
        source_tree_sha256=source_tree_sha256, timeout=timeout,
        required_mode="certificate")


def run_shadow_cell(cut, test_root, exact_receipt, serial_report, policy,
                    timing_profile, output_root, *, source_tree_sha256,
                    timeout=2400):
    """Run non-authoritative sharded evidence beside one serial authority cell."""
    output_root = Path(output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    try:
        certificate = _execute_cell(
            cut, test_root, exact_receipt, policy, timing_profile, output_root,
            source_tree_sha256=source_tree_sha256, timeout=timeout,
            required_mode="serial")
        comparison = compare_shadow(serial_report, certificate)
        _write(output_root / "shadow-comparison.json", comparison)
        return comparison
    except (OSError, loom_operation_supervisor.SupervisorError,
            loom_suite_worker.SuiteWorkerError, CertificateError,
            loom_suite_plan.SuitePlanError) as exc:
        findings = list(getattr(exc, "findings", None) or ["SCHEMA"])
        primary = _primary(findings)
        body = {"schema_version": 1, "status": "mismatched",
                "primary_reason": primary, "findings": sorted(set(findings)),
                "failure_code": _shadow_failure_code(exc)}
        if isinstance(exc, CertificateError):
            body["failure_details"] = exc.public_details
        result = {**body, "comparison_sha256": loom_suite_plan.digest(body)}
        _write(output_root / "shadow-comparison.json", result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    cell = subs.add_parser("cell")
    cell.add_argument("--inventory", required=True)
    cell.add_argument("--plan", required=True)
    cell.add_argument("--policy", required=True)
    cell.add_argument("--worker-receipt", action="append", required=True)
    cell.add_argument("--output", required=True)
    matrix = subs.add_parser("matrix")
    matrix.add_argument("--consumer", required=True)
    matrix.add_argument("--cell-certificate", action="append", required=True)
    matrix.add_argument("--required-environment", action="append", required=True)
    matrix.add_argument("--output", required=True)
    verify = subs.add_parser("verify")
    verify.add_argument("certificate")
    shadow = subs.add_parser("compare-shadow")
    shadow.add_argument("--serial-report", required=True)
    shadow.add_argument("--cell-certificate", required=True)
    shadow.add_argument("--output", required=True)
    cell_shadow = subs.add_parser("shadow-cell")
    cell_shadow.add_argument("--cut", required=True)
    cell_shadow.add_argument("--test-root", required=True)
    cell_shadow.add_argument("--exact-receipt", required=True)
    cell_shadow.add_argument("--serial-report", required=True)
    cell_shadow.add_argument("--policy", required=True)
    cell_shadow.add_argument("--timing-profile", required=True)
    cell_shadow.add_argument("--source-tree-sha256", required=True)
    cell_shadow.add_argument("--output-root", required=True)
    cell_shadow.add_argument("--timeout", type=float, default=2400)
    run_cell = subs.add_parser("run-cell")
    run_cell.add_argument("--cut", required=True)
    run_cell.add_argument("--test-root", required=True)
    run_cell.add_argument("--exact-receipt", required=True)
    run_cell.add_argument("--policy", required=True)
    run_cell.add_argument("--timing-profile", required=True)
    run_cell.add_argument("--source-tree-sha256", required=True)
    run_cell.add_argument("--output-root", required=True)
    run_cell.add_argument("--timeout", type=float, default=2400)
    qualification = subs.add_parser("verify-qualification")
    qualification.add_argument("--qualification", required=True)
    qualification.add_argument("--matrix-certificate", action="append", required=True)
    qualification.add_argument("--policy", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "cell":
            result = compile_cell(
                _load(args.inventory), _load(args.plan),
                [_load(path) for path in args.worker_receipt],
                policy=_load(args.policy))
            _write(args.output, result)
        elif args.command == "matrix":
            result = compile_matrix(
                [_load(path) for path in args.cell_certificate],
                consumer=args.consumer,
                required_environments=args.required_environment)
            _write(args.output, result)
        elif args.command == "verify":
            value = _load(args.certificate)
            result = (verify_matrix(value) if "matrix_certificate_sha256" in value
                      else verify_cell(value))
        elif args.command == "compare-shadow":
            result = compare_shadow(
                _load(args.serial_report), _load(args.cell_certificate))
            _write(args.output, result)
        elif args.command == "shadow-cell":
            result = run_shadow_cell(
                args.cut, args.test_root, _load(args.exact_receipt),
                _load(args.serial_report), _load(args.policy),
                _load(args.timing_profile), args.output_root,
                source_tree_sha256=args.source_tree_sha256,
                timeout=args.timeout)
        elif args.command == "run-cell":
            result = run_certificate_cell(
                args.cut, args.test_root, _load(args.exact_receipt),
                _load(args.policy), _load(args.timing_profile), args.output_root,
                source_tree_sha256=args.source_tree_sha256,
                timeout=args.timeout)
        else:
            result = verify_qualification(
                _load_qualification(args.qualification),
                [_load(path) for path in args.matrix_certificate],
                policy=_load(args.policy))
    except (CertificateError, loom_suite_worker.SuiteWorkerError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
