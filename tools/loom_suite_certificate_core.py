#!/usr/bin/env python3
"""Product-independent suite cell, shadow, and matrix certificates."""

import hashlib
import re

import loom_suite_harness
import loom_suite_plan
import loom_suite_worker


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


def shadow_failure_code(exc):
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


def primary(findings):
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
        raise CertificateError(
            "suite certificate inputs are invalid", ["WRONG_POLICY"])
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
        if shard_ids != sorted(expected_tests) \
                or len(shard_ids) != len(set(shard_ids)) \
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
        raise CertificateError(
            "cell certificate is invalid", ["RECEIPT_DIGEST"])
    fields = {
        "schema_version", "status", "subject", "environment",
        "environment_sha256", "inventory_sha256", "harness_sha256",
        "policy_sha256", "timing_profile_sha256", "plan_sha256",
        "worker_receipts", "execution_microseconds", "outcomes",
        "outcomes_sha256", "test_count", "passed_count", "failure_count",
        "error_count", "skip_count",
    }
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
        raise CertificateError(
            "cell certificate is invalid", ["SCHEMA"]) from exc
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
    if worker_ids != sorted(worker_ids) \
            or len(worker_ids) != len(set(worker_ids)) \
            or len(worker_digests) != len(set(worker_digests)):
        raise CertificateError(
            "cell certificate is invalid", ["INVENTORY_MISMATCH"])
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
        expected_fields = ({
            "test", "status", "skip_reason_code", "skip_reason_sha256",
        } if row["status"] == "skipped" else {"test", "status"})
        if set(row) != expected_fields \
                or (row["status"] == "skipped" and
                    (row.get("skip_reason_code") not in
                     loom_suite_harness.AUTHORIZED_SKIP_REASON_CODES
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
        raise CertificateError(
            "cell certificate is invalid", ["INVENTORY_MISMATCH"])
    return value


def compare_shadow(serial_report, certificate):
    verify_cell(certificate)
    if not isinstance(serial_report, dict):
        raise CertificateError("shadow parity report is invalid", ["SCHEMA"])
    skip_hashes = {
        row["test"]: (row["reason_sha256"] if isinstance(
            row.get("reason_sha256"), str) else hashlib.sha256(
                str(row.get("reason", "")).encode("utf-8")).hexdigest())
        for row in serial_report.get("skip_receipts", [])
        if isinstance(row, dict) and isinstance(row.get("test"), str)
    }
    skip_codes = {
        row["test"]: (
            row.get("reason_code") if row.get("reason_code") in
            loom_suite_harness.AUTHORIZED_SKIP_REASON_CODES else
            loom_suite_harness.skip_reason_code(row.get("reason", "")))
        for row in serial_report.get("skip_receipts", [])
        if isinstance(row, dict) and isinstance(row.get("test"), str)
    }
    outcomes = []
    for row in serial_report.get("timings", []):
        if not isinstance(row, dict) or row.get("status") not in {
                "passed", "failed", "error", "skipped"}:
            raise CertificateError(
                "shadow parity report is invalid", ["SCHEMA"])
        outcome = {"test": row["test"], "status": row["status"]}
        if row["status"] == "skipped":
            outcome["skip_reason_code"] = skip_codes.get(
                row["test"], "unclassified")
            outcome["skip_reason_sha256"] = skip_hashes.get(
                row["test"], hashlib.sha256(b"").hexdigest())
        outcomes.append(outcome)
    outcomes.sort(key=lambda row: row["test"])
    if outcomes != certificate["outcomes"]:
        raise CertificateError(
            "shadow parity mismatch", ["INVENTORY_MISMATCH"])
    serial_microseconds = serial_report.get("elapsed_microseconds")
    if type(serial_microseconds) is not int or serial_microseconds < 0:
        serial_microseconds = 0
        for row in serial_report.get("timings", []):
            duration = row.get("duration_microseconds") \
                if isinstance(row, dict) else None
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
        raise CertificateError(
            "matrix certificate inputs are invalid", ["SCHEMA"])
    for certificate in certificates:
        verify_cell(certificate)
    environments = [row["environment_sha256"] for row in certificates]
    subjects = [row["subject"] for row in certificates]
    if len(environments) != len(set(environments)) \
            or set(environments) != set(required_environments):
        raise CertificateError(
            "matrix certificate coverage is incomplete",
            ["INVENTORY_MISMATCH"])
    if any(subject != subjects[0] for subject in subjects[1:]):
        raise CertificateError(
            "matrix certificate subjects differ", ["WRONG_SUBJECT"])
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
            "matrix certificate contains uncovered skips",
            ["UNAUTHORIZED_SKIP"])
    test_inventories = [[outcome["test"] for outcome in row["outcomes"]]
                        for row in certificates]
    if any(inventory != test_inventories[0]
           for inventory in test_inventories[1:]):
        raise CertificateError(
            "matrix certificate test inventories differ",
            ["INVENTORY_MISMATCH"])
    for field in ("harness_sha256", "policy_sha256", "timing_profile_sha256"):
        if any(row[field] != certificates[0][field]
               for row in certificates[1:]):
            raise CertificateError(
                "matrix certificate policies differ", ["WRONG_POLICY"])
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
        raise CertificateError(
            "matrix certificate is invalid", ["RECEIPT_DIGEST"])
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
        raise CertificateError(
            "matrix certificate is invalid", ["SCHEMA"]) from exc
    if cells != sorted(cells, key=lambda item: item["environment_sha256"]):
        raise CertificateError(
            "matrix certificate is invalid", ["INVENTORY_MISMATCH"])
    environments = [row["environment_sha256"] for row in cells]
    if len(environments) != len(set(environments)):
        raise CertificateError(
            "matrix certificate is invalid", ["INVENTORY_MISMATCH"])
    if any(row["subject"] != body["subject"] for row in cells):
        raise CertificateError(
            "matrix certificate is invalid", ["WRONG_SUBJECT"])
    _require_release_topology(cells, body["consumer"])
    inventories = [[outcome["test"] for outcome in row["outcomes"]]
                   for row in cells]
    if any(inventory != inventories[0] for inventory in inventories[1:]):
        raise CertificateError(
            "matrix certificate is invalid", ["INVENTORY_MISMATCH"])
    for field in ("harness_sha256", "policy_sha256", "timing_profile_sha256"):
        if any(row[field] != cells[0][field] for row in cells[1:]):
            raise CertificateError(
                "matrix certificate is invalid", ["WRONG_POLICY"])
    passed = {
        outcome["test"] for cell in cells for outcome in cell["outcomes"]
        if outcome["status"] == "passed"
    }
    uncovered = {
        outcome["test"] for cell in cells for outcome in cell["outcomes"]
        if outcome["status"] == "skipped" and outcome["test"] not in passed
    }
    if uncovered:
        raise CertificateError(
            "matrix certificate contains uncovered skips",
            ["UNAUTHORIZED_SKIP"])
    return value
