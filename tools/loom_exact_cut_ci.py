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
import loom_exact_cut_receipt
import loom_operation_envelope
import loom_operation_supervisor
import loom_platform_probe
import loom_publication_privacy
import loom_suite_harness
import loom_test


HEX40 = loom_exact_cut_receipt.HEX40
HEX64 = loom_exact_cut_receipt.HEX64
PUBLIC_TEST_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{2,511}$")
ABSOLUTE_OWNER_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/](?:Users|Documents|AppData)[\\/]|/(?:home|Users|root)/)",
    re.IGNORECASE)
RECEIPT_FIELDS = loom_exact_cut_receipt.RECEIPT_FIELDS
SUITE_FIELDS = loom_exact_cut_receipt.SUITE_FIELDS
ENVIRONMENT_FIELDS = loom_exact_cut_receipt.ENVIRONMENT_FIELDS
BINDING_FIELDS = loom_exact_cut_receipt.BINDING_FIELDS
MAX_SERIAL_FAILURE_DIAGNOSTIC_BYTES = 128 * 1024
MAX_SERIAL_PROGRESS_DIAGNOSTIC_BYTES = 128 * 1024
SERIAL_DIAGNOSTIC_FINALIZATION_ERROR = "SerialDiagnosticFinalizationError"
OPERATION_PROJECTION_FIELDS = {
    "operation_receipt_sha256", "status", "returncode", "primary_failure",
    "survivors_confirmed_zero", "protected_roots_unchanged",
    "network_isolation_proven", "containment_provider", "projection_sha256",
    "test_association_sha256",
}


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(_value):
    raise ValueError("non-finite JSON value")


def _seal(receipt):
    return loom_exact_cut_receipt.seal_receipt(receipt)


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


def _serial_failure_diagnostic(failures, exact_receipt):
    ordered = sorted(failures, key=lambda row: (
        row.get("test", ""), row.get("status", ""),
        row.get("exception_type", ""), row.get("error_code", ""),
        row.get("operation_projection", {}).get("projection_sha256", "")))
    canonical = {}
    for row in ordered:
        if isinstance(row, dict):
            canonical.setdefault((row.get("test"), row.get("status")), row)
    body = {
        "schema_version": 1,
        "exact_cut_receipt_sha256": exact_receipt["receipt_sha256"],
        "failures": [canonical[(row["test"], row["status"])]
                     for row in exact_receipt["suite"]["failed_tests"]
                     if (row["test"], row["status"]) in canonical],
    }
    value = {**body, "failure_diagnostic_sha256": _digest(body)}
    return verify_serial_failure_diagnostic(value, exact_receipt)


def verify_serial_failure_diagnostic(value, exact_receipt):
    """Verify one closed privacy-safe serial failure sidecar."""
    if not isinstance(exact_receipt, dict) \
            or set(exact_receipt) != RECEIPT_FIELDS \
            or exact_receipt.get("schema_version") != 2 \
            or exact_receipt.get("status") != "failed" \
            or exact_receipt.get("receipt_sha256") != _seal(
                exact_receipt)["receipt_sha256"]:
        raise ValueError("serial diagnostic exact-cut receipt is invalid")
    suite = exact_receipt.get("suite")
    if not isinstance(suite, dict) or set(suite) != SUITE_FIELDS \
            or suite.get("schema_version") != 2 \
            or suite.get("passed") is not False \
            or not isinstance(suite.get("failed_tests"), list):
        raise ValueError("serial diagnostic exact-cut suite is invalid")
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "exact_cut_receipt_sha256", "failures",
            "failure_diagnostic_sha256"}:
        raise ValueError("serial diagnostic fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "failure_diagnostic_sha256"}
    if value.get("schema_version") != 1 \
            or value.get("exact_cut_receipt_sha256") != \
            exact_receipt["receipt_sha256"] \
            or HEX64.fullmatch(str(
                value.get("failure_diagnostic_sha256", ""))) is None \
            or value["failure_diagnostic_sha256"] != _digest(body):
        raise ValueError("serial diagnostic identity is invalid")
    failures = value.get("failures")
    if not isinstance(failures, list) or not 1 <= len(failures) <= 64:
        raise ValueError("serial diagnostic rows are invalid")
    keys = []
    for row in failures:
        required = {"test", "status", "exception_type"}
        optional = {"error_code", "operation_projection"}
        if not isinstance(row, dict) or not required <= set(row) \
                or not set(row) <= required | optional \
                or PUBLIC_TEST_ID.fullmatch(str(row.get("test", ""))) is None \
                or row.get("status") not in {"failed", "error"} \
                or loom_test.EXCEPTION_TYPE.fullmatch(str(
                    row.get("exception_type", ""))) is None \
                or ("error_code" in row and row["error_code"] not in
                    loom_test.PUBLIC_ERROR_CODES | {
                        loom_test.PUBLIC_ERROR_CODE_REDACTED}):
            raise ValueError("serial diagnostic row is invalid")
        projection = row.get("operation_projection")
        if projection is not None:
            if not isinstance(projection, dict) \
                    or set(projection) != OPERATION_PROJECTION_FIELDS:
                raise ValueError("serial diagnostic operation projection is invalid")
            projection_body = {
                key: item for key, item in projection.items()
                if key not in {
                    "projection_sha256", "test_association_sha256"}}
            association = {
                "test": row["test"], "status": row["status"],
                "operation_projection_sha256": projection.get(
                    "projection_sha256"),
            }
            primary = projection.get("primary_failure")
            returncode = projection.get("returncode")
            if HEX64.fullmatch(str(projection.get(
                    "operation_receipt_sha256", ""))) is None \
                    or projection.get("status") not in {"passed", "failed"} \
                    or (returncode is not None and type(returncode) is not int) \
                    or (primary is not None and primary not in
                        loom_operation_supervisor.PRIMARY_FAILURES) \
                    or projection["status"] != (
                        "passed" if primary is None else "failed") \
                    or any(type(projection.get(field)) is not bool for field in (
                        "survivors_confirmed_zero",
                        "protected_roots_unchanged",
                        "network_isolation_proven")) \
                    or projection.get("containment_provider") not in \
                    loom_operation_supervisor.CONTAINMENT_PROVIDERS \
                    or HEX64.fullmatch(str(projection.get(
                        "projection_sha256", ""))) is None \
                    or projection["projection_sha256"] != _digest(
                        projection_body) \
                    or HEX64.fullmatch(str(projection.get(
                        "test_association_sha256", ""))) is None \
                    or projection["test_association_sha256"] != _digest(
                        association):
                raise ValueError("serial diagnostic operation projection is invalid")
        keys.append((row["test"], row["status"], row["exception_type"],
                     row.get("error_code", ""),
                     projection.get("projection_sha256", "")
                     if projection is not None else ""))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ValueError("serial diagnostic order is invalid")
    failed_tests = suite.get("failed_tests")
    if not isinstance(failed_tests, list) \
            or not 1 <= len(failed_tests) <= 64:
        raise ValueError("serial diagnostic outcomes are invalid")
    outcome_keys = []
    for row in failed_tests:
        if not isinstance(row, dict) or set(row) != {"test", "status"} \
                or PUBLIC_TEST_ID.fullmatch(str(row.get("test", ""))) is None \
                or row.get("status") not in {"failed", "error"}:
            raise ValueError("serial diagnostic outcomes are invalid")
        outcome_keys.append((row["test"], row["status"]))
    if outcome_keys != sorted(outcome_keys) \
            or len(outcome_keys) != len(set(outcome_keys)):
        raise ValueError("serial diagnostic outcomes are invalid")
    observed = set(outcome_keys)
    diagnosed = {(row["test"], row["status"]) for row in failures}
    if diagnosed != observed:
        raise ValueError("serial diagnostic outcomes are invalid")
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")
    if ABSOLUTE_OWNER_PATH.search(encoded.decode("utf-8")) \
            or loom_publication_privacy._isolated_secret_signature_match(
                encoded) is not None:
        raise ValueError("serial diagnostic contains private evidence")
    return value


def load_serial_failure_diagnostic(path, exact_receipt):
    """Strictly load and verify a bounded serial diagnostic sidecar."""
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or path.stat().st_size > MAX_SERIAL_FAILURE_DIAGNOSTIC_BYTES:
        raise ValueError("serial diagnostic transport is unsafe")
    try:
        value = json.loads(
            path.read_bytes().decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("serial diagnostic JSON is invalid") from exc
    return verify_serial_failure_diagnostic(value, exact_receipt)


def _serial_progress_diagnostic(checkpoint, operation, exact_receipt):
    body = {
        "schema_version": 1,
        "authorizing": False,
        "exact_cut_receipt_sha256": exact_receipt["receipt_sha256"],
        "operation": operation,
        "checkpoint": checkpoint,
    }
    value = {**body, "progress_diagnostic_sha256": _digest(body)}
    return verify_serial_progress_diagnostic(value, exact_receipt)


def verify_serial_progress_diagnostic(value, exact_receipt):
    """Verify one non-authorizing timeout/progress sidecar."""
    if not isinstance(exact_receipt, dict) \
            or set(exact_receipt) != RECEIPT_FIELDS \
            or exact_receipt.get("schema_version") != 2 \
            or exact_receipt.get("status") != "failed" \
            or exact_receipt.get("receipt_sha256") != _seal(
                exact_receipt)["receipt_sha256"]:
        raise ValueError("serial progress exact-cut receipt is invalid")
    suite = exact_receipt.get("suite")
    if not isinstance(suite, dict) or set(suite) != SUITE_FIELDS \
            or suite.get("schema_version") != 2 \
            or suite.get("passed") is not False:
        raise ValueError("serial progress exact-cut suite is invalid")
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "authorizing", "exact_cut_receipt_sha256",
            "operation", "checkpoint", "progress_diagnostic_sha256"}:
        raise ValueError("serial progress diagnostic fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "progress_diagnostic_sha256"}
    if value.get("schema_version") != 1 \
            or value.get("authorizing") is not False \
            or value.get("exact_cut_receipt_sha256") != \
            exact_receipt["receipt_sha256"] \
            or HEX64.fullmatch(str(value.get(
                "progress_diagnostic_sha256", ""))) is None \
            or value["progress_diagnostic_sha256"] != _digest(body):
        raise ValueError("serial progress diagnostic identity is invalid")
    try:
        checkpoint = loom_suite_harness.validate_progress_checkpoint(
            value.get("checkpoint"))
    except loom_suite_harness.SuiteHarnessError as exc:
        raise ValueError("serial progress checkpoint is invalid") from exc
    operation = value.get("operation")
    fields = {
        "status", "returncode", "primary_failure",
        "survivors_confirmed_zero", "protected_roots_unchanged",
        "network_isolation_proven", "containment_provider", "receipt_sha256",
    }
    primary = operation.get("primary_failure") \
        if isinstance(operation, dict) else None
    returncode = operation.get("returncode") \
        if isinstance(operation, dict) else None
    if not isinstance(operation, dict) or set(operation) != fields \
            or operation.get("status") != "failed" \
            or (returncode is not None and type(returncode) is not int) \
            or primary not in loom_operation_supervisor.PRIMARY_FAILURES \
            or any(type(operation.get(field)) is not bool for field in (
                "survivors_confirmed_zero", "protected_roots_unchanged",
                "network_isolation_proven")) \
            or operation.get("containment_provider") not in \
            loom_operation_supervisor.CONTAINMENT_PROVIDERS \
            or HEX64.fullmatch(str(operation.get("receipt_sha256", ""))) is None \
            or operation["receipt_sha256"] != suite.get(
                "operation_receipt_sha256") \
            or suite.get("primary_failure_sha256") != hashlib.sha256(
                primary.encode("utf-8")).hexdigest():
        raise ValueError("serial progress operation is invalid")
    if checkpoint["status"] != "running":
        raise ValueError("serial progress checkpoint is not interrupted")
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")
    if ABSOLUTE_OWNER_PATH.search(encoded.decode("utf-8")) \
            or loom_publication_privacy._isolated_secret_signature_match(
                encoded) is not None:
        raise ValueError("serial progress diagnostic contains private evidence")
    return value


def load_serial_progress_diagnostic(path, exact_receipt):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or path.stat().st_size > MAX_SERIAL_PROGRESS_DIAGNOSTIC_BYTES:
        raise ValueError("serial progress diagnostic transport is unsafe")
    try:
        value = json.loads(
            path.read_bytes().decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("serial progress diagnostic JSON is invalid") from exc
    return verify_serial_progress_diagnostic(value, exact_receipt)


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
    failure_outcomes = {}
    for row in value.get("failed_tests", []):
        if isinstance(row, dict) \
                and PUBLIC_TEST_ID.fullmatch(str(row.get("test", ""))) \
                and row.get("status") in {"failed", "error"}:
            test_id = row["test"]
            if row["status"] == "error" \
                    or failure_outcomes.get(test_id) is None:
                failure_outcomes[test_id] = row["status"]
    failures = [
        {"test": test_id, "status": status}
        for test_id, status in sorted(failure_outcomes.items())
    ][:64]
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
        "failed_tests": failures,
        "skip_receipts": sorted(skips, key=lambda row: row["test"]),
        "timings": sorted(timings, key=lambda row: row["test"]),
        "binding": binding,
    }
    return body


def verify_receipt(value, *, require_static=None):
    """Validate one successful closed v2 receipt before evidence reuse."""
    return loom_exact_cut_receipt.verify_receipt(
        value, require_static=require_static)


def run(source, cut, output, *, suite_output=None,
        failure_diagnostic_output=None, progress_diagnostic_output=None,
        forbidden_tokens=(), static_only=False):
    source = Path(source).resolve()
    cut = Path(cut).resolve()
    output = Path(output).resolve()
    requested_failure_diagnostic_output = failure_diagnostic_output
    requested_progress_diagnostic_output = progress_diagnostic_output
    failure_diagnostic_output = None
    progress_diagnostic_output = None
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
    failure_diagnostics = None
    progress_checkpoint = None
    progress_operation = None
    diagnostic_finalization_started = False
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
        if requested_failure_diagnostic_output is not None:
            lexical_diagnostic_output = Path(os.path.abspath(
                os.fspath(requested_failure_diagnostic_output)))
            if lexical_diagnostic_output.is_symlink():
                raise ValueError("serial diagnostic output is unsafe")
            resolved_diagnostic_output = lexical_diagnostic_output.resolve()
            if resolved_diagnostic_output == output \
                    or suite_output is not None \
                    and resolved_diagnostic_output == Path(
                        suite_output).resolve():
                raise ValueError("serial diagnostic output must be distinct")
            if resolved_diagnostic_output.exists():
                if not resolved_diagnostic_output.is_file():
                    raise ValueError("serial diagnostic output is unsafe")
                resolved_diagnostic_output.unlink()
            failure_diagnostic_output = resolved_diagnostic_output
        if requested_progress_diagnostic_output is not None:
            lexical_progress_output = Path(os.path.abspath(
                os.fspath(requested_progress_diagnostic_output)))
            if lexical_progress_output.is_symlink():
                raise ValueError("serial progress diagnostic output is unsafe")
            resolved_progress_output = lexical_progress_output.resolve()
            reserved = {
                output,
                *([Path(suite_output).resolve()]
                  if suite_output is not None else []),
                *([failure_diagnostic_output]
                  if failure_diagnostic_output is not None else []),
            }
            if resolved_progress_output in reserved:
                raise ValueError(
                    "serial progress diagnostic output must be distinct")
            if resolved_progress_output.exists():
                if not resolved_progress_output.is_file():
                    raise ValueError(
                        "serial progress diagnostic output is unsafe")
                resolved_progress_output.unlink()
            progress_diagnostic_output = resolved_progress_output
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
            suite_details = details["suite"]
            base["suite"] = _public_suite(suite_details)
            if isinstance(suite_details.get("failure_diagnostics"), list):
                failure_diagnostics = suite_details["failure_diagnostics"]
            if isinstance(suite_details.get("progress_checkpoint"), dict) \
                    and isinstance(suite_details.get("operation"), dict):
                progress_checkpoint = suite_details["progress_checkpoint"]
                progress_operation = suite_details["operation"]
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
            if failure_diagnostic_output is not None \
                    and failure_diagnostics:
                diagnostic_finalization_started = True
                diagnostic = _serial_failure_diagnostic(
                    failure_diagnostics, base)
                loom_reliability.atomic_write_json(
                    failure_diagnostic_output, diagnostic)
            if progress_diagnostic_output is not None \
                    and progress_checkpoint is not None \
                    and progress_operation is not None:
                diagnostic_finalization_started = True
                progress_diagnostic = _serial_progress_diagnostic(
                    progress_checkpoint, progress_operation, base)
                loom_reliability.atomic_write_json(
                    progress_diagnostic_output, progress_diagnostic)
        except BaseException as final_exc:
            if diagnostic_finalization_started:
                original_classification = base.get("error_type") or "None"
                original_digest = base.get("error_sha256") or "0" * 64
                base.update({
                    "status": "failed",
                    "error_type": SERIAL_DIAGNOSTIC_FINALIZATION_ERROR,
                    "error_sha256": hashlib.sha256((
                        SERIAL_DIAGNOSTIC_FINALIZATION_ERROR + ":" +
                        original_classification + ":" + original_digest
                    ).encode("utf-8")).hexdigest(),
                })
                base = _seal(base)
                loom_reliability.atomic_write_json(output, base)
            elif base["error_type"] is None:
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
    parser.add_argument("--failure-diagnostic-output")
    parser.add_argument("--progress-diagnostic-output")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--forbidden-token", action="append", default=[])
    args = parser.parse_args(argv)
    result = run(args.source, args.cut, args.output, suite_output=args.suite_output,
                 failure_diagnostic_output=args.failure_diagnostic_output,
                 progress_diagnostic_output=args.progress_diagnostic_output,
                 forbidden_tokens=args.forbidden_token,
                 static_only=args.static_only)
    print(json.dumps({key: result[key] for key in (
        "status", "build_root_sha256", "verified_root_sha256", "error_type")},
        sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
