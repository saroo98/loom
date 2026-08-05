#!/usr/bin/env python3
"""Process-isolated execution of one deterministic release-suite shard."""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import loom_operation_supervisor
import loom_privacy
import loom_reliability
import loom_release
import loom_release_subject
import loom_suite_plan
import loom_test


MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_FAILURE_DIAGNOSTICS = 100000
EXCEPTION_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
ABSOLUTE_OWNER_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/](?:Users|Documents|AppData)[\\/]|/(?:home|Users|root)/)",
    re.IGNORECASE)
FORBIDDEN_PUBLIC_KEYS = {
    "stdout", "stderr", "exception", "traceback", "environment_values",
    "runner_name", "owner_path", "home_path", "prompt",
}
WORKER_PRECEDENCE = (
    "WORKER_NOT_TERMINAL", "CANDIDATE_MUTATION", "PRIVACY_FAILURE",
    "INVENTORY_MISMATCH", "TEST_FAILURE", "UNAUTHORIZED_SKIP",
)


class SuiteWorkerError(RuntimeError):
    pass


def _load(path, label):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or path.stat().st_size > MAX_RECEIPT_BYTES:
        raise SuiteWorkerError(f"{label} is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SuiteWorkerError(f"{label} is unreadable") from exc


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _seal(value):
    if "worker_receipt_sha256" in value:
        raise SuiteWorkerError("worker receipt is already sealed")
    return {**value, "worker_receipt_sha256": loom_suite_plan.digest(value)}


def validate_receipt(value):
    if not isinstance(value, dict) or "worker_receipt_sha256" not in value:
        raise SuiteWorkerError("worker receipt is invalid")
    body = {key: item for key, item in value.items()
            if key != "worker_receipt_sha256"}
    if loom_suite_plan.digest(body) != value["worker_receipt_sha256"]:
        raise SuiteWorkerError("worker receipt digest is invalid")
    if set(body) != {
            "schema_version", "status", "primary_reason", "subject",
            "environment", "inventory_sha256", "policy_sha256", "findings",
            "timing_profile_sha256", "plan_sha256", "shard_id", "exclusive",
            "expected_modules", "expected_tests", "observed_tests", "test_count",
            "failure_count", "error_count", "skip_count", "duration_microseconds",
            "pre_manifest_sha256",
            "post_manifest_sha256", "mutation_clean", "privacy_clean",
            "runtime_roots_clean", "operation"} \
            or body.get("schema_version") != 1 \
            or body.get("status") not in {"passed", "failed"}:
        raise SuiteWorkerError("worker receipt fields are invalid")
    try:
        loom_suite_plan._subject(body.get("subject"))
        loom_suite_plan._environment(body.get("environment"))
    except loom_suite_plan.SuitePlanError as exc:
        raise SuiteWorkerError("worker receipt identity is invalid") from exc
    digest_fields = (
        "inventory_sha256", "policy_sha256", "timing_profile_sha256",
        "plan_sha256", "pre_manifest_sha256", "post_manifest_sha256",
    )
    if any(loom_suite_plan.HEX64.fullmatch(str(body.get(field, ""))) is None
           for field in digest_fields) \
            or re.fullmatch(r"^(exclusive|general-[0-9]{3})$", str(
                body.get("shard_id", ""))) is None \
            or type(body.get("exclusive")) is not bool \
            or (body["shard_id"] == "exclusive") != body["exclusive"]:
        raise SuiteWorkerError("worker receipt identity is invalid")
    modules = body.get("expected_modules")
    expected = body.get("expected_tests")
    observed = body.get("observed_tests")
    if not isinstance(modules, list) or not modules \
            or len(modules) != len(set(modules)) \
            or any(loom_suite_plan.MODULE.fullmatch(str(module)) is None
                   for module in modules) \
            or not isinstance(expected, list) or not expected \
            or expected != sorted(expected) or len(expected) != len(set(expected)) \
            or any(not isinstance(test_id, str) or not 3 <= len(test_id) <= 512
                   for test_id in expected) \
            or not isinstance(observed, list):
        raise SuiteWorkerError("worker receipt inventory is invalid")
    for outcome in observed:
        if not isinstance(outcome, dict) or outcome.get("status") not in {
                "passed", "failed", "error", "skipped"} \
                or not isinstance(outcome.get("test"), str) \
                or not 3 <= len(outcome["test"]) <= 512:
            raise SuiteWorkerError("worker receipt outcome is invalid")
        expected_fields = ({"test", "status", "skip_reason_code",
                            "skip_reason_sha256"}
                           if outcome["status"] == "skipped"
                           else {"test", "status"})
        if set(outcome) != expected_fields \
                or (outcome["status"] == "skipped" and
                    (outcome.get("skip_reason_code") not in
                     loom_test.AUTHORIZED_SKIP_REASON_CODES | {"unclassified"}
                     or loom_suite_plan.HEX64.fullmatch(str(
                         outcome.get("skip_reason_sha256", ""))) is None)):
            raise SuiteWorkerError("worker receipt outcome is invalid")
    observed_ids = [row["test"] for row in observed]
    counts = {
        "test_count": len(observed),
        "failure_count": sum(row["status"] == "failed" for row in observed),
        "error_count": sum(row["status"] == "error" for row in observed),
        "skip_count": sum(row["status"] == "skipped" for row in observed),
    }
    if observed_ids != sorted(observed_ids) \
            or len(observed_ids) != len(set(observed_ids)) \
            or any(type(body.get(field)) is not int or body[field] != count
                   for field, count in counts.items()) \
            or any(type(body.get(field)) is not bool for field in (
                "mutation_clean", "privacy_clean", "runtime_roots_clean")):
        raise SuiteWorkerError("worker receipt outcome counts are invalid")
    if type(body.get("duration_microseconds")) is not int \
            or body["duration_microseconds"] < 0:
        raise SuiteWorkerError("worker receipt duration is invalid")
    reasons = {
        "CANDIDATE_MUTATION", "WORKER_NOT_TERMINAL", "INVENTORY_MISMATCH",
        "TEST_FAILURE", "UNAUTHORIZED_SKIP", "PRIVACY_FAILURE",
    }
    primary = body.get("primary_reason")
    findings = body.get("findings")
    if not isinstance(findings, list) \
            or any(item not in reasons for item in findings) \
            or findings != sorted(set(findings), key=WORKER_PRECEDENCE.index) \
            or primary != (findings[0] if findings else None) \
            or (body["status"] == "passed") != (not findings):
        raise SuiteWorkerError("worker receipt terminal state is invalid")
    unauthorized = any(
        row.get("skip_reason_code") == "unclassified"
        for row in observed if row["status"] == "skipped")
    if unauthorized != ("UNAUTHORIZED_SKIP" in findings):
        raise SuiteWorkerError("worker skip authorization state is invalid")
    operation = body.get("operation")
    operation_fields = {
        "status", "returncode", "primary_failure", "survivors_confirmed_zero",
        "protected_roots_unchanged", "network_isolation_proven",
        "containment_provider", "receipt_sha256",
    }
    if not isinstance(operation, dict) or set(operation) != operation_fields \
            or operation.get("status") not in {"passed", "failed"} \
            or (operation.get("returncode") is not None and
                type(operation["returncode"]) is not int) \
            or any(type(operation.get(field)) is not bool for field in (
                "survivors_confirmed_zero", "protected_roots_unchanged",
                "network_isolation_proven")) \
            or (operation.get("primary_failure") is not None and (
                not isinstance(operation["primary_failure"], str) or
                len(operation["primary_failure"]) > 128)) \
            or (operation.get("containment_provider") is not None and (
                not isinstance(operation["containment_provider"], str) or
                len(operation["containment_provider"]) > 128)) \
            or loom_suite_plan.HEX64.fullmatch(str(
                operation.get("receipt_sha256", ""))) is None:
        raise SuiteWorkerError("worker operation receipt is invalid")
    if body["status"] == "passed" and (
            operation["status"] != "passed" or operation["returncode"] != 0
            or operation["primary_failure"] is not None
            or operation["survivors_confirmed_zero"] is not True
            or operation["protected_roots_unchanged"] is not True
            or not body["mutation_clean"] or not body["privacy_clean"]
            or not body["runtime_roots_clean"] or body["failure_count"]
            or body["error_count"]):
        raise SuiteWorkerError("worker receipt cannot claim success")
    if not _privacy_clean(body):
        raise SuiteWorkerError("worker receipt contains private evidence")
    return value


def validate_failure_diagnostic(value, receipt):
    validate_receipt(receipt)
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "worker_receipt_sha256", "shard_id", "failures",
            "failure_diagnostic_sha256"}:
        raise SuiteWorkerError("failure diagnostic fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "failure_diagnostic_sha256"}
    if value.get("schema_version") != 1 \
            or loom_suite_plan.HEX64.fullmatch(str(
                value.get("failure_diagnostic_sha256", ""))) is None \
            or loom_suite_plan.digest(body) != value["failure_diagnostic_sha256"] \
            or value.get("worker_receipt_sha256") != \
            receipt["worker_receipt_sha256"] \
            or value.get("shard_id") != receipt["shard_id"]:
        raise SuiteWorkerError("failure diagnostic identity is invalid")
    failures = value.get("failures")
    if not isinstance(failures, list) or not failures \
            or len(failures) > MAX_FAILURE_DIAGNOSTICS:
        raise SuiteWorkerError("failure diagnostic rows are invalid")
    keys = []
    for row in failures:
        required = {"test", "status", "exception_type"}
        if not isinstance(row, dict) or (
                set(row) != required
                and set(row) != required | {"error_code"}) \
                or not isinstance(row.get("test"), str) \
                or not 3 <= len(row["test"]) <= 512 \
                or row.get("status") not in {"failed", "error"} \
                or EXCEPTION_TYPE.fullmatch(str(
                    row.get("exception_type", ""))) is None \
                or ("error_code" in row and (
                    not isinstance(row["error_code"], str)
                    or row["error_code"] not in
                    loom_test.PUBLIC_ERROR_CODES | {
                        loom_test.PUBLIC_ERROR_CODE_REDACTED})):
            raise SuiteWorkerError("failure diagnostic row is invalid")
        keys.append((row["test"], row["status"], row["exception_type"],
                     row.get("error_code", "")))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise SuiteWorkerError("failure diagnostic order is invalid")
    observed = {
        (row["test"], row["status"])
        for row in receipt["observed_tests"]
        if row["status"] in {"failed", "error"}
    }
    diagnostic_outcomes = {(row["test"], row["status"]) for row in failures}
    if not observed or diagnostic_outcomes != observed \
            or sum(status == "failed" for _, status in observed) != \
            receipt["failure_count"] \
            or sum(status == "error" for _, status in observed) != \
            receipt["error_count"] \
            or not _privacy_clean(value):
        raise SuiteWorkerError("failure diagnostic outcomes are invalid")
    return value


def _privacy_clean(value):
    def walk(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key.casefold() in FORBIDDEN_PUBLIC_KEYS:
                    return False
                if not walk(child):
                    return False
        elif isinstance(item, list):
            return all(walk(child) for child in item)
        elif isinstance(item, str) and ABSOLUTE_OWNER_PATH.search(item):
            return False
        return True
    if not walk(value):
        return False
    try:
        content = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
        return loom_privacy._isolated_secret_signature_match(content) is None
    except (TypeError, ValueError, UnicodeError, loom_privacy.PrivacyError):
        return False


def _validate_inputs(cut, inventory, plan, shard_id):
    inventory = loom_suite_plan._validate_seal(
        inventory, "inventory_sha256", loom_suite_plan.seal_inventory)
    if not isinstance(plan, dict) or plan.get("plan_sha256") != loom_suite_plan.digest({
            key: value for key, value in plan.items() if key != "plan_sha256"}) \
            or plan.get("inventory_sha256") != inventory["inventory_sha256"]:
        raise SuiteWorkerError("shard plan is invalid")
    matches = [row for row in plan.get("shards", [])
               if row.get("shard_id") == shard_id]
    if len(matches) != 1:
        raise SuiteWorkerError("shard identity is invalid")
    cut = Path(cut).resolve()
    try:
        manifest = loom_release._verify_cut_manifest(cut)
        manifest_sha256 = hashlib.sha256(
            (cut / loom_release.MANIFEST).read_bytes()).hexdigest()
    except (OSError, loom_release.ReleaseError) as exc:
        raise SuiteWorkerError("worker public-cut subject is invalid") from exc
    if not cut.is_dir() or manifest["root_sha256"] != \
            inventory["subject"]["public_root_sha256"] \
            or manifest_sha256 != inventory["subject"]["public_manifest_sha256"] \
            or len(manifest["files"]) + 1 != inventory["subject"]["public_file_count"]:
        raise SuiteWorkerError("worker public-cut subject is invalid")
    worker_program = cut / "tools" / "loom_suite_worker.py"
    worker_entries = [
        row for row in manifest["files"]
        if row.get("path") == "tools/loom_suite_worker.py"
    ]
    if not worker_program.is_file() or worker_program.is_symlink() \
            or len(worker_entries) != 1 \
            or hashlib.sha256(worker_program.read_bytes()).hexdigest() != \
            worker_entries[0].get("sha256"):
        raise SuiteWorkerError("worker harness subject is invalid")
    return cut, inventory, plan, matches[0]


def _child(request_path, output_path):
    request = _load(request_path, "worker request")
    if set(request) != {"modules", "test_root"} \
            or not isinstance(request["modules"], list):
        raise SuiteWorkerError("worker request fields are invalid")
    report = loom_test.run_modules(
        request["modules"], start_dir=request["test_root"], verbosity=0)
    loom_reliability.atomic_write_json(Path(output_path), report)
    return 0 if report["status"] != "failed" and report["within_budget"] else 1


def _isolated_environment(worker_root, shard_id):
    # Keep runtime paths short on every platform. In particular, macOS Unix
    # sockets have a small pathname limit, and a worker root nested below an
    # Actions checkout is already too deep for several clean-host fixtures.
    # macOS commonly exposes its temporary directory through /var while the
    # canonical path is /private/var. Resolve the base before creating any
    # test-visible path so redirect-sensitive tests see one stable identity.
    temporary_base = Path(tempfile.gettempdir()).resolve()
    external_runtime_root = Path(tempfile.mkdtemp(
        prefix="loom-sw-", dir=temporary_base)).resolve()
    home = external_runtime_root / "home"
    temp = external_runtime_root / "temp"
    cache_root = external_runtime_root
    paths = {
        "HOME": home,
        "USERPROFILE": home,
        "APPDATA": home / "appdata",
        "LOCALAPPDATA": home / "localappdata",
        "CODEX_HOME": home / ".codex",
        "TMP": temp,
        "TEMP": temp,
        "TMPDIR": temp,
        "XDG_CACHE_HOME": home / ".cache",
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_DATA_HOME": home / ".local" / "share",
        "XDG_STATE_HOME": home / ".local" / "state",
        "LOOM_TEST_CACHE_ROOT": cache_root / "test-cache",
        "CARGO_HOME": cache_root / "cargo-home",
        "CARGO_TARGET_DIR": cache_root / "cargo-target",
    }
    try:
        for path in paths.values():
            path.mkdir(parents=True, exist_ok=True)
    except OSError:
        try:
            shutil.rmtree(external_runtime_root)
        except OSError:
            pass
        raise
    environment = {key: str(path) for key, path in paths.items()}
    environment["LOOM_TEST_RESOURCE_PREFIX"] = shard_id
    rustup = Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")))
    if rustup.is_dir():
        environment["RUSTUP_HOME"] = str(rustup.resolve())
    return environment, external_runtime_root


def execute_shard(cut, inventory, plan, shard_id, output_root, *, timeout,
                  protected_roots=()):
    cut, inventory, plan, shard = _validate_inputs(cut, inventory, plan, shard_id)
    output_root = Path(output_root).resolve()
    if not output_root.is_dir():
        raise SuiteWorkerError("worker output root is invalid")
    worker_root = output_root / shard_id
    if worker_root.exists():
        raise SuiteWorkerError("worker output already exists")
    worker_root.mkdir()
    candidate = worker_root / "candidate"
    shutil.copytree(cut, candidate)
    pre_manifest = loom_release._verify_cut_manifest(candidate)
    pre_manifest_sha256 = hashlib.sha256(
        (candidate / loom_release.MANIFEST).read_bytes()).hexdigest()
    request_path = worker_root / "request.json"
    report_path = worker_root / "suite-report.json"
    receipt_path = worker_root / "worker-receipt.json"
    diagnostic_path = worker_root / "failure-diagnostic.json"
    request = {"modules": shard["modules"],
               "test_root": str((candidate / "tools").resolve())}
    loom_reliability.atomic_write_json(request_path, request)
    runtime_roots_clean = True
    environment, external_runtime_root = _isolated_environment(worker_root, shard_id)
    started_ns = time.monotonic_ns()
    try:
        operation_result = loom_operation_supervisor.run(
            operation_class="release-suite-worker",
            command=[sys.executable, "-B",
                     str((candidate / "tools" / "loom_suite_worker.py").resolve()),
                     "_child", str(request_path), str(report_path)],
            cwd=(candidate / "tools").resolve(), timeout=timeout,
            environment=environment, allowed_roots=[worker_root],
            protected_roots=[cut, *protected_roots],
            capabilities=["local-process", "descendant-containment"],
            capture_output=True)
    finally:
        if external_runtime_root is not None:
            try:
                shutil.rmtree(external_runtime_root)
                runtime_roots_clean = not external_runtime_root.exists()
            except OSError:
                runtime_roots_clean = False
    duration_microseconds = max(0, (time.monotonic_ns() - started_ns) // 1000)
    operation, _stdout, _stderr = operation_result
    report = None
    if report_path.is_file() and not report_path.is_symlink():
        try:
            report = _load(report_path, "worker suite report")
        except SuiteWorkerError:
            report = None
    try:
        post_manifest = loom_release._verify_cut_manifest(candidate)
        post_manifest_sha256 = hashlib.sha256(
            (candidate / loom_release.MANIFEST).read_bytes()).hexdigest()
        mutation_clean = pre_manifest == post_manifest \
            and pre_manifest_sha256 == post_manifest_sha256
    except (OSError, loom_release.ReleaseError):
        post_manifest_sha256 = "0" * 64
        mutation_clean = False
    expected_modules = list(shard["modules"])
    expected_tests = sorted(
        test_id for row in inventory["modules"]
        if row["module"] in set(expected_modules) for test_id in row["tests"])
    observed = []
    failure_count = error_count = skip_count = 0
    raw_failure_count = raw_error_count = 0
    if isinstance(report, dict):
        skip_hashes = {
            row["test"]: hashlib.sha256(
                str(row["reason"]).encode("utf-8")).hexdigest()
            for row in report.get("skip_receipts", []) if isinstance(row, dict)
            and isinstance(row.get("test"), str)
        }
        for row in report.get("timings", []):
            if not isinstance(row, dict) or not isinstance(row.get("test"), str) \
                    or row.get("status") not in {
                        "passed", "failed", "error", "skipped"}:
                continue
            outcome = {"test": row["test"], "status": row["status"]}
            if row["status"] == "skipped":
                reason = next((str(item.get("reason", ""))
                               for item in report.get("skip_receipts", [])
                               if isinstance(item, dict)
                               and item.get("test") == row["test"]), "")
                outcome["skip_reason_code"] = loom_test.skip_reason_code(reason)
                outcome["skip_reason_sha256"] = skip_hashes.get(
                    row["test"], hashlib.sha256(b"").hexdigest())
            observed.append(outcome)
    observed.sort(key=lambda row: row["test"])
    failure_count = sum(row["status"] == "failed" for row in observed)
    error_count = sum(row["status"] == "error" for row in observed)
    skip_count = sum(row["status"] == "skipped" for row in observed)
    if isinstance(report, dict):
        raw_failure_count = int(report.get("failures", 0))
        raw_error_count = int(report.get("errors", 0))
    operation_public = {
        key: operation.get(key) for key in (
            "status", "returncode", "primary_failure",
            "survivors_confirmed_zero", "protected_roots_unchanged",
            "network_isolation_proven", "containment_provider", "receipt_sha256")
    }
    observed_ids = [row["test"] for row in observed]
    findings = []
    operation_terminal = isinstance(report, dict) and runtime_roots_clean \
        and operation.get("survivors_confirmed_zero") is True \
        and operation.get("protected_roots_unchanged") is True \
        and (operation.get("status") == "passed" or (
            operation.get("returncode") == 1
            and operation.get("primary_failure") == "nonzero-exit"))
    if not operation_terminal:
        findings.append("WORKER_NOT_TERMINAL")
    if not mutation_clean:
        findings.append("CANDIDATE_MUTATION")
    if observed_ids != expected_tests or not isinstance(report, dict) \
            or report.get("selected_modules") != expected_modules:
        findings.append("INVENTORY_MISMATCH")
    if failure_count or error_count or raw_failure_count or raw_error_count \
            or (isinstance(report, dict) and report.get("status") == "failed"):
        findings.append("TEST_FAILURE")
    if any(row.get("skip_reason_code") not in
           loom_test.AUTHORIZED_SKIP_REASON_CODES for row in observed
           if row["status"] == "skipped"):
        findings.append("UNAUTHORIZED_SKIP")
    findings = sorted(set(findings), key=WORKER_PRECEDENCE.index)
    primary_reason = findings[0] if findings else None
    body = {
        "schema_version": 1,
        "status": "passed" if primary_reason is None else "failed",
        "primary_reason": primary_reason, "findings": findings,
        "subject": inventory["subject"],
        "environment": inventory["environment"],
        "inventory_sha256": inventory["inventory_sha256"],
        "policy_sha256": plan["policy_sha256"],
        "timing_profile_sha256": plan["timing_profile_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "shard_id": shard_id, "exclusive": shard["exclusive"],
        "expected_modules": expected_modules, "expected_tests": expected_tests,
        "observed_tests": observed, "test_count": len(observed),
        "failure_count": failure_count, "error_count": error_count,
        "skip_count": skip_count, "duration_microseconds": duration_microseconds,
        "pre_manifest_sha256": pre_manifest_sha256,
        "post_manifest_sha256": post_manifest_sha256,
        "mutation_clean": mutation_clean,
        "privacy_clean": True,
        "runtime_roots_clean": runtime_roots_clean,
        "operation": operation_public,
    }
    body["privacy_clean"] = _privacy_clean(body)
    if not body["privacy_clean"]:
        body["findings"] = sorted(
            set(body["findings"] + ["PRIVACY_FAILURE"]),
            key=WORKER_PRECEDENCE.index)
        body["status"] = "failed"
        body["primary_reason"] = body["findings"][0]
    receipt = _seal(body)
    validate_receipt(receipt)
    diagnostic = None
    if failure_count or error_count:
        diagnostic_body = {
            "schema_version": 1,
            "worker_receipt_sha256": receipt["worker_receipt_sha256"],
            "shard_id": shard_id,
            "failures": report.get("failure_diagnostics")
            if isinstance(report, dict) else None,
        }
        diagnostic = {
            **diagnostic_body,
            "failure_diagnostic_sha256": loom_suite_plan.digest(
                diagnostic_body),
        }
        validate_failure_diagnostic(diagnostic, receipt)
    loom_reliability.atomic_write_json(receipt_path, receipt)
    if diagnostic is not None:
        loom_reliability.atomic_write_json(diagnostic_path, diagnostic)
    return receipt


def run_plan(cut, inventory, plan, output_root, *, timeout, protected_roots=()):
    output_root = Path(output_root).resolve()
    if not output_root.is_dir():
        raise SuiteWorkerError("worker output root is invalid")
    shards = list(plan.get("shards", []))
    results = []
    exclusive = [shard for shard in shards if shard.get("exclusive") is True]
    general = [shard for shard in shards if shard.get("exclusive") is False]
    if len(exclusive) > 1 or len(exclusive) + len(general) != len(shards):
        raise SuiteWorkerError("shard execution lanes are invalid")
    worker_budget = int(plan.get("max_parallel_workers", 1))
    # A two-slot host cannot give the mutation/native-heavy exclusive lane and
    # the general lane enough independent headroom. Qualify them sequentially
    # there; wider hosts retain concurrent exclusive/general execution.
    if exclusive and worker_budget <= 2:
        results.append(execute_shard(
            cut, inventory, plan, exclusive[0]["shard_id"], output_root,
            timeout=timeout, protected_roots=protected_roots))
        scheduled = general
    else:
        scheduled = exclusive + general
    if not scheduled:
        return sorted(results, key=lambda row: row["shard_id"])
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(worker_budget, len(scheduled))) as executor:
        futures = {
            executor.submit(
                execute_shard, cut, inventory, plan, shard["shard_id"],
                output_root, timeout=timeout, protected_roots=protected_roots):
            shard["shard_id"] for shard in scheduled
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda row: row["shard_id"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    child = subparsers.add_parser("_child")
    child.add_argument("request")
    child.add_argument("output")
    run_parser = subparsers.add_parser("run-plan")
    run_parser.add_argument("cut")
    run_parser.add_argument("inventory")
    run_parser.add_argument("plan")
    run_parser.add_argument("output_root")
    run_parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args(argv)
    if args.command == "_child":
        return _child(args.request, args.output)
    inventory_value = _load(args.inventory, "suite inventory")
    plan_value = _load(args.plan, "shard plan")
    receipts = run_plan(
        args.cut, inventory_value, plan_value, args.output_root,
        timeout=args.timeout)
    print(json.dumps({
        "status": "passed" if all(row["status"] == "passed" for row in receipts)
        else "failed", "workers": len(receipts),
    }, sort_keys=True))
    return 0 if all(row["status"] == "passed" for row in receipts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
