#!/usr/bin/env python3
"""Product-independent unittest execution and privacy-safe result projection."""

import contextlib
import hashlib
import io
import json
import os
import re
import sys
import time
import unittest
from pathlib import Path

import loom_operation_supervisor


class SuiteHarnessError(RuntimeError):
    pass


DIAGNOSTIC_POLICY_FIELDS = {
    "schema_version", "public_error_codes",
    "authorized_skip_reason_codes",
}
DIAGNOSTIC_POLICY_DIGEST_DOMAIN = b"loom.release-suite-diagnostics.v1\0"
ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
TEST_MODULE = re.compile(r"^test_[A-Za-z0-9_]+$")
EXCEPTION_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
PUBLIC_ERROR_CODE_REDACTED = "PUBLIC_ERROR_CODE_REDACTED"
STATUS_SEVERITY = {
    "passed": 0, "skipped": 1, "failed": 2, "error": 3,
}
FIXTURE_HOLDER = re.compile(
    r"^(setUpClass|tearDownClass|setUpModule|tearDownModule) "
    r"\(([A-Za-z_][A-Za-z0-9_.]*)\)$")
EXPECTED_SKIP_REASON_CODES = {
    "platform-boundary", "host-capability-unavailable", "tool-unavailable",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_TEST_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{2,511}$")
PROGRESS_FIELDS = {
    "schema_version", "status", "authorizing",
    "diagnostic_policy_sha256", "selected_modules_sha256",
    "checkpoint_sequence", "completed_test_count", "last_started_test",
    "last_completed_test",
}
PROGRESS_DIGEST_DOMAIN = b"loom.suite-progress-checkpoint.v1\0"


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def seal_diagnostic_policy(value):
    if not isinstance(value, dict) or set(value) != DIAGNOSTIC_POLICY_FIELDS \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("public_error_codes"), list) \
            or not isinstance(value.get("authorized_skip_reason_codes"), list):
        raise SuiteHarnessError("release suite diagnostic policy fields are invalid")
    public = value["public_error_codes"]
    skips = value["authorized_skip_reason_codes"]
    if public != sorted(set(public)) or not public \
            or any(type(code) is not str or ERROR_CODE.fullmatch(code) is None
                   for code in public) \
            or skips != sorted(EXPECTED_SKIP_REASON_CODES):
        raise SuiteHarnessError("release suite diagnostic policy fields are invalid")
    body = {
        "schema_version": 1,
        "public_error_codes": list(public),
        "authorized_skip_reason_codes": list(skips),
    }
    return {
        **body,
        "policy_sha256": hashlib.sha256(
            DIAGNOSTIC_POLICY_DIGEST_DOMAIN + canonical(body)).hexdigest(),
    }


def validate_diagnostic_policy(value):
    if not isinstance(value, dict) or "policy_sha256" not in value:
        raise SuiteHarnessError("release suite diagnostic policy digest is missing")
    body = {key: item for key, item in value.items()
            if key != "policy_sha256"}
    try:
        expected = seal_diagnostic_policy(body)
    except SuiteHarnessError as exc:
        raise SuiteHarnessError(
            "release suite diagnostic policy fields are invalid") from exc
    if value != expected:
        raise SuiteHarnessError("release suite diagnostic policy digest is invalid")
    return value


def load_diagnostic_policy(root, *, path=None):
    root = Path(root).resolve()
    path = root / "contracts" / "release-suite-diagnostics-v1.json" \
        if path is None else Path(path)
    try:
        if not root.is_dir() or not path.is_file() or path.is_symlink() \
                or path.stat().st_size > 1024 * 1024:
            raise SuiteHarnessError("release suite diagnostic policy is unsafe")
        value = json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SuiteHarnessError(
            "release suite diagnostic policy is invalid") from exc
    return validate_diagnostic_policy(value)


_POLICY = load_diagnostic_policy(Path(__file__).resolve().parents[1])
PUBLIC_ERROR_CODES = frozenset(_POLICY["public_error_codes"])
AUTHORIZED_SKIP_REASON_CODES = frozenset(
    _POLICY["authorized_skip_reason_codes"])


def seal_progress_checkpoint(value):
    if not isinstance(value, dict) or set(value) != PROGRESS_FIELDS \
            or value.get("schema_version") != 1 \
            or value.get("status") not in {"running", "completed"} \
            or value.get("authorizing") is not False \
            or HEX64.fullmatch(str(value.get(
                "diagnostic_policy_sha256", ""))) is None \
            or value.get("selected_modules_sha256") is not None and \
            HEX64.fullmatch(str(value["selected_modules_sha256"])) is None \
            or type(value.get("checkpoint_sequence")) is not int \
            or not 0 <= value["checkpoint_sequence"] <= 10_000_000 \
            or type(value.get("completed_test_count")) is not int \
            or not 0 <= value["completed_test_count"] <= 1_000_000:
        raise SuiteHarnessError("suite progress checkpoint fields are invalid")
    for field in ("last_started_test", "last_completed_test"):
        test_id = value.get(field)
        if test_id is not None and (
                not isinstance(test_id, str)
                or PUBLIC_TEST_ID.fullmatch(test_id) is None):
            raise SuiteHarnessError("suite progress checkpoint fields are invalid")
    if value["completed_test_count"] == 0 \
            and value["last_completed_test"] is not None \
            or value["completed_test_count"] > 0 \
            and value["last_completed_test"] is None:
        raise SuiteHarnessError("suite progress checkpoint fields are invalid")
    body = {
        "schema_version": 1,
        "status": value["status"],
        "authorizing": False,
        "diagnostic_policy_sha256": value["diagnostic_policy_sha256"],
        "selected_modules_sha256": value["selected_modules_sha256"],
        "checkpoint_sequence": value["checkpoint_sequence"],
        "completed_test_count": value["completed_test_count"],
        "last_started_test": value["last_started_test"],
        "last_completed_test": value["last_completed_test"],
    }
    return {
        **body,
        "checkpoint_sha256": hashlib.sha256(
            PROGRESS_DIGEST_DOMAIN + canonical(body)).hexdigest(),
    }


def validate_progress_checkpoint(value):
    if not isinstance(value, dict) or "checkpoint_sha256" not in value:
        raise SuiteHarnessError("suite progress checkpoint digest is missing")
    body = {key: item for key, item in value.items()
            if key != "checkpoint_sha256"}
    try:
        expected = seal_progress_checkpoint(body)
    except SuiteHarnessError as exc:
        raise SuiteHarnessError("suite progress checkpoint fields are invalid") from exc
    if value != expected:
        raise SuiteHarnessError("suite progress checkpoint digest is invalid")
    if value["diagnostic_policy_sha256"] != _POLICY["policy_sha256"]:
        raise SuiteHarnessError("suite progress checkpoint policy is stale")
    return value


def load_progress_checkpoint(path):
    path = Path(path)
    try:
        if not path.is_file() or path.is_symlink() \
                or path.stat().st_size > 64 * 1024:
            raise SuiteHarnessError("suite progress checkpoint is unsafe")
        value = json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SuiteHarnessError("suite progress checkpoint is invalid") from exc
    return validate_progress_checkpoint(value)


class ProgressCheckpoint:
    def __init__(self, path, selected_modules):
        self.path = Path(path).resolve()
        if not self.path.parent.is_dir() or self.path.is_symlink():
            raise SuiteHarnessError("suite progress checkpoint output is unsafe")
        selected_digest = (hashlib.sha256(canonical(list(selected_modules))).hexdigest()
                           if selected_modules is not None else None)
        self.state = {
            "schema_version": 1,
            "status": "running",
            "authorizing": False,
            "diagnostic_policy_sha256": _POLICY["policy_sha256"],
            "selected_modules_sha256": selected_digest,
            "checkpoint_sequence": 0,
            "completed_test_count": 0,
            "last_started_test": None,
            "last_completed_test": None,
        }
        self._commit()

    @staticmethod
    def _safe_test_id(test):
        value = TimingResult._test_id(test)
        return value if PUBLIC_TEST_ID.fullmatch(value) else None

    def _commit(self):
        self.state["checkpoint_sequence"] += 1
        value = seal_progress_checkpoint(self.state)
        temporary = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.tmp")
        try:
            if temporary.exists():
                temporary.unlink()
            with temporary.open("xb") as stream:
                stream.write(canonical(value) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            try:
                if temporary.exists() and not temporary.is_symlink():
                    temporary.unlink()
            except OSError:
                pass
            raise SuiteHarnessError(
                "suite progress checkpoint cannot be committed") from exc

    def started(self, test):
        self.state["last_started_test"] = self._safe_test_id(test)
        self._commit()

    def completed(self, test):
        self.state["completed_test_count"] += 1
        self.state["last_completed_test"] = self._safe_test_id(test)
        self._commit()

    def finalize(self):
        self.state["status"] = "completed"
        self._commit()


def skip_reason_code(reason):
    """Map a private unittest reason onto one public, reviewable policy code."""
    value = str(reason).casefold()
    if re.search(
            r"windows|non-windows|posix|ntfs|fifo|platform|macos|linux|darwin|"
            r"chmod|alternate (?:data )?streams?|native", value):
        return "platform-boundary"
    if re.search(r"\b(?:git|cargo|rust|toolchain)\b.*unavailable", value):
        return "tool-unavailable"
    if re.search(
            r"unavailable|unsupported|symlinks?|hardlinks?|xattrs?|key store|"
            r"backend|privilege", value):
        return "host-capability-unavailable"
    return "unclassified"


def _verified_operation_projection(error):
    """Project a duck-typed verified native operation without product imports."""
    receipt = getattr(error, "receipt", None)
    if receipt is None:
        return None
    try:
        receipt = loom_operation_supervisor.verify_receipt(receipt)
    except loom_operation_supervisor.SupervisorError:
        return None
    if receipt["operation_class"] != "vault-helper-build":
        return None
    body = {
        "operation_receipt_sha256": receipt["receipt_sha256"],
        "status": receipt["status"],
        "returncode": receipt["returncode"],
        "primary_failure": receipt["primary_failure"],
        "survivors_confirmed_zero": receipt["survivors_confirmed_zero"],
        "protected_roots_unchanged": receipt["protected_roots_unchanged"],
        "network_isolation_proven": receipt["network_isolation_proven"],
        "containment_provider": receipt["containment_provider"],
    }
    return {
        **body,
        "projection_sha256": hashlib.sha256(canonical(body)).hexdigest(),
    }


class TimingResult(unittest.TextTestResult):
    def __init__(self, *args, progress_checkpoint=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.progress_checkpoint = progress_checkpoint
        self._statuses = {}
        self._failure_diagnostic_keys = set()
        self.failure_diagnostics = []
        self.timings = []

    @staticmethod
    def _test_id(test):
        test_id = test.id()
        fixture = FIXTURE_HOLDER.fullmatch(test_id)
        if fixture is None:
            return test_id
        scope = "class" if fixture.group(1).endswith("Class") else "module"
        return f"fixture.{scope}.{fixture.group(2)}"

    def _record_failure_diagnostic(self, test, status, err=None, *,
                                   unexpected_success=False):
        if unexpected_success:
            exception_type = "UnexpectedSuccess"
            error_code = None
            operation_projection = None
        else:
            exception_type = getattr(err[0], "__name__", "UnknownException")
            if not isinstance(exception_type, str) \
                    or EXCEPTION_TYPE.fullmatch(exception_type) is None:
                exception_type = "UnknownException"
            raw_error_code = getattr(err[1], "code", None)
            error_code = (
                raw_error_code
                if type(raw_error_code) is str
                and raw_error_code in PUBLIC_ERROR_CODES
                else PUBLIC_ERROR_CODE_REDACTED
                if raw_error_code is not None else None)
            operation_projection = _verified_operation_projection(err[1])
        test_id = self._test_id(test)
        if not unexpected_success and operation_projection is not None:
            association = {
                "test": test_id,
                "status": status,
                "operation_projection_sha256": operation_projection[
                    "projection_sha256"],
            }
            operation_projection = {
                **operation_projection,
                "test_association_sha256": hashlib.sha256(
                    canonical(association)).hexdigest(),
            }
        projection_digest = (
            operation_projection.get("projection_sha256", "")
            if not unexpected_success and operation_projection else "")
        key = (test_id, status, exception_type, error_code or "",
               projection_digest)
        if key in self._failure_diagnostic_keys:
            return
        self._failure_diagnostic_keys.add(key)
        row = {
            "test": test_id, "status": status,
            "exception_type": exception_type,
        }
        if error_code is not None:
            row["error_code"] = error_code
        if not unexpected_success and operation_projection is not None:
            row["operation_projection"] = operation_projection
        self.failure_diagnostics.append(row)
        self._canonicalize_failure_diagnostics(test_id)

    def _canonicalize_failure_diagnostics(self, test_id):
        final_status = self._statuses.get(test_id)
        if final_status in {"failed", "error"}:
            self.failure_diagnostics = [
                row for row in self.failure_diagnostics
                if row["test"] != test_id or row["status"] == final_status
            ]
        self._failure_diagnostic_keys = {
            (row["test"], row["status"], row["exception_type"],
             row.get("error_code", ""), row.get(
                 "operation_projection", {}).get("projection_sha256", ""))
            for row in self.failure_diagnostics
        }
        self.failure_diagnostics.sort(key=lambda item: (
            item["test"], item["status"], item["exception_type"],
            item.get("error_code", ""), item.get(
                "operation_projection", {}).get("projection_sha256", "")))

    def _promote_status(self, test, status):
        test_id = self._test_id(test)
        current = self._statuses.get(test_id)
        if current is None or STATUS_SEVERITY[status] > STATUS_SEVERITY[current]:
            self._statuses[test_id] = status
        return test_id

    def startTest(self, test):
        self._started_at = time.perf_counter()
        self._statuses[self._test_id(test)] = "passed"
        if self.progress_checkpoint is not None:
            self.progress_checkpoint.started(test)
        super().startTest(test)

    def stopTest(self, test):
        elapsed = time.perf_counter() - self._started_at
        test_id = self._test_id(test)
        self._canonicalize_failure_diagnostics(test_id)
        self.timings.append({
            "test": test_id, "seconds": round(elapsed, 6),
            "status": self._statuses[test_id],
        })
        if self.progress_checkpoint is not None:
            self.progress_checkpoint.completed(test)
        super().stopTest(test)

    def addFailure(self, test, err):
        self._promote_status(test, "failed")
        self._record_failure_diagnostic(test, "failed", err)
        super().addFailure(test, err)

    def addError(self, test, err):
        test_id = self._test_id(test)
        synthetic = test_id not in self._statuses
        self._promote_status(test, "error")
        self._record_failure_diagnostic(test, "error", err)
        if synthetic:
            self.timings.append({
                "test": test_id, "seconds": 0.0, "status": "error",
            })
        super().addError(test, err)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            status = ("failed" if issubclass(err[0], test.failureException)
                      else "error")
            self._promote_status(test, status)
            self._record_failure_diagnostic(test, status, err)
        super().addSubTest(test, subtest, err)

    def addUnexpectedSuccess(self, test):
        self._promote_status(test, "failed")
        self._record_failure_diagnostic(
            test, "failed", unexpected_success=True)
        super().addUnexpectedSuccess(test)

    def addSkip(self, test, reason):
        self._promote_status(test, "skipped")
        super().addSkip(test, reason)


def execute_suite(suite, *, mode, budget, verbosity, selected_modules=None,
                  progress_path=None):
    started = time.perf_counter()
    captured_stdout = io.StringIO()
    progress = (ProgressCheckpoint(progress_path, selected_modules)
                if progress_path is not None else None)
    with contextlib.redirect_stdout(captured_stdout):
        result = unittest.TextTestRunner(
            stream=sys.stderr, verbosity=verbosity,
            resultclass=lambda *args, **kwargs: TimingResult(
                *args, progress_checkpoint=progress, **kwargs)).run(suite)
    if progress is not None:
        progress.finalize()
    elapsed = time.perf_counter() - started
    within_budget = budget is None or elapsed <= budget
    skip_receipts = sorted(
        ({"test": test.id(), "reason": str(reason)}
         for test, reason in result.skipped),
        key=lambda item: item["test"])
    capability_complete = not skip_receipts
    successful = result.wasSuccessful() and within_budget and capability_complete
    report = {
        "schema_version": 1, "mode": mode, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "elapsed_seconds": round(elapsed, 6),
        "suppressed_stdout_chars": len(captured_stdout.getvalue()),
        "max_seconds": budget, "within_budget": within_budget,
        "capability_complete": capability_complete,
        "status": ("passed" if successful else
                   "passed-with-capability-skips" if result.wasSuccessful()
                   and within_budget else "failed"),
        "successful": successful,
        "skip_receipts": skip_receipts,
        "failure_diagnostics": list(result.failure_diagnostics),
        "timings": sorted(
            getattr(result, "timings", []),
            key=lambda item: (-item["seconds"], item["test"])),
    }
    if selected_modules is not None:
        report["selected_modules"] = list(selected_modules)
    return report


def run_modules(modules, *, start_dir=None, max_seconds=None, verbosity=1,
                progress_path=None):
    """Run an exact closed module inventory without refreshing global evidence."""
    if not isinstance(modules, (list, tuple)) or not modules \
            or len(modules) != len(set(modules)) \
            or any(not isinstance(module, str) or TEST_MODULE.fullmatch(module) is None
                   for module in modules):
        raise ValueError("module inventory is invalid")
    root = Path(__file__).parent if start_dir is None else Path(start_dir).resolve()
    if not root.is_dir():
        raise ValueError("module inventory root is invalid")
    before_modules = set(sys.modules)
    sys.path.insert(0, str(root))
    try:
        suite = unittest.defaultTestLoader.loadTestsFromNames(list(modules))
        return execute_suite(
            suite, mode="modules",
            budget=None if max_seconds is None else float(max_seconds),
            verbosity=verbosity, selected_modules=list(modules),
            progress_path=progress_path)
    finally:
        sys.path.remove(str(root))
        for name in set(sys.modules) - before_modules:
            module = sys.modules.get(name)
            filename = getattr(module, "__file__", None)
            if filename and Path(filename).resolve().is_relative_to(root):
                sys.modules.pop(name, None)
