import copy
import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_exact_cut_ci
import loom_exact_cut_receipt
import loom_lint
import loom_operation_envelope


class ExactCutCiPhase10Tests(unittest.TestCase):
    @staticmethod
    def _operation_projection(receipt_digest, primary, *, test, status="error",
                              survivors=True, protected=True):
        body = {
            "operation_receipt_sha256": receipt_digest,
            "status": "failed", "returncode": None,
            "primary_failure": primary,
            "survivors_confirmed_zero": survivors,
            "protected_roots_unchanged": protected,
            "network_isolation_proven": False,
            "containment_provider": "windows-job-object",
        }
        projection_sha256 = loom_exact_cut_ci._digest(body)
        return {
            **body, "projection_sha256": projection_sha256,
            "test_association_sha256": loom_exact_cut_ci._digest({
                "test": test, "status": status,
                "operation_projection_sha256": projection_sha256,
            }),
        }

    def test_unsafe_serial_diagnostic_target_still_emits_failed_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            unsafe = root / "diagnostic-directory"
            unsafe.mkdir()
            result = loom_exact_cut_ci.run(
                source, cut, output, failure_diagnostic_output=unsafe)

            self.assertEqual("failed", result["status"])
            self.assertEqual("ValueError", result["error_type"])
            self.assertEqual(
                result, json.loads(output.read_text(encoding="utf-8")))
            envelope = loom_operation_envelope.read(
                cut.parent / ".loom-operations" /
                f"{result['operation_id']}.json")
            self.assertEqual("failed", envelope["events"][-1]["phase"])

    def test_verifier_failure_still_emits_actionable_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=RuntimeError("injected exact-cut failure")):
                result = loom_exact_cut_ci.run(source, cut, output)
            self.assertEqual("failed", result["status"])
            self.assertEqual("RuntimeError", result["error_type"])
            self.assertRegex(result["error_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("traceback_tail", result)
            self.assertNotIn("forced verifier failure", str(result))
            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual(2, result["schema_version"])
            self.assertRegex(result["receipt_sha256"], r"^[0-9a-f]{64}$")
            envelope = loom_operation_envelope.read(
                cut.parent / ".loom-operations" / f"{result['operation_id']}.json")
            self.assertEqual("failed", envelope["events"][-1]["phase"])

    def test_success_receipt_binds_built_and_verified_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            suite_output = root / "suite.json"
            diagnostic_output = root / "serial-failure-diagnostic.json"
            diagnostic_output.write_text("stale\n", encoding="utf-8")
            verified = {
                "root_sha256": "a" * 64,
                "manifest_sha256": "b" * 64,
                "files_verified": 8,
                "suite": {
                    "passed": True, "capability_complete": True,
                    "capability_status": "complete", "returncode": 0,
                    "primary_failure": None,
                    "operation_receipt_sha256": "c" * 64,
                    "elapsed_seconds": 0.25, "tests_run": 7,
                    "failure_count": 0, "error_count": 0,
                    "failed_tests": [], "skip_receipts": [],
                    "timings": [{"test": f"tests.Example.test_{index}",
                                 "status": "passed", "seconds": 0.01}
                                for index in range(7)],
                    "output": "private raw stderr must not escape",
                },
            }
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        return_value=verified), mock.patch.dict(
                            loom_exact_cut_ci.os.environ,
                            {"GITHUB_SHA": "1" * 40}):
                result = loom_exact_cut_ci.run(
                    source, cut, output, suite_output=suite_output,
                    failure_diagnostic_output=diagnostic_output)
            self.assertEqual("verified", result["status"])
            self.assertEqual(result["build_root_sha256"], result["verified_root_sha256"])
            self.assertIn("public_manifest_sha256", result)
            self.assertIn("public_file_count", result)
            suite = json.loads(suite_output.read_text(encoding="utf-8"))
            self.assertEqual(7, suite["tests_run"])
            self.assertNotIn("output", suite)
            self.assertNotIn("private raw stderr", json.dumps(suite))
            self.assertEqual("a" * 64, suite["binding"]["public_root_sha256"])
            self.assertEqual(suite["binding"]["environment"]["environment_sha256"],
                             suite["binding"]["runner"])
            self.assertIn("requested_label", suite["binding"]["environment"])
            self.assertEqual(result["receipt_sha256"], json.loads(
                output.read_text(encoding="utf-8"))["receipt_sha256"])
            self.assertEqual(
                result, loom_exact_cut_receipt.verify_receipt(
                    result, require_static=False))
            self.assertEqual(
                result, loom_exact_cut_ci.verify_receipt(
                    result, require_static=False))
            self.assertFalse(diagnostic_output.exists())
            report = loom_lint.Report()
            loom_lint.validate_schema(
                report, __file__, result, "exact-cut-ci-receipt-v2.schema.json")
            self.assertEqual([], report.errors)
            skip_only = dict(verified["suite"])
            skip_only.update({
                "capability_complete": False,
                "capability_status": "requires-matrix",
                "returncode": 1,
                "primary_failure": "operation returned nonzero",
                "tests_run": 1,
                "skip_receipts": [{
                    "test": "tests.Example.test_platform",
                    "reason": "Windows-only platform boundary",
                }],
                "timings": [{
                    "test": "tests.Example.test_platform",
                    "status": "skipped", "seconds": 0.01,
                }],
            })
            projected = loom_exact_cut_ci._public_suite(skip_only)
            self.assertIsNone(projected["primary_failure_sha256"])
            self.assertEqual(1, projected["returncode"])
            self.assertEqual("requires-matrix", projected["capability_status"])
            envelope = loom_operation_envelope.read(
                cut.parent / ".loom-operations" / f"{result['operation_id']}.json")
            self.assertEqual("passed", envelope["events"][-1]["phase"])
            self.assertFalse((source / ".loom-operations").exists())

    def test_static_only_receipt_never_executes_the_serial_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            verified = {
                "root_sha256": "a" * 64, "manifest_sha256": "b" * 64,
                "files_verified": 7,
            }
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut_static",
                        return_value=verified), mock.patch.object(
                            loom_exact_cut_ci.loom_release, "verify_cut",
                            side_effect=AssertionError("serial suite must not run")):
                result = loom_exact_cut_ci.run(
                    source, cut, output, static_only=True)
            self.assertEqual("verified", result["status"])
            self.assertIsNone(result["suite"])
            self.assertEqual("b" * 64, result["public_manifest_sha256"])
            self.assertEqual(7, result["public_file_count"])

    def test_suite_failure_preserves_failed_test_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            suite_output = root / "suite.json"
            diagnostic_output = root / "serial-failure-diagnostic.json"
            error = loom_exact_cut_ci.loom_release.ReleaseError(
                "suite failed",
                details={"suite": {
                    "passed": False,
                    "tests_run": 704,
                    "failure_count": 1,
                    "error_count": 0,
                    "failed_tests": [{"test": "tests.ExactFailure", "status": "failed"}],
                    "failure_diagnostics": [{
                        "test": "tests.ExactFailure", "status": "failed",
                        "exception_type": "NativeHelperBuildError",
                        "error_code": "NATIVE_HELPER_BUILD_TIMEOUT",
                    }],
                }},
            )
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut", side_effect=error):
                result = loom_exact_cut_ci.run(
                    source, cut, output, suite_output=suite_output,
                    failure_diagnostic_output=diagnostic_output)
            self.assertEqual("failed", result["status"])
            self.assertEqual(
                [{"test": "tests.ExactFailure", "status": "failed"}],
                result["suite"]["failed_tests"],
            )
            self.assertEqual(result["suite"], json.loads(
                suite_output.read_text(encoding="utf-8")))
            diagnostic = json.loads(
                diagnostic_output.read_text(encoding="utf-8"))
            loom_exact_cut_ci.verify_serial_failure_diagnostic(
                diagnostic, result)
            self.assertEqual(
                diagnostic,
                loom_exact_cut_ci.load_serial_failure_diagnostic(
                    diagnostic_output, result))
            self.assertEqual(
                result["receipt_sha256"],
                diagnostic["exact_cut_receipt_sha256"])
            self.assertEqual(
                error.details["suite"]["failure_diagnostics"],
                diagnostic["failures"])
            self.assertNotIn("suite failed", json.dumps(diagnostic))
            tampered = dict(diagnostic)
            tampered["exact_cut_receipt_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                loom_exact_cut_ci.verify_serial_failure_diagnostic(
                    tampered, result)
            duplicate = diagnostic_output.with_name("duplicate.json")
            duplicate.write_text(
                diagnostic_output.read_text(encoding="utf-8").replace(
                    "{", '{"schema_version":1,', 1),
                encoding="utf-8")
            with self.assertRaises(ValueError):
                loom_exact_cut_ci.load_serial_failure_diagnostic(
                    duplicate, result)

    def test_completed_suite_failure_does_not_emit_interrupted_progress(self):
        """A terminal checkpoint cannot stale an already sealed failure sidecar."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            failure_output = root / "serial-failure-diagnostic.json"
            progress_output = root / "serial-progress-diagnostic.json"
            progress = loom_exact_cut_ci.loom_suite_harness.seal_progress_checkpoint({
                "schema_version": 1,
                "status": "completed",
                "authorizing": False,
                "diagnostic_policy_sha256": (
                    loom_exact_cut_ci.loom_suite_harness._POLICY[
                        "policy_sha256"]),
                "selected_modules_sha256": None,
                "checkpoint_sequence": 2,
                "completed_test_count": 1,
                "last_started_test": "tests.ExactFailure",
                "last_completed_test": "tests.ExactFailure",
            })
            operation = {
                "status": "failed", "returncode": 1,
                "primary_failure": "nonzero-exit",
                "survivors_confirmed_zero": True,
                "protected_roots_unchanged": True,
                "network_isolation_proven": False,
                "containment_provider": "windows-job-object",
                "receipt_sha256": "e" * 64,
            }
            error = loom_exact_cut_ci.loom_release.ReleaseError(
                "private ordinary test failure",
                details={"suite": {
                    "passed": False, "capability_complete": False,
                    "capability_status": "failed", "returncode": 1,
                    "primary_failure": "nonzero-exit",
                    "operation_receipt_sha256": "e" * 64,
                    "operation": operation,
                    "progress_checkpoint": progress,
                    "tests_run": 1, "failure_count": 1,
                    "error_count": 0,
                    "failed_tests": [{
                        "test": "tests.ExactFailure", "status": "failed"}],
                    "failure_diagnostics": [{
                        "test": "tests.ExactFailure", "status": "failed",
                        "exception_type": "AssertionError",
                    }],
                    "skip_receipts": [], "timings": [],
                }})
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), \
                    mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=error):
                result = loom_exact_cut_ci.run(
                    source, cut, output,
                    failure_diagnostic_output=failure_output,
                    progress_diagnostic_output=progress_output)

            self.assertEqual("ReleaseError", result["error_type"])
            diagnostic = loom_exact_cut_ci.load_serial_failure_diagnostic(
                failure_output, result)
            self.assertEqual(
                result["receipt_sha256"],
                diagnostic["exact_cut_receipt_sha256"])
            self.assertFalse(progress_output.exists())

    def test_native_operation_projections_survive_the_exact_cut_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            diagnostic_output = root / "serial-failure-diagnostic.json"
            cases = (
                ("Timeout", "NATIVE_HELPER_BUILD_TIMEOUT", "timed-out",
                 True, True, "1" * 64),
                ("Survivor", "NATIVE_HELPER_BUILD_SURVIVOR",
                 "survivor-census-indeterminate", False, True, "2" * 64),
                ("Mutation", "NATIVE_HELPER_BUILD_SOURCE_MUTATION",
                 "protected-root-changed", True, False, "3" * 64),
            )
            diagnostics = [{
                "test": (test_id := f"tests.Native.test_{name.lower()}"),
                "status": "error",
                "exception_type": "NativeHelperBuildError",
                "error_code": code,
                "operation_projection": self._operation_projection(
                    digest, primary, test=test_id, survivors=survivors,
                    protected=protected),
            } for name, code, primary, survivors, protected, digest in cases]
            error = loom_exact_cut_ci.loom_release.ReleaseError(
                "suite failed",
                details={"suite": {
                    "passed": False, "capability_complete": False,
                    "capability_status": "failed", "returncode": 1,
                    "primary_failure": "nonzero-exit",
                    "operation_receipt_sha256": "f" * 64,
                    "tests_run": 3, "failure_count": 0, "error_count": 3,
                    "failed_tests": [{
                        "test": row["test"], "status": row["status"],
                    } for row in diagnostics],
                    "failure_diagnostics": diagnostics,
                }},
            )
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), \
                    mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=error):
                result = loom_exact_cut_ci.run(
                    source, cut, output,
                    failure_diagnostic_output=diagnostic_output)

            self.assertEqual("f" * 64,
                             result["suite"]["operation_receipt_sha256"])
            diagnostic = json.loads(
                diagnostic_output.read_text(encoding="utf-8"))
            loom_exact_cut_ci.verify_serial_failure_diagnostic(
                diagnostic, result)
            self.assertEqual(sorted(diagnostics, key=lambda row: (
                row["test"], row["status"], row["exception_type"],
                row["error_code"],
                row["operation_projection"]["projection_sha256"])),
                diagnostic["failures"])
            projected_keys = set().union(*(
                row["operation_projection"] for row in diagnostic["failures"]))
            self.assertTrue({
                "command", "executable", "cwd", "allowed_roots",
                "protected_roots", "environment", "started_at",
                "completed_at", "stdout", "stderr", "secondary_failures",
            }.isdisjoint(projected_keys))
            raw_child = json.loads(json.dumps(diagnostic))
            raw_child["failures"][0]["operation_projection"]["cwd"] = \
                r"C:\Users\Private Owner\checkout"
            raw_child["failure_diagnostic_sha256"] = \
                loom_exact_cut_ci._digest({
                    key: value for key, value in raw_child.items()
                    if key != "failure_diagnostic_sha256"})
            with self.assertRaises(ValueError):
                loom_exact_cut_ci.verify_serial_failure_diagnostic(
                    raw_child, result)
            reassociated = json.loads(json.dumps(diagnostic))
            first = reassociated["failures"][0]["operation_projection"]
            second = reassociated["failures"][1]["operation_projection"]
            reassociated["failures"][0]["operation_projection"] = second
            reassociated["failures"][1]["operation_projection"] = first
            reassociated["failure_diagnostic_sha256"] = \
                loom_exact_cut_ci._digest({
                    key: value for key, value in reassociated.items()
                    if key != "failure_diagnostic_sha256"})
            with self.assertRaises(ValueError):
                loom_exact_cut_ci.verify_serial_failure_diagnostic(
                    reassociated, result)

    def test_repeated_subtest_events_seal_one_bounded_diagnostic_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / "fixtures"
            fixture_root.mkdir()
            (fixture_root / "test_repeated_subtests.py").write_text(
                "import unittest\n"
                "class Repeated(unittest.TestCase):\n"
                "    def test_events(self):\n"
                "        for index in range(33):\n"
                "            with self.subTest(kind='failure', index=index):\n"
                "                self.fail('private repeated failure')\n"
                "        for index in range(33):\n"
                "            with self.subTest(kind='error', index=index):\n"
                "                raise RuntimeError('private repeated error')\n",
                encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                report = loom_exact_cut_ci.loom_test.run_modules(
                    ["test_repeated_subtests"], start_dir=fixture_root,
                    verbosity=0)
            self.assertEqual(33, report["failures"])
            self.assertEqual(33, report["errors"])
            self.assertEqual(1, len(report["failure_diagnostics"]))

            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            diagnostic_output = root / "serial-failure-diagnostic.json"
            diagnostics = report["failure_diagnostics"]
            error = loom_exact_cut_ci.loom_release.ReleaseError(
                "suite failed",
                details={"suite": {
                    "passed": False, "capability_complete": False,
                    "capability_status": "failed", "returncode": 1,
                    "primary_failure": "nonzero-exit",
                    "operation_receipt_sha256": "e" * 64,
                    "tests_run": report["tests_run"],
                    "failure_count": report["failures"],
                    "error_count": report["errors"],
                    "failed_tests": [{
                        "test": row["test"], "status": row["status"],
                    } for row in diagnostics],
                    "failure_diagnostics": diagnostics,
                }},
            )
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), \
                    mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=error):
                result = loom_exact_cut_ci.run(
                    source, cut, output,
                    failure_diagnostic_output=diagnostic_output)

            self.assertEqual(33, result["suite"]["failure_count"])
            self.assertEqual(33, result["suite"]["error_count"])
            self.assertEqual([{
                "test": "test_repeated_subtests.Repeated.test_events",
                "status": "error",
            }], result["suite"]["failed_tests"])
            diagnostic = loom_exact_cut_ci.load_serial_failure_diagnostic(
                diagnostic_output, result)
            self.assertEqual(1, len(diagnostic["failures"]))
            self.assertLessEqual(
                diagnostic_output.stat().st_size,
                loom_exact_cut_ci.MAX_SERIAL_FAILURE_DIAGNOSTIC_BYTES)

    def test_diagnostic_finalization_failure_is_sealed_without_losing_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            diagnostic_output = root / "serial-failure-diagnostic.json"
            suite_details = {
                "passed": False, "capability_complete": False,
                "capability_status": "failed", "returncode": 1,
                "primary_failure": "nonzero-exit",
                "operation_receipt_sha256": "e" * 64,
                "tests_run": 1, "failure_count": 1, "error_count": 0,
                "failed_tests": [{
                    "test": "tests.ExactFailure", "status": "failed"}],
                "failure_diagnostics": [{
                    "test": "tests.ExactFailure", "status": "failed",
                    "exception_type": "AssertionError",
                }],
            }
            error = loom_exact_cut_ci.loom_release.ReleaseError(
                "private original suite failure",
                details={"suite": suite_details})
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), \
                    mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=error), \
                    mock.patch.object(
                        loom_exact_cut_ci, "_serial_failure_diagnostic",
                        side_effect=RuntimeError(
                            r"C:\Users\Private Owner\diagnostic failure")):
                result = loom_exact_cut_ci.run(
                    source, cut, output,
                    failure_diagnostic_output=diagnostic_output)

            self.assertEqual(
                "SerialDiagnosticFinalizationError", result["error_type"])
            self.assertEqual(suite_details["failure_count"],
                             result["suite"]["failure_count"])
            self.assertEqual(suite_details["failed_tests"],
                             result["suite"]["failed_tests"])
            self.assertEqual("e" * 64,
                             result["suite"]["operation_receipt_sha256"])
            self.assertRegex(result["error_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                result, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual(
                result["receipt_sha256"],
                loom_exact_cut_ci._seal(result)["receipt_sha256"])
            self.assertFalse(diagnostic_output.exists())
            self.assertNotIn("Private Owner", json.dumps(result, sort_keys=True))

    def test_timeout_progress_sidecar_is_bound_private_safe_and_non_authorizing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            cut = root / "build" / "cut"
            cut.parent.mkdir()
            output = root / "receipt.json"
            diagnostic_output = root / "serial-progress-diagnostic.json"
            progress = loom_exact_cut_ci.loom_suite_harness.seal_progress_checkpoint({
                "schema_version": 1,
                "status": "running",
                "authorizing": False,
                "diagnostic_policy_sha256": (
                    loom_exact_cut_ci.loom_suite_harness._POLICY[
                        "policy_sha256"]),
                "selected_modules_sha256": None,
                "checkpoint_sequence": 9,
                "completed_test_count": 731,
                "last_started_test": "test_owner.OwnerTests.test_concurrent",
                "last_completed_test": "test_owner.OwnerTests.test_previous",
            })
            operation = {
                "status": "failed", "returncode": None,
                "primary_failure": "timed-out",
                "survivors_confirmed_zero": True,
                "protected_roots_unchanged": True,
                "network_isolation_proven": False,
                "containment_provider": "windows-job-object",
                "receipt_sha256": "e" * 64,
            }
            error = loom_exact_cut_ci.loom_release.ReleaseError(
                "private timeout",
                details={"suite": {
                    "passed": False, "capability_complete": False,
                    "capability_status": "failed", "returncode": 1,
                    "primary_failure": "timed-out",
                    "operation_receipt_sha256": "e" * 64,
                    "operation": operation,
                    "progress_checkpoint": progress,
                    "tests_run": None, "failure_count": None,
                    "error_count": None, "failed_tests": [],
                    "failure_diagnostics": [], "skip_receipts": [],
                    "timings": [],
                }})
            with mock.patch.object(
                    loom_exact_cut_ci.loom_release, "build_public",
                    return_value={"root_sha256": "a" * 64}), \
                    mock.patch.object(
                        loom_exact_cut_ci.loom_release, "verify_cut",
                        side_effect=error):
                receipt = loom_exact_cut_ci.run(
                    source, cut, output,
                    progress_diagnostic_output=diagnostic_output)

            diagnostic = loom_exact_cut_ci.load_serial_progress_diagnostic(
                diagnostic_output, receipt)
            self.assertFalse(diagnostic["authorizing"])
            self.assertEqual(731, diagnostic["checkpoint"][
                "completed_test_count"])
            self.assertEqual("timed-out", diagnostic["operation"][
                "primary_failure"])
            self.assertTrue(diagnostic["operation"][
                "survivors_confirmed_zero"])
            self.assertTrue(diagnostic["operation"][
                "protected_roots_unchanged"])
            self.assertNotIn("private timeout", json.dumps(diagnostic))

            stale = copy.deepcopy(diagnostic)
            stale_body = {
                key: value for key, value in stale["checkpoint"].items()
                if key != "checkpoint_sha256"}
            stale_body["diagnostic_policy_sha256"] = "0" * 64
            stale["checkpoint"] = \
                loom_exact_cut_ci.loom_suite_harness.seal_progress_checkpoint(
                    stale_body)
            stale["progress_diagnostic_sha256"] = loom_exact_cut_ci._digest({
                key: value for key, value in stale.items()
                if key != "progress_diagnostic_sha256"})
            with self.assertRaisesRegex(ValueError, "checkpoint"):
                loom_exact_cut_ci.verify_serial_progress_diagnostic(
                    stale, receipt)

            unknown = copy.deepcopy(diagnostic)
            unknown["operation"]["cwd"] = r"C:\Users\Private Owner\checkout"
            unknown["progress_diagnostic_sha256"] = loom_exact_cut_ci._digest({
                key: value for key, value in unknown.items()
                if key != "progress_diagnostic_sha256"})
            with self.assertRaisesRegex(ValueError, "operation"):
                loom_exact_cut_ci.verify_serial_progress_diagnostic(
                    unknown, receipt)

            mixed = copy.deepcopy(diagnostic)
            mixed["exact_cut_receipt_sha256"] = "0" * 64
            mixed["progress_diagnostic_sha256"] = loom_exact_cut_ci._digest({
                key: value for key, value in mixed.items()
                if key != "progress_diagnostic_sha256"})
            with self.assertRaisesRegex(ValueError, "identity"):
                loom_exact_cut_ci.verify_serial_progress_diagnostic(
                    mixed, receipt)


if __name__ == "__main__":
    unittest.main()
