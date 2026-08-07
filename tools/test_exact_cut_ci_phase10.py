import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_exact_cut_ci
import loom_lint
import loom_operation_envelope


class ExactCutCiPhase10Tests(unittest.TestCase):
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
                        return_value=verified):
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


if __name__ == "__main__":
    unittest.main()
