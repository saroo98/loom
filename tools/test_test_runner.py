"""Tests for the bounded CI test runner."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_test


class TestRunnerTests(unittest.TestCase):
    def test_failures_emit_only_closed_deterministic_diagnostics(self):
        source = (
            "import unittest\n"
            "class HostFailure(AssertionError):\n"
            "    code = 'HOST_UNVERIFIED'\n"
            "class UnsafeFailure(AssertionError):\n"
            "    code = 'lowercase-code'\n"
            "class DiagnosticFixture(unittest.TestCase):\n"
            "    def test_coded(self): raise HostFailure('private host detail')\n"
            "    def test_invalid_code(self): raise UnsafeFailure('other private detail')\n"
            "    def test_subtest(self):\n"
            "        with self.subTest(case='private-case'):\n"
            "            self.fail('private subtest detail')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_diagnostics.py").write_text(source, encoding="utf-8")
            report = loom_test.run_modules(
                ["test_diagnostics"], start_dir=root, verbosity=0)

        coded_id = "test_diagnostics.DiagnosticFixture.test_coded"
        invalid_id = "test_diagnostics.DiagnosticFixture.test_invalid_code"
        subtest_id = "test_diagnostics.DiagnosticFixture.test_subtest"
        self.assertEqual([
            {
                "error_code": "HOST_UNVERIFIED",
                "exception_type": "HostFailure",
                "status": "failed", "test": coded_id,
            },
            {
                "error_code": "PUBLIC_ERROR_CODE_REDACTED",
                "exception_type": "UnsafeFailure",
                "status": "failed", "test": invalid_id,
            },
            {
                "exception_type": "AssertionError",
                "status": "failed", "test": subtest_id,
            },
        ], report.get("failure_diagnostics"))
        serialized = json.dumps(report, sort_keys=True)
        private_messages = (
                "private host detail", "other private detail",
                "private subtest detail", "private-case")
        for private in private_messages:
            self.assertNotIn(private, serialized)
        for private in private_messages[:3]:
            self.assertNotIn(
                hashlib.sha256(private.encode("utf-8")).hexdigest(), serialized)

    def test_passing_suite_emits_no_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_clean.py").write_text(
                "import unittest\n"
                "class Clean(unittest.TestCase):\n"
                "    def test_passes(self): pass\n",
                encoding="utf-8")
            report = loom_test.run_modules(
                ["test_clean"], start_dir=root, verbosity=0)
        self.assertEqual([], report.get("failure_diagnostics"))

    def test_public_error_codes_preserve_allowlisted_values_and_redact_secrets(self):
        source = (
            "import unittest\n"
            "class SafeFailure(AssertionError):\n"
            "    code = 'HOST_UNVERIFIED'\n"
            "class SecretFailure(AssertionError):\n"
            "    code = 'AKIAABCDEFGHIJKLMNOP'\n"
            "class UnhashableFailure(AssertionError):\n"
            "    code = []\n"
            "class OddCode(str):\n"
            "    __hash__ = None\n"
            "class HostileStringFailure(AssertionError):\n"
            "    code = OddCode('HOST_UNVERIFIED')\n"
            "class DiagnosticFixture(unittest.TestCase):\n"
            "    def test_safe(self): raise SafeFailure('private')\n"
            "    def test_secret(self): raise SecretFailure('private')\n"
            "    def test_unhashable(self): raise UnhashableFailure('private')\n"
            "    def test_hostile_string(self): "
            "raise HostileStringFailure('private')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_codes.py").write_text(source, encoding="utf-8")
            report = loom_test.run_modules(
                ["test_codes"], start_dir=root, verbosity=0)

        rows = {row["test"]: row for row in report["failure_diagnostics"]}
        self.assertEqual(
            "HOST_UNVERIFIED",
            rows["test_codes.DiagnosticFixture.test_safe"]["error_code"])
        self.assertEqual(
            "PUBLIC_ERROR_CODE_REDACTED",
            rows["test_codes.DiagnosticFixture.test_secret"]["error_code"])
        self.assertEqual(
            "PUBLIC_ERROR_CODE_REDACTED",
            rows["test_codes.DiagnosticFixture.test_unhashable"]["error_code"])
        self.assertEqual(
            "PUBLIC_ERROR_CODE_REDACTED",
            rows["test_codes.DiagnosticFixture.test_hostile_string"]["error_code"])
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", json.dumps(report, sort_keys=True))

    def test_mixed_subtest_status_uses_order_independent_error_precedence(self):
        cases = {
            "failure-first": (
                "with self.subTest(case='failed'): self.fail('private')\n"
                "        with self.subTest(case='error'): "
                "raise RuntimeError('private')\n"),
            "error-first": (
                "with self.subTest(case='error'): "
                "raise RuntimeError('private')\n"
                "        with self.subTest(case='failed'): self.fail('private')\n"),
        }
        for label, body in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "test_mixed.py").write_text(
                    "import unittest\n"
                    "class Mixed(unittest.TestCase):\n"
                    "    def test_outcomes(self):\n"
                    f"        {body}", encoding="utf-8")
                report = loom_test.run_modules(
                    ["test_mixed"], start_dir=root, verbosity=0)
                self.assertEqual("error", report["timings"][0]["status"])
                self.assertEqual(
                    {"error"},
                    {row["status"] for row in report["failure_diagnostics"]})

    def test_exact_module_selection_runs_only_the_declared_real_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_alpha.py").write_text(
                "import unittest\n"
                "class Alpha(unittest.TestCase):\n"
                "    def test_passes(self): pass\n",
                encoding="utf-8")
            (root / "test_beta.py").write_text(
                "import unittest\n"
                "class Beta(unittest.TestCase):\n"
                "    def test_fails(self): self.fail('must not run')\n",
                encoding="utf-8")
            report = loom_test.run_modules(
                ["test_alpha"], start_dir=root, verbosity=0)
        self.assertEqual("modules", report["mode"])
        self.assertEqual(["test_alpha"], report["selected_modules"])
        self.assertEqual(1, report["tests_run"])
        self.assertTrue(report["successful"])

    def test_exact_module_selection_rejects_duplicates_and_unsafe_names(self):
        with self.assertRaisesRegex(ValueError, "module inventory"):
            loom_test.run_modules(["test_alpha", "test_alpha"], verbosity=0)
        with self.assertRaisesRegex(ValueError, "module inventory"):
            loom_test.run_modules(["../test_alpha"], verbosity=0)

    def test_class_setup_error_is_recorded_without_runner_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_setup_error.py").write_text(
                "import unittest\n"
                "class SetupError(unittest.TestCase):\n"
                "    @classmethod\n"
                "    def setUpClass(cls): raise RuntimeError('private class setup')\n"
                "    def test_never_runs(self): pass\n",
                encoding="utf-8")
            report = loom_test.run_modules(
                ["test_setup_error"], start_dir=root, verbosity=0)
        self.assertEqual(1, report["errors"])
        self.assertEqual("failed", report["status"])
        test_id = "fixture.class.test_setup_error.SetupError"
        self.assertEqual([{
            "test": test_id, "seconds": 0.0, "status": "error",
        }], report["timings"])
        self.assertEqual([{
            "test": test_id, "status": "error",
            "exception_type": "RuntimeError",
        }], report["failure_diagnostics"])
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("private class setup", serialized)
        self.assertNotIn("setUpClass (", serialized)
        self.assertNotIn(
            hashlib.sha256(b"private class setup").hexdigest(), serialized)

    def test_module_setup_error_has_a_safe_synthetic_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_module_setup_error.py").write_text(
                "import unittest\n"
                "def setUpModule(): raise OSError('private module setup')\n"
                "class SetupError(unittest.TestCase):\n"
                "    def test_never_runs(self): pass\n",
                encoding="utf-8")
            report = loom_test.run_modules(
                ["test_module_setup_error"], start_dir=root, verbosity=0)
        test_id = "fixture.module.test_module_setup_error"
        self.assertEqual(1, report["errors"])
        self.assertEqual([{
            "test": test_id, "seconds": 0.0, "status": "error",
        }], report["timings"])
        self.assertEqual([{
            "test": test_id, "status": "error",
            "exception_type": "OSError",
        }], report["failure_diagnostics"])
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("private module setup", serialized)
        self.assertNotIn("setUpModule (", serialized)
        self.assertNotIn(
            hashlib.sha256(b"private module setup").hexdigest(), serialized)

    def test_fast_gate_inventory_is_real_bounded_and_has_no_loader_errors(self):
        # The full suite executes every selected test once, while the dedicated CI
        # fast-gate job executes this exact inventory under a bounded host-aware wall clock.
        # Re-executing the same tests recursively here adds no distinct coverage.
        self.assertEqual(30.0, loom_test.FAST_GATE_MAX_SECONDS)
        self.assertEqual(45.0, loom_test.WINDOWS_FAST_GATE_MAX_SECONDS)
        self.assertEqual(30.0, loom_test.fast_gate_max_seconds("posix"))
        self.assertEqual(45.0, loom_test.fast_gate_max_seconds("nt"))
        suite = unittest.defaultTestLoader.loadTestsFromNames(loom_test.FAST_TESTS)

        def flatten(value):
            for test in value:
                if isinstance(test, unittest.TestSuite):
                    yield from flatten(test)
                else:
                    yield test

        loaded = list(flatten(suite))
        self.assertEqual(len(loom_test.FAST_TESTS), len(loaded))
        self.assertFalse(any(
            test.__class__.__name__ == "_FailedTest" for test in loaded))
        self.assertEqual(len(set(loom_test.FAST_TESTS)), len(loom_test.FAST_TESTS))

    def test_fast_gate_budget_boundary_is_deterministically_enforced(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        ticks = iter((0.0, 0.0, 0.0, 0.0))

        def clock():
            return next(ticks, 31.0)

        with mock.patch.object(
                loom_test.unittest.defaultTestLoader, "loadTestsFromNames",
                return_value=suite), mock.patch.object(
                    loom_test.time, "perf_counter", side_effect=clock):
            report = loom_test.run("fast", max_seconds=30, verbosity=0)
        self.assertFalse(report["within_budget"])
        self.assertFalse(report["successful"])
        self.assertEqual("failed", report["status"])

    def test_full_release_suite_has_no_duplicate_wall_clock_correctness_gate(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with mock.patch.object(
                loom_test.unittest.defaultTestLoader, "discover",
                return_value=suite):
            report = loom_test.run("full", verbosity=0)
        self.assertIsNone(report["max_seconds"])
        self.assertTrue(report["within_budget"])
        self.assertTrue(report["successful"])

    def test_skip_can_never_produce_successful_certification(self):
        skipped = unittest.skip("capability-fixture")(lambda: None)
        suite = unittest.TestSuite([unittest.FunctionTestCase(skipped)])
        with mock.patch.object(
                loom_test.unittest.defaultTestLoader, "loadTestsFromNames",
                return_value=suite):
            report = loom_test.run("fast", max_seconds=30, verbosity=0)
        self.assertEqual("passed-with-capability-skips", report["status"])
        self.assertFalse(report["capability_complete"])
        self.assertFalse(report["successful"])
        self.assertEqual("capability-fixture", report["skip_receipts"][0]["reason"])

    def test_final_evidence_refresh_uses_the_last_complete_test_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "VERSION").write_text("1.8.3\n", encoding="utf-8")
            (root / "tools").mkdir()
            (root / "schemas").mkdir()
            (root / "docs").mkdir()
            (root / "docs" / "capabilities.json").write_text(json.dumps({
                "schema_version": 1, "version": "1.8.3", "capabilities": [],
            }), encoding="utf-8")
            (root / "tools" / "loom_sample.py").write_text(
                "VALUE = 1\n", encoding="utf-8")
            (root / "tools" / "test_first.py").write_text(
                "def test_first():\n    pass\n", encoding="utf-8")
            stale = loom_test.loom_docs.generate_evidence(root)
            loom_test.loom_docs._atomic_json(
                root / "docs" / "generated-evidence.json", stale)
            (root / "tools" / "test_final.py").write_text(
                "def test_second():\n    pass\n", encoding="utf-8")

            refreshed = loom_test.refresh_final_evidence(root, {
                "mode": "full", "successful": True, "tests_run": 2,
                "failures": 0, "errors": 0, "skipped": 0,
                "capability_complete": True, "within_budget": True})
            observed = json.loads((
                root / "docs" / "generated-evidence.json").read_text(encoding="utf-8"))

            self.assertEqual("refreshed", refreshed["status"])
            self.assertEqual(2, refreshed["discovered_test_methods"])
            self.assertEqual(2, observed["discovered_test_methods"])

    def test_cli_binds_final_inventory_before_suite_and_certifies_it_after(self):
        report = {
            "schema_version": 1, "mode": "full", "tests_run": 2,
            "failures": 0, "errors": 0, "skipped": 0,
            "elapsed_seconds": 1.0, "suppressed_stdout_chars": 0,
            "max_seconds": None, "within_budget": True,
            "capability_complete": True, "status": "passed",
            "successful": True, "skip_receipts": [], "timings": [],
        }
        refreshed = {
            "status": "refreshed", "discovered_test_methods": 2,
        }
        order = []
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
                loom_test, "run",
                side_effect=lambda *args, **kwargs: (
                    order.append("suite") or dict(report))), mock.patch.object(
                loom_test, "refresh_final_evidence",
                side_effect=lambda *args, **kwargs: (
                    order.append("certify") or dict(refreshed))), mock.patch.object(
                loom_test.loom_docs, "refresh_evidence",
                side_effect=lambda *args, **kwargs: order.append("bind")):
            output = Path(temp) / "report.json"
            code = loom_test.main([
                "full", "--quiet", "--refresh-generated-evidence",
                "--output", str(output)])
        self.assertEqual(0, code)
        self.assertEqual(["bind", "suite", "certify"], order)

    def test_failed_full_refresh_transaction_restores_previous_evidence(self):
        failed = {
            "schema_version": 1, "mode": "full", "tests_run": 1,
            "failures": 1, "errors": 0, "skipped": 0,
            "elapsed_seconds": 0.1, "suppressed_stdout_chars": 0,
            "max_seconds": None, "within_budget": True,
            "capability_complete": True, "status": "failed",
            "successful": False, "skip_receipts": [], "timings": [],
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tools").mkdir()
            (root / "docs").mkdir()
            evidence = root / "docs" / "generated-evidence.json"
            evidence.write_text('{"old":true}\n', encoding="utf-8")

            def bind(target):
                (Path(target) / "docs" / "generated-evidence.json").write_text(
                    '{"new":true}\n', encoding="utf-8")

            output = root / "report.json"
            with mock.patch.object(
                    loom_test, "__file__", str(root / "tools" / "loom_test.py")), \
                    mock.patch.object(loom_test, "run", return_value=dict(failed)), \
                    mock.patch.object(loom_test.loom_docs, "refresh_evidence",
                                      side_effect=bind):
                code = loom_test.main([
                    "full", "--quiet", "--refresh-generated-evidence",
                    "--output", str(output)])
            self.assertEqual(1, code)
            self.assertEqual('{"old":true}\n', evidence.read_text(encoding="utf-8"))

    def test_quiet_file_output_keeps_stdout_bounded(self):
        report = {
            "schema_version": 1, "mode": "full", "tests_run": 5000,
            "failures": 0, "errors": 0, "skipped": 0,
            "elapsed_seconds": 1.0, "suppressed_stdout_chars": 0,
            "max_seconds": None, "within_budget": True,
            "capability_complete": True, "status": "passed",
            "successful": True, "skip_receipts": [],
            "timings": [{"test": "x" * 1024, "status": "passed"}] * 500,
        }
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
                loom_test, "run", return_value=report):
            output = Path(temp) / "report.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = loom_test.main([
                    "full", "--quiet", "--output", str(output)])

            self.assertEqual(0, code)
            self.assertEqual(
                report, json.loads(output.read_text(encoding="utf-8")))
            self.assertLess(len(stdout.getvalue().encode("utf-8")), 512)
            self.assertNotIn('"timings"', stdout.getvalue())

    def test_failed_or_incomplete_suite_cannot_refresh_generated_evidence(self):
        with self.assertRaisesRegex(
                loom_test.loom_docs.DocsError, "correctness-clean complete"):
            loom_test.refresh_final_evidence(Path.cwd(), {
                "mode": "fast", "successful": True, "tests_run": 1})
        with self.assertRaisesRegex(
                loom_test.loom_docs.DocsError, "correctness-clean complete"):
            loom_test.refresh_final_evidence(Path.cwd(), {
                "mode": "full", "successful": False, "tests_run": 1,
                "failures": 1, "errors": 0, "skipped": 0,
                "capability_complete": True, "within_budget": True})
        with self.assertRaisesRegex(
                loom_test.loom_docs.DocsError, "correctness-clean complete"):
            loom_test.refresh_final_evidence(Path.cwd(), {
                "mode": "full", "successful": False, "tests_run": 1,
                "failures": 0, "errors": 0, "skipped": 1,
                "capability_complete": False, "within_budget": True})

    def test_missing_output_parent_fails_before_running_any_tests(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(
                loom_test, "run") as run:
            missing = Path(temp) / "missing" / "report.json"
            with self.assertRaises(SystemExit) as caught:
                loom_test.main(["fast", "--output", str(missing)])
        self.assertEqual(2, caught.exception.code)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
