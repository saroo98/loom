"""Tests for the bounded CI test runner."""

import unittest
from unittest import mock

import loom_test


class TestRunnerTests(unittest.TestCase):
    def test_fast_gate_is_real_bounded_and_has_no_loader_errors(self):
        report = loom_test.run("fast", max_seconds=30, verbosity=0)
        self.assertEqual(len(loom_test.FAST_TESTS), report["tests_run"])
        self.assertEqual((0, 0), (report["failures"], report["errors"]))
        self.assertTrue(report["within_budget"], report)
        self.assertTrue(report["successful"], report)
        self.assertEqual(report["tests_run"], len(report["timings"]))
        self.assertGreater(report["suppressed_stdout_chars"], 0)

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


if __name__ == "__main__":
    unittest.main()
