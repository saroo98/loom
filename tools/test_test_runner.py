"""Tests for the bounded CI test runner."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
