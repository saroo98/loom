"""Release-suite certification bound to exact cross-platform capability evidence."""

import json
import tempfile
import unittest
from pathlib import Path

import loom_release_suite


COMMIT = "1" * 40
ROOT = "2" * 64
TEST_ID = "test_capability.ExampleTests.test_platform_capability"


def report(platform, status):
    skipped = status == "skipped"
    return {
        "failures": 0,
        "errors": 0,
        "within_budget": True,
        "timings": [{"test": TEST_ID, "status": status, "seconds": 0.1}],
        "skip_receipts": ([{"test": TEST_ID, "reason": "platform fixture"}]
                          if skipped else []),
        "binding": {
            "source_commit": COMMIT,
            "public_root_sha256": ROOT,
            "platform": platform,
            "architecture": "x86_64",
            "python": "3.11.0",
            "runner": f"{platform}-runner",
        },
    }


class ReleaseSuiteTests(unittest.TestCase):
    @staticmethod
    def _write_reports(root, rows):
        paths = []
        for name, value in rows:
            path = root / f"{name}.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            paths.append(path)
        return paths

    def test_exact_matrix_pass_authorizes_local_capability_skip(self):
        local = {
            "tests_run": 1,
            "failures": 0,
            "errors": 0,
            "within_budget": True,
            "skip_receipts": [{"test": TEST_ID, "reason": "unavailable locally"}],
            "timings": [{"test": TEST_ID, "status": "skipped", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._write_reports(root, (
                ("linux", report("linux", "skipped")),
                ("windows", report("windows", "passed")),
            ))
            result = loom_release_suite.certify(
                local, paths, expected_commit=COMMIT, expected_root=ROOT)
        self.assertEqual("certified", result["status"])
        self.assertEqual([TEST_ID], result["covered_local_skips"])
        self.assertEqual(2, result["matrix"]["reports"])

    def test_uncovered_local_skip_is_refused(self):
        local = {
            "tests_run": 1, "failures": 0, "errors": 0, "within_budget": True,
            "skip_receipts": [{"test": TEST_ID, "reason": "unavailable locally"}],
            "timings": [{"test": TEST_ID, "status": "skipped", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = self._write_reports(Path(directory), (
                ("linux", report("linux", "skipped")),
            ))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "not certified|lack"):
                loom_release_suite.certify(
                    local, paths, expected_commit=COMMIT, expected_root=ROOT)

    def test_matrix_for_another_release_subject_is_refused(self):
        local = {
            "tests_run": 1, "failures": 0, "errors": 0, "within_budget": True,
            "skip_receipts": [],
            "timings": [{"test": TEST_ID, "status": "passed", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = self._write_reports(Path(directory), (
                ("windows", report("windows", "passed")),
            ))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "this release subject"):
                loom_release_suite.certify(
                    local, paths, expected_commit="3" * 40, expected_root=ROOT)

    def test_local_failure_cannot_be_hidden_by_a_green_matrix(self):
        local = {
            "tests_run": 1, "failures": 1, "errors": 0, "within_budget": True,
            "skip_receipts": [],
            "timings": [{"test": TEST_ID, "status": "failed", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = self._write_reports(Path(directory), (
                ("windows", report("windows", "passed")),
            ))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "did not pass"):
                loom_release_suite.certify(
                    local, paths, expected_commit=COMMIT, expected_root=ROOT)


if __name__ == "__main__":
    unittest.main()
