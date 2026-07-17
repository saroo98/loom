"""Cross-platform capability aggregation tests."""

import json
import tempfile
import unittest
from pathlib import Path

import loom_capability


class CapabilityAggregationTests(unittest.TestCase):
    def _report(self, root, name, status):
        path = root / f"{name}.json"
        path.write_text(json.dumps({
            "timings": [{"test": "suite.test_fifo", "status": status}],
            "skip_receipts": ([{"test": "suite.test_fifo", "reason": "no fifo"}]
                              if status == "skipped" else []),
            "failures": 0, "errors": 0, "within_budget": True,
        }), encoding="utf-8")
        return path

    def test_skip_is_certified_only_when_same_capability_passes_elsewhere(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skipped = self._report(root, "windows", "skipped")
            self.assertEqual("not-certified", loom_capability.aggregate([skipped])["status"])
            passed = self._report(root, "linux", "passed")
            result = loom_capability.aggregate([skipped, passed])
            self.assertEqual("certified", result["status"])
            self.assertEqual(1, result["covered_elsewhere"])

    def test_release_summary_with_matrix_skips_is_not_a_failed_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skipped = root / "windows.json"
            skipped.write_text(json.dumps({
                "timings": [{"test": "suite.test_fifo", "status": "skipped"}],
                "skip_receipts": [{"test": "suite.test_fifo", "reason": "no fifo"}],
                "passed": True, "returncode": 1, "capability_complete": False,
                "capability_status": "requires-matrix",
            }), encoding="utf-8")
            passed = root / "linux.json"
            passed.write_text(json.dumps({
                "timings": [{"test": "suite.test_fifo", "status": "passed"}],
                "skip_receipts": [], "passed": True, "returncode": 0,
                "capability_complete": True, "capability_status": "complete",
            }), encoding="utf-8")
            result = loom_capability.aggregate([skipped, passed])
            self.assertEqual("certified", result["status"])
            self.assertEqual(0, result["failed_reports"])

    def test_release_summary_cannot_hide_a_failed_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "failed.json"
            path.write_text(json.dumps({
                "timings": [], "skip_receipts": [], "passed": False,
                "returncode": 1, "capability_complete": False,
                "capability_status": "requires-matrix",
            }), encoding="utf-8")
            result = loom_capability.aggregate([path])
            self.assertEqual("not-certified", result["status"])
            self.assertEqual(1, result["failed_reports"])


if __name__ == "__main__":
    unittest.main()
