import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import loom_adaptation_eval
import loom_memory


EXPECTED = {
    "three-d-week-close", "accounting-after-three-d", "three-d-six-month-return",
    "alternating-projects", "two-month-pause", "autonomy-change", "stack-change",
    "harmful-inference-correction", "useful-invariant-dormancy", "twenty-project-year",
    "hundreds-outcomes-feedback", "interrupted-session", "concurrent-memory-writers",
    "corrupt-state", "wrong-instance-uuid", "disabled-profile",
    "permanent-forget-and-migration", "unknown-domain", "composite-domain",
    "second-relevant-project-improves",
}


class AdaptationEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        real_lock_init = loom_memory.FileLock.__init__
        real_atomic_store = loom_memory._atomic_store

        def short_external_lock_bound(lock, path, timeout=5.0,
                                      stale_after=None):
            real_lock_init(lock, path, timeout=0.2,
                           stale_after=stale_after)

        def bounded_slow_store(path, value):
            if "concurrent-memory-writers" in Path(path).parts:
                time.sleep(0.04)
            return real_atomic_store(path, value)

        with mock.patch.object(
                loom_memory.FileLock, "__init__", short_external_lock_bound), \
                mock.patch.object(
                    loom_memory, "_atomic_store", bounded_slow_store):
            cls.report = loom_adaptation_eval.run_suite(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_full_longitudinal_suite_executes_every_required_scenario(self):
        report = self.report
        self.assertEqual(EXPECTED, {item["id"] for item in report["scenarios"]})
        self.assertEqual("passed", report["status"], json.dumps(report, indent=2))
        self.assertTrue(all(item["passed"] for item in report["scenarios"]))
        self.assertTrue(all(item["assertions"] for item in report["scenarios"]))
        self.assertTrue(all(
            set(assertion) == {"name", "expected", "actual", "passed"}
            for item in report["scenarios"] for assertion in item["assertions"]))

    def test_time_and_scale_scenarios_report_measured_bounds(self):
        report = self.report
        by_id = {item["id"]: item for item in report["scenarios"]}
        for scenario in (
                "three-d-week-close", "three-d-six-month-return", "two-month-pause",
                "useful-invariant-dormancy", "twenty-project-year"):
            self.assertTrue(by_id[scenario]["time_controlled"], scenario)
        scale = by_id["hundreds-outcomes-feedback"]["measurements"]
        self.assertGreaterEqual(scale["outcomes_recorded"], 500)
        self.assertLessEqual(scale["active_outcomes"], scale["active_outcome_bound"])
        self.assertLessEqual(scale["feedback_active"], scale["feedback_bound"])

    def test_cli_never_deletes_a_preexisting_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "existing"
            workspace.mkdir()
            sentinel = workspace / "owner-file.txt"
            sentinel.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "must not already exist"):
                loom_adaptation_eval.main(["--workspace", str(workspace)])
            self.assertEqual("preserve\n", sentinel.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
