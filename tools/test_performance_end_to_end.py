"""Offline performance-corpus integrity and anti-gaming tests."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_benchmark


class PerformanceEndToEndTests(unittest.TestCase):
    def fixture(self, root):
        path = root / "corpus.json"
        path.write_text(json.dumps({"schema_version": 1, "workloads": [{
            "id": "tiny", "request": "Fix one documentation typo", "files": 2
        }]}), encoding="utf-8")
        return path

    def test_fixture_identity_is_deterministic_without_claiming_timing_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            corpus = self.fixture(root)
            first = loom_benchmark.run(corpus, iterations=2, warmups=1, seed=7)
            second = loom_benchmark.run(corpus, iterations=2, warmups=1, seed=7)
            self.assertEqual(first["results"][0]["fixture_sha256"],
                             second["results"][0]["fixture_sha256"])
            self.assertEqual(2, first["results"][0]["sample_count"])
            self.assertEqual(0, first["results"][0]["failure_count"])
            self.assertEqual("observed-local-offline", first["measurement_kind"])

    def test_failed_samples_are_retained_and_never_deleted_as_outliers(self):
        with tempfile.TemporaryDirectory() as temp:
            corpus = self.fixture(Path(temp))
            with mock.patch.object(
                    loom_benchmark.loom_survey, "repo_state",
                    side_effect=RuntimeError("seeded failure")):
                result = loom_benchmark.run(corpus, iterations=3, warmups=0)
            item = result["results"][0]
            self.assertEqual(0, item["sample_count"])
            self.assertEqual(3, item["failure_count"])
            self.assertEqual([0, 1, 2], [failure["sample"] for failure in item["failures"]])

    def test_public_corpus_contains_all_twenty_locked_workload_shapes(self):
        corpus = json.loads((Path(__file__).parent.parent / "benchmarks" / "performance" /
                             "corpus.json").read_text(encoding="utf-8"))
        self.assertEqual(20, len(corpus["workloads"]))
        self.assertEqual(20, len({item["id"] for item in corpus["workloads"]}))


if __name__ == "__main__":
    unittest.main()
