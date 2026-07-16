"""Trust-critical mutation gate contract tests."""

import unittest
from pathlib import Path

import loom_mutation


ROOT = Path(__file__).resolve().parents[1]


class MutationGateTests(unittest.TestCase):
    def test_every_named_trust_guard_mutation_is_killed(self):
        result = loom_mutation.run(ROOT, minimum_score=90, timeout=120)
        self.assertEqual("passed", result["status"])
        self.assertGreaterEqual(result["score"], 90)
        self.assertTrue(all(item["killed"] for item in result["receipts"]))


if __name__ == "__main__":
    unittest.main()
