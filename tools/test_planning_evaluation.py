import unittest

import loom_planning_eval


class PlanningEvaluationTests(unittest.TestCase):
    def test_release_corpus_has_zero_critical_failures(self):
        report = loom_planning_eval.run()
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(0, report["critical_harmful_activations"])
        self.assertEqual(0, report["unsafe_authorizations"])
        self.assertEqual(0, report["provenance_losses"])
        self.assertEqual(0, report["stale_fresh_claims"])
        self.assertGreaterEqual(report["split_counts"]["release-holdout"], 24)


if __name__ == "__main__":
    unittest.main()
