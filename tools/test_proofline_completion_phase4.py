import json
import unittest
from pathlib import Path

import loom_proofline_completion


ROOT = Path(__file__).resolve().parent.parent


class ProoflineCompletionTests(unittest.TestCase):
    def setUp(self):
        self.policy = loom_proofline_completion.load_policy(
            ROOT / "contracts" / "proofline-policy-v1.json")

    def test_locked_orphan_corpus_has_zero_errors(self):
        corpus = json.loads(
            (ROOT / "benchmarks" / "proofline" / "orphan-corpus.json").read_text(
                encoding="utf-8"))
        result = loom_proofline_completion.evaluate_corpus(corpus, self.policy)
        self.assertTrue(result["passed"])
        self.assertEqual([], result["false_positives"])
        self.assertEqual([], result["false_negatives"])
        self.assertGreaterEqual(result["case_count"], 12)

    def test_policy_is_closed_and_rollbackable(self):
        self.assertEqual(
            ["exact-unauthorized-project-path"],
            self.policy["promoted_predicates"])
        self.assertIn("Set mode to shadow", self.policy["rollback"])
        changed = dict(self.policy)
        changed["path_classes"] = {
            **changed["path_classes"], "mystery": ["**"]}
        with self.assertRaises(loom_proofline_completion.CompletionError):
            loom_proofline_completion.validate_policy(changed)

    def test_path_evidence_is_never_semantic_completion(self):
        self.assertIn(
            "material-intent-semantic-completion",
            self.policy["advisory_predicates"])


if __name__ == "__main__":
    unittest.main()
