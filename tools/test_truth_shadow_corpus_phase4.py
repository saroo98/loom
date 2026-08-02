import hashlib
import json
import unittest
from pathlib import Path

import loom_truth_shadow


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "truth-authority" / "corpus.json"
REGISTRY = ROOT / "contracts" / "truth-authorities-v1.json"


class TruthShadowCorpusPhase4Tests(unittest.TestCase):
    def test_locked_corpus_meets_every_promotion_threshold(self):
        value = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(
            loom_truth_shadow.STABLE_CORPUS_SUBJECT_KINDS,
            value["subject_kinds"])
        self.assertNotIn("public-cut", value["subject_kinds"])
        expected = hashlib.sha256(CORPUS.read_bytes()).hexdigest()
        first = loom_truth_shadow.run(
            CORPUS, REGISTRY, expected_corpus_sha256=expected)
        second = loom_truth_shadow.run(
            CORPUS, REGISTRY, expected_corpus_sha256=expected)
        self.assertEqual(first, second)
        self.assertEqual("passed", first["status"])
        self.assertTrue(first["promotion_eligible"])
        self.assertEqual(
            0, first["metrics"]["unsafe_supported_promotions"])
        self.assertEqual(
            0,
            first["metrics"]["false_positive_enforcement_downgrades"])
        self.assertEqual(1.0, first["metrics"]["unsafe_state_recall"])
        self.assertEqual(
            0, first["metrics"]["historical_prose_support_effects"])
        self.assertLessEqual(
            first["metrics"]["advisory_false_positive_rate"], 0.03)

    def test_candidate_digest_and_bootstrap_cannot_claim_promotion(self):
        with self.assertRaisesRegex(
                loom_truth_shadow.ShadowCorpusError, "stable-controller or CI"):
            loom_truth_shadow.run(
                CORPUS, REGISTRY, expected_corpus_sha256="0" * 64)
        bootstrap = loom_truth_shadow.run(
            CORPUS, REGISTRY, shadow_bootstrap=True)
        self.assertEqual("passed", bootstrap["status"])
        self.assertFalse(bootstrap["corpus_locked_by_external_expectation"])
        self.assertFalse(bootstrap["promotion_eligible"])


if __name__ == "__main__":
    unittest.main()
