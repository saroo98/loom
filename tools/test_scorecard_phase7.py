import unittest
from pathlib import Path

import loom_scorecard


ROOT = Path(__file__).resolve().parents[1]


class ScorecardPhase7Tests(unittest.TestCase):
    def test_v2_is_default_and_translates_legacy_evidence_classes(self):
        rubric = loom_scorecard.load_rubric()
        self.assertEqual("loom-cross-cutting-v2", rubric["rubric_id"])
        self.assertIn("ci-reproduced", rubric["evidence_classes"])
        self.assertIn("provider-native", rubric["evidence_classes"])
        self.assertNotIn("matrix-reproduced", rubric["evidence_classes"])
        self.assertNotIn("provider-attested", rubric["evidence_classes"])
        required = {item["id"]: item for category in rubric["categories"]
                    for item in category["requirements"]}
        self.assertIn("provider-native",
                      required["complete-token-accounting"]["allowed_evidence_classes"])
        self.assertIn("ci-reproduced",
                      required["cross-platform-tool-correctness"]["allowed_evidence_classes"])

    def test_v1_remains_loadable_as_an_explicit_historical_contract(self):
        rubric = loom_scorecard.load_rubric(ROOT / "contracts" / "score-rubric-v1.json")
        self.assertEqual("loom-cross-cutting-v1", rubric["rubric_id"])
        self.assertIn("provider-attested", rubric["evidence_classes"])


if __name__ == "__main__":
    unittest.main()
