"""Locked proportional-routing and compact-contract tests."""

import unittest

import loom_tier


class TierSFastPathTests(unittest.TestCase):
    def test_ordinary_small_work_stays_tier_s(self):
        for request in ("Fix one documentation typo", "Rename one CLI flag",
                        "Change one UI label", "Rename one configuration key"):
            self.assertEqual("S", loom_tier.classify(request)["tier"], request)

    def test_deceptive_small_consequences_promote(self):
        fixtures = (
            "Make a one-line authentication bypass change",
            "Change one-line tax rounding",
            "Make a one-line database migration",
            "Update one dependency and lockfile",
            "Rename one public API field",
            "Change one firmware timing constant",
            "Add one destructive cleanup command",
            "Change one production deploy setting",
            "Change one cryptographic parameter",
        )
        for request in fixtures:
            self.assertNotEqual("S", loom_tier.classify(request)["tier"], request)

    def test_small_wording_never_overrides_observed_scope(self):
        result = loom_tier.classify(
            "Make a tiny one-line change", files=9, new_components=1)
        self.assertEqual("M", result["tier"])

    def test_adaptive_effort_vector_names_obligations_and_promotion(self):
        result = loom_tier.classify(
            "Adjust one existing parser", files=1, outcomes=2,
            domain_coverage="unknown", repository_health="drifted")
        self.assertEqual(2, result["schema_version"])
        self.assertEqual(result["tier"], result["compatibility_label"])
        self.assertEqual("unknown", result["observation_vector"]["domain_coverage"])
        self.assertNotEqual("S", result["tier"])
        self.assertIn("domain-invariant-discovery", result["obligations"])
        self.assertIn("atomic-outcome-slices", result["obligations"])

    def test_every_small_promotion_trigger_prevents_tier_s(self):
        cases = (
            {"files": 6}, {"new_boundaries": 1}, {"irreversible": True},
            {"outcomes": 2}, {"domain_coverage": "unknown"},
            {"consequence": "material"}, {"repository_health": "unknown"},
        )
        for observations in cases:
            with self.subTest(observations=observations):
                self.assertNotEqual(
                    "S", loom_tier.classify(
                        "Adjust one existing parser", **observations)["tier"])


if __name__ == "__main__":
    unittest.main()
