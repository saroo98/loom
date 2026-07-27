"""Locked proportional-routing and compact-contract tests."""

import unittest

import loom_tier


class TierSFastPathTests(unittest.TestCase):
    def test_ordinary_small_work_stays_tier_s(self):
        for request in ("Fix one documentation typo", "Rename one CLI flag",
                        "Change one UI label", "Rename one configuration key"):
            self.assertEqual("S", loom_tier.classify(request)["tier"], request)

    def test_tiny_planning_only_cli_is_not_promoted_by_negated_implementation(self):
        request = (
            "Plan a tiny Python CLI greeter that accepts a name and prints "
            "Hello, <name>!, with one standard-library unittest. Planning only; "
            "excluded."
        )
        result = loom_tier.classify(request, domains=["cli"])
        self.assertEqual("S", result["tier"])
        self.assertFalse(result["plan_and_implement"])

    def test_very_small_command_line_noun_is_still_an_explicit_small_shape(self):
        result = loom_tier.classify(
            "Plan a very small Python command-line greeter that accepts --name, "
            "prints a greeting, includes one test, and a short README.",
            domains=["cli"])
        self.assertEqual("S", result["tier"])
        self.assertIn(
            "description contains an explicit small-work shape",
            result["reasons"])

    def test_delete_command_name_does_not_promote_small_cli_but_real_delete_does(self):
        for verb in ("Build", "Plan"):
            with self.subTest(verb=verb):
                command_surface = loom_tier.classify(
                    f"{verb} a small CLI with create, list, and delete commands",
                    domains=["cli"])
                self.assertEqual("S", command_surface["tier"])
                self.assertNotIn("delete", command_surface["risk_terms"])
        destructive = loom_tier.classify(
            "Build a small cleanup CLI and then delete production data",
            domains=["cli"])

        self.assertEqual("M", destructive["tier"])
        self.assertIn("delete", destructive["risk_terms"])
        command_list = loom_tier.classify(
            "Plan a small Python command-line task tracker with add, list, complete, "
            "and delete commands, tests, and a concise README.",
            domains=["cli"])
        self.assertEqual("S", command_list["tier"])

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
