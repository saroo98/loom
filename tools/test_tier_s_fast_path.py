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


if __name__ == "__main__":
    unittest.main()
