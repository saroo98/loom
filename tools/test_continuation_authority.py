import itertools
import unittest

import loom_authority


class ContinuationAuthorityTests(unittest.TestCase):
    def facts(self):
        return {
            "reversible": True, "destructive": False, "inside_scope": True,
            "external_effect": False, "cost": False, "privileged": False,
            "privacy_expanding": False, "legal_or_safety_judgment": False,
            "uncertain": False, "currently_evidenced": True,
            "verifiable_before_harm": True, "consequence": "ordinary",
        }

    def test_complete_boolean_truth_table_allows_only_the_safe_vector(self):
        boolean_fields = sorted(loom_authority.FACT_FIELDS - {"consequence"})
        automatic = 0
        for bits in itertools.product((False, True), repeat=len(boolean_fields)):
            facts = self.facts()
            facts.update(dict(zip(boolean_fields, bits)))
            result = loom_authority.decide(facts)
            loom_authority.validate(result)
            automatic += result["mode"] == "automatic"
        self.assertEqual(1, automatic)

    def test_added_consequence_never_reduces_authority(self):
        order = {"automatic": 0, "decision-needed": 1, "explicit-authority": 2}
        previous = None
        for consequence in ("ordinary", "material", "high", "critical"):
            facts = self.facts(); facts["consequence"] = consequence
            current = loom_authority.decide(facts)["mode"]
            if previous is not None:
                self.assertGreaterEqual(order[current], order[previous])
            previous = current

    def test_explicit_owner_request_is_recorded_but_never_called_automatic(self):
        facts = self.facts(); facts["external_effect"] = True
        result = loom_authority.decide(facts, owner_authorized=True)
        self.assertEqual("explicit-authority", result["mode"])
        self.assertIn("external-effect", result["blockers"])
        self.assertIsNone(result["undo"])


if __name__ == "__main__":
    unittest.main()
