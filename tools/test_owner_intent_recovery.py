"""Owner-visible recovery routing across lifecycle conditions."""

import unittest

import loom_runtime


class OwnerIntentRecoveryTests(unittest.TestCase):
    PLANNING_REQUEST = (
        "Draft an approach for a minor warehouse barcode label adjustment. "
        "This is for review, not implementation.")

    def test_planning_intent_has_no_execution_route_in_each_lifecycle_state(self):
        """Break caught: lifecycle state misclassifies ordinary planning language."""
        states = (
            ("absent", {"generation_phase": "absent"}, "new", False,
             "ROUTE_PLAN"),
            ("reviewable", {"generation_phase": "reviewable"}, "unclear", False,
             "ROUTE_PLAN"),
            ("active", {"generation_phase": "active"}, "unclear", True,
             "RELATION_REQUIRES_OWNER"),
            ("terminal", {"generation_phase": "terminal-completed"}, "new", False,
             "ROUTE_PLAN"),
            ("stale", {
                "generation_phase": "reviewable",
                "state_error": "STALE_LIFECYCLE",
            }, "unclear", True, "PLAN_DECISION_STALE"),
            ("corrupt", {
                "generation_phase": "reviewable",
                "state_error": "CORRUPT_LIFECYCLE",
            }, "unclear", True, "CORRUPT_LIFECYCLE"),
        )

        for name, state, relation, blocked, code in states:
            with self.subTest(state=name):
                decision = loom_runtime.resolve_intent(self.PLANNING_REQUEST, state)
                control = loom_runtime.request_control(
                    self.PLANNING_REQUEST, state=state)
                result = loom_runtime._apply_lifecycle_request_policy(
                    decision, state, control)
                self.assertEqual("plan", control["primary_operation"])
                self.assertEqual(relation, control["relation"])
                self.assertEqual("plan", result["intent"])
                self.assertEqual(blocked, result["blocked"])
                self.assertEqual(code, result["code"])
                if blocked:
                    self.assertTrue(result["needs_owner"])
                    self.assertTrue(result["recommendation"].strip())


if __name__ == "__main__":
    unittest.main()
