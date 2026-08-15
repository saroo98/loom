"""Owner-visible recovery routing across lifecycle conditions."""

import unittest

import loom_runtime


class OwnerIntentRecoveryTests(unittest.TestCase):
    RECOVERY_REQUEST = (
        "For a museum collection portal, outline the work needed to add an "
        "accessibility search filter. Keep this at the proposal stage; do not "
        "touch the project.")
    PLANNING_REQUEST = (
        "Draft an approach for a minor warehouse barcode label adjustment. "
        "This is for review, not implementation.")

    def test_planning_intent_has_no_execution_route_in_each_lifecycle_state(self):
        """Break caught: lifecycle state misclassifies ordinary planning language."""
        states = (
            ("absent", {"generation_phase": "absent"}),
            ("reviewable", {"generation_phase": "reviewable"}),
            ("active", {"generation_phase": "active"}),
            ("terminal", {"generation_phase": "terminal-completed"}),
            ("stale", {
                "generation_phase": "reviewable",
                "state_error": "STALE_LIFECYCLE",
            }),
            ("corrupt", {
                "generation_phase": "reviewable",
                "state_error": "CORRUPT_LIFECYCLE",
            }),
        )

        for name, state in states:
            with self.subTest(state=name):
                decision = loom_runtime.resolve_intent(self.PLANNING_REQUEST, state)
                control = loom_runtime.request_control(
                    self.PLANNING_REQUEST, state=state)
                result = loom_runtime._apply_lifecycle_request_policy(
                    decision, state, control)
                self.assertEqual("plan", result["intent"])
                self.assertNotEqual("execute", result["intent"])
                if result["blocked"]:
                    self.assertTrue(result["needs_owner"])
                    self.assertTrue(result["recommendation"].strip())

    def test_internal_recovery_conditions_give_the_owner_a_safe_next_step(self):
        """Break caught: internal planning failures strand the owner without recovery."""
        conditions = (
            "PLAN_PACK_EXISTS",
            "PLAN_DECISION_STALE",
            "REPAIR_SCOPE_INDETERMINATE",
        )
        for condition in conditions:
            with self.subTest(condition=condition):
                state = {
                    "generation_phase": "reviewable",
                    "state_error": condition,
                }
                decision = loom_runtime.resolve_intent(self.RECOVERY_REQUEST, state)
                control = loom_runtime.request_control(
                    self.RECOVERY_REQUEST, state=state)
                result = loom_runtime._apply_lifecycle_request_policy(
                    decision, state, control)
                self.assertTrue(result["blocked"])
                self.assertEqual(condition, result["code"])
                self.assertEqual("plan", result["intent"])
                self.assertTrue(result["needs_owner"])
                self.assertTrue(result["recommendation"].strip())


if __name__ == "__main__":
    unittest.main()
