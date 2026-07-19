import re
import unittest

import loom_message


class OwnerMessageTests(unittest.TestCase):
    def test_every_state_is_closed_and_never_exceeds_two_lines(self):
        for state in sorted(loom_message.STATES):
            intervention = state in loom_message.INTERVENTIONS
            with self.subTest(state=state):
                value = loom_message.build(
                    state=state, consequence="material", verification="pending",
                    freshness="unknown", changes_made=False,
                    undo_status="not-applicable",
                    summary="Work state changed.",
                    decision="Choose the safe branch." if intervention else None,
                    recommendation="Keep external effects blocked." if intervention else None,
                    next_action="Continue only after the stated condition.",
                    receipt_id="msg-test")
                self.assertLessEqual(value["human"].count("\n"), 1)
                self.assertLessEqual(len(value["human"]), loom_message.MAX_HUMAN_CHARS)
                loom_message.validate(value)

    def test_every_intervention_has_exactly_one_decision_and_recommendation(self):
        for state in loom_message.INTERVENTIONS:
            with self.assertRaises(loom_message.MessageError):
                loom_message.build(
                    state=state, consequence="high", verification="blocked",
                    freshness="unknown", changes_made=False,
                    undo_status="not-applicable",
                    summary="Stopped.",
                    next_action="Wait.", receipt_id="msg-blocked")

    def test_session_projection_hides_internal_tier_gate_and_schema_terms(self):
        value = loom_message.from_session(
            status="completed", code="plan-complete", intent="plan", tier="L",
            owner_input_required=False, reversible_action_ids=[],
            detail="internal detail", receipt_id="session-123")
        self.assertEqual("high", value["consequence"])
        self.assertIsNone(re.search(r"\b(?:tier|gate|schema)\b", value["human"], re.I))

    def test_relevant_preference_conflict_asks_one_choice_without_guessing(self):
        value = loom_message.from_session(
            status="blocked", code="preference-conflict", intent="plan", tier="M",
            owner_input_required=False, reversible_action_ids=[], detail="",
            receipt_id="session-conflict")
        self.assertEqual("decision-needed", value["state"])
        self.assertEqual("State which preference should apply to this work.",
                         value["decision"])
        self.assertEqual(2, len(value["human"].splitlines()))

    def test_human_rendering_cannot_diverge_from_machine_fields(self):
        value = loom_message.build(
            state="completed", consequence="ordinary", verification="verified",
            freshness="current", changes_made=True, undo_status="available",
            summary="Done safely.",
            next_action="Continue when ready.", receipt_id="message-bound")
        value["human"] = value["human"].replace("verified", "unknown")
        with self.assertRaises(loom_message.MessageError):
            loom_message.validate(value)

    def test_blocked_message_reports_no_change_without_claiming_irreversibility(self):
        value = loom_message.from_session(
            status="blocked", code="invalid-lifecycle", intent="plan", tier="M",
            owner_input_required=True, reversible_action_ids=[],
            detail="plans/lifecycle.json is invalid JSON; no fallback was authorized",
            receipt_id="session-blocked")
        self.assertFalse(value["changes_made"])
        self.assertEqual("not-applicable", value["undo_status"])
        self.assertIn("invalid JSON", value["human"])
        self.assertNotIn("reversible: no", value["human"])


if __name__ == "__main__":
    unittest.main()
