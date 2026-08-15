import re
import unittest

import loom_block_reason
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
            detail=(
                "LOOM_RESULT plans/loom-1.0/MANIFEST.md"
                " | Release-ready plan validated. Only the declared work-order frontier "
                "is authorized."),
            receipt_id="session-123")
        self.assertEqual(5, value["schema_version"])
        self.assertEqual("high", value["consequence"])
        self.assertEqual("plans/loom-1.0/MANIFEST.md", value["result_path"])
        self.assertIsNone(re.search(
            r"\b(?:tier|gate|schema|frontier|lifecycle|receipt|ledger)\b",
            value["human"], re.I))
        self.assertTrue(value["changes_made"])
        self.assertEqual("unavailable", value["undo_status"])
        self.assertEqual(
            "Review the plan, then say continue when you want the agent to start.",
            value["next_action"])
        self.assertIn("Your project plan is ready.", value["human"])
        self.assertIn("Open: plans/loom-1.0/MANIFEST.md.", value["human"])

    def test_non_authoritative_plan_exposes_only_its_safe_recovery_route(self):
        """Break caught: inline recovery is projected as startable plan authority."""
        private_marker = "owner-private-marker-never-project"
        value = loom_message.from_session(
            status="completed", code="non-authoritative-plan", intent="plan", tier="M",
            owner_input_required=False, reversible_action_ids=[],
            detail=(
                "NON-AUTHORITATIVE PLAN\n"
                f"Private result detail: {private_marker}\n"
                "Safe next action: Quarantine or repair the lifecycle store, then ask "
                "Loom for a fresh plan."),
            receipt_id="session-non-authoritative")

        self.assertFalse(value["changes_made"])
        self.assertEqual("not-applicable", value["undo_status"])
        self.assertIsNone(value["result_path"])
        self.assertEqual(
            "This is non-authoritative planning and recovery material. No project or "
            "plan authority was changed, and implementation cannot start from it.",
            value["summary"])
        self.assertEqual(
            "Follow the precise Safe next action in the non-authoritative result.",
            value["next_action"])
        self.assertNotIn("say continue", value["human"].casefold())
        self.assertNotIn(private_marker, value["human"])
        loom_message.validate(value)

    def test_non_authoritative_projection_rejects_hidden_authority_fields(self):
        """Break caught: projection clears authority fields instead of rejecting them."""
        cases = (
            {"reversible_action_ids": ["forged-action"], "result_path": None},
            {"reversible_action_ids": [], "result_path": "plans/forged/MANIFEST.md"},
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(
                    loom_message.MessageError):
                loom_message.from_session(
                    status="completed", code="non-authoritative-plan",
                    intent="plan", tier="M", owner_input_required=False,
                    detail="Non-authoritative recovery material.",
                    receipt_id="session-hidden-authority", **case)

    def test_current_completed_message_explains_the_actual_operation(self):
        value = loom_message.from_session(
            status="completed", code="undo-complete", intent="undo", tier="S",
            owner_input_required=False, reversible_action_ids=[],
            detail="The unchanged Loom plan was archived and removed from the active project.",
            receipt_id="session-undo")
        self.assertEqual(
            "The unchanged Loom plan was archived and removed from the active project.",
            value["summary"])
        self.assertIn("new request", value["next_action"])
        self.assertNotIn("safe verified frontier", value["human"])

    def test_v4_completed_message_remains_exactly_reconstructable(self):
        value = loom_message.v4_from_session(
            status="completed", code="undo-complete", intent="undo", tier="S",
            owner_input_required=False, reversible_action_ids=[],
            detail="The unchanged Loom plan was archived.",
            receipt_id="session-v4")
        self.assertEqual(4, value["schema_version"])
        self.assertIn("Consequence:", value["human"])
        loom_message.validate(value)

    def test_v3_completed_message_remains_exactly_reconstructable(self):
        value = loom_message.v3_from_session(
            status="completed", code="undo-complete", intent="undo", tier="S",
            owner_input_required=False, reversible_action_ids=[],
            detail="The unchanged Loom plan was archived.",
            receipt_id="session-v3")
        self.assertEqual(3, value["schema_version"])
        self.assertEqual("Loom completed the safe verified frontier.", value["summary"])
        loom_message.validate(value)

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
        value["human"] = value["human"].replace("Done safely.", "Done.")
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

    def test_blocked_intent_message_exposes_one_action_and_how_to_inspect_details(self):
        reason = loom_block_reason.build(
            code="INTENT_AMBIGUOUS", category="intent",
            expected="One unambiguous Loom action.",
            observed="The request contains more than 16 separate Loom actions.",
            finding_codes=["INTENT_AMBIGUOUS"], finding_count=1,
            ownership="not-applicable", pristine_proof="not-applicable",
            automatic_recovery="owner-decision",
            next_action=(
                "Start a fresh request with one positive action; group requirements as "
                "descriptive bullets and prohibitions under one Do not section."))

        value = loom_message.from_session(
            status="blocked", code="intent-ambiguous", intent="status", tier="S",
            owner_input_required=True, reversible_action_ids=[], detail="",
            receipt_id="session-intent-block", block_reason=reason)

        self.assertIn("could not identify one safely authorized action",
                      value["human"])
        self.assertIn("descriptive bullets", value["human"])
        self.assertIn("Details: ask Loom why.", value["human"])

    def test_project_write_block_preserves_complete_plain_sentence(self):
        observed = (
            "Loom stopped before changing the project. Creating a persistent Loom plan "
            "currently requires project-local planning files under plans/. Remove the "
            "no-file-write constraint if you want those files created.")
        reason = loom_block_reason.build(
            code="PROJECT-WRITE-PROHIBITED", category="handler",
            expected="One unambiguous, current, and safely authorized Loom action.",
            observed=observed,
            finding_codes=["PROJECT-WRITE-PROHIBITED"], finding_count=1,
            ownership="not-applicable", pristine_proof="not-applicable",
            automatic_recovery="owner-decision",
            next_action="Resolve the reported condition, then start a fresh Loom request.")

        value = loom_message.from_session(
            status="blocked", code="project-write-prohibited", intent="plan", tier="M",
            owner_input_required=False, reversible_action_ids=[], detail="",
            receipt_id="session-project-write", block_reason=reason)

        self.assertEqual(observed, value["summary"])
        self.assertIn("those files created. Details:", value["human"])
        self.assertNotIn("those files creat Details:", value["human"])

    def test_long_block_summary_uses_a_visible_word_boundary(self):
        reason = loom_block_reason.build(
            code="LONG-BLOCK", category="handler",
            expected="One bounded owner message.",
            observed="A " + ("lengthy observation " * 11),
            finding_codes=["LONG-BLOCK"], finding_count=1,
            ownership="not-applicable", pristine_proof="not-applicable",
            automatic_recovery="owner-decision",
            next_action="Inspect the bounded condition.")

        value = loom_message.from_session(
            status="blocked", code="long-block", intent="plan", tier="M",
            owner_input_required=False, reversible_action_ids=[], detail="",
            receipt_id="session-long-block", block_reason=reason)

        self.assertLessEqual(len(value["summary"]), 240)
        self.assertTrue(value["summary"].endswith("\u2026"))
        self.assertRegex(value["summary"], r"(?:lengthy|observation)\u2026$")

    def test_result_locator_rejects_absolute_and_parent_traversal_paths(self):
        for detail in (
                "LOOM_RESULT C:/private/plan.md | ready",
                "LOOM_RESULT ../private/plan.md | ready"):
            with self.subTest(detail=detail), self.assertRaises(
                    loom_message.MessageError):
                loom_message.from_session(
                    status="completed", code="plan-complete", intent="plan", tier="S",
                    owner_input_required=False, reversible_action_ids=[],
                    detail=detail, receipt_id="session-result")


if __name__ == "__main__":
    unittest.main()
