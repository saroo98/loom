import json
import unittest

import loom_lint
import loom_runtime


class LifecycleIntentMetamorphicTests(unittest.TestCase):
    def test_semantic_planning_requests_do_not_depend_on_lifecycle_keywords(self):
        """Break caught: ordinary owner planning language is mistaken for review."""
        requests = (
            "For a museum collection portal, outline the work needed to add an "
            "accessibility search filter. Keep this at the proposal stage; do "
            "not touch the project.",
            "Our bakery ordering screen needs a small allergen preference panel. "
            "Before any work begins, give me a step-by-step approach only.",
            "I am weighing an extensive migration of our public-health appointment "
            "service. What would a safe delivery plan look like? No execution.",
            "Draft an approach for a minor warehouse barcode label adjustment. "
            "This is for review, not implementation.",
        )

        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request)
                self.assertFalse(decision["blocked"], decision)
                self.assertEqual("plan", decision["intent"])

    def test_plan_and_execution_contradiction_keeps_a_provisional_plan(self):
        """Break caught: an owner contradiction silently authorizes implementation."""
        decision = loom_runtime.resolve_intent(
            "Plan a school attendance dashboard, then implement it immediately.")

        self.assertFalse(decision["blocked"], decision)
        self.assertEqual("plan", decision["intent"])
        self.assertTrue(decision["needs_owner"], decision)
        self.assertEqual(1, decision["routine_question_count"])
        self.assertTrue(decision["recommendation"].strip())

    def test_discuss_another_design_never_changes_the_current_plan(self):
        """Break caught: a negated alternative design request starts lifecycle work."""
        decision = loom_runtime.resolve_intent(
            "Discuss another design but do not change the current plan.")
        control = loom_runtime.request_control(
            "Discuss another design but do not change the current plan.",
            state={"generation_phase": "reviewable"})

        self.assertNotEqual("execute", decision["intent"])
        self.assertNotIn(
            control["relation"],
            {"start-exact", "continue-active", "repair-active", "supersede-generation"},
        )

    def test_plan_only_equivalents_ignore_descriptive_build_verbs(self):
        """Break caught: harmless wording changes alter lifecycle authority."""
        requests = [
            "Create a local tracker. Plan the work only; do not implement.",
            "Plan only, and do not implement, a local tracker I want to build.",
            "Design a local tracker, but only produce the plan. Do not execute it.",
            "Please make a plan for creating a local tracker. No implementation yet.",
        ]

        decisions = [loom_runtime.resolve_intent(value) for value in requests]

        self.assertTrue(all(not item["blocked"] for item in decisions), decisions)
        self.assertEqual({"plan"}, {item["intent"] for item in decisions})

    def test_replacement_plan_only_equivalents_remain_planning_controls(self):
        """Break caught: plan modifiers turn a planning request into implementation."""
        requests = [
            "Create and present a fresh replacement plan. Do not implement.",
            "Create a tracker, but only produce a fresh replacement plan. "
            "Do not implement.",
            "Prepare an updated superseding plan only; do not execute it.",
        ]

        decisions = [loom_runtime.resolve_intent(value) for value in requests]

        self.assertTrue(all(not item["blocked"] for item in decisions), decisions)
        self.assertEqual({"plan"}, {item["intent"] for item in decisions})

    def test_reviewable_explicit_replacement_plan_is_a_supersession(self):
        """Break caught: explicit replacement authority degrades to an unclear relation."""
        control = loom_runtime.request_control(
            "Create and present a fresh replacement plan reviewed against the "
            "current world, explicitly superseding the stale unstarted plan "
            "generation. Do not implement.",
            state={"generation_phase": "reviewable"},
        )

        self.assertFalse(control["blocked"])
        self.assertEqual("plan", control["primary_operation"])
        self.assertEqual("supersede-generation", control["relation"])
        self.assertEqual(["implementation"], control["prohibitions"])
        self.assertIn("explicit-supersession", control["evidence"])

    def test_negated_replacement_plan_does_not_authorize_supersession(self):
        """Break caught: a negated plan request becomes lifecycle authority."""
        for request in (
                "Do not create a replacement plan.",
                "Never present a replacement plan."):
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})

                self.assertNotEqual("supersede-generation", control["relation"])
                self.assertNotIn("explicit-supersession", control["evidence"])

    def test_real_plan_and_implementation_contradiction_still_blocks(self):
        """Break caught: parser improvement accidentally makes authority permissive."""
        decision = loom_runtime.resolve_intent(
            "Plan only and do not implement, but also implement the project now.")

        self.assertTrue(decision["blocked"])
        self.assertEqual("INTENT_AMBIGUOUS", decision["code"])

    def test_structured_control_preserves_explicit_new_relation_after_terminal_history(self):
        """Break caught: terminal history silently rewrites new work as repair."""
        control = loom_runtime.request_control(
            "This is a new standalone feature action, not a repair or continuation. "
            "Add export support.",
            state={"generation_phase": "terminal-completed"},
        )

        self.assertFalse(control["blocked"])
        self.assertEqual("plan", control["primary_operation"])
        self.assertEqual("new", control["relation"])
        self.assertIn("repair", control["prohibitions"])
        self.assertIn("continuation", control["prohibitions"])
        self.assertNotIn("standalone feature", json.dumps(control))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "request-control-v1.schema.json", control,
            "request-control-v1.schema.json")
        self.assertEqual([], report.errors)

    def test_active_unqualified_mutation_requires_typed_owner_choice(self):
        """Break caught: unclear work attaches to an active generation by guessing."""
        control = loom_runtime.request_control(
            "Add export support.",
            state={"generation_phase": "active"},
        )

        self.assertTrue(control["blocked"])
        self.assertEqual("unclear", control["relation"])
        self.assertEqual("RELATION_REQUIRES_OWNER", control["block_reason"])

    def test_active_explicit_new_work_becomes_an_explicit_supersession(self):
        """Break caught: explicit new work has no legal active-state relation."""
        control = loom_runtime.request_control(
            "This is a new standalone feature action, not a repair or continuation.",
            state={"generation_phase": "active"},
        )

        self.assertFalse(control["blocked"])
        self.assertEqual("supersede-generation", control["relation"])

    def test_lifecycle_policy_never_silently_rewrites_drift_to_repair(self):
        def route(intent):
            return {
                "intent": intent, "blocked": False, "code": "ROUTED",
                "needs_owner": False, "confidence": 1.0,
                "recommendation": "", "evidence": [],
            }

        terminal_new = loom_runtime._apply_lifecycle_request_policy(
            route("plan"), {
                "generation_phase": "terminal-completed",
                "state_error": "STALE_LIFECYCLE",
            }, loom_runtime.request_control(
                "Add a new standalone feature, not a repair.",
                state={"generation_phase": "terminal-completed"}))
        active_continue = loom_runtime._apply_lifecycle_request_policy(
            route("execute"), {
                "generation_phase": "active",
                "state_error": "STALE_LIFECYCLE",
            }, loom_runtime.request_control(
                "Continue the active work.",
                state={"generation_phase": "active"}))
        active_repair = loom_runtime._apply_lifecycle_request_policy(
            route("repair"), {
                "generation_phase": "active",
                "state_error": "STALE_LIFECYCLE",
            }, loom_runtime.request_control(
                "Repair the drifted active plan.",
                state={"generation_phase": "active"}))

        self.assertEqual("plan", terminal_new["intent"])
        self.assertFalse(terminal_new["blocked"])
        self.assertNotEqual("AUTO_REGATE_REQUIRED", terminal_new["code"])
        self.assertEqual("execute", active_continue["intent"])
        self.assertTrue(active_continue["blocked"])
        self.assertEqual("ACTIVE_WORLD_CHANGED", active_continue["code"])
        self.assertEqual("repair", active_repair["intent"])
        self.assertFalse(active_repair["blocked"])

    def test_host_bound_start_bypasses_free_text_reclassification(self):
        """Break caught: exact start authority is reinterpreted as ordinary prose."""
        control = loom_runtime.request_control(
            "arbitrary display text",
            state={"generation_phase": "reviewable"},
            host_control={
                "primary_operation": "execute",
                "relation": "start-exact",
            },
        )

        self.assertFalse(control["blocked"])
        self.assertEqual("host-bound", control["explicitness"])
        self.assertEqual("start-exact", control["relation"])

    def test_request_control_is_closed_and_self_bound(self):
        """Break caught: sealed actions can carry a reinterpreted lifecycle relation."""
        control = loom_runtime.request_control(
            "Start this exact approved plan.",
            state={"generation_phase": "reviewable"},
            host_control={
                "primary_operation": "execute",
                "relation": "start-exact",
            },
        )

        self.assertIs(control, loom_runtime.validate_request_control(control))
        control["relation"] = "repair-active"
        with self.assertRaises(loom_runtime.RuntimeError):
            loom_runtime.validate_request_control(control)

    def test_structured_policy_rejects_relations_that_have_no_state_target(self):
        """Break caught: continuation can silently turn into fresh planning."""
        route = {
            "intent": "execute", "blocked": False, "code": "ROUTED",
            "needs_owner": False, "confidence": 1.0,
            "recommendation": "", "evidence": [],
        }
        cases = (
            ("absent", "execute", "continue-active", "NO_ACTIVE_GENERATION"),
            ("reviewable", "recover", "repair-active", "GENERATION_NOT_ACTIVE"),
            ("active", "plan", "revise-exact",
             "PLAN_REVISION_REQUIRES_SUPERSESSION"),
            ("terminal-completed", "cancel", "cancel-generation",
             "GENERATION_TERMINAL"),
        )
        for phase, operation, relation, code in cases:
            with self.subTest(phase=phase, relation=relation):
                control = loom_runtime.request_control(
                    "host display text", state={"generation_phase": phase},
                    host_control={
                        "primary_operation": operation,
                        "relation": relation,
                    })
                result = loom_runtime._apply_lifecycle_request_policy(
                    route, {"generation_phase": phase}, control)
                self.assertTrue(result["blocked"])
                self.assertEqual(code, result["code"])

    def test_explicit_quarantine_request_has_one_closed_recovery_relation(self):
        """Break caught: invalid store recovery depends on an internal shortcut."""
        control = loom_runtime.request_control(
            "Quarantine this invalid blocking Loom plan store without interpreting it.")

        self.assertFalse(control["blocked"])
        self.assertEqual("recover", control["primary_operation"])
        self.assertEqual("quarantine-generation", control["relation"])
        self.assertEqual("explicit", control["explicitness"])
        self.assertNotIn("invalid blocking Loom plan store", json.dumps(control))

    def test_read_only_audit_accepts_a_natural_mutation_prohibition(self):
        """Break caught: 'make no changes' is misread as positive implementation."""
        requests = (
            "Audit the completed project only; make no changes.",
            "Make no changes; please inspect the completed project read-only.",
            "Review the historical result, but do not modify any files.",
        )

        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request)
                control = loom_runtime.request_control(
                    request,
                    state={"generation_phase": "terminal-completed"})
                self.assertFalse(decision["blocked"], decision)
                self.assertEqual("review", decision["intent"])
                self.assertFalse(control["blocked"], control)
                self.assertEqual("read-only", control["relation"])
                self.assertIn("mutation", control["prohibitions"])

    def test_new_standalone_relation_survives_domain_specific_nouns(self):
        """A noun between 'standalone' and 'work' cannot erase explicit new authority."""
        requests = (
            "Create fresh standalone backup work; do not continue the old action.",
            "Plan new standalone schema migration work, not a repair.",
            "Prepare a fresh standalone accessibility task, not a continuation.",
        )

        for request in requests:
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request,
                    state={"generation_phase": "terminal-completed"})
                self.assertFalse(control["blocked"], control)
                self.assertEqual("new", control["relation"])

    def test_exact_revision_and_execution_prohibition_are_compatible_controls(self):
        """Reviewing a revised plan does not authorize its implementation."""
        requests = (
            "Revise this exact reviewed plan; do not implement.",
            "Do not implement. Please revise the approved plan exactly.",
            "Revise the reviewed exact plan only, with no implementation.",
        )

        for request in requests:
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})
                self.assertFalse(control["blocked"], control)
                self.assertEqual("plan", control["primary_operation"])
                self.assertEqual("revise-exact", control["relation"])
                self.assertIn("implementation", control["prohibitions"])

    def test_free_text_exact_controls_require_the_host_bound_plan_reference(self):
        """Natural wording proposes a relation but cannot invent exact-plan identity."""
        cases = (
            ("Start this exact approved plan.", "reviewable", "execute"),
            ("Please begin the reviewed exact plan.", "reviewable", "execute"),
            ("Revise the approved plan exactly.", "reviewable", "plan"),
        )
        for request, phase, operation in cases:
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request, state={"generation_phase": phase})
                route = loom_runtime.resolve_intent(request)
                result = loom_runtime._apply_lifecycle_request_policy(
                    route, {"generation_phase": phase}, control)
                self.assertEqual(operation, control["primary_operation"])
                self.assertTrue(result["blocked"], result)
                self.assertEqual("EXACT_PLAN_REFERENCE_REQUIRED", result["code"])

    def test_materially_different_owner_requests_keep_one_closed_lifecycle_relation(self):
        """Project nouns and clause order cannot silently change lifecycle authority."""
        cases = (
            (
                "After prior completion, plan fresh standalone backup and restore work; "
                "do not continue the old action.",
                "terminal-completed", "plan", "new", (),
            ),
            (
                "This does not repair prior work. Create a new standalone database "
                "schema evolution task.",
                "terminal-completed", "plan", "new", ("repair",),
            ),
            (
                "Please continue the currently active plan.",
                "active", "execute", "continue-active", (),
            ),
            (
                "Fix the drift in the active generation; this is a repair.",
                "active", "recover", "repair-active", (),
            ),
            (
                "Without modifying files, verify the archived completion evidence.",
                "terminal-completed", "review", "read-only", ("mutation",),
            ),
            (
                "Cancel this reviewed generation.",
                "reviewable", "cancel", "cancel-generation", (),
            ),
        )

        for request, phase, operation, relation, prohibitions in cases:
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request, state={"generation_phase": phase})
                self.assertFalse(control["blocked"], control)
                self.assertEqual(operation, control["primary_operation"])
                self.assertEqual(relation, control["relation"])
                for prohibition in prohibitions:
                    self.assertIn(prohibition, control["prohibitions"])
                self.assertNotIn(request.casefold(), json.dumps(control).casefold())


if __name__ == "__main__":
    unittest.main()
