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
        self.assertEqual(0, decision["routine_question_count"])
        self.assertEqual(1, decision["recommendation"].count("?"))
        self.assertTrue(decision["recommendation"].strip())

    def test_descriptive_build_with_implementation_prohibition_is_planning(self):
        """Break caught: a project-description verb becomes execution authority."""
        decision = loom_runtime.resolve_intent(
            "Build a tracker. Do not implement.")

        self.assertFalse(decision["blocked"], decision)
        self.assertEqual("plan", decision["intent"])
        self.assertFalse(decision["needs_owner"], decision)

    def test_execution_and_execution_prohibition_is_one_provisional_plan(self):
        """Break caught: a contradiction without 'plan' dead-ends or executes."""
        requests = (
            "Implement now and do not implement anything.",
            "Execute now and do not execute anything.",
            "Start implementation now and do not start anything.",
        )

        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request)
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "absent"})

                self.assertFalse(decision["blocked"], decision)
                self.assertEqual("plan", decision["intent"])
                self.assertTrue(decision["needs_owner"], decision)
                self.assertEqual(0, decision["routine_question_count"])
                self.assertEqual(1, decision["recommendation"].count("?"))
                self.assertEqual("plan", control["primary_operation"])
                self.assertEqual("new", control["relation"])
                self.assertIn("implementation", control["prohibitions"])

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

    def test_inert_lifecycle_language_never_materializes_a_successor(self):
        """Break caught: inert lifecycle vocabulary becomes a persistent plan."""
        requests = (
            (
                "Explain what a replacement plan would look like without creating "
                "one. Keep the current plan unchanged.",
                "hypothetical",
            ),
            (
                "If I later asked for a different architecture, what would Loom do? "
                "Do not change the current plan.",
                "hypothetical",
            ),
            (
                "What would Loom do if I asked for a new plan later? Keep the "
                "current plan unchanged.",
                "hypothetical-interrogative",
            ),
            (
                "What if we created a replacement plan someday? Do not change "
                "anything.",
                "hypothetical-conditional",
            ),
            (
                "Could a replacement plan be created later? Keep the current plan "
                "unchanged.",
                "hypothetical-passive",
            ),
            (
                'The reviewer wrote "Create a fresh replacement plan." Explain '
                "whether that would be safe; do not act on the quote.",
                "quoted",
            ),
            (
                "The incident report says the owner requested a fresh replacement "
                "plan. Summarize the report only; make no changes.",
                "reported",
            ),
            (
                "The reviewer asks whether a new plan would help. Summarize that "
                "question only.",
                "reported-interrogative",
            ),
            (
                "Do not revise, replace, or create a new plan. Show the current plan.",
                "negative",
            ),
        )

        for request, semantic_scope in requests:
            with self.subTest(scope=semantic_scope):
                decision = loom_runtime.resolve_intent(request)
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})

                self.assertFalse(decision["blocked"], decision)
                self.assertIn(decision["intent"], {"review", "status", "why"})
                self.assertFalse(control["blocked"], control)
                self.assertIn(
                    control["primary_operation"], {"review", "status"})
                self.assertEqual("read-only", control["relation"])
                self.assertFalse(any(
                    item.startswith("planning-")
                    for item in control["evidence"]))
                self.assertNotIn("explicit-supersession", control["evidence"])

    def test_auxiliary_or_unknown_assistance_is_non_authorizing(self):
        """Break caught: an unproved assistance request inherits planning authority."""
        requests = (
            "Can you explain what replacing the plan would do?",
            "Would you compare the current plan with another architecture?",
            "Could you show what a different plan might contain?",
            "Could this be simpler?",
            "What about a different architecture?",
        )

        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request)
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})

                self.assertFalse(decision["blocked"], decision)
                self.assertIn(decision["intent"], {"review", "status", "why"})
                self.assertFalse(control["blocked"], control)
                self.assertIn(control["primary_operation"], {"review", "status"})
                self.assertEqual("read-only", control["relation"])
                self.assertFalse(any(
                    item.startswith("planning-") for item in control["evidence"]))

    def test_arbitrary_quoted_or_reported_speaker_cannot_mint_plan_authority(self):
        """Break caught: speaker names or quote punctuation leak reported authority."""
        requests = (
            'Morgan wrote, "Create a new plan." Explain the implications.',
            "Morgan wrote, “Create a new plan.” Explain the implications.",
            "A build log says: create a replacement plan. Summarize it.",
            "The note contains `Create a replacement plan.` Please summarize it.",
            'Morgan wrote, "Create a new plan. Explain the implications.',
        )

        for request in requests:
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})

                self.assertFalse(control["blocked"], control)
                self.assertIn(control["primary_operation"], {"review", "status"})
                self.assertEqual("read-only", control["relation"])
                self.assertFalse(any(
                    item.startswith("planning-") for item in control["evidence"]))

    def test_product_approach_constraint_does_not_negate_direct_feature_plan(self):
        """Break caught: a product noun is mistaken for lifecycle-plan authority."""
        control = loom_runtime.request_control(
            "Keep the migration approach unchanged and add CSV export.",
            state={"generation_phase": "reviewable"})
        read_only = loom_runtime.request_control(
            "Keep the current reviewed plan unchanged; explain CSV export options.",
            state={"generation_phase": "reviewable"})

        self.assertFalse(control["blocked"], control)
        self.assertEqual("plan", control["primary_operation"])
        self.assertEqual("supersede-generation", control["relation"])
        self.assertIn("planning-candidate-successor", control["evidence"])
        self.assertFalse(read_only["blocked"], read_only)
        self.assertEqual("read-only", read_only["relation"])

    def test_true_plan_materialization_contradiction_requests_clarification(self):
        """Break caught: contradictory authority silently creates a candidate."""
        requests = (
            "Create a new plan now. Do not create, revise, or replace the current plan.",
            "Create a new plan, but do not create or replace the current plan.",
            "Please create a new plan and do not create a new plan.",
            "Create a new plan, but do not replace the plan.",
            "Create a new plan. Don't change the plan.",
        )

        for request in requests:
            with self.subTest(request=request):
                decision = loom_runtime.resolve_intent(request)
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})

                self.assertTrue(decision["blocked"], decision)
                self.assertEqual("INTENT_AMBIGUOUS", decision["code"])
                self.assertTrue(control["blocked"], control)
                self.assertEqual("unclear", control["relation"])
                self.assertFalse(any(
                    item.startswith("planning-") for item in control["evidence"]))

    def test_direct_planning_survives_inert_context_and_implementation_negation(self):
        """Break caught: semantic scoping suppresses a separate direct plan command."""
        requests = (
            "Use a different architecture for this project now.",
            (
                'The reviewer wrote "Create a replacement plan." Now make that the '
                "new direction for this project."),
            "Plan a local tracker; do not implement it.",
        )

        for request in requests:
            with self.subTest(request=request):
                control = loom_runtime.request_control(
                    request, state={"generation_phase": "reviewable"})

                self.assertFalse(control["blocked"], control)
                self.assertEqual("plan", control["primary_operation"])
                self.assertEqual("supersede-generation", control["relation"])
                self.assertTrue(any(
                    item.startswith("planning-") for item in control["evidence"]))

    def test_real_plan_and_implementation_contradiction_stays_provisional(self):
        """Break caught: a contradiction blocks planning or authorizes execution."""
        decision = loom_runtime.resolve_intent(
            "Plan only and do not implement, but also implement the project now.")

        self.assertFalse(decision["blocked"], decision)
        self.assertEqual("plan", decision["intent"])
        self.assertTrue(decision["needs_owner"], decision)
        self.assertEqual(0, decision["routine_question_count"])
        self.assertEqual(1, decision["recommendation"].count("?"))
        self.assertTrue(decision["recommendation"].strip())

    def test_polite_audit_question_keeps_route_and_control_read_only(self):
        """Break caught: question grammar hides a direct read-only audit control."""
        request = "Could you audit the completed project?"
        decision = loom_runtime.resolve_intent(request)
        control = loom_runtime.request_control(
            request, state={"generation_phase": "terminal-completed"})
        noun_control = loom_runtime.request_control(
            "Could you build an audit dashboard?",
            state={"generation_phase": "absent"})

        self.assertFalse(decision["blocked"], decision)
        self.assertEqual("review", decision["intent"])
        self.assertEqual("review", control["primary_operation"])
        self.assertEqual("read-only", control["relation"])
        self.assertEqual("plan", noun_control["primary_operation"])

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

    def test_active_unqualified_change_defaults_to_a_candidate_plan(self):
        """Break caught: an ordinary planning request dead-ends on active history."""
        control = loom_runtime.request_control(
            "Add export support.",
            state={"generation_phase": "active"},
        )

        self.assertFalse(control["blocked"], control)
        self.assertEqual("plan", control["primary_operation"])
        self.assertEqual("supersede-generation", control["relation"])
        self.assertIsNone(control["block_reason"])

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
