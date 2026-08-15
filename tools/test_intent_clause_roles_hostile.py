#!/usr/bin/env python3
"""Adversarial clause-role corpus for deterministic, no-effect intent routing."""

import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_runtime  # noqa: E402


AUTHORIZED_STATE = {
    "pack_exists": True,
    "authorized": True,
    "active_frontier": True,
}
DRIFTED_STATE = {
    "pack_exists": True,
    "authorized": True,
    "active_frontier": True,
    "drift": True,
}


class IntentClauseRolesHostileTests(unittest.TestCase):
    def assertRoute(
            self, request, *, intent, blocked, code, state=None,
            needs_owner=None):
        decision = loom_runtime.resolve_intent(request, dict(state or {}))
        repeated = loom_runtime.resolve_intent(request, dict(state or {}))
        self.assertEqual(decision, repeated, request)
        self.assertEqual(intent, decision["intent"], request)
        self.assertIs(blocked, decision["blocked"], request)
        self.assertEqual(code, decision["code"], request)
        self.assertIs(
            blocked if needs_owner is None else needs_owner,
            decision["needs_owner"], request)
        if blocked:
            self.assertIsNotNone(decision["block_reason"], request)
        else:
            self.assertIsNone(decision["block_reason"], request)
        for field in loom_runtime.EFFECT_COUNT_FIELDS:
            self.assertEqual(0, decision[field], f"{request}: {field}")
        return decision

    def assertNonAuthorizingPlan(
            self, request, *, code, needs_owner, evidence, state=None):
        decision = self.assertRoute(
            request, intent="plan", blocked=False, code=code, state=state,
            needs_owner=needs_owner)
        self.assertEqual(evidence, decision["evidence"], request)
        self.assertEqual(
            1 if needs_owner else 0,
            decision["recommendation"].count("?"), request)
        control = loom_runtime.request_control(request, state=dict(state or {}))
        self.assertEqual("plan", control["primary_operation"], request)
        self.assertEqual("new", control["relation"], request)
        self.assertFalse(control["blocked"], request)
        self.assertIn("implementation", control["prohibitions"], request)
        return decision, control

    def test_explanation_with_no_write_constraint_routes_to_why(self):
        self.assertRoute(
            "Explain why Loom chose this plan route and what it authorized. "
            "Do not change project files.",
            intent="why", blocked=False, code="ROUTE_WHY",
            state=AUTHORIZED_STATE)

    def test_status_and_why_is_one_read_only_transparency_request(self):
        for request in (
                "Show me the current status and explain why.",
                "What is the status and why did Loom choose it?",
                "Status and why, please.",
                (
                    "Report the current Loom action status for this project and explain "
                    "why it is in that state. Do not create or modify a plan."
                )):
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="status", blocked=False, code="ROUTE_STATUS",
                    state=AUTHORIZED_STATE)

    def test_each_true_negation_blocks_without_authorizing_its_opposite(self):
        cases = [
            ("Do not remember this preference.", {}),
            ("Do not forget this preference.", {}),
            ("Do not repair the stale plan.", DRIFTED_STATE),
            ("Don't fix the broken plan.", DRIFTED_STATE),
            ("Never resume the current plan.", AUTHORIZED_STATE),
            ("Do not build the next phase.", {}),
            ("Do not implement this change.", {}),
        ]
        for request, state in cases:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="status", blocked=True,
                    code="INTENT_NEGATED", state=state)

    def test_do_not_want_you_to_negates_every_control_family(self):
        cases = [
            ("I do not want you to remember this preference.", {}),
            ("I do not want you to forget this preference.", {}),
            ("I do not want you to repair the stale plan.", DRIFTED_STATE),
            ("I do not want you to fix the broken plan.", DRIFTED_STATE),
            ("I do not want you to resume the current plan.", AUTHORIZED_STATE),
            ("I do not want you to build the next phase.", {}),
            ("I do not want you to implement this change.", {}),
        ]
        for request, state in cases:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="status", blocked=True,
                    code="INTENT_NEGATED", state=state)

    def test_positive_build_clause_survives_a_separate_prohibition(self):
        requests = [
            "Do not remember this request, implement the bridge.",
            "Implement the bridge, and do not remember this request.",
            "Do not remember this request; implement the bridge.",
            "Implement the bridge; do not remember this request.",
            "Do not remember this request.\nImplement the bridge.",
            "Implement the bridge.\nDo not remember this request.",
            "Do not remember this request; then implement the bridge.",
            "Implement the bridge, but do not remember this request.",
            "Do not repair the stale plan, but implement the bridge.",
            "Implement the bridge, and do not repair the stale plan.",
            "I do not want you to remember this request; implement the bridge.",
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="plan", blocked=False, code="ROUTE_PLAN",
                    state=DRIFTED_STATE)

    def test_planning_only_is_not_confused_with_implementation_authority(self):
        requests = [
            "Plan a tiny Python CLI. Do not implement it.",
            "/loom Plan a tiny Python CLI. Do not implement it.",
            "Plan a tiny Python CLI; do not implement.",
            "Plan a tiny Python CLI, and do not implement it.",
            "Plan a tiny Python CLI and do not implement it.",
            (
                "Plan a tiny Python CLI greeter that accepts a name and prints "
                "Hello, <name>!, with one standard-library unittest. "
                "Planning only; do not implement."
            ),
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_review_as_method_for_a_plan_is_not_a_review_lifecycle_operation(self):
        requests = [
            (
                "Review this small research write-up project and produce a "
                "reviewable plan for developing the evidence-based briefing. "
                "Use the notes and identify evidence gaps. Do not implement the "
                "plan, publish anything, or modify files outside this project."
            ),
            (
                "Review the current README and create an implementation plan for "
                "a clearer usage section. Do not change the README."
            ),
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_long_domain_checklists_do_not_exhaust_the_control_clause_budget(self):
        request = (
            "Create exactly one implementation plan, and no other outcome, for a "
            "browser-based real-time 3D room configurator in this repository. "
            "The plan must cover spatial selection, placement, dragging, rotation, "
            "snapping, collision and room-boundary behavior; explicit world, model, "
            "room, camera, screen, and raycast coordinate conversions with units and "
            "axis conventions; frame-time, draw-call, triangle, texture-memory, "
            "load-time, and bundle budgets by device class; a glTF/GLB asset pipeline "
            "with validation, compression, LODs, materials, pivots, bounds, metadata, "
            "and CDN/cache policy; deterministic visual verification using reference "
            "scenes, screenshots, interaction checks, performance traces, and tolerance "
            "rules; and graceful fallbacks including quality tiers and a usable non-3D "
            "product-selection path. Define sequencing, ownership boundaries, acceptance "
            "evidence, risks, and failure handling. Preserve the existing metric "
            "room-dimension contract and Y-up convention. Prohibitions: do not implement, "
            "add dependencies, change repository files, deploy, publish, or introduce "
            "rules unrelated to this configurator."
        )

        self.assertRoute(
            request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_multisection_program_scope_does_not_exhaust_the_control_clause_budget(self):
        scope = "\n".join(
            f"Build bounded subsystem {index}, define its data contract, document "
            "failure behavior, prove recovery, and specify acceptance evidence."
            for index in range(1, 41))
        request = (
            "Plan one reviewable, implementation-ready multi-year software program.\n"
            f"{scope}\n"
            "Do not implement source code, publish, deploy, install, contact external "
            "services, or modify files outside the disposable planning project."
        )

        self.assertGreater(len(request.splitlines()), loom_runtime.MAX_ROUTE_CLAUSES)
        self.assertRoute(
            request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_maximal_plan_treats_inspection_and_reporting_as_acceptance_methods(self):
        request = (
            "Plan the largest realistic production project Loom can support. "
            "Treat this as a genuine high-consequence, multi-year product program. "
            "The plan must be reviewable and implementation-ready, with architecture, "
            "data model, bounded work orders, dependency graph, expected touch paths, "
            "acceptance evidence, real verification media, rollback and recovery, "
            "security and privacy boundaries, unknowns, assumptions, explicit non-goals, "
            "staged releases, migration strategy, operational ownership, and measurable "
            "completion criteria. Inspect only what is necessary and bounded. "
            "This is also a Loom stress test. Follow Loom's installed contract exactly. "
            "Preserve and report every observable Loom status, refusal, timeout, "
            "validation error, generated artifact, owner message, elapsed-time signal, "
            "and lifecycle stage. Do not implement source code, publish, deploy, install, "
            "contact external services, or write outside this disposable test project."
        )

        clauses, overflow = loom_runtime._split_control_clauses(request)
        self.assertFalse(overflow)
        self.assertNotIn(
            "status",
            {loom_runtime._classify_control_clause(clause)["intent"]
             for _separator, clause in clauses})
        self.assertRoute(
            request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_explicit_plan_and_separate_current_status_request_remain_ambiguous(self):
        decision = self.assertRoute(
            "Plan the new API. Report the current Loom status.",
            intent="status", blocked=True, code="INTENT_AMBIGUOUS")

        self.assertIn("positive:plan/planning", decision["evidence"])
        self.assertIn("positive:status/status", decision["evidence"])
        self.assertIn(
            "plan/planning, status/status",
            decision["block_reason"]["observed"])

    def test_true_control_clause_overflow_names_the_limit_and_exact_recovery(self):
        request = "\n".join(
            f"Plan independent product {index}." for index in range(1, 19))

        decision = self.assertRoute(
            request, intent="status", blocked=True, code="INTENT_AMBIGUOUS")

        self.assertEqual(["clause-limit"], decision["evidence"])
        self.assertIn("16", decision["block_reason"]["observed"])
        self.assertIn("separate Loom actions",
                      decision["block_reason"]["observed"])
        self.assertIn("one positive action",
                      decision["block_reason"]["next_action"])
        self.assertIn("descriptive bullets",
                      decision["block_reason"]["next_action"])

    def test_detailed_plan_with_semicolon_prohibitions_remains_planning(self):
        request = (
            "Create one detailed implementation plan, and only a plan, for a "
            "real-time 3D room configurator. The plan must cover spatial selection, "
            "placement, dragging, rotation, snapping, collision and room-boundary "
            "behavior; explicit world, model, room, camera, screen, and raycast "
            "coordinate conversions; frame-time, draw-call, triangle, texture-memory, "
            "load-time, and bundle budgets; a glTF/GLB asset pipeline; deterministic "
            "visual verification; and graceful fallbacks. Explicit prohibitions: do "
            "not implement code; do not modify files; do not install dependencies; "
            "do not run builds, tests, benchmarks, profilers, or external research; "
            "do not commit, push, deploy, publish, or delete anything. These "
            "prohibitions are constraints, not contradictory outcomes."
        )

        self.assertRoute(
            request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_plan_deliverable_modifiers_do_not_create_implementation_authority(self):
        requests = [
            "Create one detailed implementation plan. Do not implement code.",
            "Create a detailed coding plan. Explicit prohibition: do not modify files.",
            "Draft only one release-ready implementation plan; do not implement it.",
            "Write the implementation plan. Explicit constraints: do not run tests.",
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_explicit_prohibition_without_positive_outcome_still_blocks(self):
        self.assertRoute(
            "Explicit prohibitions: do not implement code; do not modify files.",
            intent="status", blocked=True, code="INTENT_NEGATED")

    def test_implementation_request_and_implementation_prohibition_conflict(self):
        cases = [
            (
                "Implement the bridge. Do not implement the bridge.",
                "PLAN_EXECUTION_CONTRADICTION", True,
                ["plan-execution-contradiction", "implementation-prohibited"],
            ),
            (
                "Build a CLI; do not implement it.",
                "ROUTE_PLAN", False, ["role:plan", "role:prohibition"],
            ),
            (
                "Create the application and do not implement it.",
                "ROUTE_PLAN", False, ["role:plan", "role:prohibition"],
            ),
        ]
        for request, code, needs_owner, evidence in cases:
            with self.subTest(request=request):
                self.assertNonAuthorizingPlan(
                    request, code=code, needs_owner=needs_owner,
                    evidence=evidence)

    def test_positive_repair_clause_survives_a_separate_memory_prohibition(self):
        requests = [
            "Fix the stale plan; do not remember this request.",
            "Do not remember this request; then fix the stale plan.",
            "Repair the stale plan, but do not remember this request.",
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="repair", blocked=False,
                    code="ROUTE_REPAIR", state=DRIFTED_STATE)

    def test_genuinely_ambiguous_coordination_blocks_once(self):
        requests = [
            "Either repair the stale plan or implement the bridge.",
            "Implement the bridge or repair the stale plan.",
            "Remember that I prefer concise reports and implement the bridge.",
            "Forget this preference and repair the stale plan.",
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="status", blocked=True,
                    code="INTENT_AMBIGUOUS", state=DRIFTED_STATE)
        self.assertNonAuthorizingPlan(
            "Implement and do not implement the bridge.",
            code="PLAN_EXECUTION_CONTRADICTION", needs_owner=True,
            evidence=[
                "plan-execution-contradiction", "implementation-prohibited"],
            state=DRIFTED_STATE)

    def test_durable_preferences_remain_memory_operations(self):
        requests = [
            "Remember that I prefer process isolation for future projects.",
            "I prefer careful review from now on.",
            "Correct what you learned: I prefer concise reports.",
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="remember", blocked=False,
                    code="ROUTE_REMEMBER")

    def test_task_local_preferences_and_corrections_remain_plan_constraints(self):
        requests = [
            "Prefer process isolation while implementing the request transport.",
            "Implement the bridge; prefer process isolation for this task.",
            "Use concise reports for this task; then implement the bridge.",
            "Correct the failing transport test and implement the bridge.",
            (
                "Do not remember this as a preference; use process isolation for this "
                "task; then implement the bridge."
            ),
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="plan", blocked=False, code="ROUTE_PLAN")

    def test_positive_memory_and_repair_controls_still_work(self):
        self.assertRoute(
            "Forget the obsolete preference.", intent="forget", blocked=False,
            code="ROUTE_FORGET")
        self.assertRoute(
            "Fix the stale plan.", intent="repair", blocked=False,
            code="ROUTE_REPAIR", state=DRIFTED_STATE)
        self.assertRoute(
            "Resume the current plan.", intent="execute", blocked=False,
            code="ROUTE_EXECUTE", state=AUTHORIZED_STATE)


if __name__ == "__main__":
    unittest.main()
