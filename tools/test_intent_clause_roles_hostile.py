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
    def assertRoute(self, request, *, intent, blocked, code, state=None):
        decision = loom_runtime.resolve_intent(request, dict(state or {}))
        repeated = loom_runtime.resolve_intent(request, dict(state or {}))
        self.assertEqual(decision, repeated, request)
        self.assertEqual(intent, decision["intent"], request)
        self.assertIs(blocked, decision["blocked"], request)
        self.assertEqual(code, decision["code"], request)
        self.assertIs(blocked, decision["needs_owner"], request)
        if blocked:
            self.assertIsNotNone(decision["block_reason"], request)
        else:
            self.assertIsNone(decision["block_reason"], request)
        for field in loom_runtime.EFFECT_COUNT_FIELDS:
            self.assertEqual(0, decision[field], f"{request}: {field}")
        return decision

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
            "Implement and do not implement the bridge.",
        ]
        for request in requests:
            with self.subTest(request=request):
                self.assertRoute(
                    request, intent="status", blocked=True,
                    code="INTENT_AMBIGUOUS", state=DRIFTED_STATE)

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
