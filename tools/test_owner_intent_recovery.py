"""Owner-visible recovery routing across lifecycle conditions."""

import dataclasses
import inspect
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_lint
import loom_owner_intent
import loom_runtime


class OwnerIntentRecoveryTests(unittest.TestCase):
    PLANNING_REQUEST = (
        "Draft an approach for a minor warehouse barcode label adjustment. "
        "This is for review, not implementation.")

    def test_planning_disposition_has_one_pure_closed_call_surface(self):
        """Break caught: raw wording or an effectful dependency enters disposition."""
        signature = inspect.signature(
            loom_owner_intent.resolve_planning_disposition)

        self.assertEqual(
            [
                "primary_operation", "generation_phase", "state_error",
                "prohibitions", "exact_reference",
            ],
            list(signature.parameters),
        )
        self.assertTrue(all(
            parameter.kind is inspect.Parameter.KEYWORD_ONLY
            for parameter in signature.parameters.values()))
        self.assertEqual(
            {"Sequence", "dataclass"},
            {
                name for name in loom_owner_intent.__dict__
                if name in {
                    "Sequence", "dataclass", "os", "pathlib", "subprocess",
                    "sqlite3", "loom_runtime", "loom_orchestrator",
                }
            },
        )

    def test_planning_disposition_is_frozen_and_closed(self):
        """Break caught: an invalid relation or mode can escape the pure boundary."""
        value = loom_owner_intent.PlanningDisposition(
            relation="new",
            mode="direct",
            preserve_current=False,
            reason_code="DIRECT_PLAN",
        )

        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.mode = "inline-recovery"
        for field, invalid in (
                ("relation", "invented-relation"),
                ("relation", []),
                ("mode", "invented-mode"),
                ("mode", [])):
            with self.subTest(field=field):
                arguments = {
                    "relation": "new",
                    "mode": "direct",
                    "preserve_current": False,
                    "reason_code": "DIRECT_PLAN",
                }
                arguments[field] = invalid
                with self.assertRaises(ValueError):
                    loom_owner_intent.PlanningDisposition(**arguments)

    def test_planning_disposition_uses_the_closed_state_matrix(self):
        """Break caught: prompt-independent planning selects the wrong state mode."""
        cases = (
            ("absent", None, None, (), "new", "direct", False),
            ("reviewable", "reviewable", None, (),
             "supersede-generation", "candidate-successor", True),
            ("active", "active", None, (),
             "supersede-generation", "candidate-successor", True),
            ("terminal", "terminal-completed", None, (),
             "new", "direct", False),
            ("stale-reviewable", "reviewable", "STALE_LIFECYCLE", (),
             "supersede-generation", "current-world-replan", True),
            ("stale-active", "active", "STALE_TIME", (),
             "supersede-generation", "current-world-replan", True),
            ("invalid", "invalid", "INVALID_LIFECYCLE", (),
             "unclear", "inline-recovery", True),
            ("writes-prohibited", "reviewable", None, ("mutation",),
             "unclear", "inline-recovery", True),
        )

        for name, phase, error, prohibitions, relation, mode, preserve in cases:
            with self.subTest(state=name):
                disposition = loom_owner_intent.resolve_planning_disposition(
                    primary_operation="plan",
                    generation_phase=phase,
                    state_error=error,
                    prohibitions=prohibitions,
                    exact_reference=False,
                )
                self.assertEqual(relation, disposition.relation)
                self.assertEqual(mode, disposition.mode)
                self.assertEqual(preserve, disposition.preserve_current)
                self.assertRegex(disposition.reason_code, r"^[A-Z][A-Z0-9_]*$")

    def test_exact_revision_never_becomes_an_ordinary_planning_relation(self):
        """Break caught: exact revision falls through to state-derived supersession."""
        cases = (
            ("absent", "revise-exact", "inline-recovery", True),
            ("reviewable", "revise-exact", "candidate-successor", True),
            ("active", "revise-exact", "inline-recovery", True),
            ("terminal-completed", "revise-exact", "inline-recovery", True),
        )

        for phase, relation, mode, preserve in cases:
            with self.subTest(phase=phase):
                disposition = loom_owner_intent.resolve_planning_disposition(
                    primary_operation="plan",
                    generation_phase=phase,
                    state_error=None,
                    prohibitions=(),
                    exact_reference=True,
                )
                self.assertEqual(relation, disposition.relation)
                self.assertEqual(mode, disposition.mode)
                self.assertEqual(preserve, disposition.preserve_current)

    def test_planning_disposition_rejects_unknown_inputs(self):
        """Break caught: an open operation, state, error, or prohibition is inferred."""
        defaults = {
            "primary_operation": "plan",
            "generation_phase": "absent",
            "state_error": None,
            "prohibitions": (),
            "exact_reference": False,
        }
        cases = (
            ("primary_operation", "invented-operation"),
            ("primary_operation", []),
            ("generation_phase", "invented-state"),
            ("generation_phase", []),
            ("state_error", "INVENTED_ERROR"),
            ("state_error", []),
            ("prohibitions", ("invented-prohibition",)),
            ("prohibitions", ([],)),
        )

        for field, invalid in cases:
            with self.subTest(field=field):
                arguments = {**defaults, field: invalid}
                with self.assertRaises(ValueError):
                    loom_owner_intent.resolve_planning_disposition(**arguments)

    def test_planning_disposition_requires_an_ordered_sequence_of_prohibitions(self):
        """Break caught: mappings, sets, generators, or text become controls."""
        invalid_containers = (
            "implementation",
            {"implementation": True},
            {"implementation"},
            (item for item in ("implementation",)),
            iter(("implementation",)),
        )

        for prohibitions in invalid_containers:
            with self.subTest(container=type(prohibitions).__name__):
                with self.assertRaises(ValueError):
                    loom_owner_intent.resolve_planning_disposition(
                        primary_operation="plan",
                        generation_phase="absent",
                        state_error=None,
                        prohibitions=prohibitions,
                        exact_reference=False,
                    )

    def test_provisional_contradiction_crosses_real_preparation_without_authority(self):
        """Break caught: one clarification cannot cross the prepared boundary."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo = root / "project"
            repo.mkdir()
            subprocess.run(
                ["git", "-C", str(repo), "init"], check=True,
                capture_output=True, text=True, encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repo), "add", "."], check=True,
                capture_output=True, text=True, encoding="utf-8")
            subprocess.run(
                [
                    "git", "-C", str(repo), "-c", "user.name=Loom Test",
                    "-c", "user.email=loom@example.invalid", "commit", "-m",
                    "fixture",
                ],
                check=True, capture_output=True, text=True, encoding="utf-8")
            request = (
                "Plan a school attendance dashboard, then implement it immediately.")
            prepared = loom_runtime.prepare_invocation(
                request,
                instance_id=str(uuid.uuid4()),
                invocation_id=str(uuid.uuid4()),
                cwd=repo,
                owner_home=root / "owner-home",
                now="2026-08-15T12:00:00Z",
            )

        route = prepared.route_contract
        control = loom_runtime.request_control(
            request, state={"generation_phase": "absent"})
        self.assertEqual("plan", prepared.intent)
        self.assertEqual("PLAN_EXECUTION_CONTRADICTION", route["code"])
        self.assertFalse(route["blocked"])
        self.assertTrue(route["needs_owner"])
        self.assertEqual(0, route["routine_question_count"])
        self.assertEqual(1, route["recommendation"].count("?"))
        self.assertEqual("plan", control["primary_operation"])
        self.assertNotEqual("execute", control["primary_operation"])
        self.assertEqual(0, route["target_mutation_count"])
        for field, invalid in (
                ("intent", "execute"),
                ("needs_owner", False),
                ("routine_question_count", 1),
                ("recommendation", 17)):
            with self.subTest(unsafe_field=field):
                unsafe_route = dict(route)
                unsafe_route[field] = invalid
                with self.assertRaises(loom_runtime.RuntimeError):
                    loom_runtime._validate_route(unsafe_route)
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "intent.schema.json", prepared.to_dict(),
            "intent.schema.json")
        self.assertEqual([], report.errors)

    def test_planning_intent_has_no_execution_route_in_each_lifecycle_state(self):
        """Break caught: lifecycle state misclassifies ordinary planning language."""
        states = (
            ("absent", {"generation_phase": "absent"}, "new", False,
             "ROUTE_PLAN"),
            ("reviewable", {"generation_phase": "reviewable"},
             "supersede-generation", False,
             "ROUTE_PLAN"),
            ("active", {"generation_phase": "active"},
             "supersede-generation", False, "ROUTE_PLAN"),
            ("terminal", {"generation_phase": "terminal-completed"}, "new", False,
             "ROUTE_PLAN"),
            ("stale", {
                "generation_phase": "reviewable",
                "state_error": "STALE_LIFECYCLE",
            }, "supersede-generation", True, "PLAN_DECISION_STALE"),
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
