"""Focused lifecycle-hook scope and continuity tests."""

import io
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_codex_lifecycle


class CodexLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.action = {
            "action_id": "00000000-0000-4000-8000-000000000001",
            "project_id": "p-" + "1" * 32,
            "explicit_target": str(self.root),
            "cwd": str(self.root),
            "intent": "plan",
            "tier": "S",
            "work_order": None,
        }

    def tearDown(self):
        self.tmp.cleanup()

    def event(self, name="PreToolUse", **extra):
        return {"hook_event_name": name, "cwd": str(self.root), **extra}

    def handle(self, event):
        with mock.patch.object(
                loom_codex_lifecycle, "_active_action", return_value=self.action), \
                mock.patch.object(loom_codex_lifecycle, "_record"):
            return loom_codex_lifecycle.handle(
                event, home=self.root / ".loom", install_root=self.root)

    def continuation(self):
        value = {
            "schema_version": 1,
            "authority_effect": "none",
            "project_id": "p-" + "1" * 32,
            "generation_id": "generation-" + "2" * 32,
            "active_action_id": "00000000-0000-4000-8000-000000000001",
            "plan_semantics_sha256": "3" * 64,
            "lifecycle_state_sha256": "4" * 64,
            "observed_world_sha256": "5" * 64,
            "work_order_id": "WO-001",
            "outcome_sha256": "6" * 64,
            "allowed_touches": ["src/app.py"],
            "acceptance_sha256": "7" * 64,
            "negative_acceptance_sha256": "8" * 64,
            "evidence_requirements_sha256": "9" * 64,
            "rejection_code": "UNAUTHORIZED_PROJECT_TOUCH",
            "safe_next_operation": "resume-exact-action",
        }
        value["continuation_sha256"] = hashlib.sha256(json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("utf-8")).hexdigest()
        return value

    def test_plan_write_inside_plans_is_allowed(self):
        code, output = self.handle(self.event(
            tool_name="apply_patch",
            tool_input={"patch": "*** Add File: plans/WO-001.md\n+x"}))
        self.assertEqual(0, code)
        self.assertIsNone(output)

    def test_plan_write_outside_plans_is_blocked(self):
        with mock.patch.object(
                loom_codex_lifecycle.loom_orchestrator,
                "authorized_continuation", return_value=self.continuation()):
            code, output = self.handle(self.event(
                tool_name="apply_patch",
                tool_input={"patch": "*** Update File: src/app.py\n+x"}))
        self.assertEqual(0, code)
        self.assertIn("outside declared touches", output["systemMessage"])
        self.assertEqual(
            {
                "hookEventName", "permissionDecision",
                "permissionDecisionReason", "additionalContext",
            }, set(output["hookSpecificOutput"]))
        self.assertEqual(
            "PreToolUse", output["hookSpecificOutput"]["hookEventName"])
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("WO-001", context)
        self.assertIn("src/app.py", context)
        self.assertIn("not authority", context)
        self.assertIn(
            self.continuation()["continuation_sha256"], context)

    def test_distinct_executor_deviations_are_denied_and_reassert_one_path(self):
        """Break caught: one blocked shortcut dead-ends the valid exact action."""
        self.action.update({
            "intent": "execute",
            "generation_id": "generation-" + "2" * 32,
            "work_order": "work-orders/WO-001-feature.md",
        })
        attempts = {
            "scope reduction": "tests/required_acceptance.py",
            "acceptance weakening": "tests/test_contract.py",
            "architecture substitution": "architecture/alternate.py",
            "invented extra scope": "src/unplanned_extra.py",
            "omitted required work": "docs/claim-complete.md",
            "premature completion": "plans/completion-evidence/WO-001.json",
            "repair loophole": "repairs/shortcut.py",
            "executor replanning": "plans/plan-semantics.json",
        }
        with mock.patch.object(
                loom_codex_lifecycle, "_work_order_touches",
                return_value=(self.root, ["src/app.py"])), \
                mock.patch.object(
                    loom_codex_lifecycle.loom_orchestrator,
                    "authorized_continuation", return_value=self.continuation()):
            for label, path in attempts.items():
                with self.subTest(label=label):
                    code, output = self.handle(self.event(
                        tool_name="Write", tool_input={"file_path": path}))
                    self.assertEqual(0, code)
                    specific = output["hookSpecificOutput"]
                    self.assertEqual("deny", specific["permissionDecision"])
                    self.assertIn("WO-001", specific["additionalContext"])

    def test_malformed_continuation_is_dropped_without_weakening_denial(self):
        """Break caught: malformed reassertion turns a denied write into a hook failure."""
        with mock.patch.object(
                loom_codex_lifecycle.loom_orchestrator,
                "authorized_continuation", return_value={"schema_version": 1}):
            code, output = self.handle(self.event(
                tool_name="apply_patch",
                tool_input={"patch": "*** Update File: src/app.py\n+x"}))

        self.assertEqual(0, code)
        self.assertEqual(
            {"hookEventName", "permissionDecision", "permissionDecisionReason"},
            set(output["hookSpecificOutput"]))
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("outside declared touches", output["systemMessage"])

    def test_unavailable_continuation_keeps_the_same_supported_denial(self):
        with mock.patch.object(
                loom_codex_lifecycle.loom_orchestrator,
                "authorized_continuation", return_value=None):
            code, output = self.handle(self.event(
                tool_name="apply_patch",
                tool_input={"patch": "*** Update File: src/app.py\n+x"}))

        self.assertEqual(0, code)
        specific = output["hookSpecificOutput"]
        self.assertEqual(
            {"hookEventName", "permissionDecision", "permissionDecisionReason"},
            set(specific))
        self.assertEqual("deny", specific["permissionDecision"])
        self.assertEqual(
            output["systemMessage"], specific["permissionDecisionReason"])

    def test_v3_execution_scope_uses_the_resolved_generation_root(self):
        """Break caught: lifecycle hooks look for v3 work under legacy plans/."""
        generation = self.root / "plans" / "generations" / "generation-1"
        work_orders = generation / "work-orders"
        work_orders.mkdir(parents=True)
        (work_orders / "WO-001-feature.md").write_text(
            "---\nid: WO-001\nstatus: in-progress\n"
            "touches: [src/app.py]\ndepends_on: []\n---\n",
            encoding="utf-8")
        self.action.update({
            "intent": "execute",
            "work_order": "work-orders/WO-001-feature.md",
        })

        with mock.patch.object(
                loom_codex_lifecycle.loom_orchestrator,
                "_action_pack_root", return_value=generation) as resolver:
            target, patterns = loom_codex_lifecycle._work_order_touches(self.action)

        resolver.assert_called_once_with(self.action)
        self.assertEqual(self.root, target)
        self.assertEqual(["src/app.py"], patterns)

    def test_absolute_escape_is_blocked(self):
        outside = self.root.parent / "outside.txt"
        code, output = self.handle(self.event(
            tool_name="Write", tool_input={"file_path": str(outside)}))
        self.assertEqual(0, code)
        self.assertIn("escapes", output["systemMessage"])
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])

    def test_unknown_structured_input_warns_without_claiming_enforcement(self):
        code, output = self.handle(self.event(
            tool_name="Write", tool_input={"unknown": "value"}))
        self.assertEqual(0, code)
        self.assertIn("could not prove", output["systemMessage"])

    def test_shell_is_observed_but_not_misrepresented_as_confined(self):
        code, output = self.handle(self.event(
            tool_name="Bash", tool_input={"command": "echo ok"}))
        self.assertEqual(0, code)
        self.assertIsNone(output)

    def test_compaction_context_is_bounded_and_not_new_authority(self):
        code, output = self.handle(self.event(name="PreCompact"))
        self.assertEqual(0, code)
        self.assertLessEqual(len(output["systemMessage"]), 1024)
        self.assertIn("not new authority", output["systemMessage"])

    def test_no_active_action_is_a_true_noop(self):
        with mock.patch.object(
                loom_codex_lifecycle, "_active_action", return_value=None):
            code, output = loom_codex_lifecycle.handle(
                self.event(name="Stop"), home=self.root / ".loom",
                install_root=self.root)
        self.assertEqual((0, None), (code, output))

    def test_strict_event_rejects_duplicate_fields(self):
        raw = (b'{"hook_event_name":"Stop","hook_event_name":"Stop",'
               + json.dumps({"cwd": str(self.root)}).encode("utf-8")[1:])
        with self.assertRaisesRegex(loom_codex_lifecycle.LifecycleError, "duplicate"):
            loom_codex_lifecycle._read_event(io.BytesIO(raw))


if __name__ == "__main__":
    unittest.main()
