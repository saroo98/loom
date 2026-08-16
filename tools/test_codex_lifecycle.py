"""Focused lifecycle-hook scope and continuity tests."""

import io
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import loom_codex_lifecycle
import loom_executor_guard
import loom_reliability


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
            "safe_next_operation": "continue-current-execution",
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

    def test_denial_output_is_bounded_and_never_echoes_private_paths(self):
        private = "private-owner-segment-" + "x" * 12000
        attempts = [
            private + "/outside.py",
            "../" + private,
            str(self.root.parent / private / "outside.py"),
        ]
        with mock.patch.object(
                loom_codex_lifecycle.loom_orchestrator,
                "authorized_continuation", return_value=self.continuation()):
            for raw in attempts:
                with self.subTest(raw=raw[:32]):
                    code, output = self.handle(self.event(
                        tool_name="Write", tool_input={"file_path": raw}))
                    serialized = json.dumps(
                        output, separators=(",", ":"), ensure_ascii=False)
                    self.assertEqual(0, code)
                    self.assertEqual(
                        "deny", output["hookSpecificOutput"][
                            "permissionDecision"])
                    self.assertLessEqual(
                        len(serialized.encode("utf-8")),
                        loom_codex_lifecycle.MAX_DENIAL_OUTPUT_BYTES)
                    self.assertNotIn("private-owner-segment", serialized)
                    self.assertNotIn("..", output["systemMessage"])

    def test_launcher_emits_structured_denial_and_keeps_allowed_no_output(self):
        denied_event = self.event(
            tool_name="Write", tool_input={"file_path": "outside.py"})
        allowed_event = self.event(
            tool_name="Write", tool_input={"file_path": "plans/plan.md"})

        def launch(event):
            output = io.StringIO()
            with mock.patch.object(
                    loom_codex_lifecycle, "_read_event", return_value=event), \
                    mock.patch.object(
                        loom_codex_lifecycle, "_active_action",
                        return_value=self.action), \
                    mock.patch.object(loom_codex_lifecycle, "_record"), \
                    mock.patch.object(
                        loom_codex_lifecycle.loom_orchestrator,
                        "authorized_continuation",
                        return_value=self.continuation()), \
                    redirect_stdout(output):
                code = loom_codex_lifecycle.main([
                    "--home", str(self.root / ".loom"),
                    "--install-root", str(self.root)])
            return code, output.getvalue()

        denied_code, denied_stdout = launch(denied_event)
        self.assertEqual(0, denied_code)
        self.assertEqual(
            "deny", json.loads(denied_stdout)[
                "hookSpecificOutput"]["permissionDecision"])
        allowed_code, allowed_stdout = launch(allowed_event)
        self.assertEqual(0, allowed_code)
        self.assertEqual("", allowed_stdout)

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
        self.assertIn("code=OUTSIDE_PROJECT_TARGET", output["systemMessage"])
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])

    def test_unknown_structured_input_is_denied_before_execution(self):
        """Break caught: an unprovable structured write is allowed after a warning."""
        code, output = self.handle(self.event(
            tool_name="Write", tool_input={"unknown": "value"}))
        self.assertEqual(0, code)
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("code=WRITE_SCOPE_UNPROVEN", output["systemMessage"])

    def test_unsupervised_shell_and_process_mutation_is_denied(self):
        """Break caught: raw process execution bypasses the active plan before PostToolUse."""
        commands = [
            "echo ok > result.txt",
            "python build.py",
            "cmd /c del result.txt",
            "powershell -Command Remove-Item result.txt",
            "tool.exe &",
            "tool.exe | other.exe",
        ]
        for command in commands:
            with self.subTest(command=command):
                code, output = self.handle(self.event(
                    tool_name="Bash", tool_input={"command": command}))
                self.assertEqual(0, code)
                self.assertEqual(
                    "deny", output["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "code=PROCESS_MUTATION_UNPROVEN", output["systemMessage"])

    def test_unknown_tool_is_denied_when_mutation_cannot_be_excluded(self):
        """Break caught: a new host tool silently escapes active-action enforcement."""
        code, output = self.handle(self.event(
            tool_name="FutureMutationTool", tool_input={"value": "opaque"}))
        self.assertEqual(0, code)
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("code=TOOL_EFFECT_UNPROVEN", output["systemMessage"])

    def test_exact_loom_lifecycle_control_remains_available(self):
        """Break caught: catch-all hook matching blocks Loom's own safe transition."""
        code, output = self.handle(self.event(
            tool_name="mcp__loom__cancel", tool_input={}))
        self.assertEqual((0, None), (code, output))

        code, output = self.handle(self.event(
            tool_name="mcp__loom__cancel_extra", tool_input={}))
        self.assertEqual(0, code)
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("code=TOOL_EFFECT_UNPROVEN", output["systemMessage"])

    def test_mechanically_read_only_tool_remains_available(self):
        """Break caught: fail-closed mutation policy blocks a host read operation."""
        code, output = self.handle(self.event(
            tool_name="Read", tool_input={"file_path": "src/app.py"}))
        self.assertEqual(0, code)
        self.assertIsNone(output)

    def _guarded_execution(self):
        owner = self.root / "owner"
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.create_private_directory(owner)
        else:
            owner.mkdir(mode=0o700)
        self.action.update({
            "owner_home": str(owner),
            "instance_id": "10000000-0000-4000-8000-000000000001",
            "generation_id": "generation-" + "2" * 32,
            "operation_id": "3" * 64,
            "intent": "execute",
            "work_order": "work-orders/WO-001-feature.md",
        })
        directory = loom_reliability.ensure_private_directory(owner, [
            "instances", self.action["instance_id"], "runtime", "projects",
            self.action["project_id"], "orchestrations",
        ])
        loom_executor_guard.initialize(directory, self.action)
        loom_executor_guard.observe_post(
            directory, self.action, self.event(
                name="PostToolUse", session_id="host-session-1",
                turn_id="host-turn-1", tool_use_id="start-1",
                tool_name="mcp__loom__start", tool_input={}),
            lifecycle_control=True)
        return directory

    def test_execute_hook_opens_and_closes_exact_structured_operation(self):
        """Break caught: PostToolUse cannot prove which allowed write actually closed."""
        directory = self._guarded_execution()
        pre = self.event(
            session_id="host-session-1", turn_id="host-turn-1",
            tool_use_id="write-1", tool_name="Write",
            tool_input={"file_path": "src/app.py"})
        post = {**pre, "hook_event_name": "PostToolUse"}
        with mock.patch.object(
                loom_codex_lifecycle, "_work_order_touches",
                return_value=(self.root, ["src/app.py"])):
            code, output = self.handle(pre)
            self.assertEqual((0, None), (code, output))
            self.assertEqual(
                "open", loom_executor_guard.read(
                    directory, self.action)["operations"][0]["state"])
            code, output = self.handle(post)
            self.assertEqual((0, None), (code, output))
        self.assertEqual(
            "closed", loom_executor_guard.read(
                directory, self.action)["operations"][0]["state"])

    def test_execute_hook_denies_new_write_after_persisted_freeze(self):
        """Break caught: restart-visible cancellation freeze is ignored by PreToolUse."""
        directory = self._guarded_execution()
        loom_executor_guard.freeze(
            directory, self.action, reason_code="owner-cancelled")
        with mock.patch.object(
                loom_codex_lifecycle, "_work_order_touches",
                return_value=(self.root, ["src/app.py"])):
            code, output = self.handle(self.event(
                session_id="host-session-1", turn_id="host-turn-2",
                tool_use_id="write-2", tool_name="Write",
                tool_input={"file_path": "src/app.py"}))
        self.assertEqual(0, code)
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("code=EXECUTION_FROZEN", output["systemMessage"])
        self.assertEqual([], loom_executor_guard.read(
            directory, self.action)["operations"])

    def test_malformed_guarded_write_is_an_explicit_bounded_denial(self):
        """Break caught: missing host identity escapes as an unstructured hook error."""
        self._guarded_execution()
        with mock.patch.object(
                loom_codex_lifecycle, "_work_order_touches",
                return_value=(self.root, ["src/app.py"])):
            code, output = self.handle(self.event(
                tool_name="Write", tool_input={"file_path": "src/app.py"}))
        serialized = json.dumps(
            output, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(0, code)
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("code=EXECUTOR_GUARD_UNPROVEN", output["systemMessage"])
        self.assertLessEqual(
            len(serialized), loom_codex_lifecycle.MAX_DENIAL_OUTPUT_BYTES)

    def test_loom_control_pre_and_post_do_not_poison_the_guard(self):
        """Break caught: allowed lifecycle closure is classified as an unknown mutation."""
        directory = self._guarded_execution()
        event = self.event(
            session_id="host-session-1", turn_id="host-turn-2",
            tool_use_id="complete-1", tool_name="mcp__loom__complete",
            tool_input={})
        self.assertEqual((0, None), self.handle(event))
        self.assertEqual(
            (0, None), self.handle({**event, "hook_event_name": "PostToolUse"}))
        guard = loom_executor_guard.read(directory, self.action)
        self.assertFalse(guard["coverage_failure"])
        self.assertEqual([], guard["operations"])

    def test_frozen_executor_denies_completion_but_allows_cancel_retry(self):
        """A completion control cannot escape a durable cancellation freeze."""
        directory = self._guarded_execution()
        loom_executor_guard.freeze(
            directory, self.action, reason_code="authority-retirement")
        complete_event = self.event(
            session_id="host-session-1", turn_id="host-turn-2",
            tool_use_id="complete-frozen", tool_name="mcp__loom__complete",
            tool_input={})

        code, output = self.handle(complete_event)
        self.assertEqual(0, code)
        self.assertEqual(
            "deny", output["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("code=EXECUTION_FROZEN", output["systemMessage"])
        self.assertEqual(
            (0, None), self.handle({
                **complete_event, "tool_use_id": "cancel-retry",
                "tool_name": "mcp__loom__cancel"}))

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

    def test_launcher_failure_is_bounded_and_does_not_echo_private_input(self):
        private = "owner-secret-" + "x" * 12000
        output = io.StringIO()
        with mock.patch.object(
                loom_codex_lifecycle, "_read_event",
                side_effect=loom_codex_lifecycle.LifecycleError(private)), \
                redirect_stdout(output):
            code = loom_codex_lifecycle.main([
                "--home", str(self.root / ".loom"),
                "--install-root", str(self.root)])
        raw = output.getvalue().encode("utf-8")
        self.assertEqual(2, code)
        self.assertLessEqual(len(raw), loom_codex_lifecycle.MAX_DENIAL_OUTPUT_BYTES)
        self.assertNotIn("owner-secret", output.getvalue())
        self.assertIn("code=HOOK_EVENT_INVALID", output.getvalue())


if __name__ == "__main__":
    unittest.main()
