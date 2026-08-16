"""Durable executor freeze and exact host-operation ledger regressions."""

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import loom_executor_guard
import loom_operation_supervisor
import loom_reliability


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")).hexdigest()


class ExecutorGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.owner = self.root / "owner"
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.create_private_directory(self.owner)
        else:
            self.owner.mkdir(mode=0o700)
        self.directory = loom_reliability.ensure_private_directory(
            self.owner, ["orchestration", "p-" + "1" * 32])
        self.action = {
            "action_id": "00000000-0000-4000-8000-000000000001",
            "project_id": "p-" + "1" * 32,
            "generation_id": "generation-" + "2" * 32,
            "operation_id": "3" * 64,
            "owner_home": str(self.owner),
            "intent": "execute",
        }
        self.control_post = self.event(
            "PostToolUse", tool_name="mcp__loom__start",
            tool_use_id="control-start")

    def tearDown(self):
        self.tmp.cleanup()

    def event(self, name, *, tool_name, tool_use_id, tool_input=None):
        return {
            "hook_event_name": name,
            "cwd": str(self.root),
            "session_id": "host-session-1",
            "turn_id": "host-turn-1",
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "tool_input": tool_input or {},
        }

    def initialize_and_arm(self):
        initialized = loom_executor_guard.initialize(
            self.directory, self.action)
        self.assertEqual("awaiting-host", initialized["coverage_state"])
        armed = loom_executor_guard.observe_post(
            self.directory, self.action, self.control_post,
            lifecycle_control=True)
        self.assertEqual("active", armed["coverage_state"])
        return armed

    def test_freeze_waits_for_open_write_then_seals_after_exact_post(self):
        """Break caught: cancellation clears authority while a write remains in flight."""
        self.initialize_and_arm()
        pre = self.event(
            "PreToolUse", tool_name="apply_patch", tool_use_id="write-1",
            tool_input={"patch": "*** Update File: src/app.py\n+x"})
        post = self.event(
            "PostToolUse", tool_name="apply_patch", tool_use_id="write-1",
            tool_input=pre["tool_input"])
        opened = loom_executor_guard.begin_operation(
            self.directory, self.action, pre, operation_kind="structured-write")
        self.assertEqual("open", opened["operations"][0]["state"])
        frozen = loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        self.assertIsNotNone(frozen["freeze"])
        with self.assertRaises(loom_executor_guard.GuardPending):
            loom_executor_guard.seal_quiescence(
                self.directory, self.action,
                project_world_sha256="4" * 64,
                terminal_state="cancelled")

        closed = loom_executor_guard.observe_post(
            self.directory, self.action, post)
        self.assertEqual("closed", closed["operations"][0]["state"])
        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="cancelled")
        self.assertEqual("verified-host-terminal", evidence["case"])
        self.assertEqual(0, evidence["open_operation_count"])
        self.assertEqual(
            evidence,
            loom_executor_guard.seal_quiescence(
                self.directory, self.action,
                project_world_sha256="4" * 64,
                terminal_state="cancelled"))

    def test_guard_storage_uses_the_host_private_directory_boundary(self):
        """The ledger is private on Windows and POSIX rather than only self-hashed."""
        loom_executor_guard.initialize(self.directory, self.action)
        root = loom_executor_guard.guard_path(
            self.directory, self.action).parent
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.verify_private_directory(root)
        else:
            self.assertEqual(0, stat.S_IMODE(root.stat().st_mode) & 0o077)

    def test_freeze_survives_reload_and_denies_a_new_operation(self):
        """Break caught: restart drops the freeze and permits a new mutation."""
        self.initialize_and_arm()
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        with self.assertRaises(loom_executor_guard.GuardFrozen):
            loom_executor_guard.begin_operation(
                self.directory, self.action,
                self.event(
                    "PreToolUse", tool_name="Write", tool_use_id="write-2",
                    tool_input={"file_path": "src/app.py"}),
                operation_kind="structured-write")
        loaded = loom_executor_guard.read(self.directory, self.action)
        self.assertEqual("owner-cancelled", loaded["freeze"]["reason_code"])

    def test_post_without_pre_invalidates_positive_host_proof(self):
        """Break caught: an unobserved process is ignored when quiescence is sealed."""
        self.initialize_and_arm()
        loom_executor_guard.observe_post(
            self.directory, self.action,
            self.event(
                "PostToolUse", tool_name="Bash", tool_use_id="process-1",
                tool_input={"command": "python build.py"}))
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        with self.assertRaises(loom_executor_guard.GuardPending):
            loom_executor_guard.seal_quiescence(
                self.directory, self.action,
                project_world_sha256="4" * 64,
                terminal_state="cancelled")

    def test_tampered_guard_and_caller_injected_evidence_are_rejected(self):
        """Break caught: self-hashed host_result text substitutes for a trusted ledger."""
        self.initialize_and_arm()
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="cancelled")
        injected = dict(evidence)
        injected["action_operation_id"] = "5" * 64
        injected["binding_sha256"] = _digest({
            key: item for key, item in injected.items()
            if key != "binding_sha256"})
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.validate_evidence(
                self.directory, self.action, injected,
                project_world_sha256="4" * 64)

        path = loom_executor_guard.guard_path(self.directory, self.action)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["coverage_failure"] = True
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.read(self.directory, self.action)

    def test_supervised_process_requires_zero_survivors_and_unchanged_roots(self):
        """Break caught: a failed containment receipt is counted as terminal-safe."""
        self.initialize_and_arm()
        pre = self.event(
            "PreToolUse", tool_name="LoomSupervisedProcess",
            tool_use_id="supervised-1", tool_input={"receipt": "sealed"})
        loom_executor_guard.begin_operation(
            self.directory, self.action, pre,
            operation_kind="supervised-process")
        receipt = loom_operation_supervisor.run(
            operation_class="executor-guard-test",
            command=[sys.executable, "-c", "pass"], cwd=self.root,
            timeout=10, allowed_roots=[self.root], protected_roots=[self.owner])
        unsafe = dict(receipt)
        unsafe.update({
            "status": "failed",
            "survivors_confirmed_zero": False,
            "primary_failure": "survivor-census-indeterminate",
        })
        unsafe["receipt_sha256"] = _digest({
            key: item for key, item in unsafe.items()
            if key != "receipt_sha256"})
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.observe_post(
                self.directory, self.action,
                self.event(
                    "PostToolUse", tool_name="LoomSupervisedProcess",
                    tool_use_id="supervised-1", tool_input={"receipt": "sealed"}),
                supervisor_receipt=unsafe)

        changed = dict(receipt)
        changed.update({
            "status": "failed",
            "protected_roots_unchanged": False,
            "primary_failure": "protected-root-changed",
        })
        changed["receipt_sha256"] = _digest({
            key: item for key, item in changed.items()
            if key != "receipt_sha256"})
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.observe_post(
                self.directory, self.action,
                self.event(
                    "PostToolUse", tool_name="LoomSupervisedProcess",
                    tool_use_id="supervised-1", tool_input={"receipt": "sealed"}),
                supervisor_receipt=changed)


if __name__ == "__main__":
    unittest.main()
