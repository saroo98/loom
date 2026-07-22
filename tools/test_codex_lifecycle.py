"""Focused lifecycle-hook scope and continuity tests."""

import io
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

    def test_plan_write_inside_plans_is_allowed(self):
        code, output = self.handle(self.event(
            tool_name="apply_patch",
            tool_input={"patch": "*** Add File: plans/WO-001.md\n+x"}))
        self.assertEqual(0, code)
        self.assertIsNone(output)

    def test_plan_write_outside_plans_is_blocked(self):
        code, output = self.handle(self.event(
            tool_name="apply_patch",
            tool_input={"patch": "*** Update File: src/app.py\n+x"}))
        self.assertEqual(2, code)
        self.assertIn("outside declared touches", output["systemMessage"])

    def test_absolute_escape_is_blocked(self):
        outside = self.root.parent / "outside.txt"
        code, output = self.handle(self.event(
            tool_name="Write", tool_input={"file_path": str(outside)}))
        self.assertEqual(2, code)
        self.assertIn("escapes", output["systemMessage"])

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
