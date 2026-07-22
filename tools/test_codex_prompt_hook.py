"""Codex UserPromptSubmit transport tests for sealed Loom invocation."""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "loom_codex_prompt.py"
SPEC = importlib.util.spec_from_file_location("loom_codex_prompt", SCRIPT)
loom_codex_prompt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(loom_codex_prompt)


def event(prompt, cwd, *, session="session-a", turn="turn-a"):
    return {
        "hook_event_name": "UserPromptSubmit",
        "session_id": session,
        "turn_id": turn,
        "cwd": str(cwd),
        "prompt": prompt,
        "model": "test",
        "permission_mode": "default",
        "transcript_path": None,
    }


class PromptExtractionTests(unittest.TestCase):
    def test_slash_surface_preserves_multiline_unicode_and_metacharacters(self):
        request = "first line\n  second % ! & | < > ^ ( ) ' \" café کوردی"
        self.assertEqual(
            request, loom_codex_prompt.extract_request("/loom " + request))

    def test_explicit_skill_surface_preserves_request(self):
        request = "Plan this exactly\n  with indentation"
        prompt = "[$loom:loom](C:\\\\Users\\\\owner\\\\SKILL.md) " + request
        self.assertEqual(request, loom_codex_prompt.extract_request(prompt))

    def test_non_loom_prompt_is_not_intercepted(self):
        self.assertIsNone(loom_codex_prompt.extract_request(
            "Explain why the text /loom appears in this document"))

    def test_empty_explicit_request_fails_closed(self):
        with self.assertRaisesRegex(loom_codex_prompt.HookError, "requires a request"):
            loom_codex_prompt.extract_request("/loom")


class HookContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "owner" / ".loom"
        self.action = self.home / "operations" / "action.json"
        self.action.parent.mkdir(parents=True)
        self.action_id = str(uuid.uuid4())
        action = {"schema_version": 1, "kind": "loom-encrypted-action-v1",
                  "action_id": self.action_id, "owner_vault_id": str(uuid.uuid4()),
                  "ciphertext": "sealed"}
        self.action.write_text(json.dumps(action, sort_keys=True) + "\n", encoding="utf-8")
        self.action_file_sha256 = hashlib.sha256(self.action.read_bytes()).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_frames_preserve_exact_request_identity_without_request_argv(self):
        request = "line one\nline two % ! & | < > ^ ( ) café کوردی"
        frames, identity = loom_codex_prompt._bridge_frames(
            request, event(request, self.root))
        messages = [json.loads(line) for line in frames.splitlines()]
        self.assertEqual(request, messages[1]["request"])
        self.assertEqual(hashlib.sha256(request.encode("utf-8")).hexdigest(), identity)
        self.assertNotIn(request, messages[0].values())

    def test_character_and_utf8_frame_boundaries_fail_closed(self):
        with self.assertRaisesRegex(loom_codex_prompt.HookError, "character bound"):
            loom_codex_prompt._bridge_frames(
                "x" * (loom_codex_prompt.MAX_REQUEST_CHARACTERS + 1),
                event("ignored", self.root))
        with self.assertRaisesRegex(loom_codex_prompt.HookError, "UTF-8 frame bound"):
            loom_codex_prompt._bridge_frames(
                "😀" * loom_codex_prompt.MAX_REQUEST_CHARACTERS,
                event("ignored", self.root))

    def test_bounded_context_rejects_action_outside_owner_root(self):
        outside = self.root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(loom_codex_prompt.HookError, "escapes"):
            loom_codex_prompt._bounded_context({
                "status": "action-required", "action_path": str(outside),
                "action_id": self.action_id,
                "owner_message": {},
            }, request_sha256="a" * 64, runtime_version="1.8.5",
                loom_home=self.home)

    def test_bounded_context_rejects_malformed_action_before_injection(self):
        self.action.write_text('{"schema_version":1,"status":"completed"}\n',
                               encoding="utf-8")
        with self.assertRaisesRegex(loom_codex_prompt.HookError, "envelope linkage"):
            loom_codex_prompt._bounded_context({
                "status": "action-required", "action_path": str(self.action),
                "action_id": self.action_id, "owner_message": {},
            }, request_sha256="a" * 64, runtime_version="1.8.5",
                loom_home=self.home)

    def test_bounded_context_rejects_action_id_unlinked_from_file(self):
        with self.assertRaisesRegex(loom_codex_prompt.HookError, "envelope linkage"):
            loom_codex_prompt._bounded_context({
                "status": "action-required", "action_path": str(self.action),
                "action_id": str(uuid.uuid4()), "owner_message": {},
            }, request_sha256="a" * 64, runtime_version="1.8.5",
                loom_home=self.home)

    def test_success_injects_sealed_context_and_never_reinvokes(self):
        request = "Plan exactly\n  preserve this"
        captured = {}

        def bridge(_launcher, _home, frames):
            messages = [json.loads(line) for line in frames.splitlines()]
            captured["request"] = messages[1]["request"]
            return ({"runtime_version": "1.8.5"}, {
                "status": "action-required", "action_id": self.action_id,
                "action_path": str(self.action),
                "owner_message": {"human": "Plan is ready."},
            })

        stdin = io.BytesIO(json.dumps(event("/loom " + request, self.root)).encode())
        stdout = io.StringIO()
        with mock.patch.object(loom_codex_prompt.sys, "stdin",
                               mock.Mock(buffer=stdin)), \
                mock.patch.object(loom_codex_prompt, "_run_bootstrap",
                                  return_value=(self.root / "loom.py", {})), \
                mock.patch.object(loom_codex_prompt, "_run_bridge", side_effect=bridge), \
                mock.patch.object(loom_codex_prompt.Path, "home",
                                  return_value=self.root / "owner"), \
                mock.patch("sys.stdout", stdout):
            self.assertEqual(0, loom_codex_prompt.main())
        output = json.loads(stdout.getvalue())
        context = json.loads(
            output["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(request, captured["request"])
        self.assertEqual(loom_codex_prompt.HOOK_PROTOCOL, context["protocol"])
        self.assertEqual(self.action_file_sha256, context["action_file_sha256"])
        self.assertNotIn(request, output["hookSpecificOutput"]["additionalContext"])

    def test_explicit_loom_bootstrap_failure_blocks_without_fallback(self):
        stdin = io.BytesIO(json.dumps(event("/loom plan safely", self.root)).encode())
        stdout = io.StringIO()
        with mock.patch.object(loom_codex_prompt.sys, "stdin",
                               mock.Mock(buffer=stdin)), \
                mock.patch.object(loom_codex_prompt, "_run_bootstrap",
                                  side_effect=loom_codex_prompt.HookError("bad receipt")), \
                mock.patch.object(loom_codex_prompt.Path, "home",
                                  return_value=self.root / "owner"), \
                mock.patch("sys.stdout", stdout):
            self.assertEqual(0, loom_codex_prompt.main())
        self.assertEqual(
            {"decision": "block", "reason": "Loom blocked: bad receipt"},
            json.loads(stdout.getvalue()))

    def test_bridge_surfaces_bounded_sealed_block_reason(self):
        responses = [
            {"message_type": "initialize-result", "runtime_version": "1.8.5"},
            {"message_type": "result", "returncode": 2,
             "payload": {"status": "blocked", "error": "split-brain route"}},
        ]
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=("\n".join(json.dumps(item) for item in responses) + "\n").encode(),
            stderr=b"")
        with mock.patch.object(loom_codex_prompt.subprocess, "run",
                               return_value=completed), \
                self.assertRaisesRegex(loom_codex_prompt.HookError,
                                            "split-brain route"):
            loom_codex_prompt._run_bridge(self.root / "loom.py", self.home, b"{}\n")

    def test_non_loom_subprocess_event_is_silent_and_side_effect_free(self):
        shutil.rmtree(self.home)
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT)],
            input=json.dumps(event("ordinary project request", self.root)),
            capture_output=True, text=True, timeout=10, check=False,
            env={**os.environ, "HOME": str(self.root / "owner"),
                 "USERPROFILE": str(self.root / "owner")})
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stdout)
        self.assertFalse(self.home.exists())

    def test_plugin_declares_fixed_prompt_hook(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"))
        self.assertEqual("./hooks/hooks.json", manifest["hooks"])
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(
            encoding="utf-8"))
        handler = hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        self.assertNotIn("request", handler["command"].lower())
        self.assertNotIn("request", handler["commandWindows"].lower())
        self.assertIn("loom_codex_prompt.py", handler["command"])
        self.assertIn("loom_codex_prompt.py", handler["commandWindows"])
        self.assertLessEqual(handler["timeout"], 180)


if __name__ == "__main__":
    unittest.main()
