"""Codex plugin and receipt-owned shared-agent adapter tests."""

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_adapters
import loom_launcher
import loom_update


ROOT = Path(__file__).resolve().parents[1]


class PluginPackageTests(unittest.TestCase):
    def test_skills_only_plugin_is_versioned_bounded_and_has_one_canonical_skill(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"))
        self.assertEqual("loom", manifest["name"])
        self.assertEqual("1.6.0", manifest["version"])
        self.assertEqual("./skills/", manifest["skills"])
        self.assertNotIn("mcpServers", manifest)
        self.assertNotIn("apps", manifest)
        plugin_skill = (ROOT / "skills" / "loom" / "SKILL.md").read_text(encoding="utf-8")
        canonical = (ROOT / "skill" / "loom" / "SKILL.md").read_text(encoding="utf-8")
        self.assertEqual(canonical, plugin_skill)
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        handler = hooks["hooks"]["SessionStart"][0]["hooks"][0]
        self.assertLessEqual(handler["timeout"], 2)
        self.assertIn("PLUGIN_ROOT", handler["command"])
        self.assertIn("PLUGIN_ROOT", handler["commandWindows"])


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "user"
        self.home.mkdir()
        for relative in (".codex", ".claude", ".cursor", ".gemini",
                         ".config/opencode", ".copilot", ".factory", ".agents"):
            (self.home / relative).mkdir(parents=True)
        self.runtime = loom_update.SharedRuntime(
            self.home / ".loom", plugin_roots=[self.root])
        self.runtime.install_baseline("1.1.0", b"runtime", release_sequence=1)
        self.launcher = loom_adapters.install_launcher(
            self.home / ".loom", ROOT / "tools" / "loom_launcher.py")

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_approval_connects_detected_agents_without_touching_repositories(self):
        project = self.root / "project"
        project.mkdir()
        before = list(project.rglob("*"))
        result = loom_adapters.connect_all(
            self.home, self.home / ".loom", approved=True)
        self.assertEqual(5, result["connected"])
        self.assertEqual(result["connected"], result["verified"])
        self.assertEqual(
            ["cursor", "factory-droid", "generic-agent-skills"],
            result["unsupported"])
        self.assertEqual(before, list(project.rglob("*")))
        for receipt in result["receipts"]:
            self.assertTrue(Path(receipt).is_file())
        probe = subprocess.run(
            [sys.executable, str(Path(self.launcher["python_launcher"])),
             "--home", str(self.home / ".loom"), "adapter-probe"],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(0, probe.returncode, probe.stderr)
        self.assertEqual("1.1.0", json.loads(probe.stdout)["version"])
        self.assertEqual(2, json.loads(probe.stdout)["protocol_version"])

    def test_unowned_conflict_blocks_split_brain_and_is_not_overwritten(self):
        conflict = self.home / ".codex" / "skills" / "loom" / "SKILL.md"
        conflict.parent.mkdir(parents=True)
        conflict.write_text("unowned custom Loom\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_adapters.AdapterError, "unowned|split-brain"):
            loom_adapters.connect_all(self.home, self.home / ".loom", approved=True)
        self.assertEqual("unowned custom Loom\n", conflict.read_text(encoding="utf-8"))

    def test_no_approval_performs_no_agent_configuration_write(self):
        result = loom_adapters.connect_all(
            self.home, self.home / ".loom", approved=False)
        self.assertEqual("approval-required", result["status"])
        self.assertFalse((self.home / ".codex" / "skills" / "loom").exists())
        self.assertEqual(5, len(result["eligible"]))

    def test_partial_adapter_write_is_rolled_back_completely(self):
        real_write = loom_adapters.loom_reliability.atomic_write_bytes
        calls = {"count": 0}

        def fail_third(path, content):
            calls["count"] += 1
            if calls["count"] == 3:
                raise OSError("injected adapter write failure")
            return real_write(path, content)

        with mock.patch.object(
                loom_adapters.loom_reliability, "atomic_write_bytes", side_effect=fail_third):
            with self.assertRaisesRegex(loom_adapters.AdapterError, "restored"):
                loom_adapters.connect_all(
                    self.home, self.home / ".loom", approved=True)
        for relative in loom_adapters.AGENTS.values():
            self.assertFalse(self.home.joinpath(*Path(relative).parts).exists())

    def test_disconnect_removes_only_unchanged_receipt_owned_adapters(self):
        connected = loom_adapters.connect_all(
            self.home, self.home / ".loom", approved=True)
        preview = loom_adapters.disconnect_all(
            self.home, self.home / ".loom", approved=False)
        self.assertEqual(0, preview["removed"])
        self.assertEqual(connected["connected"], preview["connected"])
        target = self.home / ".codex" / "skills" / "loom" / "SKILL.md"
        target.write_text(target.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_adapters.AdapterError, "changed"):
            loom_adapters.disconnect_all(self.home, self.home / ".loom", approved=True)
        self.assertTrue(target.is_file())
        target.write_bytes(loom_adapters._adapter("codex"))
        removed = loom_adapters.disconnect_all(
            self.home, self.home / ".loom", approved=True)
        self.assertEqual(connected["connected"], removed["removed"])
        self.assertFalse(target.exists())

    def test_changed_capability_receipt_blocks_adapter_upgrade(self):
        loom_adapters.connect_all(self.home, self.home / ".loom", approved=True)
        capability = loom_adapters._capability_path(self.home / ".loom", "codex")
        capability.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_adapters.AdapterError, "capability receipt"):
            loom_adapters.connect_all(self.home, self.home / ".loom", approved=True)

    def test_exact_v1_receipt_migrates_to_v2_without_overwriting_modified_content(self):
        target = self.home / ".codex" / "skills" / "loom" / "SKILL.md"
        target.parent.mkdir(parents=True)
        content = loom_adapters._adapter("codex")
        target.write_bytes(content)
        receipt = loom_adapters._receipt_path(self.home / ".loom", "codex")
        receipt.parent.mkdir(parents=True)
        legacy = {"schema_version": 1, "agent": "codex", "path": str(target),
                  "sha256": loom_adapters._sha(content),
                  "launcher": "~/.loom/bin/loom"}
        receipt.write_text(json.dumps(legacy), encoding="utf-8")
        result = loom_adapters.connect_all(
            self.home, self.home / ".loom", approved=True,
            versions={"codex": "test"})
        self.assertIn("codex", result["eligible"])
        migrated = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(2, migrated["schema_version"])
        self.assertEqual(2, migrated["protocol_version"])
        self.assertRegex(migrated["legacy_receipt_sha256"], r"^[0-9a-f]{64}$")

    def test_repo_local_unowned_skill_is_rejected_as_split_brain(self):
        project = self.root / "project"
        shadow = project / ".codex" / "skills" / "loom" / "SKILL.md"
        shadow.parent.mkdir(parents=True)
        shadow.write_text("unowned local Loom", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "split-brain"):
            loom_launcher._reject_local_shadow(project)

    def test_active_runtime_tampering_or_unlisted_file_blocks_launch(self):
        runtime = self.root / "verified-runtime"
        tool = runtime / "tools" / "loom.py"
        tool.parent.mkdir(parents=True)
        tool.write_text("print('ok')\n", encoding="utf-8")
        raw = tool.read_bytes()
        (runtime / "RUNTIME-MANIFEST.json").write_text(json.dumps({
            "schema_version": 1, "version": "1.1.0", "platform": loom_update.platform_id(),
            "files": [{"path": "tools/loom.py", "bytes": len(raw),
                       "sha256": hashlib.sha256(raw).hexdigest()}],
        }), encoding="utf-8")
        loom_launcher._verify_runtime(runtime, "1.1.0")
        tool.write_text("print('changed')\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "do not match"):
            loom_launcher._verify_runtime(runtime, "1.1.0")
        tool.write_bytes(raw)
        (runtime / "unlisted.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "unlisted"):
            loom_launcher._verify_runtime(runtime, "1.1.0")

    def test_crash_exit_is_recorded_as_unhealthy_for_automatic_rollback(self):
        runtime = self.root / "runtime"
        orchestrator = runtime / "tools" / "loom_orchestrator.py"
        orchestrator.parent.mkdir(parents=True)
        orchestrator.write_text("raise SystemExit(1)\n", encoding="utf-8")
        manager = mock.Mock()
        manager.begin_session.return_value = {
            "session_id": "00000000-0000-4000-8000-000000000001",
            "version": "1.1.0",
        }
        failed = mock.Mock(returncode=1)

        with mock.patch.object(
                loom_launcher.loom_update, "SharedRuntime", return_value=manager), \
                mock.patch.object(
                    loom_launcher, "_current",
                    return_value=({"version": "1.1.0", "release_sequence": 2}, runtime)), \
                mock.patch.object(loom_launcher, "_reject_local_shadow"), \
                mock.patch.object(loom_launcher.subprocess, "run", return_value=failed):
            result = loom_launcher.main([
                "--home", str(self.home / ".loom"), "invoke",
                "--request", "plan safely", "--cwd", str(self.root),
                "--agent", "codex", "--agent-version", "test"])

        self.assertEqual(1, result)
        manager.end_session.assert_called_once_with(
            "00000000-0000-4000-8000-000000000001", successful=False)
        manager.record_trust_health.assert_called_once_with(
            healthy=False, reason="runtime-exit-1")


if __name__ == "__main__":
    unittest.main()
