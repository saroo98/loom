"""Codex plugin and receipt-owned shared-agent adapter tests."""

import json
import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_adapters
import loom_adapter_protocol
import loom_launcher
import loom_update


ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


class PluginPackageTests(unittest.TestCase):
    def test_skills_only_plugin_is_versioned_bounded_and_has_one_canonical_skill(self):
        manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"))
        self.assertEqual("loom", manifest["name"])
        self.assertEqual(CURRENT_VERSION, manifest["version"])
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
        self.assertEqual(4, result["connected"])
        self.assertEqual(result["connected"], result["verified"])
        self.assertEqual(
            ["cursor", "gemini-cli", "factory-droid", "generic-agent-skills"],
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

    def test_windows_command_wrapper_refuses_instead_of_reparsing_arguments(self):
        wrapper = Path(self.launcher["windows_launcher"]).read_text(encoding="utf-8")
        self.assertNotIn("%*", wrapper)
        self.assertNotIn("loom.py\" %", wrapper)
        self.assertIn("disabled", wrapper.lower())
        self.assertIn("exit /b 2", wrapper.lower())

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
        self.assertEqual(4, len(result["eligible"]))

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

    def test_partial_launcher_write_is_rolled_back_completely(self):
        fresh = self.root / "fresh-user" / ".loom"
        real_write = loom_adapters.loom_reliability.atomic_write_bytes
        calls = {"count": 0}

        def fail_third(path, content):
            calls["count"] += 1
            if calls["count"] == 3:
                raise OSError("injected launcher write failure")
            return real_write(path, content)

        with mock.patch.object(
                loom_adapters.loom_reliability, "atomic_write_bytes", side_effect=fail_third):
            with self.assertRaisesRegex(loom_adapters.AdapterError, "restored"):
                loom_adapters.install_launcher(
                    fresh, ROOT / "tools" / "loom_launcher.py")
        binary = fresh / "bin"
        self.assertFalse((binary / "loom.py").exists())
        self.assertFalse((binary / "loom").exists())
        self.assertFalse((binary / "loom.cmd").exists())
        recovered = json.loads((fresh / "adapters" / "transaction.json").read_text(
            encoding="utf-8"))
        self.assertEqual("rolled-back", recovered["status"])

    def test_launcher_rejects_unlisted_redirected_runtime_directory(self):
        runtime = self.home / ".loom" / "runtime" / "versions" / "1.1.0"
        redirected = runtime / "redirected"
        redirected.mkdir()
        real_redirect = loom_launcher.loom_reliability._is_redirect

        def redirect_probe(path):
            return Path(path) == redirected or real_redirect(path)

        with mock.patch.object(
                loom_launcher.loom_reliability, "_is_redirect",
                side_effect=redirect_probe):
            with self.assertRaisesRegex(RuntimeError, "unsafe|redirected"):
                loom_launcher._verify_runtime(runtime, "1.1.0")

    def test_transaction_refuses_symlinked_target_parent(self):
        target_root = self.root / "redirect-target"
        target_root.mkdir()
        redirect = self.home / "redirect"
        try:
            redirect.symlink_to(target_root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        target = redirect / "SKILL.md"
        with self.assertRaisesRegex(loom_adapters.AdapterError, "symlink|invalid"):
            loom_adapters._begin_transaction(
                self.home, self.home / ".loom", "connect", [(target, b"new")])

    def test_interrupted_adapter_transaction_recovers_before_next_writer(self):
        target = self.home / ".codex" / "skills" / "loom" / "SKILL.md"
        journal, _journal_path, _generation_path = loom_adapters._begin_transaction(
            self.home, self.home / ".loom", "connect", [(target, b"new")])
        target.parent.mkdir(parents=True)
        target.write_bytes(b"new")
        recovered_generation = loom_adapters._recover_transaction(
            self.home, self.home / ".loom")
        self.assertEqual(journal["generation"], recovered_generation)
        self.assertFalse(target.exists())
        recovered = json.loads((self.home / ".loom" / "adapters" /
                                "transaction.json").read_text(encoding="utf-8"))
        self.assertEqual("rolled-back", recovered["status"])
        self.assertTrue(recovered["recovered_after_interruption"])

    def test_forged_transaction_cannot_delete_unrelated_user_file(self):
        victim = self.home / "owner-document.txt"
        victim.write_bytes(b"valuable")
        _lock, journal_path, _generation = loom_adapters._transaction_paths(
            self.home / ".loom")
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        journal_path.write_text(json.dumps({
            "schema_version": 1,
            "transaction_id": "forged",
            "generation": 1,
            "operation": "connect",
            "status": "prepared",
            "entries": [{
                "path": str(victim),
                "before_base64": None,
                "before_sha256": None,
                "after_sha256": hashlib.sha256(b"valuable").hexdigest(),
            }],
        }), encoding="utf-8")
        with self.assertRaisesRegex(loom_adapters.AdapterError, "escapes|owned"):
            loom_adapters._recover_transaction(self.home, self.home / ".loom")
        self.assertEqual(b"valuable", victim.read_bytes())

    def test_unowned_alternate_global_route_blocks_without_overwrite(self):
        alternate = self.home / ".agents" / "skills" / "loom" / "SKILL.md"
        alternate.parent.mkdir(parents=True)
        alternate.write_text("different Loom", encoding="utf-8")
        with self.assertRaisesRegex(loom_adapters.AdapterError, "alternate|split-brain"):
            loom_adapters.connect_all(self.home, self.home / ".loom", approved=True)
        self.assertEqual("different Loom", alternate.read_text(encoding="utf-8"))

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
        self.assertEqual("~/.loom/bin/loom.py", migrated["launcher"])
        self.assertRegex(migrated["legacy_receipt_sha256"], r"^[0-9a-f]{64}$")

    def test_owned_protocol_2_adapter_upgrades_from_argv_to_stdio_authority(self):
        target = self.home / ".codex" / "skills" / "loom" / "SKILL.md"
        target.parent.mkdir(parents=True)
        old_content = (
            "---\nname: loom\n---\n"
            "Run ~/.loom/bin/loom invoke --request <verbatim-request>.\n").encode("utf-8")
        target.write_bytes(old_content)
        capability_path = loom_adapters._capability_path(self.home / ".loom", "codex")
        capability_path.parent.mkdir(parents=True)
        capability = b'{"adapter_version":"2.0.0"}\n'
        capability_path.write_bytes(capability)
        receipt_path = loom_adapters._receipt_path(self.home / ".loom", "codex")
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        old_receipt = {
            "schema_version": 2, "protocol_version": 2, "agent": "codex",
            "host_version": "test", "adapter_version": "2.0.0",
            "path": str(target), "sha256": loom_adapters._sha(old_content),
            "launcher": "~/.loom/bin/loom", "evidence_status": "simulated-conformant",
            "capability_receipt_sha256": loom_adapters._sha(capability),
            "legacy_receipt_sha256": None,
        }
        old_receipt_bytes = loom_adapters._json_bytes(old_receipt)
        receipt_path.write_bytes(old_receipt_bytes)

        loom_adapters.connect_all(
            self.home, self.home / ".loom", approved=True,
            versions={"codex": "test"})

        upgraded = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(loom_adapter_protocol.ADAPTER_VERSION,
                         upgraded["adapter_version"])
        self.assertEqual("~/.loom/bin/loom.py", upgraded["launcher"])
        self.assertEqual(loom_adapters._sha(old_receipt_bytes),
                         upgraded["legacy_receipt_sha256"])
        self.assertNotIn(b"--request", target.read_bytes())

    def test_repo_local_unowned_skill_is_rejected_as_split_brain(self):
        project = self.root / "project"
        shadow = project / ".codex" / "skills" / "loom" / "SKILL.md"
        shadow.parent.mkdir(parents=True)
        shadow.write_text("unowned local Loom", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "split-brain"):
            loom_launcher._reject_local_shadow(project)

    def test_owner_global_skill_is_not_misclassified_for_non_git_project(self):
        owner = self.root / "owner"
        project = owner / "projects" / "plain"
        project.mkdir(parents=True)
        global_skill = owner / ".codex" / "skills" / "loom" / "SKILL.md"
        global_skill.parent.mkdir(parents=True)
        global_skill.write_text("global Loom", encoding="utf-8")
        with mock.patch.object(loom_launcher.Path, "home", return_value=owner):
            loom_launcher._reject_local_shadow(project)

        local_skill = project / ".codex" / "skills" / "loom" / "SKILL.md"
        local_skill.parent.mkdir(parents=True)
        local_skill.write_text("local Loom", encoding="utf-8")
        with mock.patch.object(loom_launcher.Path, "home", return_value=owner), \
                self.assertRaisesRegex(RuntimeError, "split-brain"):
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
            message = {
                "schema_version": 2, "message_type": "invoke",
                "request_id": "req-crash", "request": "plan safely",
                "cwd": str(self.root),
            }
            frame = loom_adapter_protocol.canonical_bytes(
                loom_adapter_protocol.request_envelope(
                    message, {"id": "codex", "version": "test"})) + b"\n"
            stdin = mock.Mock(buffer=io.BytesIO(frame))
            with mock.patch.object(loom_launcher.sys, "stdin", stdin):
                result = loom_launcher.main([
                    "--home", str(self.home / ".loom"), "invoke-stdio"])

        self.assertEqual(1, result)
        manager.end_session.assert_called_once_with(
            "00000000-0000-4000-8000-000000000001", successful=False)
        manager.record_trust_health.assert_called_once_with(
            healthy=False, reason="runtime-exit-1")


if __name__ == "__main__":
    unittest.main()
