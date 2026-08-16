"""Ownership, rollback, and preservation tests for Codex integration."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_codex_integration
import loom_adapters


ROOT = Path(__file__).resolve().parents[1]


class CodexIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.user = self.root / "user"
        self.home = self.user / ".loom"
        self.codex_home = self.user / ".codex"
        self.launcher = self.home / "bin" / "loom.py"
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text("# launcher\n", encoding="utf-8")
        self.codex_home.mkdir(parents=True)
        self.codex = self.root / "codex.exe"
        self.codex.write_bytes(b"stub")

    def mcp_row(self):
        return {"name": "loom", "transport":
                loom_codex_integration._expected_mcp_transport(
                    self.launcher, self.home)}

    def plugin_mcp_row(self):
        return {
            "name": "loom",
            "enabled": True,
            "transport": {
                "type": "stdio",
                "command": "python",
                "args": ["-B", "./scripts/loom_codex_mcp.py"],
                "env": None,
                "env_vars": list(
                    loom_codex_integration.PLUGIN_MCP_SERVER["env_vars"]),
                "cwd": str(ROOT),
            },
            "tool_timeout_sec": 900.0,
        }

    def plugin(self):
        return {
            "plugin_id": "loom@test",
            "marketplace": "test",
            "version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "root": str(ROOT),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_preview_changes_nothing(self):
        with mock.patch.object(loom_codex_integration, "_mcp_rows") as rows:
            result = loom_codex_integration.install(
                self.user, self.home, approved=False, codex_executable=self.codex)
        self.assertEqual("approval-required", result["status"])
        self.assertFalse((self.codex_home / "hooks.json").exists())
        rows.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows desktop binary precedence")
    def test_desktop_codex_binary_precedes_stale_path_wrapper(self):
        local = self.root / "local"
        desktop = local / "OpenAI" / "Codex" / "bin" / "codex.exe"
        desktop.parent.mkdir(parents=True)
        desktop.write_bytes(b"desktop")
        stale = self.root / "stale" / "codex.exe"
        stale.parent.mkdir()
        stale.write_bytes(b"stale")
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}), \
                mock.patch.object(
                    loom_codex_integration.shutil, "which",
                    return_value=str(stale)), \
                mock.patch.object(
                    loom_codex_integration, "_supports_plugin_inventory",
                    side_effect=lambda candidate, _home: candidate == desktop.resolve()):
            selected = loom_codex_integration._codex_executable(self.user)
        self.assertEqual(desktop.resolve(), selected)

    def test_install_preserves_unrelated_hooks_and_owns_exact_entries(self):
        original = {"description": "mine", "hooks": {"Stop": [{
            "hooks": [{"type": "command", "command": "python mine.py"}]}]}}
        (self.codex_home / "hooks.json").write_text(
            json.dumps(original), encoding="utf-8")
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state.append(self.mcp_row())
            else:
                state.clear()

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            result = loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)
        self.assertEqual("standard+verified", result["mode"])
        installed = json.loads((self.codex_home / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(original["hooks"]["Stop"][0], installed["hooks"]["Stop"][0])
        self.assertEqual(2, len(installed["hooks"]["Stop"]))
        self.assertEqual({
            "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
            "PreCompact", "PostCompact", "Stop", "SubagentStart", "SubagentStop",
        }, set(installed["hooks"]))
        command_text = installed["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
        self.assertIn(str(self.launcher), command_text)
        self.assertNotIn("PLUGIN_ROOT", command_text)

    def test_pre_tool_hook_covers_unknown_and_process_capable_tools(self):
        """Break caught: process or newly introduced tools run before Loom can deny them."""
        installed = loom_codex_integration._commands(self.launcher, self.home)
        self.assertEqual(".*", installed["PreToolUse"]["matcher"])
        self.assertEqual(".*", installed["PostToolUse"]["matcher"])

    def test_unowned_loom_hook_fails_closed(self):
        hooks = {"hooks": {"UserPromptSubmit": [{
            "hooks": [{"type": "command", "command": "python ~/.loom/other.py"}]}]}}
        (self.codex_home / "hooks.json").write_text(json.dumps(hooks), encoding="utf-8")
        with mock.patch.object(loom_codex_integration, "_mcp_rows", return_value=[]), \
                self.assertRaisesRegex(loom_codex_integration.IntegrationError, "unowned"):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)

    def test_failed_mcp_add_restores_exact_hook_bytes(self):
        hooks_path = self.codex_home / "hooks.json"
        original = b'{"hooks":{"Stop":[]}}\n'
        hooks_path.write_bytes(original)
        with mock.patch.object(loom_codex_integration, "_mcp_rows", return_value=[]), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_command",
                    side_effect=loom_codex_integration.IntegrationError("failed")), \
                self.assertRaises(loom_codex_integration.IntegrationError):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)
        self.assertEqual(original, hooks_path.read_bytes())

    def test_standard_only_writes_no_hooks(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state.append(self.mcp_row())

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            result = loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex,
                verified=False)
        self.assertEqual("standard", result["mode"])
        hooks = json.loads((self.codex_home / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual({}, hooks["hooks"])

    def test_standard_install_can_upgrade_to_verified_without_losing_other_hooks(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state.append(self.mcp_row())

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex,
                verified=False)
            result = loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex,
                verified=True)
        self.assertEqual("standard+verified", result["mode"])
        hooks = json.loads((self.codex_home / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual({
            "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
            "PreCompact", "PostCompact", "Stop", "SubagentStart", "SubagentStop",
        }, set(hooks["hooks"]))

    def test_owned_mcp_name_with_changed_transport_fails_closed(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state.append(self.mcp_row())

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)
            state[0] = {"name": "loom", "transport": {
                **state[0]["transport"], "command": "other-python"}}
            with self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError, "transport changed"):
                loom_codex_integration.install(
                    self.user, self.home, approved=True, codex_executable=self.codex)

    def test_hooks_only_mode_never_reads_or_changes_mcp(self):
        with mock.patch.object(loom_codex_integration, "_mcp_rows") as rows, \
                mock.patch.object(loom_codex_integration, "_mcp_command") as command:
            result = loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=None,
                manage_mcp=False)
            removed = loom_codex_integration.uninstall(
                self.user, self.home, approved=True, codex_executable=None)
        self.assertEqual("verified-hooks", result["mode"])
        self.assertFalse(removed["mcp_removed"])
        rows.assert_not_called()
        command.assert_not_called()

    def test_plugin_mode_uses_plugin_mcp_without_registering_user_shadow(self):
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.plugin_mcp_row()]) as rows, \
                mock.patch.object(loom_codex_integration, "_mcp_command") as command:
            result = loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertEqual("plugin-standard+verified", result["mode"])
        self.assertEqual("plugin:loom", result["mcp"])
        self.assertEqual(self.plugin(), result["plugin"])
        receipt = loom_codex_integration._load_receipt(
            loom_codex_integration._receipt_path(self.home))
        self.assertFalse(receipt["mcp_managed"])
        self.assertIsNone(receipt["mcp_name"])
        self.assertGreaterEqual(rows.call_count, 2)
        command.assert_not_called()

    def test_plugin_mode_requires_the_exact_active_plugin_mcp(self):
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows", return_value=[]), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError,
                    "plugin MCP is not active"):
            loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)

    def test_plugin_canonicalization_is_noop_on_clean_host_and_preserves_hook_bytes(self):
        hooks_path = self.codex_home / "hooks.json"
        original = b'{ "description": "owner", "hooks": {"Stop": []} }\n'
        hooks_path.write_bytes(original)
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.plugin_mcp_row()]), \
                mock.patch.object(
                    loom_codex_integration.loom_reliability,
                    "atomic_write_bytes") as write:
            result = loom_codex_integration.canonicalize_plugin(
                self.user, self.home, approved=True,
                codex_executable=self.codex)
        self.assertEqual("current", result["status"])
        self.assertEqual("plugin-standard", result["mode"])
        self.assertEqual(original, hooks_path.read_bytes())
        self.assertFalse(
            loom_codex_integration._receipt_path(self.home).exists())
        write.assert_not_called()

    def test_plugin_canonicalization_preserves_owned_hooks_while_retiring_owned_mcp(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state[:] = [self.mcp_row()]
            else:
                state[:] = [self.plugin_mcp_row()]

        with mock.patch.object(
                loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex)
            before = (self.codex_home / "hooks.json").read_bytes()
            with mock.patch.object(
                    loom_codex_integration, "_verified_loom_plugin",
                    return_value=self.plugin()):
                result = loom_codex_integration.canonicalize_plugin(
                    self.user, self.home, approved=True,
                    codex_executable=self.codex)
        self.assertEqual("installed", result["status"])
        self.assertEqual([self.plugin_mcp_row()], state)
        self.assertEqual(before, (self.codex_home / "hooks.json").read_bytes())
        receipt = loom_codex_integration._load_receipt(
            loom_codex_integration._receipt_path(self.home))
        self.assertFalse(receipt["mcp_managed"])
        self.assertEqual(9, len(receipt["entries"]))

    def test_plugin_canonicalization_refuses_unowned_loom_hook_without_rewrite(self):
        hooks_path = self.codex_home / "hooks.json"
        original = json.dumps({"hooks": {"UserPromptSubmit": [{
            "hooks": [{"type": "command",
                       "command": "python ~/.loom/unowned.py"}]}]}}).encode("utf-8")
        hooks_path.write_bytes(original)
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError,
                    "unowned Loom UserPromptSubmit"):
            loom_codex_integration.canonicalize_plugin(
                self.user, self.home, approved=True,
                codex_executable=self.codex)
        self.assertEqual(original, hooks_path.read_bytes())

    def test_plugin_mode_retires_exact_receipt_owned_user_mcp(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state[:] = [self.mcp_row()]
            else:
                state[:] = [self.plugin_mcp_row()]

        with mock.patch.object(
                loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)
            self.assertEqual([self.mcp_row()], state)
            with mock.patch.object(
                    loom_codex_integration, "_verified_loom_plugin",
                    return_value=self.plugin()):
                result = loom_codex_integration.install(
                    self.user, self.home, approved=True,
                    codex_executable=self.codex, manage_mcp=False,
                    plugin_mode=True)
        self.assertEqual([self.plugin_mcp_row()], state)
        self.assertEqual("plugin-standard+verified", result["mode"])
        receipt = loom_codex_integration._load_receipt(
            loom_codex_integration._receipt_path(self.home))
        self.assertFalse(receipt["mcp_managed"])
        self.assertIsNone(receipt["mcp_command_sha256"])

    def test_plugin_mode_refuses_unowned_user_mcp_shadow(self):
        state = [self.mcp_row()]
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows", return_value=state), \
                mock.patch.object(loom_codex_integration, "_mcp_command") as command, \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError, "unowned or changed"):
            loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertFalse((self.codex_home / "hooks.json").exists())
        command.assert_not_called()

    def test_plugin_mode_archives_exact_legacy_skill_outside_discovery_root(self):
        legacy_source = self.root / "legacy-source"
        (legacy_source / "skill" / "loom").mkdir(parents=True)
        (legacy_source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\nlegacy\n", encoding="utf-8")
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        adapter_receipt = loom_codex_integration.loom_adapters._receipt_path(
            self.home, "codex")
        capability = loom_codex_integration.loom_adapters._capability_path(
            self.home, "codex")
        capability.parent.mkdir(parents=True, exist_ok=True)
        capability.write_bytes(b'{"schema_version":2}\n')
        adapter_receipt.parent.mkdir(parents=True, exist_ok=True)
        adapter_receipt.write_text(json.dumps({
            "schema_version": 2,
            "protocol_version": 2,
            "agent": "codex",
            "path": str(legacy / "SKILL.md"),
            "sha256": loom_codex_integration._sha(
                (legacy / "SKILL.md").read_bytes()),
            "capability_receipt_sha256": loom_codex_integration._sha(
                capability.read_bytes()),
        }), encoding="utf-8")
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.plugin_mcp_row()]):
            result = loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertFalse(legacy.exists())
        archived = Path(result["legacy_skill"]["archive"])
        self.assertTrue(archived.is_dir())
        self.assertEqual("retired", result["legacy_skill"]["status"])
        self.assertFalse(adapter_receipt.exists())
        self.assertFalse(capability.exists())
        migration = loom_codex_integration._read_plugin_migration(
            loom_codex_integration._plugin_migration_path(self.user))
        self.assertEqual("retired", migration["state"])

    def test_plugin_mode_archives_large_exact_receipt_owned_legacy_skill(self):
        legacy_source = self.root / "large-legacy-source"
        payload = legacy_source / "payload"
        payload.mkdir(parents=True)
        for index in range(270):
            (payload / f"entry-{index:03d}.txt").write_bytes(b"x")
        (payload / "large.bin").write_bytes(b"x" * (3 * 1024 * 1024))
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.plugin_mcp_row()]):
            result = loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertFalse(legacy.exists())
        archive = Path(result["legacy_skill"]["archive"])
        self.assertTrue(archive.is_dir())
        self.assertEqual(
            b"x" * (3 * 1024 * 1024),
            (archive / "payload" / "large.bin").read_bytes())
        migration = loom_codex_integration._read_plugin_migration(
            loom_codex_integration._plugin_migration_path(self.user))
        self.assertEqual("retired", migration["state"])
        self.assertGreater(
            len(migration["tree_manifest"]["entries"]),
            loom_codex_integration.loom_reliability.MAX_EXACT_TREE_ENTRIES)

    def test_plugin_mode_refuses_large_legacy_skill_with_unowned_file(self):
        legacy_source = self.root / "large-unowned-source"
        payload = legacy_source / "payload"
        payload.mkdir(parents=True)
        for index in range(270):
            (payload / f"entry-{index:03d}.txt").write_bytes(b"x")
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        (legacy / "unowned.txt").write_text("owner", encoding="utf-8")
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError,
                    "unowned or missing"):
            loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertTrue(legacy.is_dir())
        self.assertFalse(
            loom_codex_integration._plugin_migration_path(self.user).exists())

    def test_plugin_mode_failure_restores_exact_legacy_skill(self):
        legacy_source = self.root / "legacy-source-failure"
        (legacy_source / "skill" / "loom").mkdir(parents=True)
        (legacy_source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\nlegacy\n", encoding="utf-8")
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        before = loom_codex_integration.loom_reliability.exact_tree_manifest(legacy)
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.mcp_row()]), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError, "unowned or changed"):
            loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        after = loom_codex_integration.loom_reliability.exact_tree_manifest(legacy)
        self.assertTrue(
            loom_codex_integration.loom_reliability.exact_tree_manifests_equal(
                before, after))
        self.assertFalse(
            loom_codex_integration._plugin_migration_path(self.user).exists())

    def test_plugin_mode_resumes_after_process_death_following_legacy_move(self):
        legacy_source = self.root / "legacy-source-resume"
        (legacy_source / "skill" / "loom").mkdir(parents=True)
        (legacy_source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\nlegacy\n", encoding="utf-8")
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        retirement = loom_codex_integration._activate_legacy_skill_retirement(
            loom_codex_integration._prepare_legacy_skill_retirement(
                self.user, self.plugin()))
        self.assertTrue(retirement["moved_this_call"])
        self.assertFalse(legacy.exists())
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.plugin_mcp_row()]):
            result = loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertEqual("retired", result["legacy_skill"]["status"])
        self.assertFalse(legacy.exists())

    def test_plugin_mode_reconciles_process_death_between_move_and_receipt_update(self):
        legacy_source = self.root / "legacy-source-move-boundary"
        (legacy_source / "skill" / "loom").mkdir(parents=True)
        (legacy_source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\nlegacy\n", encoding="utf-8")
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        retirement = loom_codex_integration._prepare_legacy_skill_retirement(
            self.user, self.plugin())
        original_write = loom_codex_integration.loom_reliability.atomic_write_json

        def interrupted_write(path, value):
            if Path(path) == retirement["path"] and value.get("state") == "moved":
                raise SystemExit("process died after the directory move")
            return original_write(path, value)

        with mock.patch.object(
                loom_codex_integration.loom_reliability, "atomic_write_json",
                side_effect=interrupted_write), self.assertRaises(SystemExit):
            loom_codex_integration._activate_legacy_skill_retirement(retirement)
        self.assertFalse(legacy.exists())
        persisted = loom_codex_integration._read_plugin_migration(
            retirement["path"])
        self.assertEqual("prepared", persisted["state"])

        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_rows",
                    return_value=[self.plugin_mcp_row()]):
            result = loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)
        self.assertEqual("retired", result["legacy_skill"]["status"])
        self.assertFalse(legacy.exists())

    def test_plugin_mode_refuses_tampered_legacy_archive(self):
        legacy_source = self.root / "legacy-source-tamper"
        (legacy_source / "skill" / "loom").mkdir(parents=True)
        (legacy_source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\nlegacy\n", encoding="utf-8")
        legacy = self.codex_home / "skills" / "loom"
        loom_codex_integration.loom_install.install(legacy_source, legacy)
        retirement = loom_codex_integration._activate_legacy_skill_retirement(
            loom_codex_integration._prepare_legacy_skill_retirement(
                self.user, self.plugin()))
        (Path(retirement["receipt"]["archive"]) / "SKILL.md").write_text(
            "tampered\n", encoding="utf-8")
        with mock.patch.object(
                loom_codex_integration, "_verified_loom_plugin",
                return_value=self.plugin()), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError, "namespace changed"):
            loom_codex_integration.install(
                self.user, self.home, approved=True,
                codex_executable=self.codex, manage_mcp=False, plugin_mode=True)

    def test_plugin_inventory_requires_exact_enabled_payload(self):
        cache = (
            self.codex_home / "plugins" / "cache" / "test" / "loom"
            / (ROOT / "VERSION").read_text(encoding="utf-8").strip())
        (cache / ".codex-plugin").mkdir(parents=True)
        (cache / "scripts").mkdir()
        shutil.copyfile(
            ROOT / ".codex-plugin" / "plugin.json",
            cache / ".codex-plugin" / "plugin.json")
        shutil.copyfile(ROOT / ".mcp.json", cache / ".mcp.json")
        shutil.copyfile(
            ROOT / "scripts" / "loom_codex_mcp.py",
            cache / "scripts" / "loom_codex_mcp.py")
        row = {
            "pluginId": "loom@test", "name": "loom", "marketplaceName": "test",
            "version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "installed": True, "enabled": True,
            "source": {"source": "local", "path": str(ROOT)},
        }
        with mock.patch.object(
                loom_codex_integration, "_plugin_rows", return_value=[row]):
            result = loom_codex_integration._verified_loom_plugin(
                self.codex, codex_home=self.codex_home)
        self.assertEqual(str(cache.resolve()), result["root"])
        with mock.patch.object(
                loom_codex_integration, "_plugin_rows",
                return_value=[{**row, "enabled": False}]), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError, "exactly one enabled"):
            loom_codex_integration._verified_loom_plugin(
                self.codex, codex_home=self.codex_home)
        duplicate = {
            **row, "pluginId": "loom@other", "marketplaceName": "other"}
        with mock.patch.object(
                loom_codex_integration, "_plugin_rows",
                return_value=[row, duplicate]), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError,
                    r"observed 2: loom@other, loom@test"):
            loom_codex_integration._verified_loom_plugin(
                self.codex, codex_home=self.codex_home)

    def test_next_invocation_rolls_back_interrupted_mcp_install_as_one_unit(self):
        hooks_path = self.codex_home / "hooks.json"
        original = b'{"hooks":{"Stop":[]}}\n'
        hooks_path.write_bytes(original)
        value, _raw = loom_codex_integration._read_hooks(hooks_path)
        desired = loom_codex_integration._commands(self.launcher, self.home)
        merged, entries = loom_codex_integration._merge_hooks(value, desired, None)
        receipt_path = loom_codex_integration._receipt_path(self.home)
        receipt = {
            "schema_version": loom_codex_integration.RECEIPT_VERSION,
            "hooks_path": str(hooks_path),
            "entries": entries,
            "mcp_name": "loom",
            "mcp_command_sha256": loom_codex_integration._entry_hash(
                loom_codex_integration._expected_mcp_transport(
                    self.launcher, self.home)),
            "mcp_managed": True,
            "generation": 1,
        }
        loom_adapters._begin_transaction(
            self.user, self.home, "codex-integration-install-mcp-add",
            [(hooks_path, loom_codex_integration._hooks_bytes(merged)),
             (receipt_path, loom_adapters._json_bytes(receipt))])
        hooks_path.write_bytes(loom_codex_integration._hooks_bytes(merged))
        state = [self.mcp_row()]

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            self.assertEqual("remove", action)
            state.clear()

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration._reconcile_transaction(
                self.user, self.home, self.codex)
        self.assertEqual(original, hooks_path.read_bytes())
        self.assertFalse(receipt_path.exists())
        self.assertEqual([], state)
        journal = json.loads((self.home / "adapters" / "transaction.json").read_text(
            encoding="utf-8"))
        self.assertEqual("rolled-back", journal["status"])

    def test_next_invocation_restores_interrupted_mcp_uninstall_as_one_unit(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state[:] = [self.mcp_row()]
            else:
                state.clear()

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)
        hooks_path = self.codex_home / "hooks.json"
        receipt_path = loom_codex_integration._receipt_path(self.home)
        installed_hooks = hooks_path.read_bytes()
        installed_receipt = receipt_path.read_bytes()
        receipt = loom_codex_integration._load_receipt(receipt_path)
        changed = loom_codex_integration._remove_hooks(
            json.loads(installed_hooks), receipt)
        loom_adapters._begin_transaction(
            self.user, self.home, "codex-integration-uninstall-mcp-remove",
            [(hooks_path, loom_codex_integration._hooks_bytes(changed)),
             (receipt_path, None)])
        hooks_path.write_bytes(loom_codex_integration._hooks_bytes(changed))
        receipt_path.unlink()
        state.clear()
        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration._reconcile_transaction(
                self.user, self.home, self.codex)
        self.assertEqual(installed_hooks, hooks_path.read_bytes())
        self.assertEqual(installed_receipt, receipt_path.read_bytes())
        self.assertEqual([self.mcp_row()], state)

    def test_next_plugin_invocation_restores_interrupted_owned_mcp_migration(self):
        plugin_row = self.plugin_mcp_row()
        state = [plugin_row, self.mcp_row()]
        loom_adapters._begin_transaction(
            self.user, self.home,
            "codex-integration-plugin-migrate-mcp-remove", [])
        state[:] = [plugin_row]

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            self.assertEqual("add", action)
            state.append(self.mcp_row())

        with mock.patch.object(
                loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(
                    loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration._reconcile_transaction(
                self.user, self.home, self.codex, plugin=self.plugin())

        canonical, shadows = loom_codex_integration._plugin_mcp_inventory(
            state, self.plugin())
        self.assertEqual([plugin_row], canonical)
        self.assertEqual([self.mcp_row()], shadows)
        journal = json.loads(
            (self.home / "adapters" / "transaction.json").read_text(
                encoding="utf-8"))
        self.assertEqual("rolled-back", journal["status"])
        self.assertTrue(journal["recovered_after_interruption"])

    def test_unknown_codex_transaction_operation_fails_closed(self):
        _lock, journal_path, _generation = loom_adapters._transaction_paths(self.home)
        journal_path.parent.mkdir(parents=True, exist_ok=True)
        journal_path.write_text(json.dumps({
            "schema_version": 1,
            "status": "prepared",
            "operation": "codex-integration-unknown",
            "entries": [],
        }), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_codex_integration.IntegrationError, "unsupported"):
            loom_codex_integration._reconcile_transaction(
                self.user, self.home, self.codex)

    def test_uninstall_finalization_failure_restores_mcp_hooks_and_receipt(self):
        state = []

        def rows(*_args, **_kwargs):
            return list(state)

        def command(_codex, action, **_kwargs):
            if action == "add":
                state[:] = [self.mcp_row()]
            else:
                state.clear()

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command):
            loom_codex_integration.install(
                self.user, self.home, approved=True, codex_executable=self.codex)
        hooks_path = self.codex_home / "hooks.json"
        receipt_path = loom_codex_integration._receipt_path(self.home)
        hooks_before = hooks_path.read_bytes()
        receipt_before = receipt_path.read_bytes()
        real_finish = loom_adapters._finish_transaction

        def fail_after_commit(journal, journal_path, generation_path, status):
            real_finish(journal, journal_path, generation_path, status)
            raise OSError("injected generation finalization failure")

        with mock.patch.object(loom_codex_integration, "_mcp_rows", side_effect=rows), \
                mock.patch.object(loom_codex_integration, "_mcp_command", side_effect=command), \
                mock.patch.object(loom_adapters, "_finish_transaction",
                                  side_effect=fail_after_commit), \
                self.assertRaisesRegex(
                    loom_codex_integration.IntegrationError, "prior state was restored"):
            loom_codex_integration.uninstall(
                self.user, self.home, approved=True, codex_executable=self.codex)
        self.assertEqual([self.mcp_row()], state)
        self.assertEqual(hooks_before, hooks_path.read_bytes())
        self.assertEqual(receipt_before, receipt_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
