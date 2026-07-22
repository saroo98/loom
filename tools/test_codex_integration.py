"""Ownership, rollback, and preservation tests for Codex integration."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_codex_integration
import loom_adapters


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

    def tearDown(self):
        self.tmp.cleanup()

    def test_preview_changes_nothing(self):
        with mock.patch.object(loom_codex_integration, "_mcp_rows") as rows:
            result = loom_codex_integration.install(
                self.user, self.home, approved=False, codex_executable=self.codex)
        self.assertEqual("approval-required", result["status"])
        self.assertFalse((self.codex_home / "hooks.json").exists())
        rows.assert_not_called()

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
