"""Failure-injection and recovery tests for durable local state."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_privacy
import loom_reliability


class ReliabilityExcellenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "project"
        self.recovery = self.base / "recovery"
        self.root.mkdir()
        self.recovery.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_atomic_replace_failure_preserves_original_and_cleans_temp(self):
        target = self.root / "state.json"
        target.write_text("old\n", encoding="utf-8")
        with mock.patch("loom_reliability.os.replace", side_effect=OSError("injected")):
            with self.assertRaisesRegex(OSError, "injected"):
                loom_reliability.atomic_write_text(target, "new\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
        self.assertEqual(list(self.root.glob(".state.json.*.tmp")), [])

    def test_atomic_write_failure_before_replace_preserves_original(self):
        target = self.root / "state.json"
        target.write_text("old\n", encoding="utf-8")
        with mock.patch("loom_reliability.os.write", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                loom_reliability.atomic_write_bytes(target, b"new\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "old\n")

    def test_migration_is_dry_run_then_idempotent_and_rollback_restores(self):
        target = self.root / "config.json"
        target.write_text('{"version":1}\n', encoding="utf-8")
        plan = loom_reliability.plan_migration(
            self.root, {"config.json": b'{"version":2}\n', "new.txt": b"new\n"})
        self.assertEqual(target.read_text(encoding="utf-8"), '{"version":1}\n')
        first = loom_reliability.apply_migration(self.root, plan, self.recovery)
        second = loom_reliability.apply_migration(self.root, plan, self.recovery)
        self.assertEqual(first["status"], "applied")
        self.assertEqual(second["status"], "applied")
        self.assertTrue(second["idempotent"])
        rolled = loom_reliability.rollback_migration(
            self.root, plan["plan_id"], self.recovery)
        self.assertEqual(rolled["status"], "rolled-back")
        self.assertEqual(target.read_text(encoding="utf-8"), '{"version":1}\n')
        self.assertFalse((self.root / "new.txt").exists())

    def test_interrupted_migration_recovers_without_double_application(self):
        one = self.root / "one.txt"
        two = self.root / "two.txt"
        one.write_text("old-one", encoding="utf-8")
        two.write_text("old-two", encoding="utf-8")
        plan = loom_reliability.plan_migration(
            self.root, {"one.txt": b"new-one", "two.txt": b"new-two"})
        real_write = loom_reliability.atomic_write_bytes
        calls = {"count": 0}

        def interrupt(path, content):
            if Path(path).name in {"one.txt", "two.txt"}:
                calls["count"] += 1
                if calls["count"] == 2:
                    raise KeyboardInterrupt("crash")
            return real_write(path, content)

        with mock.patch("loom_reliability.atomic_write_bytes", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                loom_reliability.apply_migration(self.root, plan, self.recovery)
        recovered = loom_reliability.apply_migration(self.root, plan, self.recovery)
        self.assertEqual(recovered["status"], "applied")
        self.assertEqual(one.read_bytes(), b"new-one")
        self.assertEqual(two.read_bytes(), b"new-two")

    def test_corruption_quarantine_is_external_and_original_remains_blocking(self):
        target = self.root / "active.json"
        target.write_bytes(b"{invalid")
        quarantine = self.base / "quarantine"
        receipt = loom_reliability.quarantine_corrupt(target, quarantine, reason="invalid-json")
        self.assertEqual(target.read_bytes(), b"{invalid")
        copy = Path(receipt["quarantine_path"])
        self.assertTrue(copy.is_file())
        self.assertFalse(copy.is_relative_to(self.root))
        self.assertEqual(loom_reliability.file_sha256(target), receipt["sha256"])

    def test_reproducible_manifest_has_no_absolute_or_time_fields(self):
        (self.root / "b.txt").write_text("b", encoding="utf-8")
        (self.root / "a.txt").write_text("a", encoding="utf-8")
        first = loom_reliability.deterministic_manifest(self.root)
        second = loom_reliability.deterministic_manifest(self.root)
        self.assertEqual(first, second)
        self.assertEqual([item["path"] for item in first["files"]], ["a.txt", "b.txt"])
        serialized = json.dumps(first)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("created_at", serialized)

    def test_uninstaller_removes_only_proven_unchanged_files(self):
        owned = self.root / "owned.txt"
        keep = self.root / "keep.txt"
        owned.write_text("owned", encoding="utf-8")
        keep.write_text("keep", encoding="utf-8")
        receipt = loom_reliability.installation_receipt(
            self.root, ["owned.txt"], install_id="install-001")
        result = loom_reliability.uninstall_owned_files(
            self.root, receipt, confirmation="install-001")
        self.assertEqual(result["removed_files"], 1)
        self.assertFalse(owned.exists())
        self.assertTrue(keep.exists())

    def test_uninstaller_fails_closed_when_owned_file_changed(self):
        owned = self.root / "owned.txt"
        owned.write_text("owned", encoding="utf-8")
        receipt = loom_reliability.installation_receipt(
            self.root, ["owned.txt"], install_id="install-002")
        owned.write_text("user change", encoding="utf-8")
        with self.assertRaisesRegex(loom_reliability.ReliabilityError, "changed"):
            loom_reliability.uninstall_owned_files(
                self.root, receipt, confirmation="install-002")
        self.assertEqual(owned.read_text(encoding="utf-8"), "user change")

    def test_symlink_rejection_is_enforced_even_without_os_symlink_privilege(self):
        cut = self.root / "cut"
        cut.mkdir()
        fake = mock.Mock()
        fake.name = "redirect"
        fake.path = str(cut / "redirect")
        fake.is_symlink.return_value = True
        with mock.patch("loom_privacy.os.scandir", return_value=[fake]):
            with self.assertRaisesRegex(loom_privacy.PrivacyError, "symlink|reparse"):
                loom_privacy.scan_publication(cut, forbidden_tokens=[])

    def test_macos_system_alias_is_allowed_only_for_its_canonical_target(self):
        with mock.patch.object(loom_reliability.sys, "platform", "darwin"), \
                mock.patch.object(
                    loom_reliability.Path, "resolve", return_value=Path("/private/var")):
            self.assertTrue(loom_reliability._is_trusted_os_alias(Path("/var")))
            self.assertFalse(loom_reliability._is_trusted_os_alias(Path("/home")))

        with mock.patch.object(loom_reliability.sys, "platform", "darwin"), \
                mock.patch.object(
                    loom_reliability.Path, "resolve", return_value=Path("/attacker/var")):
            self.assertFalse(loom_reliability._is_trusted_os_alias(Path("/var")))


if __name__ == "__main__":
    unittest.main()
