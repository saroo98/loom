#!/usr/bin/env python3
"""Adversarial recovery races that must preserve project and owner bytes."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import loom_install  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_release  # noqa: E402
import loom_reliability  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ControlPlaneRecoveryRaceTests(unittest.TestCase):
    """Prove that ambiguous recovery never consumes its evidence or authority."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_temp = tempfile.TemporaryDirectory(prefix="loom-recovery-race-fixture-")
        cls.fixture_root = Path(cls.fixture_temp.name)
        cls.public = cls.fixture_root / "public"
        cls.installed = cls.fixture_root / "installed"
        loom_release.build_public(
            ROOT, cls.public,
            forbidden_tokens=[
                "-".join(("private", "recovery", "race", "fixture")),
                "-".join(("owner", "recovery", "race", "fixture")),
            ],
            source_classification="public-release")
        loom_install.install(cls.public, cls.installed)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temp.cleanup()

    def setUp(self):
        self.prior_backend = os.environ.get("LOOM_TEST_ALLOW_LEGACY_BACKEND")
        os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = "1"
        self.prior_umask = os.umask(0o077) if os.name != "nt" else None
        self.temp = tempfile.TemporaryDirectory(prefix="loom-recovery-race-")
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        if os.name != "nt":
            self.home.chmod(0o700)
        (self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        self.repo = self.root / "target"
        _write(self.repo / "src" / "app.py", "VALUE = 1\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "config", "user.email",
            "test@example.invalid",
        ], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "config", "user.name", "test",
        ], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "commit", "-qm", "baseline",
        ], check=True)
        self.request = "Plan a financial double-entry accounting change to src/app.py"

    def tearDown(self):
        if self.prior_umask is not None:
            os.umask(self.prior_umask)
        if self.prior_backend is None:
            os.environ.pop("LOOM_TEST_ALLOW_LEGACY_BACKEND", None)
        else:
            os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = self.prior_backend
        self.temp.cleanup()

    def invoke(self):
        return loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)

    @staticmethod
    def read_action(action_path):
        return json.loads(Path(action_path).read_text(encoding="utf-8"))

    @staticmethod
    def pointer_path(action_path):
        return Path(action_path).parent / loom_orchestrator.ACTIVE_POINTER_FILE

    def assert_active_authority(self, action_path, *, statuses=("initializing", "pending")):
        action_path = Path(action_path)
        action = self.read_action(action_path)
        pointer_path = self.pointer_path(action_path)
        self.assertTrue(pointer_path.is_file(), "ambiguous recovery cleared its authority")
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        self.assertEqual(action["action_id"], pointer["action_id"])
        self.assertEqual("active", pointer["state"])
        self.assertIn(action["status"], statuses)
        self.assertIsNone(action.get("recovery_receipt"))
        return action

    @staticmethod
    def exact_tree(path):
        return loom_reliability.exact_tree_manifest(
            path, max_entries=64,
            max_file_bytes=loom_orchestrator.MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=loom_orchestrator.MAX_RECOVERY_TOTAL_BYTES)

    def assert_safety_refusal(self, callable_, allowed_codes):
        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            callable_()
        self.assertIn(caught.exception.code, set(allowed_codes))
        return caught.exception

    def recovery_quarantine(self, action_path):
        action_path = Path(action_path)
        return action_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY / \
            action_path.stem / "plans"

    def leave_unsealed_stage(self):
        original = loom_orchestrator._write_action
        writes = 0

        def interrupt_prepared_write(path, value, security=None):
            nonlocal writes
            writes += 1
            if writes == 2 and value["pack_seed"]["state"] == "prepared":
                raise OSError("seeded prepared-action interruption")
            return original(path, value, security)

        with mock.patch.object(
                loom_orchestrator, "_write_action", side_effect=interrupt_prepared_write):
            with self.assertRaisesRegex(OSError, "prepared-action interruption"):
                self.invoke()
        action_directory = next((self.home / "instances").glob(
            "*/runtime/projects/*/orchestrations"))
        action_path = next(
            path for path in action_directory.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE)
        action = self.read_action(action_path)
        stage = loom_orchestrator._project_stage_path(action)
        self.assertTrue(stage.is_dir())
        self.assert_active_authority(action_path, statuses=("initializing",))
        return action_path, stage

    def assert_unsealed_stage_blocks_then_cancel_preserves(self, action_path, stage,
                                                           artifact_assertion):
        self.assert_safety_refusal(
            self.invoke, {"RECOVERY_DECISION_REQUIRED", "RECOVERY_RACE"})
        self.assert_active_authority(action_path, statuses=("initializing",))
        artifact_assertion()

        cancelled = loom_orchestrator.cancel(action_path)

        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual(
            "preserved-in-place",
            cancelled["recovery_receipt"]["source_disposition"])
        self.assertEqual("cancelled", self.read_action(action_path)["status"])
        self.assertFalse(self.pointer_path(action_path).exists())
        self.assertTrue(stage.exists() or stage.is_symlink())
        artifact_assertion()

    def test_pack_destination_created_at_native_boundary_is_never_replaced(self):
        pack = self.repo / "plans"
        real_native = loom_reliability._native_atomic_rename_noreplace
        injected = False

        def destination_race(*arguments):
            nonlocal injected
            source, destination = map(Path, arguments[:2])
            if destination == pack:
                injected = True
                destination.mkdir()
                (destination / "owner.txt").write_bytes(b"owner destination")
            return real_native(*arguments)

        with mock.patch.object(
                loom_reliability, "_native_atomic_rename_noreplace",
                side_effect=destination_race):
            self.assert_safety_refusal(
                self.invoke,
                {"BASELINE_CONFLICT", "BASELINE_ATOMIC_INSTALL_FAILED",
                 "BASELINE_ATOMICITY_UNAVAILABLE"})

        self.assertTrue(injected, "pack installation bypassed the no-replace primitive")
        self.assertEqual(b"owner destination", (pack / "owner.txt").read_bytes())
        action_path = next(
            path for path in (self.home / "instances").glob(
                "*/runtime/projects/*/orchestrations/*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE)
        action = self.assert_active_authority(action_path, statuses=("initializing",))
        stage = loom_orchestrator._project_stage_path(action)
        self.assertEqual(action["pack_seed"]["manifest"], self.exact_tree(stage))

    def test_quarantine_destination_created_at_native_boundary_preserves_both_trees(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        pack_before = self.exact_tree(pack)
        quarantine = self.recovery_quarantine(action_path)
        real_native = loom_reliability._native_atomic_rename_noreplace
        injected = False

        def destination_race(*arguments):
            nonlocal injected
            _source, destination = map(Path, arguments[:2])
            if destination == quarantine:
                injected = True
                destination.mkdir(parents=True)
                (destination / "owner.txt").write_bytes(b"owner quarantine")
            return real_native(*arguments)

        with mock.patch.object(
                loom_reliability, "_native_atomic_rename_noreplace",
                side_effect=destination_race):
            refusal = self.assert_safety_refusal(
                self.invoke,
                {"RECOVERY_QUARANTINE_CONFLICT", "RECOVERY_DECISION_REQUIRED",
                 "RECOVERY_DURABILITY"})

        self.assertTrue(
            injected,
            f"quarantine bypassed the no-replace primitive: "
            f"{refusal.code}: {refusal.message}")
        self.assertEqual(pack_before, self.exact_tree(pack))
        self.assertEqual(b"owner quarantine", (quarantine / "owner.txt").read_bytes())
        self.assert_active_authority(action_path, statuses=("pending",))

    def test_source_root_substitution_after_exact_scan_is_refused_without_consuming_evidence(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        original_manifest = self.exact_tree(pack)
        displaced = self.repo / "owner-preserved-original-plans"
        quarantine = self.recovery_quarantine(action_path)
        real_native = loom_reliability._native_atomic_rename_noreplace
        injected = False

        def source_race(*arguments):
            nonlocal injected
            source, destination = map(Path, arguments[:2])
            if source == pack and destination == quarantine:
                injected = True
                source.rename(displaced)
                source.mkdir()
                (source / "owner.txt").write_bytes(b"replacement owner tree")
            return real_native(*arguments)

        with mock.patch.object(
                loom_reliability, "_native_atomic_rename_noreplace",
                side_effect=source_race):
            refusal = self.assert_safety_refusal(
                self.invoke,
                {"RECOVERY_DECISION_REQUIRED", "RECOVERY_DURABILITY", "RECOVERY_RACE"})

        self.assertTrue(
            injected,
            f"source recovery bypassed the identity-bound primitive: "
            f"{refusal.code}: {refusal.message}")
        self.assertEqual(original_manifest, self.exact_tree(displaced))
        self.assertEqual(b"replacement owner tree", (pack / "owner.txt").read_bytes())
        self.assertFalse(quarantine.exists())
        self.assert_active_authority(action_path, statuses=("pending",))

    def test_replaced_existing_quarantine_blocks_and_preserves_every_artifact(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        pack_before = self.exact_tree(pack)
        quarantine = self.recovery_quarantine(action_path)
        _write(quarantine / "owner.txt", "unrelated replacement quarantine\n")
        quarantine_before = self.exact_tree(quarantine)

        self.assert_safety_refusal(self.invoke, {"RECOVERY_DECISION_REQUIRED"})

        self.assertEqual(pack_before, self.exact_tree(pack))
        self.assertEqual(quarantine_before, self.exact_tree(quarantine))
        self.assert_active_authority(action_path, statuses=("pending",))

    def test_unsafe_hardlinked_existing_quarantine_blocks_without_unlinking_owner_data(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        pack_before = self.exact_tree(pack)
        quarantine = self.recovery_quarantine(action_path)
        quarantine.mkdir(parents=True)
        owner_file = self.root / "owner-hardlink-source.txt"
        owner_file.write_bytes(b"owner hardlink bytes")
        linked = quarantine / "linked.txt"
        try:
            os.link(owner_file, linked)
        except OSError as exc:
            self.skipTest(f"hardlinks unavailable: {exc}")

        self.assert_safety_refusal(self.invoke, {"RECOVERY_DECISION_REQUIRED"})

        self.assertEqual(pack_before, self.exact_tree(pack))
        self.assertEqual(b"owner hardlink bytes", owner_file.read_bytes())
        self.assertEqual(b"owner hardlink bytes", linked.read_bytes())
        self.assertGreaterEqual(owner_file.stat().st_nlink, 2)
        self.assert_active_authority(action_path, statuses=("pending",))

    def assert_move_refusal_retains_authority(self, message):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        before = self.exact_tree(pack)
        with mock.patch.object(
                loom_reliability, "_native_atomic_rename_noreplace",
                side_effect=loom_reliability.ReliabilityError(message)):
            self.assert_safety_refusal(
                self.invoke,
                {"RECOVERY_DECISION_REQUIRED", "RECOVERY_DURABILITY"})
        self.assertEqual(before, self.exact_tree(pack))
        self.assertFalse(self.recovery_quarantine(action_path).exists())
        self.assert_active_authority(action_path, statuses=("pending",))

    def test_unavailable_quarantine_move_retains_authority(self):
        self.assert_move_refusal_retains_authority(
            "atomic no-replace move is unavailable on this filesystem")

    def test_cross_volume_quarantine_move_retains_authority(self):
        self.assert_move_refusal_retains_authority(
            "atomic no-replace paths are on different filesystems")

    def test_cross_volume_explicit_cancel_writes_readable_preserved_receipt(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        before = self.exact_tree(pack)

        with mock.patch.object(
                loom_reliability, "_native_atomic_rename_noreplace",
                side_effect=loom_reliability.ReliabilityError(
                    "atomic no-replace paths are on different filesystems")):
            cancelled = loom_orchestrator.cancel(action_path)

        receipt = cancelled["recovery_receipt"]
        self.assertEqual("preserved-in-place", receipt["source_disposition"])
        self.assertFalse(receipt["complete_seed"])
        self.assertIsNone(receipt["quarantined_manifest_sha256"])
        self.assertEqual(before, self.exact_tree(pack))
        self.assertFalse(self.pointer_path(action_path).exists())
        self.assertEqual(
            receipt,
            loom_orchestrator._read_action(
                action_path, owner_home=self.home,
                install_root=self.installed)[1]["recovery_receipt"])

        next_result = self.invoke()
        self.assertEqual("blocked", next_result["status"])
        self.assertEqual("invalid_lifecycle", next_result["code"])
        self.assertNotEqual("ACTION_CORRUPT", next_result["code"])

    def test_same_volume_explicit_cancel_quarantines_seed_and_allows_next_action(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        pack = self.repo / "plans"
        before = self.exact_tree(pack)

        cancelled = loom_orchestrator.cancel(action_path)

        receipt = cancelled["recovery_receipt"]
        self.assertEqual("quarantined", receipt["source_disposition"])
        self.assertTrue(receipt["complete_seed"])
        self.assertEqual(before["root_sha256"], receipt["quarantined_manifest_sha256"])
        self.assertFalse(pack.exists())
        stored = loom_orchestrator._read_action(
            action_path, owner_home=self.home,
            install_root=self.installed)[1]
        self.assertEqual(receipt, stored["recovery_receipt"])
        self.assertFalse(self.pointer_path(action_path).exists())

        next_action = self.invoke()
        self.assertEqual("action-required", next_action["status"])
        self.assertEqual("plan", next_action["intent"])
        self.assertNotEqual(opened["action_id"], next_action["action_id"])

    def test_absent_seed_cancellation_records_not_present_without_inventing_changes(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        shutil.rmtree(self.repo / "plans")

        cancelled = loom_orchestrator.cancel(action_path)

        receipt = cancelled["recovery_receipt"]
        self.assertEqual("not-present", receipt["source_disposition"])
        self.assertFalse(receipt["complete_seed"])
        self.assertFalse(receipt["changes_made"])
        activation = receipt["activation_atomic_rename"]
        self.assertIsNotNone(activation)
        expected_phase = (
            "gc-complete"
            if activation["namespace_state"] == "committed"
            and activation["durability"] == "confirmed"
            else "reconciliation-required"
        )
        self.assertEqual(expected_phase, receipt["cleanup_phase"])
        self.assertIsNone(receipt["quarantined_manifest_sha256"])
        self.assertEqual([], receipt["preserved_project_relatives"])
        self.assertEqual([], receipt["preserved_relatives"])
        self.assertEqual(
            receipt,
            loom_orchestrator._read_action(
                action_path, owner_home=self.home,
                install_root=self.installed)[1]["recovery_receipt"])
        self.assertFalse(self.pointer_path(action_path).exists())

    def test_invalid_generated_recovery_receipt_is_never_persisted(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        original = self.read_action(action_path)
        real_receipt = loom_orchestrator._recovery_receipt

        def inconsistent_receipt(*args, **kwargs):
            receipt = real_receipt(*args, **kwargs)
            receipt["complete_seed"] = True
            body = dict(receipt)
            body.pop("receipt_hash")
            receipt["receipt_hash"] = loom_orchestrator._hash(body)
            return receipt

        with mock.patch.object(
                loom_reliability, "_native_atomic_rename_noreplace",
                side_effect=loom_reliability.ReliabilityError(
                    "atomic no-replace paths are on different filesystems")), \
                mock.patch.object(
                    loom_orchestrator, "_recovery_receipt",
                    side_effect=inconsistent_receipt):
            with self.assertRaisesRegex(
                    loom_orchestrator.OrchestratorError,
                    "recovery receipt v3"):
                loom_orchestrator.cancel(action_path)

        persisted = self.read_action(action_path)
        self.assertEqual(original["action_hash"], persisted["action_hash"])
        self.assertIsNone(persisted["recovery_receipt"])

    def test_multiple_simultaneous_recovery_artifacts_block_without_mutation(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        action = self.read_action(action_path)
        pack = self.repo / "plans"
        project_stage = loom_orchestrator._project_stage_path(action)
        owner_stage = loom_orchestrator._stage_path(action_path)
        tombstone = self.repo / f".loom-recovery-{action['action_id']}"
        for path in (project_stage, owner_stage, tombstone):
            shutil.copytree(pack, path, copy_function=shutil.copy2)
        snapshots = {
            path: self.exact_tree(path)
            for path in (pack, project_stage, owner_stage, tombstone)
        }

        self.assert_safety_refusal(self.invoke, {"RECOVERY_DECISION_REQUIRED"})

        for path, before in snapshots.items():
            self.assertEqual(before, self.exact_tree(path))
        self.assertFalse(self.recovery_quarantine(action_path).exists())
        self.assert_active_authority(action_path, statuses=("pending",))

    def test_unsealed_exact_stage_blocks_and_explicit_cancel_preserves_it(self):
        action_path, stage = self.leave_unsealed_stage()
        before = self.exact_tree(stage)

        self.assert_unsealed_stage_blocks_then_cancel_preserves(
            action_path, stage, lambda: self.assertEqual(before, self.exact_tree(stage)))

    def test_unsealed_symlink_stage_blocks_and_explicit_cancel_preserves_it(self):
        action_path, stage = self.leave_unsealed_stage()
        victim = next(path for path in stage.rglob("*") if path.is_file())
        external = self.root / "owner-external.txt"
        external.write_bytes(b"external owner bytes")
        victim.unlink()
        try:
            os.symlink(external, victim)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")

        def assertion():
            self.assertTrue(victim.is_symlink())
            self.assertEqual(b"external owner bytes", external.read_bytes())

        self.assert_unsealed_stage_blocks_then_cancel_preserves(
            action_path, stage, assertion)

    def test_unsealed_hardlink_stage_blocks_and_explicit_cancel_preserves_it(self):
        action_path, stage = self.leave_unsealed_stage()
        victim = next(path for path in stage.rglob("*") if path.is_file())
        linked = stage / "owner-hardlink.txt"
        try:
            os.link(victim, linked)
        except OSError as exc:
            self.skipTest(f"hardlinks unavailable: {exc}")

        def assertion():
            self.assertTrue(victim.is_file())
            self.assertTrue(linked.is_file())
            self.assertGreaterEqual(victim.stat().st_nlink, 2)

        self.assert_unsealed_stage_blocks_then_cancel_preserves(
            action_path, stage, assertion)

    @unittest.skipUnless(os.name == "nt", "NTFS alternate streams require Windows")
    def test_unsealed_ads_stage_blocks_and_explicit_cancel_preserves_it(self):
        action_path, stage = self.leave_unsealed_stage()
        victim = next(path for path in stage.rglob("*") if path.is_file())
        stream = Path(str(victim) + ":loom-owner-race")
        try:
            stream.write_bytes(b"owner stream bytes")
        except OSError as exc:
            self.skipTest(f"alternate streams unavailable: {exc}")

        def assertion():
            self.assertEqual(b"owner stream bytes", stream.read_bytes())
            self.assertTrue(victim.is_file())

        self.assert_unsealed_stage_blocks_then_cancel_preserves(
            action_path, stage, assertion)

    @unittest.skipUnless(hasattr(os, "mkfifo") and os.name != "nt",
                         "FIFO creation requires a POSIX filesystem")
    def test_unsealed_special_stage_blocks_and_explicit_cancel_preserves_it(self):
        action_path, stage = self.leave_unsealed_stage()
        fifo = stage / "owner.fifo"
        os.mkfifo(fifo)

        def assertion():
            self.assertTrue(stat.S_ISFIFO(fifo.lstat().st_mode))

        self.assert_unsealed_stage_blocks_then_cancel_preserves(
            action_path, stage, assertion)


if __name__ == "__main__":
    unittest.main()
