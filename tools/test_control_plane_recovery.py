"""Crash and abandonment regressions for the project-scoped orchestration authority."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import loom_install  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_release  # noqa: E402
import loom_reliability  # noqa: E402


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ControlPlaneRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_temp = tempfile.TemporaryDirectory()
        cls.fixture_root = Path(cls.fixture_temp.name)
        cls.source = Path(__file__).resolve().parents[1]
        cls.public = cls.fixture_root / "public"
        cls.installed = cls.fixture_root / "installed"
        loom_release.build_public(
            cls.source, cls.public,
            forbidden_tokens=[
                "-".join(("private", "fixture", "token")),
                "-".join(("owner", "fixture", "token")),
            ],
            source_classification="public-release")
        loom_install.install(cls.public, cls.installed)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temp.cleanup()

    def setUp(self):
        self.prior_backend = os.environ.get("LOOM_TEST_ALLOW_LEGACY_BACKEND")
        os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = "1"
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        (self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        self.repo = self.root / "target"
        _write(self.repo / "src" / "app.py", "VALUE = 1\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "config", "user.email",
            "test@example.invalid"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "config", "user.name", "test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "commit", "-qm", "baseline"], check=True)
        self.request = "Plan a financial double-entry accounting change to src/app.py"

    def tearDown(self):
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
    def action(result):
        return json.loads(Path(result["action_path"]).read_text(encoding="utf-8"))

    def test_pristine_abandoned_plan_is_quarantined_and_superseded(self):
        first = self.invoke()
        first_action = self.action(first)

        second = self.invoke()

        receipt = second["prior_recovery"]
        self.assertEqual("superseded", receipt["reason"])
        self.assertTrue(receipt["changes_made"])
        self.assertTrue(receipt["reversible"])
        self.assertTrue(receipt["complete_seed"])
        old = json.loads(Path(first["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual("superseded", old["status"])
        self.assertEqual(receipt, old["recovery_receipt"])
        quarantine = self.home.joinpath(*receipt["quarantine_relative"].split("/"))
        self.assertEqual(first_action["pack_seed"]["manifest"],
                         loom_reliability.deterministic_manifest(quarantine))
        self.assertTrue((self.repo / "plans").is_dir())

    def test_owner_modified_pack_blocks_without_deleting_or_quarantining(self):
        first = self.invoke()
        manifest = self.repo / "plans" / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + "\nOwner-authored content.\n",
            encoding="utf-8")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "content that is not byte-identical") as raised:
            self.invoke()

        self.assertEqual("RECOVERY_DECISION_REQUIRED", raised.exception.code)
        self.assertIn("Owner-authored content", manifest.read_text(encoding="utf-8"))
        self.assertEqual("pending", self.action(first)["status"])

    def test_partial_seed_install_recovers_on_next_invocation(self):
        def interrupted(stage, pack, expected):
            pack.mkdir(parents=True)
            item = expected["files"][0]
            raw = Path(stage).joinpath(*item["path"].split("/")).read_bytes()
            loom_reliability.atomic_write_bytes(
                Path(pack).joinpath(*item["path"].split("/")), raw)
            raise OSError("seeded interruption")

        with mock.patch.object(
                loom_orchestrator, "_copy_seed_stage", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded interruption"):
                self.invoke()
        partial = loom_reliability.deterministic_manifest(self.repo / "plans")
        self.assertEqual(1, len(partial["files"]))

        resumed = self.invoke()

        self.assertEqual("interrupted-initialization",
                         resumed["prior_recovery"]["reason"])
        self.assertFalse(resumed["prior_recovery"]["complete_seed"])

    def test_partial_quarantine_copy_resumes_idempotently(self):
        self.invoke()
        def interrupted(source, destination, manifest):
            destination = Path(destination)
            destination.mkdir(parents=True, exist_ok=True)
            item = manifest["files"][0]
            raw = Path(source).joinpath(*item["path"].split("/")).read_bytes()
            loom_reliability.atomic_write_bytes(
                destination.joinpath(*item["path"].split("/")), raw)
            raise OSError("seeded quarantine interruption")

        with mock.patch.object(
                loom_orchestrator, "_copy_recovery_tree", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded quarantine interruption"):
                self.invoke()
        self.assertTrue((self.repo / "plans").is_dir())

        resumed = self.invoke()

        self.assertEqual("superseded", resumed["prior_recovery"]["reason"])

    def test_recovery_resumes_after_detachment_before_action_receipt_write(self):
        first = self.invoke()
        original = loom_orchestrator._write_action

        def interrupted(path, value, security=None):
            if value["action_id"] == first["action_id"] \
                    and value["status"] == "superseded":
                raise OSError("seeded receipt interruption")
            return original(path, value, security)

        with mock.patch.object(
                loom_orchestrator, "_write_action", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded receipt interruption"):
                self.invoke()
        self.assertFalse((self.repo / "plans").exists())

        resumed = self.invoke()

        self.assertEqual("superseded", resumed["prior_recovery"]["reason"])
        self.assertTrue(resumed["prior_recovery"]["changes_made"])

    def test_explicit_cancel_clears_pointer_and_only_removes_pristine_seed(self):
        opened = self.invoke()
        action = self.action(opened)
        pointer = Path(opened["action_path"]).parent / loom_orchestrator.ACTIVE_POINTER_FILE
        self.assertTrue(pointer.is_file())

        cancelled = loom_orchestrator.cancel(opened["action_path"])

        self.assertEqual("cancelled", cancelled["status"])
        self.assertFalse(pointer.exists())
        self.assertFalse((self.repo / "plans").exists())
        self.assertTrue(action["remove_pristine_pack"])


if __name__ == "__main__":
    unittest.main()
