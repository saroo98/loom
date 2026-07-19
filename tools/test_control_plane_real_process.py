"""Real-process crash and concurrency regressions for planning recovery."""

import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_fault_harness  # noqa: E402
import loom_install  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_release  # noqa: E402
import loom_reliability  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _receipt_quarantine(home, repo, receipt):
    if receipt["schema_version"] == 3:
        if receipt["quarantine_scope"] == "owner-home":
            return Path(home).joinpath(
                *receipt["owner_quarantine_relative"].split("/"))
        if receipt["quarantine_scope"] == "project-local":
            return Path(repo) / receipt["project_quarantine_relative"]
        raise AssertionError("receipt has no quarantine locator")
    return Path(home).joinpath(*receipt["quarantine_relative"].split("/"))


class RealProcessControlPlaneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_temp = tempfile.TemporaryDirectory(prefix="loom-real-process-fixture-")
        cls.fixture_root = Path(cls.fixture_temp.name)
        cls.public = cls.fixture_root / "public"
        cls.installed = cls.fixture_root / "installed"
        loom_release.build_public(
            ROOT, cls.public,
            forbidden_tokens=[
                "-".join(("private", "real", "process", "fixture")),
                "-".join(("owner", "real", "process", "fixture")),
            ],
            source_classification="public-release")
        loom_install.install(cls.public, cls.installed)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="loom-real-process-")
        self.root = Path(self.temp.name)
        self.home, self.repo = self._initialize_case(self.root)
        self.request = "Plan a financial double-entry accounting change to src/app.py"

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _initialize_case(root):
        home = root / "home"
        home.mkdir(parents=True)
        (home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        repo = root / "target"
        _write(repo / "src" / "app.py", "VALUE = 1\n")
        environment = loom_fault_harness.disposable_environment(home)
        subprocess.run(["git", "init", "-q", str(repo)], check=True, env=environment)
        subprocess.run([
            "git", "-C", str(repo), "config", "user.email", "test@example.invalid",
        ], check=True, env=environment)
        subprocess.run([
            "git", "-C", str(repo), "config", "user.name", "test",
        ], check=True, env=environment)
        subprocess.run([
            "git", "-C", str(repo), "add", "-A",
        ], check=True, env=environment)
        subprocess.run([
            "git", "-C", str(repo), "commit", "-qm", "baseline",
        ], check=True, env=environment)
        return home, repo

    def make_case(self):
        temporary = tempfile.TemporaryDirectory(prefix="loom-real-process-case-")
        root = Path(temporary.name)
        home, repo = self._initialize_case(root)
        return temporary, root, home, repo

    def payload(self, home, repo, *, operation="invoke", boundary=None,
                action_path=None, hold=None, marker=None, release=None):
        value = {
            "operation": operation,
            "home": str(home),
            "install_root": str(self.installed),
        }
        if operation == "invoke":
            value.update({"cwd": str(repo), "request": self.request})
            if boundary is not None:
                value["boundary"] = boundary
        else:
            value["action_path"] = str(action_path)
        if hold is not None:
            value.update({
                "hold": hold, "marker": str(marker), "release": str(release),
            })
        return value

    def run_invoke(self, home=None, repo=None, *, boundary=None):
        return loom_fault_harness.run_orchestrator_process(
            ROOT, self.payload(home or self.home, repo or self.repo, boundary=boundary))

    @staticmethod
    def result(process):
        try:
            return json.loads(process.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AssertionError(
                f"child returned invalid JSON; rc={process.returncode}; "
                f"stdout={process.stdout!r}; stderr={process.stderr!r}") from exc

    @staticmethod
    def pointer_path(home):
        matches = list(Path(home).glob(
            "instances/*/runtime/projects/*/orchestrations/active-action.json"))
        if len(matches) != 1:
            raise AssertionError(f"expected one active pointer, found {matches}")
        return matches[0]

    @classmethod
    def pointer(cls, home):
        return json.loads(cls.pointer_path(home).read_text(encoding="utf-8"))

    @staticmethod
    def action_files(home):
        return sorted(
            path for path in Path(home).glob(
                "instances/*/runtime/projects/*/orchestrations/*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE)

    @classmethod
    def assert_current_action(cls, test, home, expected_action_id):
        pointer = cls.pointer(home)
        test.assertEqual(expected_action_id, pointer["action_id"])
        action_path = cls.pointer_path(home).parent / f"{expected_action_id}.json"
        test.assertTrue(action_path.is_file())
        action = json.loads(action_path.read_text(encoding="utf-8"))
        test.assertEqual("pending", action["status"])
        return action

    @staticmethod
    def wait_for(path, process, *, timeout=20):
        deadline = time.monotonic() + timeout
        while not Path(path).exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                raise AssertionError(
                    f"barrier child exited early; rc={process.returncode}; "
                    f"stdout={stdout!r}; stderr={stderr!r}")
            if time.monotonic() >= deadline:
                process.kill()
                process.wait(timeout=10)
                raise AssertionError(f"timed out waiting for barrier {path}")
            time.sleep(0.02)

    def test_missing_action_without_artifacts_blocks_and_preserves_pointer(self):
        crashed = self.run_invoke(boundary="after-active-pointer")
        self.assertEqual(
            loom_fault_harness.ORCHESTRATION_CRASH_CODES["after-active-pointer"],
            crashed.returncode, crashed.stderr.decode("utf-8", errors="replace"))
        pointer = self.pointer(self.home)
        action_path = self.pointer_path(self.home).parent / f"{pointer['action_id']}.json"
        self.assertTrue(action_path.is_file())
        self.assertFalse((self.repo / "plans").exists())
        action_path.unlink()
        pointer_path = self.pointer_path(self.home)
        pointer_before = pointer_path.read_bytes()

        retried = self.run_invoke()

        self.assertEqual(2, retried.returncode, retried.stderr.decode("utf-8", errors="replace"))
        self.assertEqual("RECOVERY_DECISION_REQUIRED", self.result(retried)["code"])
        self.assertEqual(pointer_before, pointer_path.read_bytes())
        self.assertFalse(action_path.exists())
        self.assertFalse((self.repo / "plans").exists())

    def test_missing_action_with_pack_blocks_and_preserves_every_byte(self):
        opened = self.run_invoke()
        self.assertEqual(0, opened.returncode, opened.stderr.decode("utf-8", errors="replace"))
        opened_result = self.result(opened)
        action_path = Path(opened_result["action_path"])
        action_path.unlink()
        pointer_path = self.pointer_path(self.home)
        pointer_before = pointer_path.read_bytes()
        pack_before = loom_reliability.deterministic_manifest(self.repo / "plans")

        retried = self.run_invoke()

        self.assertEqual(2, retried.returncode, retried.stderr.decode("utf-8", errors="replace"))
        self.assertEqual("RECOVERY_DECISION_REQUIRED", self.result(retried)["code"])
        self.assertEqual(pointer_before, pointer_path.read_bytes())
        self.assertEqual(pack_before, loom_reliability.deterministic_manifest(self.repo / "plans"))
        recovery = list(Path(self.home).glob(
            "instances/*/runtime/projects/*/planning-recovery/*"))
        self.assertEqual([], recovery)

    def test_mismatched_pointer_blocks_without_mutation(self):
        opened = self.run_invoke()
        self.assertEqual(0, opened.returncode, opened.stderr.decode("utf-8", errors="replace"))
        pointer_path = self.pointer_path(self.home)
        pointer = self.pointer(self.home)
        pointer["project_id"] = "p-" + "0" * 32
        pointer["pointer_hash"] = loom_orchestrator._pointer_hash(pointer)
        pointer_path.write_text(
            json.dumps(pointer, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        pointer_before = pointer_path.read_bytes()
        pack_before = loom_reliability.deterministic_manifest(self.repo / "plans")

        retried = self.run_invoke()

        self.assertEqual(2, retried.returncode, retried.stderr.decode("utf-8", errors="replace"))
        self.assertEqual("ACTION_POINTER_CONFLICT", self.result(retried)["code"])
        self.assertEqual(pointer_before, pointer_path.read_bytes())
        self.assertEqual(pack_before, loom_reliability.deterministic_manifest(self.repo / "plans"))

    def test_recoverable_initialization_process_deaths_converge(self):
        boundaries = (
            "after-initializing-action",
            "after-prepared-action",
            "after-pack-install",
            "after-installed-action",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                temporary, _root, home, repo = self.make_case()
                try:
                    crashed = self.run_invoke(home, repo, boundary=boundary)
                    self.assertEqual(
                        loom_fault_harness.ORCHESTRATION_CRASH_CODES[boundary],
                        crashed.returncode,
                        crashed.stderr.decode("utf-8", errors="replace"))

                    retried = self.run_invoke(home, repo)

                    self.assertEqual(
                        0, retried.returncode,
                        retried.stderr.decode("utf-8", errors="replace"))
                    result = self.result(retried)
                    self.assert_current_action(self, home, result["action_id"])
                    tombstones = list(repo.glob(".loom-recovery-*"))
                    self.assertEqual([], tombstones)
                finally:
                    temporary.cleanup()

    def test_unsealed_stage_process_death_blocks_without_moving_unknown_data(self):
        crashed = self.run_invoke(boundary="after-seed-stage")
        self.assertEqual(
            loom_fault_harness.ORCHESTRATION_CRASH_CODES["after-seed-stage"],
            crashed.returncode, crashed.stderr.decode("utf-8", errors="replace"))
        stages = list(Path(self.home).glob(
            "instances/*/runtime/projects/*/orchestrations/.staging/*/plans"))
        stages.extend(self.repo.glob(".loom-plan-stage-*"))
        self.assertEqual(1, len(stages))
        stage_before = loom_reliability.deterministic_manifest(stages[0])
        old_pointer = self.pointer(self.home)
        old_action_path = self.pointer_path(self.home).parent / \
            f"{old_pointer['action_id']}.json"

        retried = self.run_invoke()

        self.assertEqual(2, retried.returncode)
        self.assertEqual("RECOVERY_DECISION_REQUIRED", self.result(retried)["code"])
        self.assertEqual(stage_before, loom_reliability.deterministic_manifest(stages[0]))
        cancelled = loom_fault_harness.run_orchestrator_process(
            ROOT, self.payload(
                self.home, self.repo, operation="cancel", action_path=old_action_path))
        self.assertEqual(0, cancelled.returncode)
        receipt = self.result(cancelled)["recovery_receipt"]
        self.assertEqual("preserved-in-place", receipt["source_disposition"])
        self.assertEqual(stage_before, loom_reliability.deterministic_manifest(stages[0]))

    def test_recovery_process_deaths_converge_with_exact_quarantine(self):
        boundaries = (
            "after-quarantine-move",
            "after-recovery-action-write",
            "after-pointer-clear",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                temporary, _root, home, repo = self.make_case()
                try:
                    opened = self.run_invoke(home, repo)
                    self.assertEqual(0, opened.returncode)
                    opened_result = self.result(opened)
                    old_action_path = Path(opened_result["action_path"])
                    seed = json.loads(old_action_path.read_text(
                        encoding="utf-8"))["pack_seed"]["manifest"]

                    crashed = self.run_invoke(home, repo, boundary=boundary)
                    self.assertEqual(
                        loom_fault_harness.ORCHESTRATION_CRASH_CODES[boundary],
                        crashed.returncode,
                        crashed.stderr.decode("utf-8", errors="replace"))

                    retried = self.run_invoke(home, repo)

                    self.assertEqual(
                        0, retried.returncode,
                        retried.stderr.decode("utf-8", errors="replace"))
                    result = self.result(retried)
                    self.assert_current_action(self, home, result["action_id"])
                    old_action = json.loads(old_action_path.read_text(encoding="utf-8"))
                    receipt = old_action["recovery_receipt"]
                    quarantine = _receipt_quarantine(home, repo, receipt)
                    self.assertEqual(seed, loom_reliability.exact_tree_manifest(
                        quarantine, max_entries=64,
                        max_file_bytes=loom_orchestrator.MAX_RECOVERY_FILE_BYTES,
                        max_total_bytes=loom_orchestrator.MAX_RECOVERY_TOTAL_BYTES))
                    self.assertEqual([], list(repo.glob(".loom-recovery-*")))
                finally:
                    temporary.cleanup()

    def test_legacy_partial_tombstone_is_preserved_in_auxiliary_quarantine(self):
        opened = self.run_invoke()
        self.assertEqual(0, opened.returncode)
        opened_result = self.result(opened)
        old_action_path = Path(opened_result["action_path"])
        seed = json.loads(old_action_path.read_text(
            encoding="utf-8"))["pack_seed"]["manifest"]
        tombstone = self.repo / f".loom-recovery-{opened_result['action_id']}"
        (self.repo / "plans").rename(tombstone)
        recovery_root = loom_reliability.ensure_private_directory(
            old_action_path.parent.parent,
            [loom_orchestrator.RECOVERY_DIRECTORY, opened_result["action_id"]])
        quarantine = recovery_root / "plans"
        shutil.copytree(tombstone, quarantine, copy_function=shutil.copy2)
        first_file = next(path for path in tombstone.rglob("*") if path.is_file())
        first_file.unlink()
        tombstone_before = loom_reliability.exact_tree_manifest(
            tombstone, max_entries=64,
            max_file_bytes=loom_orchestrator.MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=loom_orchestrator.MAX_RECOVERY_TOTAL_BYTES)
        quarantine_before = loom_reliability.exact_tree_manifest(
            quarantine, max_entries=64,
            max_file_bytes=loom_orchestrator.MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=loom_orchestrator.MAX_RECOVERY_TOTAL_BYTES)
        self.assertEqual(seed, quarantine_before)

        retried = self.run_invoke()

        self.assertEqual(0, retried.returncode, retried.stderr.decode(
            "utf-8", errors="replace"))
        result = self.result(retried)
        self.assert_current_action(self, self.home, result["action_id"])
        self.assertFalse(tombstone.exists())
        old_action = json.loads(old_action_path.read_text(encoding="utf-8"))
        self.assertEqual("superseded", old_action["status"])
        receipt = old_action["recovery_receipt"]
        self.assertEqual(1, len(receipt["preserved_relatives"]))
        preserved = Path(self.home).joinpath(
            *receipt["preserved_relatives"][0].split("/"))
        self.assertEqual("legacy-tombstone", preserved.name)
        self.assertTrue(preserved.is_relative_to(self.home))
        self.assertEqual(tombstone_before, loom_reliability.exact_tree_manifest(
            preserved, max_entries=64,
            max_file_bytes=loom_orchestrator.MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=loom_orchestrator.MAX_RECOVERY_TOTAL_BYTES))
        self.assertEqual(quarantine_before, loom_reliability.exact_tree_manifest(
            quarantine, max_entries=64,
            max_file_bytes=loom_orchestrator.MAX_RECOVERY_FILE_BYTES,
            max_total_bytes=loom_orchestrator.MAX_RECOVERY_TOTAL_BYTES))
        body = dict(receipt)
        claimed = body.pop("receipt_hash")
        self.assertEqual(loom_orchestrator._hash(body), claimed)

    def _race(self, *, first_operation):
        opened = self.run_invoke()
        self.assertEqual(0, opened.returncode)
        opened_result = self.result(opened)
        old_action_path = Path(opened_result["action_path"])
        marker = self.root / f"{first_operation}.ready"
        release = self.root / f"{first_operation}.release"
        if first_operation == "cancel":
            first_payload = self.payload(
                self.home, self.repo, operation="cancel",
                action_path=old_action_path, hold="cancel-after-lock",
                marker=marker, release=release)
            second_payload = self.payload(self.home, self.repo)
        else:
            first_payload = self.payload(
                self.home, self.repo, hold="invoke-after-lock",
                marker=marker, release=release)
            second_payload = self.payload(
                self.home, self.repo, operation="cancel", action_path=old_action_path)
        first = loom_fault_harness.start_orchestrator_process(ROOT, first_payload)
        self.wait_for(marker, first)
        second = loom_fault_harness.start_orchestrator_process(ROOT, second_payload)
        time.sleep(0.2)
        self.assertIsNone(second.poll(), "the competing operation bypassed the project lock")
        release.write_text("continue\n", encoding="utf-8")
        first_done = loom_fault_harness.finish_orchestrator_process(first)
        second_done = loom_fault_harness.finish_orchestrator_process(second)
        return old_action_path, first_done, second_done

    def test_cancel_then_invoke_race_serializes_to_one_new_action(self):
        old_action_path, cancelled, invoked = self._race(first_operation="cancel")

        self.assertEqual(0, cancelled.returncode, cancelled.stderr.decode(
            "utf-8", errors="replace"))
        self.assertEqual("cancelled", self.result(cancelled)["status"])
        self.assertEqual(0, invoked.returncode, invoked.stderr.decode(
            "utf-8", errors="replace"))
        new_result = self.result(invoked)
        self.assert_current_action(self, self.home, new_result["action_id"])
        self.assertEqual("cancelled", json.loads(old_action_path.read_text(
            encoding="utf-8"))["status"])

    def test_invoke_then_cancel_race_serializes_without_cancelling_new_action(self):
        old_action_path, invoked, cancelled = self._race(first_operation="invoke")

        self.assertEqual(0, invoked.returncode, invoked.stderr.decode(
            "utf-8", errors="replace"))
        new_result = self.result(invoked)
        self.assert_current_action(self, self.home, new_result["action_id"])
        self.assertEqual(2, cancelled.returncode, cancelled.stderr.decode(
            "utf-8", errors="replace"))
        self.assertEqual("ACTION_TERMINAL", self.result(cancelled)["code"])
        self.assertEqual("superseded", json.loads(old_action_path.read_text(
            encoding="utf-8"))["status"])


if __name__ == "__main__":
    unittest.main()
