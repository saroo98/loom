"""Crash and abandonment regressions for the project-scoped orchestration authority."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock
import copy

sys.path.insert(0, str(Path(__file__).parent))
import loom_install  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_release  # noqa: E402
import loom_reliability  # noqa: E402


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

    def make_case(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        home = root / "home"
        home.mkdir()
        (home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        repo = root / "target"
        _write(repo / "src" / "app.py", "VALUE = 1\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run([
            "git", "-C", str(repo), "config", "user.email",
            "test@example.invalid"], check=True)
        subprocess.run([
            "git", "-C", str(repo), "config", "user.name", "test"], check=True)
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run([
            "git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
        return temporary, home, repo

    def invoke_case(self, home, repo, *, now=None):
        return loom_orchestrator.invoke(
            request=self.request, cwd=repo, home=home,
            install_root=self.installed, now=now)

    @staticmethod
    def action(result):
        return json.loads(Path(result["action_path"]).read_text(encoding="utf-8"))

    def test_pristine_abandoned_plan_is_quarantined_and_superseded(self):
        first = self.invoke()
        first_action = self.action(first)

        second = self.invoke()

        receipt = second["prior_recovery"]
        self.assertEqual(3, receipt["schema_version"])
        self.assertEqual("superseded", receipt["reason"])
        self.assertTrue(receipt["changes_made"])
        self.assertTrue(receipt["reversible"])
        self.assertTrue(receipt["complete_seed"])
        old = json.loads(Path(first["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual("superseded", old["status"])
        self.assertEqual(receipt, old["recovery_receipt"])
        quarantine = _receipt_quarantine(self.home, self.repo, receipt)
        self.assertEqual(first_action["pack_seed"]["manifest"],
                         loom_reliability.exact_tree_manifest(quarantine))
        self.assertTrue((self.repo / "plans").is_dir())

    def test_historical_v2_recovery_receipt_remains_readable(self):
        first = self.invoke()
        self.invoke()
        action_path = Path(first["action_path"])
        action = self.action(first)
        current = action["recovery_receipt"]
        legacy = {
            "schema_version": 2,
            "recovery_id": current["recovery_id"],
            "action_id": current["action_id"],
            "project_id": current["project_id"],
            "reason": current["reason"],
            "source_path": current["source_path"],
            "quarantine_relative": current["owner_quarantine_relative"],
            "preserved_relatives": current["preserved_relatives"],
            "seed_manifest_sha256": current["seed_manifest_sha256"],
            "quarantined_manifest_sha256": current["quarantined_manifest_sha256"],
            "manifest_schema_version": current["manifest_schema_version"],
            "complete_seed": current["complete_seed"],
            "changes_made": current["changes_made"],
            "reversible": current["reversible"],
            "source_disposition": current["source_disposition"],
            "cleanup_phase": "gc-complete",
            "recovered_at": current["recovered_at"],
        }
        legacy["receipt_hash"] = loom_orchestrator._hash(legacy)
        action["recovery_receipt"] = legacy
        action["action_hash"] = loom_orchestrator._action_hash(action)
        action_path.write_text(
            json.dumps(action, sort_keys=True, separators=(",", ":")), encoding="utf-8")

        _path, opened, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)

        self.assertEqual(2, opened["recovery_receipt"]["schema_version"])

    def test_rehashed_v3_recovery_tampering_fails_before_project_mutation(self):
        first = self.invoke()
        self.invoke()
        action_path = Path(first["action_path"])
        original = self.action(first)
        before = loom_reliability.deterministic_manifest(self.repo / "plans")
        mutations = {
            "scope": lambda receipt: receipt.update({"quarantine_scope": "project-local"}),
            "relocated-scope": lambda receipt: receipt.update({
                "quarantine_scope": "project-local",
                "owner_quarantine_relative": None,
                "project_quarantine_relative": (
                    f".loom-recovery-{receipt['action_id']}"),
                "project_namespace_changed": True,
                "owner_control_changed": False,
            }),
            "owner-locator": lambda receipt: receipt.update({
                "owner_quarantine_relative": receipt["owner_quarantine_relative"].replace(
                    "/plans", "/other")}),
            "control-claim": lambda receipt: receipt.update({
                "project_namespace_changed": False}),
            "rename-role": lambda receipt: receipt["quarantine_atomic_rename"].update({
                "source_role": "wrong-role"}),
            "cleanup": lambda receipt: receipt.update({
                "cleanup_phase": (
                    "reconciliation-required"
                    if receipt["cleanup_phase"] == "gc-complete"
                    else "gc-complete")}),
            "unsupported": lambda receipt: receipt.update({"schema_version": 99}),
        }
        for label, mutate in mutations.items():
            with self.subTest(tamper=label):
                action = copy.deepcopy(original)
                mutate(action["recovery_receipt"])
                receipt = action["recovery_receipt"]
                if receipt.get("schema_version") == 3:
                    body = dict(receipt)
                    body.pop("receipt_hash")
                    receipt["receipt_hash"] = loom_orchestrator._hash(body)
                action["action_hash"] = loom_orchestrator._action_hash(action)
                action_path.write_text(
                    json.dumps(action, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8")
                with self.assertRaisesRegex(
                        loom_orchestrator.OrchestratorError, "recovery receipt"):
                    loom_orchestrator._read_action(
                        action_path, owner_home=self.home, install_root=self.installed)
                self.assertEqual(
                    before, loom_reliability.deterministic_manifest(self.repo / "plans"))

    def test_pristine_seed_recovers_and_retry_proceeds(self):
        first = self.invoke()
        original = self.action(first)

        retried = self.invoke()

        receipt = retried["prior_recovery"]
        quarantine = _receipt_quarantine(self.home, self.repo, receipt)
        self.assertEqual("superseded", receipt["reason"])
        self.assertEqual(original["pack_seed"]["manifest"],
                         loom_reliability.exact_tree_manifest(quarantine))
        self.assertNotEqual(first["action_id"], retried["action_id"])
        self.assertEqual("pending", self.action(retried)["status"])

    def test_observation_and_memory_intents_do_not_supersede_active_plan(self):
        requests = (
            "Show Loom status",
            "Why is Loom blocked?",
            "Remember that I prefer concise plans",
            "Forget that I prefer concise plans",
        )
        for request in requests:
            with self.subTest(request=request):
                temporary, home, repo = self.make_case()
                try:
                    first = self.invoke_case(home, repo)
                    action_path = Path(first["action_path"])
                    pointer_path = action_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
                    action_before = action_path.read_bytes()
                    pointer_before = pointer_path.read_bytes()
                    pack_before = loom_reliability.exact_tree_manifest(repo / "plans")

                    loom_orchestrator.invoke(
                        request=request, cwd=repo, home=home,
                        install_root=self.installed)

                    self.assertEqual(action_before, action_path.read_bytes())
                    self.assertEqual(pointer_before, pointer_path.read_bytes())
                    self.assertEqual(
                        pack_before,
                        loom_reliability.exact_tree_manifest(repo / "plans"))
                finally:
                    temporary.cleanup()

    def test_owner_modified_pack_blocks_until_explicit_safe_cancellation(self):
        first = self.invoke()
        manifest = self.repo / "plans" / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + "\nOwner-authored content.\n",
            encoding="utf-8")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "cannot be proven from the exact v2 seed"):
            self.invoke()

        self.assertIn("Owner-authored content", manifest.read_text(encoding="utf-8"))
        self.assertEqual("pending", self.action(first)["status"])
        cancelled = loom_orchestrator.cancel(first["action_path"])
        self.assertEqual("preserved-in-place",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertIn("Owner-authored content", manifest.read_text(encoding="utf-8"))

    def test_preexisting_owner_plans_are_never_initialized_or_modified(self):
        _write(self.repo / "plans" / "owner-notes.md", "owner-authored plan\n")
        before = loom_reliability.exact_tree_manifest(self.repo / "plans")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "PLAN_PACK_EXISTS"):
            self.invoke()

        self.assertEqual(
            before, loom_reliability.exact_tree_manifest(self.repo / "plans"))
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertFalse((self.repo / "plans" / "MANIFEST.md").exists())
        self.assertFalse((self.repo / "plans" / ".loom-small-lifecycle.json").exists())

    def test_unproven_pack_is_preserved(self):
        scenarios = ["unknown", "file-link", "root-link", "special", "mismatched"]
        executed = set()
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                temporary, home, repo = self.make_case()
                try:
                    first = self.invoke_case(home, repo)
                    pack = repo / "plans"
                    if scenario == "unknown":
                        _write(pack / "owner-notes.md", "owner material\n")
                    elif scenario == "file-link":
                        target = next(path for path in pack.rglob("*") if path.is_file())
                        external = repo / "owner-external.txt"
                        external.write_bytes(target.read_bytes())
                        target.unlink()
                        try:
                            os.symlink(external, target)
                        except OSError:
                            continue
                    elif scenario == "root-link":
                        real_pack = repo / "owner-plans"
                        pack.rename(real_pack)
                        try:
                            os.symlink(real_pack, pack, target_is_directory=True)
                        except OSError:
                            real_pack.rename(pack)
                            continue
                    elif scenario == "special":
                        if not hasattr(os, "mkfifo") or os.name == "nt":
                            continue
                        os.mkfifo(pack / "owner.fifo")
                    else:
                        action_path = Path(first["action_path"])
                        action = json.loads(action_path.read_text(encoding="utf-8"))
                        manifest = dict(action["pack_seed"]["manifest"])
                        entries = [dict(item) for item in manifest["entries"]]
                        file_index = next(
                            index for index, item in enumerate(entries)
                            if item["kind"] == "file")
                        entries[file_index]["sha256"] = "0" * 64
                        manifest["entries"] = entries
                        body = dict(manifest)
                        body.pop("root_sha256")
                        manifest["root_sha256"] = loom_orchestrator._hash(body)
                        action["pack_seed"] = {**action["pack_seed"],
                                               "manifest": manifest}
                        action["action_hash"] = loom_orchestrator._action_hash(action)
                        action_path.write_text(
                            json.dumps(action, sort_keys=True, separators=(",", ":")),
                            encoding="utf-8")
                    before = loom_reliability.deterministic_manifest(pack) \
                        if scenario not in {"file-link", "root-link", "special"} else None
                    try:
                        self.invoke_case(home, repo)
                    except loom_orchestrator.OrchestratorError:
                        # The next project survey may independently reject a linked or special
                        # entry. Recovery itself must already have preserved the prior tree.
                        pass
                    if before is not None:
                        self.assertEqual(before, loom_reliability.deterministic_manifest(pack))
                    self.assertTrue(pack.exists() or pack.is_symlink())
                    executed.add(scenario)
                finally:
                    temporary.cleanup()
        self.assertIn("unknown", executed)
        self.assertIn("mismatched", executed)

    def test_concurrent_invocations_serialize_without_losing_a_seed(self):
        original = loom_orchestrator._invoke_under_lock
        entered = threading.Event()
        release = threading.Event()
        calls = 0
        calls_lock = threading.Lock()

        def delayed(**kwargs):
            nonlocal calls
            with calls_lock:
                calls += 1
                first = calls == 1
            if first:
                entered.set()
                self.assertTrue(release.wait(5))
            return original(**kwargs)

        with mock.patch.object(loom_orchestrator, "_invoke_under_lock", side_effect=delayed):
            with ThreadPoolExecutor(max_workers=2) as pool:
                one = pool.submit(self.invoke)
                self.assertTrue(entered.wait(5))
                two = pool.submit(self.invoke)
                time.sleep(0.1)
                release.set()
                results = [one.result(timeout=15), two.result(timeout=15)]

        self.assertEqual(2, len({item["action_id"] for item in results}))
        recovered = [item for item in results if "prior_recovery" in item]
        self.assertEqual(1, len(recovered))
        pointer = json.loads((Path(recovered[0]["action_path"]).parent /
                              loom_orchestrator.ACTIVE_POINTER_FILE).read_text(
                                  encoding="utf-8"))
        self.assertEqual(recovered[0]["action_id"], pointer["action_id"])

    def test_unsealed_staging_bytes_block_until_explicit_safe_cancellation(self):
        original = loom_orchestrator._write_action
        writes = 0

        def interrupted(path, value, security=None):
            nonlocal writes
            writes += 1
            if writes == 2 and value["pack_seed"]["state"] == "prepared":
                raise OSError("prepared action write interrupted")
            return original(path, value, security)

        with mock.patch.object(loom_orchestrator, "_write_action", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "prepared action write interrupted"):
                self.invoke()
        stage = next(self.repo.glob(".loom-plan-stage-*"))
        before = loom_reliability.deterministic_manifest(stage)
        action_dir = next((self.home / "instances").glob(
            "*/runtime/projects/*/orchestrations"))
        action_path = next(
            path for path in action_dir.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE)

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "cannot be proven from the exact v2 seed"):
            self.invoke()

        self.assertEqual(before, loom_reliability.deterministic_manifest(stage))
        cancelled = loom_orchestrator.cancel(action_path)
        self.assertEqual("preserved-in-place",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertEqual(before, loom_reliability.deterministic_manifest(stage))

    def test_partial_seed_install_recovers_on_next_invocation(self):
        def interrupted(stage, pack, expected, expected_source_identity):
            raise OSError("seeded interruption")

        with mock.patch.object(
                loom_orchestrator, "_copy_seed_stage", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded interruption"):
                self.invoke()
        self.assertFalse((self.repo / "plans").exists())
        self.assertEqual(1, len(list(self.repo.glob(".loom-plan-stage-*"))))

        resumed = self.invoke()

        self.assertEqual("interrupted-initialization",
                         resumed["prior_recovery"]["reason"])
        self.assertTrue(resumed["prior_recovery"]["complete_seed"])

    def test_quarantine_rename_resumes_idempotently(self):
        self.invoke()
        original = loom_orchestrator._atomic_quarantine_tree

        def interrupted(source, destination, **kwargs):
            self.assertTrue(original(source, destination, **kwargs))
            raise OSError("seeded quarantine interruption")

        with mock.patch.object(
                loom_orchestrator, "_atomic_quarantine_tree", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded quarantine interruption"):
                self.invoke()
        self.assertFalse((self.repo / "plans").exists())

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

    def test_recovery_resumes_when_pointer_clear_is_interrupted(self):
        first = self.invoke()
        original = loom_orchestrator._clear_active_pointer
        failed = False

        def interrupted(directory, action_id):
            nonlocal failed
            action = self.action(first)
            if not failed and action["status"] in {"superseded", "abandoned", "expired"}:
                failed = True
                raise OSError("pointer clear interruption")
            return original(directory, action_id)

        with mock.patch.object(
                loom_orchestrator, "_clear_active_pointer", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "pointer clear interruption"):
                self.invoke()

        resumed = self.invoke()
        self.assertNotEqual(first["action_id"], resumed["action_id"])

    def test_quarantine_receipt_is_bounded_authenticated_and_restorable(self):
        first = self.invoke()
        seed = self.action(first)["pack_seed"]["manifest"]

        second = self.invoke()

        receipt = second["prior_recovery"]
        body = dict(receipt)
        claimed = body.pop("receipt_hash")
        self.assertEqual(loom_orchestrator._hash(body), claimed)
        self.assertLessEqual(len(json.dumps(receipt, separators=(",", ":"))), 4096)
        quarantine = _receipt_quarantine(self.home, self.repo, receipt)
        self.assertFalse(quarantine.is_relative_to(self.repo))
        restored = self.root / "restored-plans"
        shutil.copytree(quarantine, restored, copy_function=shutil.copy2)
        self.assertEqual(seed, loom_reliability.exact_tree_manifest(restored))

    def test_tampered_recovery_receipt_blocks_without_project_mutation(self):
        first = self.invoke()
        second = self.invoke()
        action_path = Path(first["action_path"])
        action = json.loads(action_path.read_text(encoding="utf-8"))
        action["recovery_receipt"]["receipt_hash"] = "0" * 64
        action["action_hash"] = loom_orchestrator._action_hash(action)
        action_path.write_text(
            json.dumps(action, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        pointer_path = Path(second["action_path"]).parent / \
            loom_orchestrator.ACTIVE_POINTER_FILE
        pointer = {
            "schema_version": 1, "action_id": first["action_id"],
            "project_id": action["project_id"], "state": "active",
        }
        pointer["pointer_hash"] = loom_orchestrator._pointer_hash(pointer)
        pointer_path.write_text(
            json.dumps(pointer, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        before = loom_reliability.deterministic_manifest(self.repo / "plans")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "recovery receipt v3 digest"):
            self.invoke()

        self.assertEqual(before, loom_reliability.deterministic_manifest(self.repo / "plans"))
        self.assertEqual("pending", self.action(second)["status"])

    def test_expired_seed_is_recovered_before_retry(self):
        first = self.invoke()
        action = self.action(first)
        after_expiry = loom_orchestrator.loom_runtime._parse_time(
            action["expires_at"]) + loom_orchestrator.dt.timedelta(seconds=1)

        retried = self.invoke_case(self.home, self.repo, now=after_expiry)

        self.assertEqual("expired", retried["prior_recovery"]["reason"])
        self.assertEqual("expired", self.action(first)["status"])

    def test_explicit_cancel_clears_pointer_and_only_removes_pristine_seed(self):
        opened = self.invoke()
        action = self.action(opened)
        pointer = Path(opened["action_path"]).parent / loom_orchestrator.ACTIVE_POINTER_FILE
        self.assertTrue(pointer.is_file())

        cancelled = loom_orchestrator.cancel(opened["action_path"])

        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual("quarantined",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertFalse(pointer.exists())
        self.assertFalse((self.repo / "plans").exists())
        self.assertTrue(action["remove_pristine_pack"])

    def test_cancel_preserves_owner_added_empty_directory_and_is_terminal(self):
        opened = self.invoke()
        owner_directory = self.repo / "plans" / "owner-empty"
        owner_directory.mkdir()

        cancelled = loom_orchestrator.cancel(opened["action_path"])

        self.assertEqual("preserved-in-place",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertTrue(owner_directory.is_dir())
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "already cancelled"):
            loom_orchestrator.cancel(opened["action_path"])
        self.assertTrue(owner_directory.is_dir())

    @unittest.skipUnless(os.name == "nt", "NTFS alternate streams require Windows")
    def test_cancel_preserves_owner_added_alternate_data_stream(self):
        opened = self.invoke()
        manifest = self.repo / "plans" / "MANIFEST.md"
        stream = Path(str(manifest) + ":loom-owner-test")
        try:
            stream.write_bytes(b"owner-stream-bytes")
        except OSError as exc:
            self.skipTest(f"alternate streams unavailable: {exc}")

        cancelled = loom_orchestrator.cancel(opened["action_path"])

        self.assertEqual("preserved-in-place",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertEqual(b"owner-stream-bytes", stream.read_bytes())
        self.assertTrue(manifest.is_file())

    def test_manifest_v1_never_authorizes_automatic_pack_removal(self):
        opened = self.invoke()
        action_path = Path(opened["action_path"])
        action = json.loads(action_path.read_text(encoding="utf-8"))
        action["pack_seed"]["manifest"] = loom_reliability.deterministic_manifest(
            self.repo / "plans")
        action["action_hash"] = loom_orchestrator._action_hash(action)
        action_path.write_text(
            json.dumps(action, sort_keys=True, separators=(",", ":")), encoding="utf-8")

        cancelled = loom_orchestrator.cancel(action_path)

        self.assertEqual(1, cancelled["recovery_receipt"]["manifest_schema_version"])
        self.assertEqual("preserved-in-place",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertTrue((self.repo / "plans" / "MANIFEST.md").is_file())

    def test_historical_cancelled_actions_remain_readable_after_upgrade(self):
        for schema_version in (7, loom_orchestrator.ACTION_SCHEMA_VERSION):
            with self.subTest(schema_version=schema_version):
                temporary, home, repo = self.make_case()
                try:
                    opened = self.invoke_case(home, repo)
                    action_path = Path(opened["action_path"])
                    action = json.loads(action_path.read_text(encoding="utf-8"))
                    action["status"] = "cancelled"
                    if schema_version == 7:
                        action = {
                            key: value for key, value in action.items()
                            if key in loom_orchestrator.ACTION_FIELDS_V7}
                        action["schema_version"] = 7
                    action["action_hash"] = loom_orchestrator._action_hash(action)
                    action_path.write_text(
                        json.dumps(action, sort_keys=True, separators=(",", ":")),
                        encoding="utf-8")
                    (action_path.parent /
                     loom_orchestrator.ACTIVE_POINTER_FILE).unlink()

                    retried = self.invoke_case(home, repo)

                    self.assertNotEqual("ACTION_CORRUPT", retried.get("code"))
                    self.assertIn(retried["status"], {"blocked", "action-required"})
                    self.assertTrue((repo / "plans" / "MANIFEST.md").is_file())
                finally:
                    temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
