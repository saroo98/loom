"""Crash and abandonment regressions for the project-scoped orchestration authority."""

import json
import hashlib
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
import loom_fault_harness  # noqa: E402
import loom_message  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_plan_store  # noqa: E402
import loom_release  # noqa: E402
import loom_reliability  # noqa: E402
import loom_session  # noqa: E402


CONCURRENCY_EVENT_TIMEOUT_SECONDS = 30
CONCURRENCY_RESULT_TIMEOUT_SECONDS = 60


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


def _owned_pack(result):
    action = json.loads(Path(result["action_path"]).read_text(encoding="utf-8"))
    return loom_orchestrator._action_pack_root(action)


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
        cls.repo_fixture = cls.fixture_root / "repo-fixture"
        _write(cls.repo_fixture / "src" / "app.py", "VALUE = 1\n")
        cls.fixture_home = cls.fixture_root / "fixture-home"
        loom_fault_harness.initialize_git_fixture(
            cls.repo_fixture, cls.fixture_home)

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
        loom_fault_harness.clone_git_fixture(
            self.repo_fixture, self.repo, self.home / "git-home")
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

    def supersede(self):
        return loom_orchestrator.invoke(
            request=self.request + " Include one revised acceptance requirement.",
            cwd=self.repo, home=self.home, install_root=self.installed)

    def make_case(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        home = root / "home"
        home.mkdir()
        (home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        repo = root / "target"
        loom_fault_harness.clone_git_fixture(
            self.repo_fixture, repo, home / "git-home")
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

        second = self.supersede()

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
        self.assertTrue(_owned_pack(second).is_dir())

    def test_historical_v2_recovery_receipt_remains_readable(self):
        first = self.invoke()
        self.supersede()
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
        second = self.supersede()
        action_path = Path(first["action_path"])
        original = self.action(first)
        current_pack = _owned_pack(second)
        before = loom_reliability.deterministic_manifest(current_pack)
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
                    before, loom_reliability.deterministic_manifest(current_pack))

    def test_pristine_seed_recovers_and_retry_proceeds(self):
        first = self.invoke()
        original = self.action(first)

        retried = self.supersede()

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
                    pack = _owned_pack(first)
                    pack_before = loom_reliability.exact_tree_manifest(pack)

                    loom_orchestrator.invoke(
                        request=request, cwd=repo, home=home,
                        install_root=self.installed)

                    self.assertEqual(action_before, action_path.read_bytes())
                    self.assertEqual(pointer_before, pointer_path.read_bytes())
                    self.assertEqual(
                        pack_before,
                        loom_reliability.exact_tree_manifest(pack))
                finally:
                    temporary.cleanup()

    def test_owner_modified_pack_blocks_until_explicit_safe_cancellation(self):
        first = self.invoke()
        manifest = _owned_pack(first) / "MANIFEST.md"
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
        private_marker = "owner-private-marker-never-project"
        _write(
            self.repo / "plans" / "owner-notes.md",
            f"owner-authored plan {private_marker}\n")
        project_before = loom_reliability.exact_tree_manifest(self.repo)
        plans_before = loom_reliability.exact_tree_manifest(self.repo / "plans")
        safe_next_action = (
            "Quarantine or repair the lifecycle store, then ask Loom for a fresh plan.")

        result = self.invoke()

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertEqual("plan", result["intent"])
        self.assertFalse(result["owner_message"]["changes_made"])
        self.assertEqual("not-applicable", result["owner_message"]["undo_status"])
        self.assertIsNone(result["owner_message"]["result_path"])
        self.assertEqual(
            "Follow the precise Safe next action in the non-authoritative result.",
            result["owner_message"]["next_action"])
        self.assertEqual(
            1, result["user_message"].count(
                f"Safe next action: {safe_next_action}"))
        self.assertNotIn("say continue", json.dumps(result, sort_keys=True).casefold())
        self.assertNotIn(private_marker, json.dumps(result, sort_keys=True))
        self.assertNotIn("action_id", result)
        self.assertNotIn("action_path", result)
        self.assertNotIn("generation_id", result)
        self.assertNotIn("plan_identity", result)
        self.assertNotIn("result_path", result)
        self.assertIsNone(
            result["terminal_authority"]["implementation_authorized"])
        self.assertEqual(project_before, loom_reliability.exact_tree_manifest(self.repo))
        self.assertEqual(
            plans_before, loom_reliability.exact_tree_manifest(self.repo / "plans"))
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertFalse((self.repo / "plans" / "MANIFEST.md").exists())
        self.assertFalse((self.repo / "plans" / ".loom-small-lifecycle.json").exists())
        self.assertFalse(
            (self.repo / "plans" / loom_plan_store.INDEX_NAME).exists())
        orchestration_directories = list((self.home / "instances").glob(
            "*/runtime/projects/*/orchestrations"))
        for directory in orchestration_directories:
            self.assertEqual(
                [], list(directory.glob(
                    "????????-????-????-????-????????????.json")))
            self.assertFalse(
                (directory / loom_orchestrator.ACTIVE_POINTER_FILE).exists())

    def test_tier_s_promotion_preserves_inline_recovery_identity(self):
        """Break caught: Tier-S promotion truncates the sealed recovery class."""
        private_marker = "owner-private-marker-tier-s-recovery"
        _write(
            self.repo / "plans" / "owner-notes.md",
            f"owner-authored plan {private_marker}\n")
        self.request = "Plan a tiny Python command-line greeting tool."
        project_before = loom_reliability.exact_tree_manifest(self.repo)
        observed_prepared = []
        original_capsule = loom_orchestrator._tier_s_host_capsule
        original_run = loom_session.SessionController.run

        def force_tier_s_overflow(contract):
            if contract["tier"] == "S":
                raise loom_orchestrator.OrchestratorError(
                    "TIER_PROMOTION_REQUIRED",
                    "complete Tier S decision context exceeds the host capsule bound")
            return original_capsule(contract)

        def capture_prepared(controller, request, **kwargs):
            observed_prepared.append(kwargs["prepared"])
            return original_run(controller, request, **kwargs)

        with mock.patch.object(
                loom_orchestrator, "_tier_s_host_capsule",
                side_effect=force_tier_s_overflow), \
                mock.patch.object(
                    loom_session.SessionController, "run", capture_prepared):
            try:
                result = self.invoke()
            except loom_session.SessionInterrupted as exc:
                self.fail(
                    "genuine promoted inline recovery was interrupted: "
                    f"{exc.__cause__}")

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertEqual("M", result["tier"])
        self.assertEqual(1, len(observed_prepared))
        route = observed_prepared[0].route_contract
        evidence = list(route["evidence"])
        self.assertLessEqual(len(evidence), 16)
        self.assertIn("tier-s-host-capsule-overflow", evidence)
        self.assertEqual([
            "useful-planning-recovery",
            "inline-plan-lifecycle-authority-untrusted",
        ], evidence[-2:])
        self.assertEqual(project_before, loom_reliability.exact_tree_manifest(self.repo))
        self.assertNotIn(private_marker, json.dumps(result, sort_keys=True))

    def test_forged_inline_recovery_handler_cannot_seal_owner_authority(self):
        """Break caught: a relabelled recovery handler can seal hidden action authority."""
        private_marker = "owner-private-marker-forged-result"
        _write(
            self.repo / "plans" / "owner-notes.md",
            f"owner-authored plan {private_marker}\n")
        project_before = loom_reliability.exact_tree_manifest(self.repo)
        original_run = loom_session.SessionController.run

        def run_with_forged_handler(controller, request, **kwargs):
            handler = controller.handlers["plan"]

            def forged(context):
                return {
                    **handler(context),
                    "reversible_action_ids": ["forged-action-authority"],
                }

            controller.handlers["plan"] = forged
            return original_run(controller, request, **kwargs)

        with mock.patch.object(
                loom_session.SessionController, "run", run_with_forged_handler), \
                self.assertRaises(loom_session.SessionInterrupted) as raised:
            self.invoke()

        self.assertIsInstance(raised.exception.__cause__, loom_session.SessionBlocked)
        self.assertEqual("HANDLER_RESULT_INVALID", raised.exception.__cause__.code)
        self.assertEqual(project_before, loom_reliability.exact_tree_manifest(self.repo))
        journals = list((self.home / "instances").glob(
            "*/runtime/projects/*/session-journal.json"))
        self.assertEqual(1, len(journals))
        journal = json.loads(journals[0].read_text(encoding="utf-8"))
        self.assertNotIn(
            "session-receipt-sealed", [event["kind"] for event in journal["events"]])
        self.assertNotIn(private_marker, json.dumps(journal, sort_keys=True))

    def test_unproven_pack_is_preserved(self):
        scenarios = ["unknown", "file-link", "root-link", "special", "mismatched"]
        executed = set()
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                temporary, home, repo = self.make_case()
                try:
                    first = self.invoke_case(home, repo)
                    pack = _owned_pack(first)
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
                self.assertTrue(
                    release.wait(CONCURRENCY_EVENT_TIMEOUT_SECONDS),
                    "concurrency test did not release the first invocation")
            return original(**kwargs)

        with mock.patch.object(loom_orchestrator, "_invoke_under_lock", side_effect=delayed):
            with ThreadPoolExecutor(max_workers=2) as pool:
                one = pool.submit(self.invoke)
                try:
                    self.assertTrue(
                        entered.wait(CONCURRENCY_EVENT_TIMEOUT_SECONDS),
                        "first invocation did not reach the serialized section")
                    two = pool.submit(self.invoke)
                    time.sleep(0.1)
                finally:
                    release.set()
                results = [
                    one.result(timeout=CONCURRENCY_RESULT_TIMEOUT_SECONDS),
                    two.result(timeout=CONCURRENCY_RESULT_TIMEOUT_SECONDS),
                ]

        self.assertEqual(1, len({item["action_id"] for item in results}))
        recovered = [item for item in results if "prior_recovery" in item]
        self.assertEqual([], recovered)
        pointer = json.loads((Path(results[0]["action_path"]).parent /
                              loom_orchestrator.ACTIVE_POINTER_FILE).read_text(
                                  encoding="utf-8"))
        self.assertEqual(results[0]["action_id"], pointer["action_id"])

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

    def test_partial_seed_stage_is_preserved_and_requires_owner_recovery(self):
        def interrupted(stage, *_args, **_kwargs):
            _write(Path(stage) / "partial-seed.txt", "partial\n")
            raise OSError("seeded interruption")

        with mock.patch.object(
                loom_orchestrator, "_seed_manifest", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded interruption"):
                self.invoke()
        self.assertFalse((self.repo / "plans").exists())
        stages = list(self.repo.glob(".loom-plan-stage-*"))
        self.assertEqual(1, len(stages))
        before = loom_reliability.deterministic_manifest(stages[0])

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "cannot be proven from the exact v2 seed"):
            self.invoke()

        self.assertEqual(before, loom_reliability.deterministic_manifest(stages[0]))

    def test_quarantine_rename_resumes_idempotently(self):
        self.invoke()
        original = loom_orchestrator._atomic_quarantine_tree

        def interrupted(source, destination, **kwargs):
            self.assertTrue(original(source, destination, **kwargs))
            raise OSError("seeded quarantine interruption")

        with mock.patch.object(
                loom_orchestrator, "_atomic_quarantine_tree", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "seeded quarantine interruption"):
                self.supersede()
        self.assertFalse((self.repo / "plans").exists())

        resumed = self.supersede()

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
                self.supersede()
        self.assertFalse((self.repo / "plans").exists())

        resumed = self.supersede()

        self.assertEqual("superseded", resumed["prior_recovery"]["reason"])
        self.assertTrue(resumed["prior_recovery"]["changes_made"])

    def test_recovery_resumes_when_successor_pointer_publication_is_interrupted(self):
        """A pre-publication interruption retains one receipt-bound successor."""
        first = self.invoke()
        first_path = Path(first["action_path"])
        pointer_path = first_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        transition = (
            first_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / first["action_id"] / loom_orchestrator.RECOVERY_CONTROL_TRANSITION)
        stage_path = (
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_POINTER)
        receipt_path = (
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_RECEIPT)
        original = loom_reliability.atomic_rename_noreplace
        injected = False

        def interrupt_before_publication(source, destination, **kwargs):
            nonlocal injected
            if not injected \
                    and kwargs.get("source_role") == "successor_pointer_stage" \
                    and kwargs.get("destination_role") == "active_successor_pointer":
                injected = True
                raise loom_reliability.ReliabilityError(
                    "successor pointer publication interruption")
            return original(source, destination, **kwargs)

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=interrupt_before_publication):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
                self.supersede()

        self.assertTrue(injected)
        self.assertEqual("RECOVERY_RACE", interrupted.exception.code)
        retired = self.action(first)
        self.assertIn(retired["status"], loom_orchestrator.TERMINAL_ACTION_STATUSES)
        self.assertFalse(pointer_path.exists())
        self.assertTrue(stage_path.is_file())
        self.assertTrue(receipt_path.is_file())
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(first["action_id"], receipt["source_action_id"])
        self.assertEqual(
            retired["recovery_receipt"]["receipt_hash"],
            receipt["source_recovery_receipt_hash"])
        self.assertEqual(
            hashlib.sha256(stage_path.read_bytes()).hexdigest(),
            receipt["pointer_sha256"])
        pending = [
            action for action in first_path.parent.glob("*.json")
            if action.name != loom_orchestrator.ACTIVE_POINTER_FILE
            and json.loads(action.read_text(encoding="utf-8"))["status"]
            not in loom_orchestrator.TERMINAL_ACTION_STATUSES
        ]
        self.assertEqual(1, len(pending))
        successor_id = json.loads(pending[0].read_text(encoding="utf-8"))["action_id"]
        self.assertEqual(successor_id, receipt["successor_action_id"])

        resumed = self.supersede()

        self.assertEqual(successor_id, resumed["action_id"])
        self.assertEqual(
            successor_id,
            loom_orchestrator._read_active_pointer(first_path.parent)["action_id"])
        self.assertIn(
            self.action(first)["status"], loom_orchestrator.TERMINAL_ACTION_STATUSES)
        self.assertFalse(stage_path.exists())
        remaining = [
            action for action in first_path.parent.glob("*.json")
            if action.name != loom_orchestrator.ACTIVE_POINTER_FILE
            and json.loads(action.read_text(encoding="utf-8"))["status"]
            not in loom_orchestrator.TERMINAL_ACTION_STATUSES
        ]
        self.assertEqual([successor_id], [
            json.loads(action.read_text(encoding="utf-8"))["action_id"]
            for action in remaining])

    def test_quarantine_receipt_is_bounded_authenticated_and_restorable(self):
        first = self.invoke()
        seed = self.action(first)["pack_seed"]["manifest"]

        second = self.supersede()

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
        second = self.supersede()
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
        current_pack = _owned_pack(second)
        before = loom_reliability.deterministic_manifest(current_pack)

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "recovery receipt v3 digest"):
            self.invoke()

        self.assertEqual(before, loom_reliability.deterministic_manifest(current_pack))
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
        owner_directory = _owned_pack(opened) / "owner-empty"
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
        manifest = _owned_pack(opened) / "MANIFEST.md"
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
        pack = _owned_pack(opened)
        action["pack_seed"]["manifest"] = loom_reliability.deterministic_manifest(pack)
        action["action_hash"] = loom_orchestrator._action_hash(action)
        action_path.write_text(
            json.dumps(action, sort_keys=True, separators=(",", ":")), encoding="utf-8")

        cancelled = loom_orchestrator.cancel(action_path)

        self.assertEqual(1, cancelled["recovery_receipt"]["manifest_schema_version"])
        self.assertEqual("preserved-in-place",
                         cancelled["recovery_receipt"]["source_disposition"])
        self.assertTrue((pack / "MANIFEST.md").is_file())

    def test_historical_cancelled_actions_remain_readable_after_upgrade(self):
        for schema_version in (
                7, loom_orchestrator.OWNER_MESSAGE_ACTION_SCHEMA_VERSION,
                loom_orchestrator.ACTION_SCHEMA_VERSION):
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
                    elif schema_version == \
                            loom_orchestrator.OWNER_MESSAGE_ACTION_SCHEMA_VERSION:
                        action = {
                            key: value for key, value in action.items()
                            if key in loom_orchestrator.ACTION_FIELDS_V10}
                        action["schema_version"] = schema_version
                        action["owner_message"] = loom_message.build(
                            state="progress",
                            consequence={"S": "ordinary", "M": "material", "L": "high",
                                         "XL": "critical"}[action["tier"]],
                            verification="pending", freshness="current",
                            changes_made=False, undo_status="not-applicable",
                            summary="Loom prepared the next safe frontier.",
                            next_action="Complete and verify the sealed frontier.",
                            receipt_id="action-" + action["action_id"])
                    action["action_hash"] = loom_orchestrator._action_hash(action)
                    action_path.write_text(
                        json.dumps(action, sort_keys=True, separators=(",", ":")),
                        encoding="utf-8")
                    (action_path.parent /
                     loom_orchestrator.ACTIVE_POINTER_FILE).unlink()

                    retried = self.invoke_case(home, repo)

                    self.assertNotEqual("ACTION_CORRUPT", retried.get("code"))
                    self.assertIn(retried["status"], {"blocked", "action-required"})
                    self.assertTrue((_owned_pack(retried) / "MANIFEST.md").is_file())
                finally:
                    temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
