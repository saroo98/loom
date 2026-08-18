"""Durable executor freeze and exact host-operation ledger regressions."""

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import loom_executor_guard
import loom_operation_supervisor
import loom_reliability
import loom_vault
from test_loom_vault_v11 import TestCrypto


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")).hexdigest()


class ExecutorGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.owner = self.root / "owner"
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.create_private_directory(self.owner)
        else:
            self.owner.mkdir(mode=0o700)
        self.directory = loom_reliability.ensure_private_directory(
            self.owner, ["orchestration", "p-" + "1" * 32])
        self.action = {
            "action_id": "00000000-0000-4000-8000-000000000001",
            "project_id": "p-" + "1" * 32,
            "generation_id": "generation-" + "2" * 32,
            "operation_id": "3" * 64,
            "owner_home": str(self.owner),
            "intent": "execute",
        }
        self.control_post = self.event(
            "PostToolUse", tool_name="mcp__loom__start",
            tool_use_id="control-start")

        class FakeCrypto:
            def blind_index(inner_self, label, value):
                return hashlib.sha256(
                    ("owner-secret\0" + label + "\0" + value).encode(
                        "utf-8")).hexdigest()

        self.security = (
            FakeCrypto(), "10000000-0000-4000-8000-000000000001")
        self.vault_crypto = TestCrypto()
        self.vault = loom_vault.OwnerVault.create(
            self.owner / "vault" / "owner.sqlite3", crypto=self.vault_crypto,
            allow_test_crypto=True)
        self.canonical_security = loom_executor_guard.GuardSecurity(
            self.vault, self.vault_crypto,
            self.vault.identity()["owner_vault_id"])

    def tearDown(self):
        self.tmp.cleanup()

    def event(
            self, name, *, tool_name, tool_use_id, tool_input=None,
            session_id="host-session-1", turn_id="host-turn-1"):
        return {
            "hook_event_name": name,
            "cwd": str(self.root),
            "session_id": session_id,
            "turn_id": turn_id,
            "tool_name": tool_name,
            "tool_use_id": tool_use_id,
            "tool_input": tool_input or {},
        }

    def initialize_and_arm(self):
        initialized = loom_executor_guard.initialize(
            self.directory, self.action)
        self.assertEqual("awaiting-host", initialized["coverage_state"])
        armed = loom_executor_guard.observe_post(
            self.directory, self.action, self.control_post,
            lifecycle_control=True)
        self.assertEqual("active", armed["coverage_state"])
        return armed

    def test_freeze_waits_for_open_write_then_seals_after_exact_post(self):
        """Break caught: cancellation clears authority while a write remains in flight."""
        self.initialize_and_arm()
        pre = self.event(
            "PreToolUse", tool_name="apply_patch", tool_use_id="write-1",
            tool_input={"patch": "*** Update File: src/app.py\n+x"})
        post = self.event(
            "PostToolUse", tool_name="apply_patch", tool_use_id="write-1",
            tool_input=pre["tool_input"])
        opened = loom_executor_guard.begin_operation(
            self.directory, self.action, pre, operation_kind="structured-write")
        self.assertEqual("open", opened["operations"][0]["state"])
        frozen = loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        self.assertIsNotNone(frozen["freeze"])
        with self.assertRaises(loom_executor_guard.GuardPending):
            loom_executor_guard.seal_quiescence(
                self.directory, self.action,
                project_world_sha256="4" * 64,
                terminal_state="cancelled")

        closed = loom_executor_guard.observe_post(
            self.directory, self.action, post)
        self.assertEqual("closed", closed["operations"][0]["state"])
        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="cancelled")
        self.assertEqual("verified-host-terminal", evidence["case"])
        self.assertEqual(0, evidence["open_operation_count"])
        self.assertEqual(
            evidence,
            loom_executor_guard.seal_quiescence(
                self.directory, self.action,
                project_world_sha256="4" * 64,
                terminal_state="cancelled"))

    def test_frozen_never_admitted_guard_seals_without_host_session(self):
        """A start that admitted no mutation is exact positive quiescence evidence."""
        loom_executor_guard.initialize(self.directory, self.action)
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="authority-retirement")

        # Lifecycle/read-only posts can arrive after the freeze.  They did not
        # mutate the project and must not convert the exact zero-admission case
        # into an unprovable host session.
        loom_executor_guard.observe_post(
            self.directory, self.action,
            self.event(
                "PostToolUse", tool_name="Read", tool_use_id="late-read",
                session_id="another-session"),
            nonmutating=True)
        loom_executor_guard.observe_post(
            self.directory, self.action,
            self.event(
                "PostToolUse", tool_name="mcp__loom__status",
                tool_use_id="late-control", session_id="another-session"),
            lifecycle_control=True)

        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="cancelled")
        self.assertEqual("host-never-admitted", evidence["case"])
        self.assertIsNone(evidence["host_session_sha256"])
        self.assertEqual(0, evidence["operation_count"])

    def test_untracked_cross_session_read_and_control_do_not_poison_active_coverage(self):
        """Session identity scopes recorded mutation, not harmless untracked Posts."""
        self.initialize_and_arm()
        for event, kwargs in (
                (self.event(
                    "PostToolUse", tool_name="Read", tool_use_id="read-2",
                    session_id="host-session-2"), {"nonmutating": True}),
                (self.event(
                    "PostToolUse", tool_name="mcp__loom__status",
                    tool_use_id="status-2", session_id="host-session-2"),
                 {"lifecycle_control": True})):
            observed = loom_executor_guard.observe_post(
                self.directory, self.action, event, **kwargs)
            self.assertFalse(observed["coverage_failure"])
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="authority-retirement")
        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="cancelled")
        self.assertEqual("verified-host-terminal", evidence["case"])

    def test_post_binds_turn_and_operation_identity_and_rejects_replay(self):
        """A Post from another turn or a replay cannot close an admitted write."""
        self.initialize_and_arm()
        pre = self.event(
            "PreToolUse", tool_name="Write", tool_use_id="write-turn",
            tool_input={"file_path": "src/app.py"}, turn_id="host-turn-a")
        loom_executor_guard.begin_operation(
            self.directory, self.action, pre, operation_kind="structured-write")
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.observe_post(
                self.directory, self.action,
                self.event(
                    "PostToolUse", tool_name="Write", tool_use_id="write-turn",
                    tool_input={"file_path": "src/app.py"},
                    turn_id="host-turn-b"))
        exact = self.event(
            "PostToolUse", tool_name="Write", tool_use_id="write-turn",
            tool_input={"file_path": "src/app.py"}, turn_id="host-turn-a")
        closed = loom_executor_guard.observe_post(
            self.directory, self.action, exact)
        self.assertEqual("closed", closed["operations"][0]["state"])
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.observe_post(
                self.directory, self.action, exact)

    def test_freeze_never_initializes_a_missing_legacy_guard(self):
        """Retirement cannot invent host coverage for an already-running executor."""
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.freeze(
                self.directory, self.action,
                reason_code="authority-retirement")
        self.assertFalse(
            loom_executor_guard.guard_path(self.directory, self.action).exists())

    def test_guard_storage_uses_the_host_private_directory_boundary(self):
        """The ledger is private on Windows and POSIX rather than only self-hashed."""
        loom_executor_guard.initialize(self.directory, self.action)
        root = loom_executor_guard.guard_path(
            self.directory, self.action).parent
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.verify_private_directory(root)
        else:
            self.assertEqual(0, stat.S_IMODE(root.stat().st_mode) & 0o077)

    def test_owner_vault_authentication_rejects_a_rehashed_forgery(self):
        """A caller cannot forge guard authority by recomputing public hashes."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["coverage_failure"] = True
        value["guard_sha256"] = _digest({
            key: item for key, item in value.items()
            if key not in {"guard_sha256", "guard_authentication"}
        })
        path.write_text(json.dumps(value), encoding="utf-8")

        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security)

    def test_vault_head_rejects_replayed_projection_and_repairs_exact_predecessor(self):
        """Break caught: an authenticated old JSON snapshot can roll guard authority back."""
        initial = loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        initial_bytes = path.read_bytes()
        armed = loom_executor_guard.observe_post(
            self.directory, self.action, self.control_post,
            lifecycle_control=True, security=self.canonical_security)
        self.assertGreater(armed["sequence"], initial["sequence"])
        latest = loom_executor_guard.begin_operation(
            self.directory, self.action,
            self.event(
                "PreToolUse", tool_name="Write", tool_use_id="replay-depth-write",
                tool_input={"file_path": "src/app.py"}),
            operation_kind="structured-write", security=self.canonical_security)

        path.write_bytes(initial_bytes)
        repaired = loom_executor_guard.read(
            self.directory, self.action, security=self.canonical_security)

        self.assertEqual(latest, repaired)
        self.assertEqual(latest, json.loads(path.read_text(encoding="utf-8")))

    def test_vault_commit_before_projection_crash_repairs_on_restart(self):
        """Break caught: a crash after canonical CAS leaves the active guard unreadable."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        with unittest.mock.patch.object(
                loom_executor_guard, "_write_projection",
                side_effect=loom_executor_guard.GuardError("injected projection crash")), \
                self.assertRaisesRegex(
                    loom_executor_guard.GuardError, "injected projection crash"):
            loom_executor_guard.observe_post(
                self.directory, self.action, self.control_post,
                lifecycle_control=True, security=self.canonical_security)

        recovered = loom_executor_guard.read(
            self.directory, self.action, security=self.canonical_security)
        self.assertEqual("active", recovered["coverage_state"])
        self.assertEqual(
            recovered,
            json.loads(loom_executor_guard.guard_path(
                self.directory, self.action).read_text(encoding="utf-8")))

    def test_missing_projection_repairs_but_v2_without_head_requires_upgrade(self):
        """Break caught: absence either destroys canonical authority or mints it from v2."""
        canonical = loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        path.unlink()
        self.assertEqual(
            canonical,
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security))

        other = dict(self.action)
        other["action_id"] = "00000000-0000-4000-8000-000000000002"
        other["project_id"] = "p-" + "2" * 32
        legacy_security = (
            self.vault_crypto, self.vault.identity()["owner_vault_id"])
        loom_executor_guard.initialize(
            self.directory, other, security=legacy_security)
        with self.assertRaises(loom_executor_guard.GuardMissing):
            loom_executor_guard.initialize(
                self.directory, other, security=self.canonical_security)
        with self.assertRaises(loom_executor_guard.GuardMissing):
            loom_executor_guard.read(
                self.directory, other, security=self.canonical_security)

    def test_uncommitted_ahead_projection_and_parent_substitution_fail_closed(self):
        """Break caught: projection bytes or same-path storage can outrank vault authority."""
        current = loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        ahead = json.loads(json.dumps(current))
        ahead["sequence"] += 1
        ahead["previous_head_sha256"] = current["guard_sha256"]
        ahead["coverage_failure"] = True
        ahead = loom_executor_guard._finalize_canonical(
            ahead, self.canonical_security)
        path.write_text(json.dumps(ahead), encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)
        with self.assertRaisesRegex(loom_executor_guard.GuardError, "ahead"):
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security)

        loom_executor_guard._write_projection(
            path, current, self.action, security=self.canonical_security)
        original_root = path.parent
        displaced = original_root.with_name("canonical-guard-displaced")
        original_root.rename(displaced)
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.create_private_directory(original_root)
        else:
            original_root.mkdir(mode=0o700)
        shutil.copy2(displaced / path.name, original_root / path.name)
        with self.assertRaisesRegex(loom_executor_guard.GuardError, "parent"):
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security)
        shutil.rmtree(original_root)
        displaced.rename(original_root)
        self.assertEqual(
            current,
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security))

    def test_canonical_sequence_predecessor_and_tag_tamper_fail_closed(self):
        """Break caught: head-chain metadata can be changed without losing authority."""
        current = loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        cases = {
            "sequence": lambda value: value.__setitem__(
                "sequence", value["sequence"] + 1),
            "predecessor": lambda value: value.__setitem__(
                "previous_head_sha256", "f" * 64),
            "tag": lambda value: value["guard_authentication"].__setitem__(
                "tag", "e" * 64),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                changed = json.loads(json.dumps(current))
                mutate(changed)
                path.write_text(json.dumps(changed), encoding="utf-8")
                if os.name == "posix":
                    path.chmod(0o600)
                with self.assertRaises(loom_executor_guard.GuardError):
                    loom_executor_guard.read(
                        self.directory, self.action,
                        security=self.canonical_security)
                loom_executor_guard._write_projection(
                    path, current, self.action,
                    security=self.canonical_security)

    def test_canonical_replayed_zero_operation_snapshot_cannot_seal(self):
        """Break caught: replaying the pre-operation head fabricates zero-operation closure."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        armed = loom_executor_guard.observe_post(
            self.directory, self.action, self.control_post,
            lifecycle_control=True, security=self.canonical_security)
        armed_bytes = loom_executor_guard.guard_path(
            self.directory, self.action).read_bytes()
        pre = self.event(
            "PreToolUse", tool_name="Write", tool_use_id="canonical-write",
            tool_input={"file_path": "src/app.py"})
        opened = loom_executor_guard.begin_operation(
            self.directory, self.action, pre, operation_kind="structured-write",
            security=self.canonical_security)
        self.assertEqual("open", opened["operations"][0]["state"])
        loom_executor_guard.guard_path(
            self.directory, self.action).write_bytes(armed_bytes)

        repaired = loom_executor_guard.read(
            self.directory, self.action, security=self.canonical_security)
        self.assertEqual(opened, repaired)
        self.assertEqual("open", repaired["operations"][0]["state"])

    def test_canonical_first_terminal_freeze_is_immutable_and_evidence_bound(self):
        """Break caught: timeout or cancellation can relabel a prior completion freeze."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        completion_subject = "c" * 64
        frozen = loom_executor_guard.freeze(
            self.directory, self.action,
            operation_class="action-completion", reason_code="action-completion",
            subject_sha256=completion_subject, security=self.canonical_security)
        repeated = loom_executor_guard.freeze(
            self.directory, self.action,
            operation_class="action-completion", reason_code="action-completion",
            subject_sha256=completion_subject, security=self.canonical_security)
        self.assertEqual(frozen, repeated)

        with self.assertRaisesRegex(
                loom_executor_guard.GuardError, "action-completion"):
            loom_executor_guard.freeze(
                self.directory, self.action,
                operation_class="action-timeout", reason_code="action-timeout",
                subject_sha256="d" * 64, security=self.canonical_security)

        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="completed", security=self.canonical_security)
        self.assertEqual("action-completion", evidence["freeze_operation_class"])
        self.assertEqual(completion_subject, evidence["freeze_subject_sha256"])

    def test_successor_head_preserves_only_terminal_predecessor_projection_as_history(self):
        """Break caught: one per-project head either erases history or revives old authority."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        loom_executor_guard.freeze(
            self.directory, self.action,
            operation_class="action-cancel", reason_code="action-cancel",
            subject_sha256="e" * 64, security=self.canonical_security)
        predecessor = dict(self.action)
        predecessor["status"] = "cancelled"
        successor = dict(self.action)
        successor["action_id"] = "00000000-0000-4000-8000-000000000003"
        successor["generation_id"] = "generation-" + "4" * 32
        successor["operation_id"] = "5" * 64
        loom_executor_guard.initialize(
            self.directory, successor, security=self.canonical_security)

        historical = loom_executor_guard.read(
            self.directory, predecessor, security=self.canonical_security)
        self.assertEqual("action-cancel", historical["freeze"]["operation_class"])
        with self.assertRaisesRegex(loom_executor_guard.GuardError, "another action"):
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security)

    def test_live_canonical_head_cannot_be_replaced_by_a_successor(self):
        """A new action cannot erase a predecessor whose executor is still live."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        successor = dict(self.action)
        successor["action_id"] = "00000000-0000-4000-8000-000000000004"
        successor["generation_id"] = "generation-" + "6" * 32
        successor["operation_id"] = "7" * 64

        with self.assertRaisesRegex(
                loom_executor_guard.GuardError, "predecessor.*quiescent"):
            loom_executor_guard.initialize(
                self.directory, successor, security=self.canonical_security)

        head = self.vault.read_executor_guard_head(self.action["project_id"])
        self.assertEqual(self.action["action_id"], head["action_id"])

    def test_concurrent_guard_updates_have_one_canonical_cas_winner(self):
        """Break caught: concurrent guard writers can both commit from one head."""
        current = loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        candidates = []
        for index in range(2):
            candidate = json.loads(json.dumps(current))
            candidate["coverage_failure"] = bool(index)
            candidates.append(candidate)
        barrier = threading.Barrier(2)
        outcomes = []
        path = loom_executor_guard.guard_path(self.directory, self.action)

        def commit(candidate):
            barrier.wait()
            try:
                loom_executor_guard._commit_canonical(
                    path, candidate, self.action, self.canonical_security)
                outcomes.append("stored")
            except loom_executor_guard.GuardError:
                outcomes.append("blocked")

        threads = [threading.Thread(target=commit, args=(candidate,))
                   for candidate in candidates]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(["blocked", "stored"], sorted(outcomes))
        self.assertFalse(any(thread.is_alive() for thread in threads))
        head = self.vault.read_executor_guard_head(self.action["project_id"])
        self.assertEqual(current["sequence"] + 1, head["sequence"])

    def test_delayed_projection_writer_repairs_to_newer_canonical_head(self):
        """A delayed earlier publisher cannot leave the projection behind the vault."""
        current = loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        first_candidate = json.loads(json.dumps(current))
        first_candidate["coverage_failure"] = True
        first_cas_done = threading.Event()
        release_first_projection = threading.Event()
        original_write = loom_executor_guard._write_projection
        outcomes = []

        def delayed_write(target, value, action, *, security):
            if threading.current_thread().name == "delayed-guard-publisher" \
                    and value["sequence"] == current["sequence"] + 1:
                first_cas_done.set()
                if not release_first_projection.wait(10):
                    raise AssertionError("timed out waiting for later canonical update")
            return original_write(target, value, action, security=security)

        def commit_first():
            try:
                outcomes.append(loom_executor_guard._commit_canonical(
                    path, first_candidate, self.action,
                    self.canonical_security))
            except Exception as exc:  # pragma: no cover - asserted below
                outcomes.append(exc)

        with mock.patch.object(
                loom_executor_guard, "_write_projection",
                side_effect=delayed_write):
            first = threading.Thread(
                target=commit_first, name="delayed-guard-publisher")
            first.start()
            self.assertTrue(first_cas_done.wait(10))
            newer_base = self.vault.read_executor_guard_head(
                self.action["project_id"])
            second_candidate = json.loads(json.dumps(newer_base))
            second_candidate["coverage_failure"] = False
            newest = loom_executor_guard._commit_canonical(
                path, second_candidate, self.action,
                self.canonical_security)
            release_first_projection.set()
            first.join(10)

        self.assertFalse(first.is_alive())
        self.assertEqual(1, len(outcomes))
        if isinstance(outcomes[0], Exception):
            raise outcomes[0]
        head = self.vault.read_executor_guard_head(self.action["project_id"])
        projection = loom_executor_guard.read(
            self.directory, self.action, security=self.canonical_security)
        self.assertEqual(newest, head)
        self.assertEqual(head, outcomes[0])
        self.assertEqual(head, projection)

    def test_guard_leaf_must_remain_regular_single_link_and_private(self):
        """Link substitution and relaxed POSIX file permissions fail closed."""
        loom_executor_guard.initialize(
            self.directory, self.action, security=self.canonical_security)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        alias = path.with_suffix(".hardlink")
        os.link(path, alias)
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.read(
                self.directory, self.action, security=self.canonical_security)
        alias.unlink()
        if os.name == "posix":
            path.chmod(0o640)
            with self.assertRaises(loom_executor_guard.GuardError):
                loom_executor_guard.read(
                    self.directory, self.action, security=self.canonical_security)

    def test_guard_rejects_private_parent_object_substitution_after_restart(self):
        """A same-path replacement directory cannot inherit the old ledger authority."""
        loom_executor_guard.initialize(self.directory, self.action)
        path = loom_executor_guard.guard_path(self.directory, self.action)
        original_root = path.parent
        displaced = original_root.with_name("executor-guards-displaced")
        original_root.rename(displaced)
        if os.name == "nt":
            import loom_windows_acl
            loom_windows_acl.create_private_directory(original_root)
        else:
            original_root.mkdir(mode=0o700)
        shutil.copy2(displaced / path.name, original_root / path.name)

        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.read(self.directory, self.action)

    def test_freeze_survives_reload_and_denies_a_new_operation(self):
        """Break caught: restart drops the freeze and permits a new mutation."""
        self.initialize_and_arm()
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        with self.assertRaises(loom_executor_guard.GuardFrozen):
            loom_executor_guard.begin_operation(
                self.directory, self.action,
                self.event(
                    "PreToolUse", tool_name="Write", tool_use_id="write-2",
                    tool_input={"file_path": "src/app.py"}),
                operation_kind="structured-write")
        loaded = loom_executor_guard.read(self.directory, self.action)
        self.assertEqual("owner-cancelled", loaded["freeze"]["reason_code"])

    def test_post_without_pre_invalidates_positive_host_proof(self):
        """Break caught: an unobserved process is ignored when quiescence is sealed."""
        self.initialize_and_arm()
        loom_executor_guard.observe_post(
            self.directory, self.action,
            self.event(
                "PostToolUse", tool_name="Bash", tool_use_id="process-1",
                tool_input={"command": "python build.py"}))
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        with self.assertRaises(loom_executor_guard.GuardPending):
            loom_executor_guard.seal_quiescence(
                self.directory, self.action,
                project_world_sha256="4" * 64,
                terminal_state="cancelled")

    def test_tampered_guard_and_caller_injected_evidence_are_rejected(self):
        """Break caught: self-hashed host_result text substitutes for a trusted ledger."""
        self.initialize_and_arm()
        loom_executor_guard.freeze(
            self.directory, self.action, reason_code="owner-cancelled")
        evidence = loom_executor_guard.seal_quiescence(
            self.directory, self.action, project_world_sha256="4" * 64,
            terminal_state="cancelled")
        injected = dict(evidence)
        injected["action_operation_id"] = "5" * 64
        injected["binding_sha256"] = _digest({
            key: item for key, item in injected.items()
            if key != "binding_sha256"})
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.validate_evidence(
                self.directory, self.action, injected,
                project_world_sha256="4" * 64)

        path = loom_executor_guard.guard_path(self.directory, self.action)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["coverage_failure"] = True
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.read(self.directory, self.action)

    def test_supervised_process_requires_zero_survivors_and_unchanged_roots(self):
        """Break caught: a failed containment receipt is counted as terminal-safe."""
        self.initialize_and_arm()
        pre = self.event(
            "PreToolUse", tool_name="LoomSupervisedProcess",
            tool_use_id="supervised-1", tool_input={"receipt": "sealed"})
        loom_executor_guard.begin_operation(
            self.directory, self.action, pre,
            operation_kind="supervised-process")
        receipt = loom_operation_supervisor.run(
            operation_class="executor-guard-test",
            command=[sys.executable, "-c", "pass"], cwd=self.root,
            timeout=10, allowed_roots=[self.root], protected_roots=[self.owner])
        unsafe = dict(receipt)
        unsafe.update({
            "status": "failed",
            "survivors_confirmed_zero": False,
            "primary_failure": "survivor-census-indeterminate",
        })
        unsafe["receipt_sha256"] = _digest({
            key: item for key, item in unsafe.items()
            if key != "receipt_sha256"})
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.observe_post(
                self.directory, self.action,
                self.event(
                    "PostToolUse", tool_name="LoomSupervisedProcess",
                    tool_use_id="supervised-1", tool_input={"receipt": "sealed"}),
                supervisor_receipt=unsafe)

        changed = dict(receipt)
        changed.update({
            "status": "failed",
            "protected_roots_unchanged": False,
            "primary_failure": "protected-root-changed",
        })
        changed["receipt_sha256"] = _digest({
            key: item for key, item in changed.items()
            if key != "receipt_sha256"})
        with self.assertRaises(loom_executor_guard.GuardError):
            loom_executor_guard.observe_post(
                self.directory, self.action,
                self.event(
                    "PostToolUse", tool_name="LoomSupervisedProcess",
                    tool_use_id="supervised-1", tool_input={"receipt": "sealed"}),
                supervisor_receipt=changed)


if __name__ == "__main__":
    unittest.main()
