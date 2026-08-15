import ast
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import loom_lifecycle_kernel as kernel
import loom_operation_supervisor
import loom_reliability
from test_lifecycle_kernel import (
    HEX_A, HEX_B, _canonical_state_inputs, _canonical_world_observation,
)


class LifecycleTransitionTests(unittest.TestCase):
    def setUp(self):
        try:
            import loom_lifecycle_transition
        except ModuleNotFoundError:
            self.fail("loom_lifecycle_transition is required")
        self.transition = loom_lifecycle_transition
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.generation = (
            self.root / "plans" / "generations" / "generation-1")
        self.generation.mkdir(parents=True)
        self.private = self.root / ".private"
        self.private.mkdir()
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)
        (self.root / "plans" / "active-generation.json").write_text(
            json.dumps(index, sort_keys=True) + "\n", encoding="utf-8")
        (self.generation / "plan-semantics.json").write_text(
            json.dumps(semantics, sort_keys=True) + "\n", encoding="utf-8")
        (self.generation / "reviewed-world.json").write_text(
            json.dumps(_canonical_world_observation(kernel), sort_keys=True) + "\n",
            encoding="utf-8")
        (self.generation / "lifecycle.json").write_text(
            json.dumps(ledger, sort_keys=True) + "\n", encoding="utf-8")
        (self.generation / "MANIFEST.md").write_text(
            "---\nexecution_policy: strict-serial-sequence-v1\n"
            "execution_sequence: [WO-001, WO-002]\n---\n",
            encoding="utf-8")
        self.witness = self.private / "head-witness.json"
        self.witness.write_text(
            json.dumps(witness, sort_keys=True) + "\n", encoding="utf-8")
        self.envelopes = self.private / "transitions"

    def tearDown(self):
        self.temporary.cleanup()

    def _command(self, *, world=HEX_B, command_id="command-start-exact"):
        semantics = json.loads(
            (self.generation / "plan-semantics.json").read_text(encoding="utf-8"))
        return {
            "schema_version": 1,
            "command_id": command_id,
            "relation": "start-exact",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": world,
            "action_id": "action-1",
            "work_order_id": None,
            "evidence_sha256": None,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        }

    def _complete_command(self, *, command_id="command-complete-exact"):
        semantics = json.loads(
            (self.generation / "plan-semantics.json").read_text(encoding="utf-8"))
        return {
            "schema_version": 1,
            "command_id": command_id,
            "relation": "complete-active",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_B,
            "action_id": "action-1",
            "work_order_id": "WO-001",
            "evidence_sha256": HEX_A,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        }

    def _replace_authority(self, *, authorized):
        index, semantics, ledger, witness = _canonical_state_inputs(
            kernel, authorized=authorized)
        (self.root / "plans" / "active-generation.json").write_text(
            json.dumps(index, sort_keys=True) + "\n", encoding="utf-8")
        (self.generation / "plan-semantics.json").write_text(
            json.dumps(semantics, sort_keys=True) + "\n", encoding="utf-8")
        (self.generation / "lifecycle.json").write_text(
            json.dumps(ledger, sort_keys=True) + "\n", encoding="utf-8")
        self.witness.write_text(
            json.dumps(witness, sort_keys=True) + "\n", encoding="utf-8")

    def _authoritative_bytes(self):
        return {
            "index": (self.root / "plans" / "active-generation.json").read_bytes(),
            "semantics": (self.generation / "plan-semantics.json").read_bytes(),
            "ledger": (self.generation / "lifecycle.json").read_bytes(),
            "witness": self.witness.read_bytes(),
        }

    def test_rejected_transition_writes_no_authority_or_envelope(self):
        """Break caught: stale start mutates lifecycle before returning failure."""
        before = self._authoritative_bytes()

        result = self.transition.transition(
            self.root, self._command(world=HEX_A),
            witness_path=self.witness, envelope_root=self.envelopes)

        self.assertFalse(result["accepted"])
        self.assertEqual("PROJECT_WORLD_CHANGED", result["primary_code"])
        self.assertEqual(before, self._authoritative_bytes())
        self.assertFalse(self.envelopes.exists())

    def test_exact_command_replay_returns_same_receipt_without_second_append(self):
        """Break caught: a lost response duplicates authorization on retry."""
        first = self.transition.transition(
            self.root, self._command(),
            witness_path=self.witness, envelope_root=self.envelopes)
        ledger_after_first = (
            self.generation / "lifecycle.json").read_bytes()

        second = self.transition.transition(
            self.root, self._command(),
            witness_path=self.witness, envelope_root=self.envelopes)

        self.assertTrue(first["accepted"])
        self.assertEqual("completed", first["status"])
        self.assertEqual(first, second)
        self.assertEqual(
            ledger_after_first, (self.generation / "lifecycle.json").read_bytes())
        ledger = json.loads(ledger_after_first)
        self.assertEqual(
            ["generation-created", "plan-reviewed", "implementation-authorized",
             "work-order-started"],
            [event["event_type"] for event in ledger["events"]],
        )

    def test_completed_replay_rejects_project_rollback_against_the_head_witness(self):
        """Break caught: a sealed receipt masks one-sided project rollback."""
        source = self._authoritative_bytes()
        self.transition.transition(
            self.root, self._command(), witness_path=self.witness,
            envelope_root=self.envelopes)
        (self.generation / "lifecycle.json").write_bytes(source["ledger"])

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "rollback|source project"):
            self.transition.transition(
                self.root, self._command(), witness_path=self.witness,
                envelope_root=self.envelopes)

    def test_completed_replay_repairs_an_exact_witness_lag(self):
        """Break caught: committed project authority leaves its witness stale forever."""
        source_witness = self.witness.read_bytes()
        self.transition.transition(
            self.root, self._command(), witness_path=self.witness,
            envelope_root=self.envelopes)
        target_witness = self.witness.read_bytes()
        self.witness.write_bytes(source_witness)

        replay = self.transition.transition(
            self.root, self._command(), witness_path=self.witness,
            envelope_root=self.envelopes)

        self.assertEqual("completed", replay["status"])
        self.assertEqual(target_witness, self.witness.read_bytes())

    def test_conflicting_reuse_of_command_identity_fails_closed(self):
        """Break caught: one command ID can authorize two different contents."""
        self.transition.transition(
            self.root, self._command(),
            witness_path=self.witness, envelope_root=self.envelopes)

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError, "command identity"):
            self.transition.transition(
                self.root, self._command(world=HEX_A),
                witness_path=self.witness, envelope_root=self.envelopes)

    def test_two_concurrent_starts_cannot_both_claim_one_source_state(self):
        """Break caught: two commands authorize the same reviewed frontier."""
        original_observe = self.transition._observe
        barrier = threading.Barrier(2)
        counter_lock = threading.Lock()
        calls = 0

        def gated_observe(*args, **kwargs):
            nonlocal calls
            observed = original_observe(*args, **kwargs)
            with counter_lock:
                calls += 1
                gate = calls <= 2
            if gate:
                barrier.wait(timeout=10)
            return observed

        def start(command_id):
            try:
                result = self.transition.transition(
                    self.root, self._command(command_id=command_id),
                    witness_path=self.witness, envelope_root=self.envelopes)
                return result["status"]
            except self.transition.LifecycleTransitionError as exc:
                return "blocked:" + str(exc)

        with mock.patch.object(self.transition, "_observe", gated_observe), \
                ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(start, ("concurrent-start-1", "concurrent-start-2")))

        self.assertEqual(1, outcomes.count("completed"), outcomes)
        self.assertEqual(1, sum(item.startswith("blocked:") for item in outcomes), outcomes)
        ledger = json.loads(
            (self.generation / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            1, sum(event["event_type"] == "implementation-authorized"
                   for event in ledger["events"]))

    def test_precommit_interruption_is_abandoned_without_authority_change(self):
        """Break caught: prepared staging is mistaken for committed authority."""
        before = self._authoritative_bytes()
        command = self._command()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes, fault_at="after-prepare")
        self.assertEqual(before, self._authoritative_bytes())

        recovered = self.transition.recover(
            self.root, command, witness_path=self.witness,
            envelope_root=self.envelopes)

        self.assertFalse(recovered["accepted"])
        self.assertEqual("abandoned", recovered["status"])
        self.assertEqual(before, self._authoritative_bytes())

    def test_transition_envelope_hardlink_blocks_recovery(self):
        """A prepared command journal cannot have an untracked second name."""
        command = self._command(command_id="hardlinked-envelope")
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes, fault_at="after-prepare")
        envelopes = list(self.envelopes.glob("*.json"))
        self.assertEqual(1, len(envelopes))
        try:
            os.link(envelopes[0], self.private / "envelope-alias.json")
        except OSError as exc:
            self.skipTest(f"hard links are unavailable: {exc}")

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError, "hardlink|redirected"):
            self.transition.recover(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes)

    def test_generation_root_replacement_during_observation_fails_closed(self):
        """Canonical JSON cannot be mixed across a replaced authority directory."""
        replacement = self.root / "replacement-generation"
        displaced = self.root / "displaced-generation"
        shutil.copytree(self.generation, replacement)
        real_load = self.transition._load_json
        replaced = False

        def replace_after_first_read(path, label, maximum=None):
            nonlocal replaced
            kwargs = {} if maximum is None else {"maximum": maximum}
            value = real_load(path, label, **kwargs)
            if not replaced and label == "reviewed plan semantics":
                replaced = True
                self.generation.replace(displaced)
                replacement.replace(self.generation)
            return value

        with mock.patch.object(
                self.transition, "_load_json",
                side_effect=replace_after_first_read):
            with self.assertRaisesRegex(
                    self.transition.LifecycleTransitionError,
                    "changed|identity|replacement"):
                self.transition.observe(
                    self.root,
                    witness_store=self.transition.FileWitnessStore(
                        self.witness))

    def test_postcommit_interruption_rolls_witness_forward_exactly_once(self):
        """Break caught: committed authorization is rolled back or left un witnessed."""
        command = self._command()
        source_witness = self.witness.read_bytes()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes, fault_at="after-project-commit")
        committed_ledger = (self.generation / "lifecycle.json").read_bytes()
        self.assertEqual(source_witness, self.witness.read_bytes())

        recovered = self.transition.recover(
            self.root, command, witness_path=self.witness,
            envelope_root=self.envelopes)

        self.assertTrue(recovered["accepted"])
        self.assertEqual("completed", recovered["status"])
        self.assertEqual(
            committed_ledger, (self.generation / "lifecycle.json").read_bytes())
        ledger = json.loads(committed_ledger)
        witness = json.loads(self.witness.read_text(encoding="utf-8"))
        self.assertEqual(
            ledger["lifecycle_sha256"], witness["authoritative_sha256"])

    def test_next_invocation_inventory_recovers_only_the_prepared_transition(self):
        """Break caught: recovery requires the owner to repeat one exact command."""
        command = self._command()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes,
                fault_at="after-project-commit")

        first = self.transition.recover_pending(
            self.root, witness_path=self.witness,
            envelope_root=self.envelopes,
            lock_path=self.private / "project.lock")
        second = self.transition.recover_pending(
            self.root, witness_path=self.witness,
            envelope_root=self.envelopes,
            lock_path=self.private / "project.lock")

        self.assertEqual(1, len(first))
        self.assertEqual("in-generation", first[0]["kind"])
        self.assertEqual("completed", first[0]["status"])
        self.assertEqual([], second)

    def test_neither_source_nor_target_observation_blocks_recovery(self):
        """Break caught: ambiguous bytes are guessed to be a successful transition."""
        command = self._command()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes, fault_at="after-prepare")
        ledger = json.loads(
            (self.generation / "lifecycle.json").read_text(encoding="utf-8"))
        ledger["events"][0]["command_id"] = "unrelated-command"
        ledger["events"][0]["event_sha256"] = kernel.digest({
            key: value for key, value in ledger["events"][0].items()
            if key != "event_sha256"
        })
        ledger["lifecycle_sha256"] = kernel.digest({
            key: value for key, value in ledger.items()
            if key != "lifecycle_sha256"
        })
        (self.generation / "lifecycle.json").write_text(
            json.dumps(ledger, sort_keys=True) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError, "neither source nor target"):
            self.transition.recover(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes)

    def test_completed_replay_preserves_the_original_decision_code(self):
        """Break caught: every replay is mislabeled as a start transition."""
        self._replace_authority(authorized=True)
        command = self._complete_command()

        first = self.transition.transition(
            self.root, command, witness_path=self.witness,
            envelope_root=self.envelopes)
        second = self.transition.transition(
            self.root, command, witness_path=self.witness,
            envelope_root=self.envelopes)

        self.assertEqual("COMPLETION_ACCEPTED", first["primary_code"])
        self.assertEqual("COMPLETION_ACCEPTED", second["primary_code"])
        self.assertEqual(first["receipt"], second["receipt"])

    def test_recovery_rolls_forward_the_required_project_projection(self):
        """Break caught: ledger recovery leaves visible work-order state stale."""
        command = self._command()
        projected = []
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes, fault_at="after-witness")

        recovered = self.transition.recover(
            self.root, command, witness_path=self.witness,
            envelope_root=self.envelopes,
            project_projection=lambda state, decision, target: projected.append((
                state.state_sha256, decision.primary_code,
                target["lifecycle_sha256"])),
        )

        self.assertEqual("completed", recovered["status"])
        self.assertEqual(1, len(projected))
        self.assertEqual("START_ACCEPTED", projected[0][1])

    def test_production_witness_adapter_uses_only_the_encrypted_vault_entity(self):
        """Break caught: the anti-rollback witness is persisted as owner plaintext."""
        initial = json.loads(self.witness.read_text(encoding="utf-8"))

        class FakeEncryptedVault:
            def __init__(self, value):
                self.value = value
                self.puts = []

            def list_entities(self, entity_type, *, limit):
                self.asserted = (entity_type, limit)
                return [{"id": "project-1", "value": self.value}]

            def put_entity(self, entity_type, entity_id, value, *, source_sequence=0):
                self.puts.append((
                    entity_type, entity_id, value, source_sequence))
                self.value = value
                return {"entity_type": entity_type, "entity_id": entity_id}

        vault = FakeEncryptedVault(initial)
        store = self.transition.VaultWitnessStore(vault, "project-1")

        result = self.transition.transition(
            self.root, self._command(), witness_store=store,
            envelope_root=self.envelopes)

        self.assertEqual("completed", result["status"])
        self.assertEqual(1, len(vault.puts))
        self.assertEqual(
            "lifecycle-head-witness-v1", vault.puts[0][0])
        self.assertEqual("project-1", vault.puts[0][1])
        self.assertEqual(
            result["receipt"]["target_witness_sha256"],
            vault.value["witness_sha256"],
        )

    def test_transition_receipt_accepts_only_closed_bound_finding_codes(self):
        """Break caught: a receipt validator silently skips finding validation."""
        result = self.transition.transition(
            self.root, self._command(), witness_path=self.witness,
            envelope_root=self.envelopes)
        receipt = dict(result["receipt"])
        receipt["findings"] = ["PROJECTION_REPAIRED"]
        receipt["receipt_sha256"] = kernel.digest({
            key: value for key, value in receipt.items()
            if key != "receipt_sha256"
        })

        self.assertEqual(receipt, self.transition.validate_receipt(receipt))

        receipt["findings"] = ["unsafe detail"]
        receipt["receipt_sha256"] = kernel.digest({
            key: value for key, value in receipt.items()
            if key != "receipt_sha256"
        })
        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError, "findings"):
            self.transition.validate_receipt(receipt)

    def test_orchestrator_owned_lock_is_not_reacquired_by_the_v3_writer(self):
        """Break caught: v3 creates a second lock domain beneath plans/."""
        with mock.patch.object(
                self.transition.loom_reliability, "exclusive_file_lock",
                side_effect=AssertionError("transition reacquired the project lock")):
            result = self.transition.transition(
                self.root, self._command(), witness_path=self.witness,
                envelope_root=self.envelopes, _lock_held=True)

        self.assertEqual("completed", result["status"])

    def test_v3_authority_writes_are_isolated_to_the_transition_service(self):
        """Runtime, host controls, and orchestrator cannot become hidden ledger writers."""
        tools = Path(__file__).parent
        forbidden = []
        writer_names = {
            "atomic_write_json", "_atomic_json", "write_text",
            "write_bytes", "_atomic_write_text",
        }
        for name in (
                "loom_orchestrator.py", "loom_runtime.py",
                "loom_codex_lifecycle.py"):
            source = (tools / name).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=name)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = (
                    node.func.attr if isinstance(node.func, ast.Attribute)
                    else node.func.id if isinstance(node.func, ast.Name)
                    else None)
                if function not in writer_names:
                    continue
                target = (
                    ast.get_source_segment(source, node.args[0])
                    if node.args else "") or ""
                if "lifecycle" in target.casefold() \
                        or "ledger" in target.casefold():
                    forbidden.append((name, node.lineno, target[:160]))

        self.assertEqual([], forbidden)


class InvalidPlanStoreQuarantineTests(unittest.TestCase):
    def setUp(self):
        import loom_lifecycle_transition
        self.transition = loom_lifecycle_transition
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.private = self.root / "owner-private"
        self.plans = self.project / "plans"
        self.plans.mkdir(parents=True)
        self.private.mkdir()
        (self.plans / "active-generation.json").write_text(
            "{\"schema_version\":1,\"schema_version\":2}\n", encoding="utf-8")
        (self.plans / "preserve-me.txt").write_text(
            "owner-reviewed plan bytes\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_explicit_invalid_store_quarantine_preserves_exact_bytes_idempotently(self):
        """Break caught: corrupt blocking authority has no bounded owner recovery."""
        before = loom_reliability.exact_tree_manifest(self.plans)
        arguments = {
            "project_id": "p-" + "1" * 32,
            "command_id": "quarantine-command-1",
            "reason_code": "invalid-plan-store",
            "quarantine_root": self.private,
            "lock_path": self.root / "quarantine.lock",
        }

        first = self.transition.quarantine_invalid_store(
            self.project, **arguments)
        second = self.transition.quarantine_invalid_store(
            self.project, **arguments)

        self.assertEqual(first, second)
        self.assertEqual("completed", first["status"])
        self.assertFalse(self.plans.exists())
        preserved = self.private / first["quarantine_id"] / "plans"
        after = loom_reliability.exact_tree_manifest(preserved)
        self.assertTrue(loom_reliability.exact_tree_manifests_equal(after, before))
        self.assertEqual(before["root_sha256"], first["source_tree_sha256"])
        public = json.dumps(first, sort_keys=True)
        self.assertNotIn(str(self.root), public)
        self.assertNotIn("owner-reviewed plan bytes", public)


class GenerationActivationTests(unittest.TestCase):
    def setUp(self):
        import loom_lifecycle_transition
        self.transition = loom_lifecycle_transition
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.stage = self.root / ".generation-stage"
        self.stage.mkdir()
        (self.stage / "MANIFEST.md").write_text(
            "---\nexecution_policy: strict-serial-sequence-v1\n"
            "execution_sequence: [WO-001, WO-002]\n---\n",
            encoding="utf-8")
        _index, self.semantics, _ledger, _witness = \
            _canonical_state_inputs(kernel)
        self.reviewed_world = _canonical_world_observation(kernel)
        self.index = {
            "schema_version": 1,
            "project_id": "project-1",
            "generation_id": "generation-1",
            "storage_kind": "generation-dir",
            "generation_path": "plans/generations/generation-1",
        }
        self.index["index_sha256"] = kernel.digest(self.index)
        self.witness = self.root / ".private" / "head-witness.json"
        self.envelopes = self.root / ".private" / "transitions"
        self.lock = self.root / ".private" / "project.lock"

    def tearDown(self):
        self.temporary.cleanup()

    def _prepare(self):
        return self.transition.prepare_generation_authority(
            self.stage, index_value=self.index,
            semantics_value=self.semantics,
            reviewed_world_value=self.reviewed_world,
            command_id="command-review-generation-1",
            relation="new", predecessor_generation_id=None,
            predecessor_witness_sha256=None,
        )

    def _command(self, relation, command_id, *, action_id=None,
                 work_order_id=None, evidence_sha256=None):
        return {
            "schema_version": 1,
            "command_id": command_id,
            "relation": relation,
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": self.semantics[
                "plan_semantics_sha256"],
            "observed_world_sha256": HEX_B,
            "action_id": action_id,
            "work_order_id": work_order_id,
            "evidence_sha256": evidence_sha256,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        }

    def _activate_terminal_initial_generation(self):
        prepared = self._prepare()
        self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        commands = (
            self._command(
                "start-exact", "start-initial-1", action_id="action-1"),
            self._command(
                "complete-active", "complete-initial-1",
                action_id="action-1", work_order_id="WO-001",
                evidence_sha256=HEX_A),
            self._command(
                "continue-active", "continue-initial-2",
                action_id="action-2"),
            self._command(
                "complete-active", "complete-initial-2",
                action_id="action-2", work_order_id="WO-002",
                evidence_sha256=HEX_A),
        )
        for command in commands:
            result = self.transition.transition(
                self.root, command, witness_path=self.witness,
                envelope_root=self.envelopes, lock_path=self.lock)
            self.assertEqual("completed", result["status"])
        return prepared

    def _prepare_successor(self, generation_id):
        stage = self.root / ("." + generation_id + "-stage")
        stage.mkdir()
        (stage / "MANIFEST.md").write_text(
            "---\nexecution_policy: strict-serial-sequence-v1\n"
            "execution_sequence: [WO-001, WO-002]\n---\n",
            encoding="utf-8")
        semantics = json.loads(json.dumps(self.semantics))
        world = json.loads(json.dumps(self.reviewed_world))
        semantics["generation_id"] = generation_id
        world["generation_id"] = generation_id
        world["observation_sha256"] = kernel.digest({
            key: value for key, value in world.items()
            if key != "observation_sha256"})
        semantics["reviewed_world_observation_sha256"] = \
            world["observation_sha256"]
        semantics["plan_semantics_sha256"] = kernel.digest({
            key: value for key, value in semantics.items()
            if key != "plan_semantics_sha256"})
        index = {
            "schema_version": 1,
            "project_id": "project-1",
            "generation_id": generation_id,
            "storage_kind": "generation-dir",
            "generation_path": "plans/generations/" + generation_id,
        }
        index["index_sha256"] = kernel.digest(index)
        predecessor = json.loads(
            self.witness.read_text(encoding="utf-8"))
        prepared = self.transition.prepare_generation_authority(
            stage, index_value=index, semantics_value=semantics,
            reviewed_world_value=world,
            command_id="review-" + generation_id,
            relation="new", predecessor_generation_id="generation-1",
            predecessor_witness_sha256=predecessor["witness_sha256"])
        return stage, prepared

    def _activate_reviewable_initial_generation(self):
        prepared = self._prepare()
        self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        return prepared

    def _prepare_live_successor(
            self, generation_id="generation-2", source=None,
            executor_quiescence=None):
        if source is None:
            source = self._activate_reviewable_initial_generation()
        stage = self.root / ("." + generation_id + "-stage")
        stage.mkdir()
        (stage / "MANIFEST.md").write_text(
            "---\nexecution_policy: strict-serial-sequence-v1\n"
            "execution_sequence: [WO-001, WO-002]\n---\n",
            encoding="utf-8")
        semantics = json.loads(json.dumps(self.semantics))
        world = json.loads(json.dumps(self.reviewed_world))
        semantics["generation_id"] = generation_id
        world["generation_id"] = generation_id
        world["observation_sha256"] = kernel.digest({
            key: value for key, value in world.items()
            if key != "observation_sha256"})
        semantics["reviewed_world_observation_sha256"] = \
            world["observation_sha256"]
        semantics["plan_semantics_sha256"] = kernel.digest({
            key: value for key, value in semantics.items()
            if key != "plan_semantics_sha256"})
        index = {
            "schema_version": 1,
            "project_id": "project-1",
            "generation_id": generation_id,
            "storage_kind": "generation-dir",
            "generation_path": "plans/generations/" + generation_id,
        }
        index["index_sha256"] = kernel.digest(index)
        owner_stage_manifest = loom_reliability.exact_tree_manifest(stage)
        prepared = self.transition.prepare_successor_authority(
            stage, index_value=index, semantics_value=semantics,
            reviewed_world_value=world,
            source_index=source["index"], source_semantics=source["semantics"],
            source_ledger=source["ledger"], source_witness=source["witness"],
            command_id="switch-" + generation_id,
            candidate_action_id="candidate-action-1",
            candidate_action_sha256=HEX_A,
            project_world_sha256=HEX_B,
            executor_quiescence=executor_quiescence or {
                "case": "no-active-executor", "action_id": None,
                "receipt_sha256": None,
            },
            candidate_projection={
                "schema_version": 1,
                "action_id": "candidate-action-1",
                "action_base_sha256": HEX_A,
                "project_id": "project-1",
                "generation_id": generation_id,
                "session_id": "00000000-0000-4000-8000-000000000001",
                "operation_id": "00000000-0000-4000-8000-000000000002",
                "invocation_id": "00000000-0000-4000-8000-000000000003",
                "journal_path_sha256": HEX_B,
                "completion_instant": "2026-08-15T12:00:00+00:00",
                "owner_stage_manifest": owner_stage_manifest,
            })
        return source, stage, prepared

    def test_live_successor_switch_terminalizes_predecessor_and_activates_candidate(self):
        """A complete candidate replaces one exact reviewable predecessor atomically."""
        source, stage, prepared = self._prepare_live_successor()

        result = self.transition.activate_successor(
            self.root, stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", result["status"])
        active = self.transition.loom_plan_store.resolve(self.root)
        self.assertEqual("generation-2", active.generation_id)
        predecessor = self.root.joinpath(
            *Path(source["index"]["generation_path"]).parts)
        old_ledger = json.loads(
            (predecessor / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            "generation-superseded", old_ledger["events"][-1]["event_type"])
        self.assertEqual(
            prepared["witness"],
            json.loads(self.witness.read_text(encoding="utf-8")))

    def test_successor_faults_recover_to_exact_source_before_index_and_target_after(self):
        """Every durable boundary yields exactly the sealed source or target."""
        for fault in (
                "after-prepare", "after-generation-install",
                "after-predecessor-terminalization", "after-index-commit",
                "after-witness", "before-projection-completion"):
            with self.subTest(fault=fault):
                self.tearDown()
                self.setUp()
                source, stage, prepared = self._prepare_live_successor()
                source_root = self.root.joinpath(
                    *Path(source["index"]["generation_path"]).parts)
                source_ledger_bytes = (source_root / "lifecycle.json").read_bytes()
                source_witness_bytes = self.witness.read_bytes()
                with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
                    self.transition.activate_successor(
                        self.root, stage, prepared,
                        witness_path=self.witness, envelope_root=self.envelopes,
                        lock_path=self.lock, fault_at=fault)
                if fault in {"after-prepare", "after-generation-install"}:
                    self.assertEqual(
                        source_ledger_bytes,
                        (source_root / "lifecycle.json").read_bytes())
                    self.assertEqual(source_witness_bytes, self.witness.read_bytes())
                recovered = self.transition.recover_successor_activation(
                    self.root, prepared["command_id"],
                    witness_path=self.witness, envelope_root=self.envelopes,
                    lock_path=self.lock)
                active = self.transition.loom_plan_store.resolve(self.root)
                if fault in {
                        "after-index-commit", "after-predecessor-terminalization",
                        "after-witness",
                        "before-projection-completion"}:
                    self.assertEqual("completed", recovered["status"])
                    self.assertEqual("generation-2", active.generation_id)
                else:
                    self.assertEqual("abandoned", recovered["status"])
                    self.assertEqual("generation-1", active.generation_id)
                    old_ledger = json.loads(
                        (active.generation_root / "lifecycle.json").read_text(
                            encoding="utf-8"))
                    self.assertEqual(source["ledger"], old_ledger)

    def test_successor_command_replay_and_conflict_are_closed(self):
        source, stage, prepared = self._prepare_live_successor()
        first = self.transition.activate_successor(
            self.root, stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        replay = self.transition.activate_successor(
            self.root, stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        self.assertEqual(first["receipt"], replay["receipt"])
        forged = json.loads(json.dumps(prepared))
        forged["candidate_action_sha256"] = HEX_B
        forged["prepared_sha256"] = kernel.digest({
            key: value for key, value in forged.items()
            if key != "prepared_sha256"})
        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError, "command identity"):
            self.transition.activate_successor(
                self.root, stage, forged,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock)

    def test_successor_completed_claim_cannot_override_exact_source_observation(self):
        source, stage, prepared = self._prepare_live_successor()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.activate_successor(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, fault_at="after-generation-install")
        path = self.transition._successor_envelope_path(
            self.envelopes, prepared["command_id"])
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["status"] = "completed"
        envelope["projection_status"] = "completed"
        envelope["receipt"] = self.transition._activation_receipt(
            {
                "prepared": prepared,
                "source_index": prepared["source_index"],
                "source_witness": prepared["source_witness"],
                "command_id": prepared["command_id"],
            }, status="completed", observation="target",
            projection_status="verified")
        self.transition.loom_reliability.atomic_write_json(path, envelope)

        recovered = self.transition.recover_successor_activation(
            self.root, prepared["command_id"], witness_path=self.witness,
            envelope_root=self.envelopes, lock_path=self.lock)

        self.assertEqual("abandoned", recovered["status"])
        self.assertEqual(
            source["index"],
            json.loads((self.root / "plans" / "active-generation.json").read_text(
                encoding="utf-8")))

    def test_successor_foreign_self_digested_receipt_is_rejected(self):
        _source, stage, prepared = self._prepare_live_successor()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.activate_successor(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, fault_at="after-generation-install")
        path = self.transition._successor_envelope_path(
            self.envelopes, prepared["command_id"])
        envelope = json.loads(path.read_text(encoding="utf-8"))
        receipt = self.transition._activation_receipt(
            {
                "prepared": prepared,
                "source_index": prepared["source_index"],
                "source_witness": prepared["source_witness"],
                "command_id": prepared["command_id"],
            }, status="completed", observation="target",
            projection_status="verified")
        receipt["command_id"] = "foreign-successor-command"
        receipt["receipt_sha256"] = kernel.digest({
            key: value for key, value in receipt.items()
            if key != "receipt_sha256"})
        envelope["status"] = "completed"
        envelope["receipt"] = receipt
        self.transition.loom_reliability.atomic_write_json(path, envelope)

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "receipt"):
            self.transition.recover_successor_activation(
                self.root, prepared["command_id"], witness_path=self.witness,
                envelope_root=self.envelopes, lock_path=self.lock)

    def test_successor_target_witness_repairs_rolled_back_index(self):
        source, stage, prepared = self._prepare_live_successor()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.activate_successor(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, fault_at="after-witness")
        self.transition.loom_reliability.atomic_write_json(
            self.root / "plans" / "active-generation.json", source["index"])
        source_root = self.root.joinpath(
            *Path(source["index"]["generation_path"]).parts)
        self.transition.loom_reliability.atomic_write_json(
            source_root / "lifecycle.json", source["ledger"])

        recovered = self.transition.recover_successor_activation(
            self.root, prepared["command_id"], witness_path=self.witness,
            envelope_root=self.envelopes, lock_path=self.lock)

        self.assertEqual("completed", recovered["status"])
        self.assertEqual(
            prepared["index"],
            json.loads((self.root / "plans" / "active-generation.json").read_text(
                encoding="utf-8")))

    def test_successor_projection_replay_always_reverifies_exact_action(self):
        _source, stage, prepared = self._prepare_live_successor()
        self.transition.activate_successor(
            self.root, stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        self.transition.complete_successor_projection(
            self.envelopes, prepared["command_id"],
            candidate_action_id=prepared["candidate_action_id"],
            projection_verifier=lambda _prepared, _receipt: None)

        def reject_stale_projection(_prepared, _receipt):
            raise self.transition.LifecycleTransitionError(
                "stale action projection")

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "stale action projection"):
            self.transition.complete_successor_projection(
                self.envelopes, prepared["command_id"],
                candidate_action_id=prepared["candidate_action_id"],
                projection_verifier=reject_stale_projection)

    def test_completed_claim_with_exact_source_authority_preserves_source(self):
        source, stage, prepared = self._prepare_live_successor()
        self.transition.activate_successor(
            self.root, stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        source_root = self.root.joinpath(
            *Path(source["index"]["generation_path"]).parts)
        self.transition.loom_reliability.atomic_write_json(
            self.root / "plans" / "active-generation.json", source["index"])
        self.transition.loom_reliability.atomic_write_json(
            source_root / "lifecycle.json", source["ledger"])
        self.transition.loom_reliability.atomic_write_json(
            self.witness, source["witness"])
        writes = []
        original_write = self.transition.loom_reliability.atomic_write_json

        def recording_write(path, value):
            writes.append(Path(path))
            return original_write(path, value)

        with mock.patch.object(
                self.transition.loom_reliability, "atomic_write_json",
                side_effect=recording_write):
            recovered = self.transition.activate_successor(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock)

        self.assertEqual("abandoned", recovered["status"])
        self.assertNotIn(
            self.root / "plans" / "active-generation.json", writes)
        self.assertNotIn(source_root / "lifecycle.json", writes)
        self.assertEqual(
            "generation-1",
            self.transition.loom_plan_store.resolve(self.root).generation_id)

    def test_successor_requires_closed_executor_quiescence(self):
        source = self._activate_reviewable_initial_generation()
        stage = self.root / ".unsafe-successor-stage"
        stage.mkdir()
        (stage / "MANIFEST.md").write_text("candidate\n", encoding="utf-8")
        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "executor quiescence"):
            self.transition.prepare_successor_authority(
                stage, index_value={**self.index,
                    "generation_id": "generation-2",
                    "generation_path": "plans/generations/generation-2",
                    "index_sha256": HEX_A},
                semantics_value=source["semantics"],
                reviewed_world_value=source["reviewed_world"],
                source_index=source["index"],
                source_semantics=source["semantics"],
                source_ledger=source["ledger"],
                source_witness=source["witness"],
                command_id="switch-unsafe", candidate_action_id="candidate-1",
                candidate_action_sha256=HEX_A, project_world_sha256=HEX_B,
                executor_quiescence={
                    "case": "active-executor-indeterminate",
                    "action_id": "action-1", "receipt_sha256": None},
                candidate_projection={
                    "schema_version": 1,
                    "action_id": "candidate-1",
                    "action_base_sha256": HEX_A,
                    "project_id": "project-1",
                    "generation_id": "generation-2",
                    "session_id": "session-1",
                    "operation_id": "operation-1",
                    "invocation_id": "invocation-1",
                    "journal_path_sha256": HEX_B,
                    "completion_instant": "2026-08-15T12:00:00+00:00",
                    "owner_stage_manifest":
                        loom_reliability.exact_tree_manifest(stage),
                })

    def test_successor_projection_rejects_nonobject_closed(self):
        _source, _stage, prepared = self._prepare_live_successor()
        malformed = json.loads(json.dumps(prepared))
        malformed["candidate_projection"] = []
        malformed["prepared_sha256"] = kernel.digest({
            key: value for key, value in malformed.items()
            if key != "prepared_sha256"})

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "action projection"):
            self.transition._validate_prepared_generation(malformed)

    def test_active_predecessor_cannot_claim_no_active_executor(self):
        self._activate_reviewable_initial_generation()
        self.transition.transition(
            self.root,
            self._command(
                "start-exact", "activate-predecessor", action_id="action-1"),
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        resolved, semantics, ledger, witness, state = self.transition._observe(
            self.root,
            self.transition._witness_store(witness_path=self.witness))
        self.assertEqual("active", state.generation_phase)
        source = {
            "index": {
                "schema_version": 1,
                "project_id": resolved.index.project_id,
                "generation_id": resolved.index.generation_id,
                "storage_kind": resolved.index.storage_kind,
                "generation_path": resolved.index.generation_path,
                "index_sha256": resolved.index.index_sha256,
            },
            "semantics": semantics,
            "ledger": ledger,
            "witness": witness,
        }

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "executor quiescence"):
            self._prepare_live_successor(source=source)

    def test_active_predecessor_receipt_binds_exact_lifecycle_action(self):
        self._activate_reviewable_initial_generation()
        self.transition.transition(
            self.root,
            self._command(
                "start-exact", "activate-predecessor", action_id="action-1"),
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        resolved, semantics, ledger, witness, state = self.transition._observe(
            self.root,
            self.transition._witness_store(witness_path=self.witness))
        self.assertEqual("active", state.generation_phase)
        source = {
            "index": {
                "schema_version": 1,
                "project_id": resolved.index.project_id,
                "generation_id": resolved.index.generation_id,
                "storage_kind": resolved.index.storage_kind,
                "generation_path": resolved.index.generation_path,
                "index_sha256": resolved.index.index_sha256,
            },
            "semantics": semantics,
            "ledger": ledger,
            "witness": witness,
        }
        receipt = loom_operation_supervisor.run(
            operation_class="successor-quiescence-test",
            command=[sys.executable, "-c", "pass"], cwd=self.root,
            timeout=10, allowed_roots=[self.root],
            protected_roots=[resolved.generation_root])
        quiescence = {
            "case": "supervisor-terminal",
            "action_id": "different-action",
            "project_id": state.project_id,
            "generation_id": state.generation_id,
            "action_sha256": HEX_A,
            "lifecycle_state_sha256": state.state_sha256,
            "pointer_expectation": "exact-action",
            "action_operation_id": "action-operation-1",
            "supervisor_operation_id": receipt["operation_id"],
            "project_world_sha256": HEX_B,
            "terminal_state": "completed",
            "receipt_sha256": receipt["receipt_sha256"],
            "supervisor_receipt": receipt,
        }
        quiescence["binding_sha256"] = kernel.digest(quiescence)

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "executor quiescence"):
            self._prepare_live_successor(
                source=source, executor_quiescence=quiescence)

        valid = json.loads(json.dumps(quiescence))
        valid["action_id"] = "action-1"
        valid["binding_sha256"] = kernel.digest({
            key: value for key, value in valid.items()
            if key != "binding_sha256"})
        _source, _stage, prepared = self._prepare_live_successor(
            "generation-3", source=source, executor_quiescence=valid)
        self.assertEqual("action-1", prepared["executor_quiescence"]["action_id"])

        repair_command = {
            **self._command("repair-active", "repair-predecessor",
                            action_id="repair-action-1"),
            "affected_scope_sha256": HEX_A,
        }
        repair_decision = kernel.decide(
            state, kernel.lifecycle_command(repair_command))
        self.assertTrue(repair_decision.accepted)
        repair_ledger = self.transition._target_ledger(
            source["ledger"], repair_decision)
        repair_witness = self.transition._target_witness(
            source["witness"], repair_decision, repair_ledger)
        repair_state = kernel.fold(
            source["index"], source["semantics"], repair_ledger,
            repair_witness)
        repair = json.loads(json.dumps(valid))
        repair["action_id"] = "repair-action-1"
        repair["lifecycle_state_sha256"] = repair_state.state_sha256
        repair["binding_sha256"] = kernel.digest({
            key: value for key, value in repair.items()
            if key != "binding_sha256"
        })
        repair_source = {**source, "ledger": repair_ledger,
                         "witness": repair_witness}
        _source, _stage, repair_prepared = self._prepare_live_successor(
            "generation-repair", source=repair_source,
            executor_quiescence=repair)
        self.assertEqual(
            "repair-action-1",
            repair_prepared["executor_quiescence"]["action_id"])

        nonterminal = json.loads(json.dumps(valid))
        nonterminal_receipt = nonterminal["supervisor_receipt"]
        nonterminal_receipt["status"] = "failed"
        nonterminal_receipt["primary_failure"] = "start-failed"
        nonterminal_receipt["returncode"] = None
        nonterminal_receipt["receipt_sha256"] = loom_operation_supervisor._hash({
            key: value for key, value in nonterminal_receipt.items()
            if key != "receipt_sha256"})
        nonterminal["receipt_sha256"] = nonterminal_receipt["receipt_sha256"]
        nonterminal["terminal_state"] = None
        nonterminal["binding_sha256"] = kernel.digest({
            key: value for key, value in nonterminal.items()
            if key != "binding_sha256"})
        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "executor quiescence"):
            self._prepare_live_successor(
                "generation-4", source=source,
                executor_quiescence=nonterminal)

        forged = json.loads(json.dumps(valid))
        forged["supervisor_receipt"]["operation_id"] = "fabricated-operation"
        forged["binding_sha256"] = kernel.digest({
            key: value for key, value in forged.items()
            if key != "binding_sha256"})
        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "executor quiescence"):
            self._prepare_live_successor(
                "generation-5", source=source,
                executor_quiescence=forged)

    def test_two_live_successors_cannot_consume_one_reviewable_source(self):
        source, first_stage, first = self._prepare_live_successor("generation-2")
        _same_source, second_stage, second = self._prepare_live_successor(
            "generation-3", source=source)
        barrier = threading.Barrier(2)

        def activate(item):
            stage, prepared = item
            barrier.wait(timeout=10)
            try:
                result = self.transition.activate_successor(
                    self.root, stage, prepared,
                    witness_path=self.witness, envelope_root=self.envelopes,
                    lock_path=self.lock)
                return "completed:" + prepared["index"]["generation_id"]
            except self.transition.LifecycleTransitionError as exc:
                return "blocked:" + str(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                activate,
                ((first_stage, first), (second_stage, second))))

        self.assertEqual(
            1, sum(item.startswith("completed:") for item in outcomes), outcomes)
        self.assertEqual(
            1, sum(item.startswith("blocked:") for item in outcomes), outcomes)
        self.assertIn(
            self.transition.loom_plan_store.resolve(self.root).generation_id,
            {"generation-2", "generation-3"})

    def test_pending_inventory_recovers_interrupted_successor_without_redispatch(self):
        _source, stage, prepared = self._prepare_live_successor()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.activate_successor(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, fault_at="after-generation-install")

        recovered = self.transition.recover_pending(
            self.root, witness_path=self.witness,
            envelope_root=self.envelopes, lock_path=self.lock)

        self.assertEqual(1, len(recovered))
        self.assertEqual("successor-activation", recovered[0]["kind"])
        self.assertEqual("abandoned", recovered[0]["status"])
        self.assertEqual(
            "generation-1",
            self.transition.loom_plan_store.resolve(self.root).generation_id)

    def test_successor_target_collision_never_replaces_existing_bytes(self):
        source, stage, prepared = self._prepare_live_successor()
        target = self.root.joinpath(
            *Path(prepared["index"]["generation_path"]).parts)
        target.mkdir(parents=True)
        marker = target / "preserve.txt"
        marker.write_text("unrelated target\n", encoding="utf-8")
        source_root = self.root.joinpath(
            *Path(source["index"]["generation_path"]).parts)
        ledger_before = (source_root / "lifecycle.json").read_bytes()
        witness_before = self.witness.read_bytes()

        with self.assertRaisesRegex(
                self.transition.LifecycleTransitionError,
                "installation failed|canonical lifecycle observation failed"):
            self.transition.activate_successor(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock)

        self.assertEqual("unrelated target\n", marker.read_text(encoding="utf-8"))
        self.assertEqual(ledger_before, (source_root / "lifecycle.json").read_bytes())
        self.assertEqual(witness_before, self.witness.read_bytes())

    def test_first_generation_activation_commits_only_the_active_index(self):
        """Break caught: a reviewed generation needs a multi-directory authority swap."""
        prepared = self._prepare()

        result = self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", result["status"])
        resolved = self.transition.loom_plan_store.resolve(self.root)
        self.assertEqual("generation-1", resolved.generation_id)
        self.assertFalse(self.stage.exists())
        self.assertEqual(
            prepared["index"],
            json.loads((self.root / "plans" / "active-generation.json").read_text(
                encoding="utf-8")),
        )
        observed_witness = json.loads(self.witness.read_text(encoding="utf-8"))
        state = kernel.fold(
            prepared["index"], prepared["semantics"],
            prepared["ledger"], observed_witness)
        self.assertEqual("reviewable", state.generation_phase)

    def test_two_concurrent_rollovers_activate_only_one_successor(self):
        """Two successors cannot both consume one terminal predecessor."""
        self._activate_terminal_initial_generation()
        first_stage, first = self._prepare_successor("generation-2")
        second_stage, second = self._prepare_successor("generation-3")
        barrier = threading.Barrier(2)

        def activate(item):
            stage, prepared = item
            barrier.wait(timeout=10)
            try:
                result = self.transition.activate_generation(
                    self.root, stage, prepared,
                    witness_path=self.witness, envelope_root=self.envelopes,
                    lock_path=self.lock)
                return "completed:" + prepared["index"]["generation_id"]
            except self.transition.LifecycleTransitionError as exc:
                return "blocked:" + str(exc)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                activate,
                ((first_stage, first), (second_stage, second))))

        self.assertEqual(
            1, sum(item.startswith("completed:") for item in outcomes), outcomes)
        self.assertEqual(
            1, sum(item.startswith("blocked:") for item in outcomes), outcomes)
        active = self.transition.loom_plan_store.resolve(self.root)
        winner = next(
            item.split(":", 1)[1] for item in outcomes
            if item.startswith("completed:"))
        self.assertEqual(winner, active.generation_id)

    def test_rollover_and_locked_status_observe_only_old_or_new_authority(self):
        """Read-only status shares the writer lock and never observes staging."""
        self._activate_terminal_initial_generation()
        stage, prepared = self._prepare_successor("generation-2")
        barrier = threading.Barrier(2)

        def activate():
            barrier.wait(timeout=10)
            return self.transition.activate_generation(
                self.root, stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock)["status"]

        def status():
            barrier.wait(timeout=10)
            with loom_reliability.exclusive_file_lock(self.lock):
                resolved = self.transition.loom_plan_store.resolve(self.root)
                witness = json.loads(
                    self.witness.read_text(encoding="utf-8"))
                semantics = json.loads(
                    (resolved.generation_root / "plan-semantics.json").read_text(
                        encoding="utf-8"))
                ledger = json.loads(
                    (resolved.generation_root / "lifecycle.json").read_text(
                        encoding="utf-8"))
                state = kernel.fold(
                    resolved.index, semantics, ledger, witness)
                return state.generation_id, state.generation_phase

        with ThreadPoolExecutor(max_workers=2) as pool:
            activation_future = pool.submit(activate)
            status_future = pool.submit(status)
            activation = activation_future.result(timeout=30)
            observed = status_future.result(timeout=30)

        self.assertEqual("completed", activation)
        self.assertIn(
            observed,
            {("generation-1", "terminal-completed"),
             ("generation-2", "reviewable")})

    def test_interrupted_non_authoritative_generation_sealing_resumes_exactly(self):
        """Break caught: a crash before activation strands an unrecoverable stage."""
        real_write = self.transition.loom_reliability.atomic_write_json
        writes = 0

        def interrupt_after_first_write(path, value):
            nonlocal writes
            real_write(path, value)
            writes += 1
            if writes == 1:
                raise self.transition.loom_reliability.ReliabilityError(
                    "injected preparation interruption")

        with mock.patch.object(
                self.transition.loom_reliability, "atomic_write_json",
                side_effect=interrupt_after_first_write):
            with self.assertRaisesRegex(
                    self.transition.LifecycleTransitionError,
                    "prepared generation could not be sealed"):
                self._prepare()

        prepared = self._prepare()

        self.assertEqual(
            prepared["semantics"],
            json.loads((self.stage / "plan-semantics.json").read_text(
                encoding="utf-8")))
        self.assertEqual(
            prepared["reviewed_world"],
            json.loads((self.stage / "reviewed-world.json").read_text(
                encoding="utf-8")))
        self.assertEqual(
            prepared["ledger"],
            json.loads((self.stage / "lifecycle.json").read_text(
                encoding="utf-8")))

    def test_generation_activation_uses_the_existing_orchestration_lock(self):
        """Break caught: activation deadlocks by reacquiring the sole project lock."""
        prepared = self._prepare()

        with mock.patch.object(
                self.transition.loom_reliability, "exclusive_file_lock",
                side_effect=AssertionError("activation reacquired the project lock")):
            result = self.transition.activate_generation(
                self.root, self.stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, _lock_held=True)

        self.assertEqual("completed", result["status"])

    def test_reviewable_revision_activates_a_new_immutable_path_in_same_generation(self):
        """Break caught: pre-start revision mutates the active generation in place."""
        initial = self._prepare()
        self.transition.activate_generation(
            self.root, self.stage, initial,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        revision_stage = self.root / ".revision-stage"
        revision_stage.mkdir()
        (revision_stage / "MANIFEST.md").write_text(
            "---\nexecution_policy: strict-serial-sequence-v1\n"
            "execution_sequence: [WO-001, WO-002]\n---\n",
            encoding="utf-8")
        semantics = json.loads(json.dumps(initial["semantics"]))
        semantics["revision_number"] = 2
        semantics["summary"] = "Revised reviewed meaning"
        semantics["plan_semantics_sha256"] = kernel.digest({
            key: value for key, value in semantics.items()
            if key != "plan_semantics_sha256"})
        relative = (
            "plans/generations/revisions/generation-1/"
            "r000002-" + semantics["plan_semantics_sha256"])
        index = {
            "schema_version": 1,
            "project_id": "project-1",
            "generation_id": "generation-1",
            "storage_kind": "generation-dir",
            "generation_path": relative,
        }
        index["index_sha256"] = kernel.digest(index)

        prepared = self.transition.prepare_revision_authority(
            revision_stage, index_value=index, semantics_value=semantics,
            reviewed_world_value=initial["reviewed_world"],
            source_index=initial["index"],
            source_semantics=initial["semantics"],
            source_ledger=initial["ledger"],
            source_witness=initial["witness"],
            command_id="command-review-revision-2")
        result = self.transition.activate_generation(
            self.root, revision_stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", result["status"])
        resolved = self.transition.loom_plan_store.resolve(self.root)
        self.assertEqual("generation-1", resolved.generation_id)
        self.assertEqual(relative, resolved.index.generation_path)
        self.assertTrue(
            self.root.joinpath(*Path(initial["index"]["generation_path"]).parts).is_dir())
        observed = json.loads(self.witness.read_text(encoding="utf-8"))
        state = kernel.fold(
            prepared["index"], prepared["semantics"],
            prepared["ledger"], observed)
        self.assertEqual("reviewable", state.generation_phase)
        self.assertEqual(2, prepared["semantics"]["revision_number"])
        self.assertEqual("plan-revised", prepared["ledger"]["events"][-1]["event_type"])

    def test_post_index_interruption_rolls_witness_forward_without_reactivation(self):
        """Break caught: committed generation activation is rolled back after restart."""
        prepared = self._prepare()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.activate_generation(
                self.root, self.stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, fault_at="after-index-commit")
        index_bytes = (
            self.root / "plans" / "active-generation.json").read_bytes()
        self.assertFalse(self.witness.exists())
        recovered = self.transition.recover_generation_activation(
            self.root, "command-review-generation-1",
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", recovered["status"])
        self.assertEqual(
            index_bytes,
            (self.root / "plans" / "active-generation.json").read_bytes())
        self.assertEqual(
            prepared["witness"]["witness_sha256"],
            json.loads(self.witness.read_text(encoding="utf-8"))["witness_sha256"],
        )

    def test_completed_activation_replay_restores_an_exact_rolled_back_index(self):
        """Break caught: a completed receipt masks active-index rollback."""
        prepared = self._prepare()
        self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        index_path = self.root / "plans" / "active-generation.json"
        index_path.unlink()

        replay = self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", replay["status"])
        self.assertEqual(
            prepared["index"],
            json.loads(index_path.read_text(encoding="utf-8")))

    def test_completed_activation_replay_repairs_an_exact_witness_lag(self):
        """Break caught: active generation authority leaves its witness absent."""
        prepared = self._prepare()
        self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)
        self.witness.unlink()

        replay = self.transition.activate_generation(
            self.root, self.stage, prepared,
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", replay["status"])
        self.assertEqual(
            prepared["witness"],
            json.loads(self.witness.read_text(encoding="utf-8")))

    def test_pre_index_interruption_does_not_make_staged_generation_authoritative(self):
        """Break caught: an orphan generation is mistaken for active authority."""
        prepared = self._prepare()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.activate_generation(
                self.root, self.stage, prepared,
                witness_path=self.witness, envelope_root=self.envelopes,
                lock_path=self.lock, fault_at="after-generation-install")

        recovered = self.transition.recover_generation_activation(
            self.root, "command-review-generation-1",
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("abandoned", recovered["status"])
        self.assertFalse(
            (self.root / "plans" / "active-generation.json").exists())
        self.assertFalse(self.witness.exists())


class LegacyGenerationAdoptionTests(unittest.TestCase):
    def setUp(self):
        import loom_lifecycle_transition
        self.transition = loom_lifecycle_transition
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plans = self.root / "plans"
        self.plans.mkdir()
        (self.plans / "MANIFEST.md").write_text(
            "---\nstatus: gated\n---\n# Historical reviewed plan\n",
            encoding="utf-8")
        work_orders = self.plans / "work-orders"
        work_orders.mkdir()
        (work_orders / "WO-001-historical.md").write_text(
            "---\nid: WO-001\nstatus: ready\ndepends_on: []\n---\n",
            encoding="utf-8")
        self.legacy_lifecycle = self.plans / "lifecycle.json"
        self.legacy_lifecycle.write_text(
            '{"schema_version":2,"events":[{"event":"plan-sealed"}]}\n',
            encoding="utf-8")
        _index, semantics, _ledger, _witness = _canonical_state_inputs(kernel)
        semantics = json.loads(json.dumps(semantics))
        semantics["generation_id"] = "historical-generation-1"
        semantics["work_orders"] = [semantics["work_orders"][0]]
        semantics["execution_sequence"] = ["WO-001"]
        self.reviewed_world = _canonical_world_observation(kernel)
        self.reviewed_world = {
            **self.reviewed_world,
            "generation_id": "historical-generation-1",
        }
        self.reviewed_world["observation_sha256"] = kernel.digest({
            key: value for key, value in self.reviewed_world.items()
            if key != "observation_sha256"
        })
        semantics["reviewed_world_observation_sha256"] = \
            self.reviewed_world["observation_sha256"]
        semantics["plan_semantics_sha256"] = kernel.digest({
            key: value for key, value in semantics.items()
            if key != "plan_semantics_sha256"
        })
        self.semantics = semantics
        self.index = {
            "schema_version": 1,
            "project_id": "project-1",
            "generation_id": "historical-generation-1",
            "storage_kind": "legacy-root",
            "generation_path": "plans",
        }
        self.index["index_sha256"] = kernel.digest(self.index)
        self.witness = self.root / ".private" / "head-witness.json"
        self.envelopes = self.root / ".private" / "transitions"
        self.lock = self.root / ".private" / "project.lock"

    def tearDown(self):
        self.temporary.cleanup()

    def _prepare(self):
        return self.transition.prepare_legacy_adoption(
            self.root, index_value=self.index,
            semantics_value=self.semantics,
            reviewed_world_value=self.reviewed_world,
            command_id="adopt-historical-generation-1",
            source_lifecycle_name="lifecycle.json")

    def test_legacy_adoption_commits_the_index_as_its_only_authority_point(self):
        """Break caught: historical execution has no journaled v3 adoption path."""
        source = loom_reliability.exact_tree_manifest(self.plans)
        prepared = self._prepare()

        result = self.transition.adopt_legacy_root(
            self.root, prepared, witness_path=self.witness,
            envelope_root=self.envelopes, lock_path=self.lock)

        self.assertEqual("completed", result["status"])
        self.assertEqual(source, prepared["source_manifest"])
        resolved = self.transition.loom_plan_store.resolve(self.root)
        self.assertEqual("legacy-root", resolved.storage_kind)
        self.assertEqual("historical-generation-1", resolved.generation_id)
        observed_witness = json.loads(self.witness.read_text(encoding="utf-8"))
        state = kernel.fold(
            prepared["index"], prepared["semantics"],
            prepared["ledger"], observed_witness)
        self.assertEqual("reviewable", state.generation_phase)

    def test_pre_index_adoption_crash_restores_the_exact_legacy_tree(self):
        """Break caught: precommit adoption changes a reviewed historical pack."""
        source = loom_reliability.exact_tree_manifest(self.plans)
        source_lifecycle = self.legacy_lifecycle.read_bytes()
        prepared = self._prepare()

        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.adopt_legacy_root(
                self.root, prepared, witness_path=self.witness,
                envelope_root=self.envelopes, lock_path=self.lock,
                fault_at="after-lifecycle")
        recovered = self.transition.recover_legacy_adoption(
            self.root, "adopt-historical-generation-1",
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("abandoned", recovered["status"])
        self.assertFalse((self.plans / "active-generation.json").exists())
        self.assertFalse(self.witness.exists())
        self.assertEqual(source_lifecycle, self.legacy_lifecycle.read_bytes())
        self.assertEqual(source, loom_reliability.exact_tree_manifest(self.plans))

    def test_prepared_adoption_rejects_a_malformed_source_manifest_closed(self):
        """A sealed adoption cannot bypass closed manifest validation."""
        prepared = self._prepare()
        prepared["source_manifest"] = {}
        prepared["prepared_sha256"] = kernel.digest({
            key: value for key, value in prepared.items()
            if key != "prepared_sha256"
        })

        with self.assertRaises(self.transition.LifecycleTransitionError):
            self.transition._validate_prepared_legacy_adoption(prepared)

    def test_post_index_adoption_crash_rolls_the_witness_forward(self):
        """Break caught: committed historical authority remains unwitnessed."""
        prepared = self._prepare()
        with self.assertRaises(self.transition.LifecycleTransitionInterrupted):
            self.transition.adopt_legacy_root(
                self.root, prepared, witness_path=self.witness,
                envelope_root=self.envelopes, lock_path=self.lock,
                fault_at="after-index-commit")

        recovered = self.transition.recover_legacy_adoption(
            self.root, "adopt-historical-generation-1",
            witness_path=self.witness, envelope_root=self.envelopes,
            lock_path=self.lock)

        self.assertEqual("completed", recovered["status"])
        self.assertEqual(
            prepared["witness"],
            json.loads(self.witness.read_text(encoding="utf-8")))

    def test_completed_adoption_replay_restores_an_exact_rolled_back_index(self):
        """Break caught: a completed receipt masks a restored legacy source index."""
        prepared = self._prepare()
        self.transition.adopt_legacy_root(
            self.root, prepared, witness_path=self.witness,
            envelope_root=self.envelopes, lock_path=self.lock)
        (self.plans / "active-generation.json").unlink()

        replay = self.transition.adopt_legacy_root(
            self.root, prepared, witness_path=self.witness,
            envelope_root=self.envelopes, lock_path=self.lock)

        self.assertEqual("completed", replay["status"])
        self.assertEqual(
            prepared["index"], json.loads(
                (self.plans / "active-generation.json").read_text(
                    encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
