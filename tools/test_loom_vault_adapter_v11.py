"""Runtime integration tests for the Loom 1.1 owner-vault memory adapter."""

import datetime as dt
import json
import tempfile
import types
import unittest
import uuid
from pathlib import Path

import loom_vault
import loom_vault_adapter
import loom_session
from test_loom_vault_v11 import TestCrypto


class VaultAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.crypto = TestCrypto()
        self.vault = loom_vault.OwnerVault.create(
            self.root / "owner.sqlite3", crypto=self.crypto,
            owner_vault_id=str(uuid.uuid4()), device_id=str(uuid.uuid4()),
            allow_test_crypto=True)
        self.adapter = loom_vault_adapter.VaultMemoryAdapter(
            owner_home=self.root, vault=self.vault)
        prepared = types.SimpleNamespace(
            domains=("accounting",), prepared_at="2026-07-15T12:00:00Z",
            route_contract={"tier": "M"})
        self.context = types.SimpleNamespace(
            prepared=prepared, intent="plan", project_id="p-" + "1" * 32,
            operation_id=str(uuid.uuid4()), selected_memory=())

    def tearDown(self):
        self.tmp.cleanup()

    def test_remember_select_outcome_and_profile_use_one_vault(self):
        record = self.adapter.remember(self.context, "Require balanced journal entries.")
        selected = self.adapter.select(self.context)
        self.assertEqual([record["id"]], [item["id"] for item in selected])
        self.context.selected_memory = tuple(selected)
        result = self.adapter.record_outcome(self.context, {
            "success": True, "metrics": {}, "evidence_ids": ["test-evidence"],
            "applied_memory_ids": [record["id"]], "rejected_memory_ids": [],
            "memory_effects": [{
                "memory_id": record["id"], "status": "verified-helped",
                "decision_target": "balanced-postings",
                "intended_effect": "prevent unbalanced journal entries",
                "evidence_id": "test-evidence", "serious_harm": False,
            }],
            "reversible_action_ids": [],
        })
        self.assertEqual(1, len(result["outcome_ids"]))
        summary = self.vault.improvement_summary()
        self.assertEqual(1, summary["memory_helped_count"])
        self.assertEqual("measurement-started", summary["evidence_state"])
        self.assertIn("balanced journal entries", self.adapter.profile_summary())

    def test_session_journal_encrypts_owner_statements_and_replays_receipt(self):
        self.adapter.remember(self.context, "Never expose the private owner phrase.")
        project = self.root / "project"
        project.mkdir()
        (project / "README.md").write_text("fixture\n", encoding="utf-8")
        controller = loom_session.SessionController(
            owner_home=self.root, instance_id=self.adapter.instance_id,
            handlers={}, memory=self.adapter)
        invocation = "00000000-0000-4000-8000-000000009901"
        first = controller.run(
            "show my remembered preferences", invocation_id=invocation, cwd=project,
            now="2026-07-15T13:00:00Z")
        self.assertIn("private owner phrase", first.user_message)
        journal = next(self.root.rglob("session-journal.json"))
        raw = journal.read_text(encoding="utf-8")
        self.assertNotIn("private owner phrase", raw)
        parsed = json.loads(raw)
        self.assertTrue(all(
            event["payload"].get("kind") == "loom-encrypted-session-payload-v1"
            for event in parsed["events"]))
        second = controller.run(
            "show my remembered preferences",
            invocation_id="00000000-0000-4000-8000-000000009902", cwd=project,
            now="2026-07-15T13:01:00Z")
        self.assertTrue(second.repeated)
        self.assertEqual(first.receipt_hash, second.receipt_hash)
        self.assertIn("private owner phrase", second.user_message)

    def test_checkpoint_is_bounded_and_not_recreated_until_due(self):
        first = self.vault.checkpoint_if_due(
            now=dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc))
        second = self.vault.checkpoint_if_due(
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))
        self.assertEqual("created", first["status"])
        self.assertEqual("not-due", second["status"])
        self.assertEqual(1, self.vault.count("checkpoints"))
        self.assertEqual(1, self.vault.count("checkpoint_acks"))

    def test_compaction_waits_for_every_active_device_acknowledgement(self):
        self.adapter.remember(self.context, "Preserve causal evidence.")
        remote = str(uuid.uuid4())
        self.vault.authorize_device(remote, self.crypto.public_key())
        checkpoint = self.vault.checkpoint_if_due(
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc), force=True)
        waiting = self.vault.compact_acknowledged()
        self.assertEqual("awaiting-active-devices", waiting["status"])
        self.assertGreater(self.vault.count("events"), 0)
        self.vault.acknowledge_checkpoint(checkpoint["checkpoint_id"], remote)
        compacted = self.vault.compact_acknowledged()
        self.assertEqual("compacted", compacted["status"])
        self.assertGreater(compacted["events_removed"], 0)
        self.assertEqual(0, self.vault.count("events"))

    def test_forget_requires_unambiguous_selected_record(self):
        record = self.adapter.remember(self.context, "Use audit-safe rounding.")
        with self.assertRaisesRegex(
                loom_vault_adapter.VaultAdapterError, "exactly one"):
            self.adapter.forget("forget this", [])
        outcome = self.adapter.forget(f"forget {record['id']}", [record])
        self.assertIn(record["id"], outcome["message"])
        self.assertTrue(self.vault.is_forgotten(record["id"]))

    def test_repeated_single_project_evidence_activates_domain_only(self):
        for index in range(3):
            self.context.operation_id = str(uuid.uuid4())
            self.context.selected_memory = ()
            self.adapter.record_outcome(self.context, {
                "success": True, "metrics": {"verification-caught-defect": 1},
                "evidence_ids": [f"evidence-{index}"], "applied_memory_ids": [],
                "rejected_memory_ids": [], "reversible_action_ids": [],
            })
        accounting = self.vault.select_memory(
            domain="accounting", project_id=self.context.project_id)
        statements = [item["statement"] for item in accounting]
        self.assertTrue(any("verification medium" in item for item in statements))
        self.assertFalse(any("owner-specific calibration" in item for item in statements))
        unrelated = self.vault.select_memory(
            domain="three-d", project_id="p-" + "2" * 32)
        self.assertFalse(any("For accounting" in item["statement"] for item in unrelated))
        self.assertFalse(any("owner-specific calibration" in item["statement"]
                             for item in unrelated))

    def test_inferred_preferences_need_repetition_and_newer_drift_wins(self):
        self.context.selected_memory = ()
        for value in ("concise", "concise"):
            self.context.operation_id = str(uuid.uuid4())
            self.adapter.record_outcome(self.context, {
                "success": True, "metrics": {}, "evidence_ids": [],
                "preference_observations": [{"key": "report_detail", "value": value}],
                "applied_memory_ids": [], "rejected_memory_ids": [],
                "reversible_action_ids": [],
            })
        self.assertEqual([], self.adapter.select_preferences(self.context))
        self.context.operation_id = str(uuid.uuid4())
        self.adapter.record_outcome(self.context, {
            "success": True, "metrics": {}, "evidence_ids": [],
            "preference_observations": [{"key": "report_detail", "value": "concise"}],
            "applied_memory_ids": [], "rejected_memory_ids": [],
            "reversible_action_ids": [],
        })
        selected = self.adapter.select_preferences(self.context)
        self.assertEqual([], selected)
        for _ in range(3):
            self.context.operation_id = str(uuid.uuid4())
            self.adapter.record_outcome(self.context, {
                "success": True, "metrics": {}, "evidence_ids": [],
                "preference_observations": [{"key": "report_detail", "value": "detailed"}],
                "applied_memory_ids": [], "rejected_memory_ids": [],
                "reversible_action_ids": [],
            })
        self.assertEqual([], self.adapter.select_preferences(self.context))


if __name__ == "__main__":
    unittest.main()
