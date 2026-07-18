"""Trust-critical regression coverage for Loom owner-learning schema v3."""

import datetime as dt
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

import loom_domain
import loom_learning_contract
import loom_learning_stats
import loom_learning
import loom_orchestrator
import loom_shadow_eval
import loom_vault
import loom_vault_adapter
from test_loom_vault_v11 import TestCrypto


class OwnerLearningPhase2Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.crypto = TestCrypto()
        self.vault = loom_vault.OwnerVault.create(
            self.root / "vault" / "owner.sqlite3", crypto=self.crypto,
            allow_test_crypto=True)

    def tearDown(self):
        self.temporary.cleanup()

    def record(self, statement, *, domain="accounting", status="active"):
        return {
            "id": str(uuid.uuid4()), "scope": "domain", "domain": domain,
            "project_id": None, "category": "domain", "statement": statement,
            "provenance": "observed", "status": status, "confidence": 0.8,
            "evidence_count": 3, "created_at": "2026-07-01T00:00:00Z",
            "preference_key": None, "preference_value": None,
        }

    def test_contract_is_single_v3_runtime_truth(self):
        result = loom_learning_contract.check_runtime()
        self.assertEqual({"status": "ok", "schema_version": 3, "checks": 10}, result)
        self.assertEqual(4096, loom_learning_contract.BOUNDS["selected_characters"])

    def test_v2_migrates_from_staged_copy_and_preserves_rollback(self):
        tables = [
            "memory_observations", "memory_effects", "preference_slots",
            "derivation_edges", "deletion_commitments", "policy_evaluations",
            "scope_aliases",
        ]
        connection = sqlite3.connect(self.vault.path)
        try:
            for table in tables:
                connection.execute(f"DROP TABLE {table}")
            connection.execute("UPDATE metadata SET value='2' WHERE key='schema_version'")
            connection.commit()
        finally:
            connection.close()
        migrated = loom_vault.OwnerVault.open(
            self.vault.path, crypto=self.crypto, allow_test_crypto=True)
        self.assertEqual(3, migrated.identity()["schema_version"])
        self.assertTrue(Path(str(self.vault.path) + ".schema-v2.rollback").is_file())
        self.assertEqual(tables, migrated.schema_migration_receipt()["tables"])

    def test_active_task_language_never_inherits_ambient_web_domains(self):
        facts = {"file_names": ["sitemap.xml", "skill.md", "plugin.json", "manifest.json"],
                 "extensions": [".md"], "dependencies": ["webextension-manifest"]}
        result = loom_domain.select_domains(
            "Implement the Loom owner-specific learning plan", project_facts=facts)
        self.assertEqual(["llm-agent"], result["active_task_domains"])
        self.assertIn("website", result["ambient_domains"])
        self.assertNotIn("website", result["memory_domains"])
        self.assertNotIn("research", result["memory_domains"])

    def test_selection_is_not_application_and_does_not_prevent_dormancy(self):
        record = self.vault.put_memory(self.record("Use exact ledger fixtures"))
        self.assertEqual(record["id"], self.vault.select_memory(
            domain="accounting", project_id=None)[0]["id"])
        receipt = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc))
        self.assertEqual(1, receipt["dormant"])
        summary = self.vault.improvement_summary()
        self.assertEqual(1, summary["memory_selection_count"])
        self.assertEqual(0, summary["memory_application_count"])

    def test_twenty_projects_remain_isolated_and_dormant_records_cost_zero_context(self):
        identifiers = []
        for index in range(20):
            project_id = "p-" + f"{index + 1:032x}"
            record = self.record(
                f"Project {index + 1} local rule", domain=f"domain-{index % 4}")
            record.update({"scope": "project", "project_id": project_id})
            stored = self.vault.put_memory(record)
            identifiers.append((project_id, record["domain"], stored["id"]))
        for project_id, domain, record_id in identifiers:
            selected = self.vault.select_memory(domain=domain, project_id=project_id)
            self.assertEqual([record_id], [item["id"] for item in selected])
        receipt = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc))
        self.assertEqual(20, receipt["dormant"])
        for project_id, domain, _record_id in identifiers:
            self.assertEqual([], self.vault.select_memory(
                domain=domain, project_id=project_id))
        self.assertLessEqual(self.vault.count("memory_records"),
                             loom_vault.MAX_ACTIVE_RECORDS)

    def test_component_and_currentness_boundaries_are_exact(self):
        project_id = "p-" + "1" * 32
        component_id = "c-" + "2" * 32
        component = self.record("Component-only rule")
        component.update({"scope": "component", "project_id": project_id,
                          "component_id": component_id})
        self.vault.put_memory(component)
        self.assertEqual([], self.vault.select_memory(
            domain="accounting", project_id=project_id))
        self.assertEqual(component["id"], self.vault.select_memory(
            domain="accounting", project_id=project_id,
            component_id=component_id)[0]["id"])
        fact = self.record("Current tax API rule")
        fact.update({"category": "technical-fact", "verify_by": "2026-07-10T00:00:00Z"})
        self.vault.put_memory(fact)
        receipt = self.vault.maintain_memory_lifecycle(
            now=dt.datetime(2026, 7, 20, tzinfo=dt.timezone.utc))
        self.assertEqual(1, receipt["revalidation-required"])
        self.assertEqual("revalidation-required", self.vault.get_memory(fact["id"])["status"])

    def test_per_memory_effects_prevent_session_wide_credit(self):
        helped = self.vault.put_memory(self.record("Verify postings balance"))
        unused = self.vault.put_memory(self.record("Review report colors"))
        receipt = self.vault.record_memory_effects("operation-1", [
            {"memory_id": helped["id"], "status": "verified-helped",
             "decision_target": "posting-check", "intended_effect": "catch imbalance",
             "evidence_id": "evidence-posting-1", "serious_harm": False},
            {"memory_id": unused["id"], "status": "selected-only",
             "decision_target": "report-style", "intended_effect": "style candidate",
             "evidence_id": None, "serious_harm": False},
        ])
        self.assertEqual(2, receipt["effects"])
        summary = self.vault.improvement_summary()
        self.assertEqual(1, summary["memory_helped_count"])
        self.assertEqual(1, summary["memory_application_count"])

    def test_serious_verified_harm_quarantines_immediately(self):
        harmful = self.vault.put_memory(self.record("Skip reconciliation"))
        receipt = self.vault.record_memory_effects("operation-harm", [{
            "memory_id": harmful["id"], "status": "verified-hurt",
            "decision_target": "reconciliation", "intended_effect": "save time",
            "evidence_id": "evidence-harm-1", "serious_harm": True,
        }])
        self.assertEqual(1, receipt["quarantined"])
        self.assertEqual("quarantined", self.vault.get_memory(harmful["id"])["status"])
        self.assertEqual([], self.vault.select_memory(domain="accounting", project_id=None))

    def test_derived_forgetting_removes_children_and_checkpoints_floor(self):
        source = self.vault.put_memory(self.record("Source observation"))
        child = self.vault.put_memory(self.record("Derived summary"))
        self.vault.add_derivation(source["id"], child["id"])
        receipt = self.vault.forget_memory(source["id"], reason="owner-request")
        self.assertEqual("complete", receipt["status"])
        self.assertEqual(1, receipt["deletion_epoch"])
        self.assertIsNone(self.vault.get_memory(source["id"]))
        self.assertIsNone(self.vault.get_memory(child["id"]))
        self.assertEqual(1, self.vault.count("deletion_commitments"))

    def test_forget_receipt_waits_for_every_active_device(self):
        record = self.vault.put_memory(self.record("Device-propagated deletion"))
        remote = str(uuid.uuid4())
        self.vault.authorize_device(remote, self.crypto.public_key())
        pending = self.vault.forget_memory(record["id"], reason="owner-request")
        self.assertEqual("pending-devices", pending["status"])
        acknowledged = self.vault.acknowledge_checkpoint(pending["checkpoint_id"], remote)
        self.assertEqual(1, acknowledged["deletion_commitments_completed"])

    def test_improvement_states_require_complete_cost_and_uncertainty(self):
        cost = {"input_tokens": 10, "cache_read_tokens": 20, "output_tokens": 5,
                "tool_tokens": 2, "retry_tokens": 0, "elapsed_seconds": 1.5}
        one = loom_learning_stats.evaluate(
            observations=[0.2], paired_effects=[], randomized=False, propensities=None,
            materiality=0.05, harm_threshold=0.05, severe_harm=False, cost=cost)
        self.assertEqual("measurement-started", one["evidence_state"])
        associated = loom_learning_stats.evaluate(
            observations=[0.2] * 16, paired_effects=[], randomized=False, propensities=None,
            materiality=0.05, harm_threshold=0.05, severe_harm=False, cost=cost)
        self.assertEqual("associated-only", associated["evidence_state"])
        with self.assertRaises(loom_learning_stats.LearningStatisticsError):
            loom_learning_stats.evaluate(
                observations=[], paired_effects=[0.5, 0.6], randomized=True,
                propensities=[0.5, 0], materiality=0.05, harm_threshold=0.05,
                severe_harm=False, cost=cost)

    def test_general_admission_requires_cross_project_cross_domain_diversity(self):
        one_project = [
            {"project_id": "p-one", "domain": "website", "component_id": None,
             "evidence_id": f"evidence-{index}", "contradicts": False}
            for index in range(5)]
        candidate = loom_learning.admission_decision(
            one_project, category="process", requested_scope="general")
        self.assertEqual("candidate", candidate["status"])
        diverse = [
            {"project_id": f"p-{index % 3}",
             "domain": "website" if index < 3 else "accounting",
             "component_id": None, "evidence_id": f"diverse-{index}",
             "contradicts": False}
            for index in range(6)]
        promoted = loom_learning.admission_decision(
            diverse, category="workflow-calibration", requested_scope="general")
        self.assertEqual("active", promoted["status"])
        technical = loom_learning.admission_decision(
            diverse, category="technical-fact", requested_scope="general")
        self.assertEqual("rejected", technical["status"])

    def test_explicit_preference_dominates_inference_and_conflicts_quarantine(self):
        resolved = loom_learning.resolve_preference([
            {"source": "inferred", "value": "autonomous", "sequence": 10},
            {"source": "owner-stated", "value": "careful", "sequence": 1},
        ])
        self.assertEqual("careful", resolved["value"])
        conflict = loom_learning.resolve_preference([
            {"source": "owner-stated", "value": "careful", "concurrent": True},
            {"source": "owner-stated", "value": "autonomous", "concurrent": True},
        ])
        self.assertEqual("quarantined", conflict["status"])

    def test_preferences_and_shadow_evaluations_use_typed_v3_tables(self):
        preference = self.record("Use careful review")
        preference.update({
            "category": "preference", "provenance": "stated",
            "preference_key": "autonomy_default",
            "preference_value": "careful-review",
        })
        self.vault.put_memory(preference)
        self.assertEqual(1, self.vault.count("preference_slots"))

        adapter = loom_vault_adapter.VaultMemoryAdapter(
            owner_home=self.root / "home", vault=self.vault)
        replay = {
            "replay_id": "replay-typed-v3", "metric": "quality",
            "domain": "accounting", "policy_version": "shadow-v1",
            "enabled": {"value": 1, "evidence_id": "e-enabled",
                        "provider_receipt": "provider-a", "token_cost": 10,
                        "elapsed_seconds": 0.2, "memory_ids": []},
            "disabled": {"value": 0, "evidence_id": "e-disabled",
                         "provider_receipt": "provider-b", "token_cost": 8,
                         "elapsed_seconds": 0.1},
        }
        ids = adapter.record_replay(replay, "p-" + "3" * 32)
        self.assertEqual(3, len(ids))
        self.assertEqual(3, self.vault.count("policy_evaluations"))
        self.assertEqual(0, len(self.vault.list_entities("policy-evaluation")))

    def test_shadow_evaluation_is_bounded_and_protected_rules_are_ineligible(self):
        self.assertFalse(loom_shadow_eval.eligible(
            {"category": "safety"}, tier="L", structurally_equivalent=True,
            propensity=0.5)["eligible"])
        with self.assertRaises(loom_shadow_eval.ShadowEvaluationError):
            loom_shadow_eval.seal_pair(
                request={}, world={}, plan_contract={}, provider="p", model_policy="m",
                rubric={}, enabled_response_id="a", disabled_response_id="b",
                enabled_response="one", disabled_response="two", memory_ids=["m"],
                propensity=0.5, rolling_tokens=1000, shadow_tokens=21, tier="L")

    def test_missing_crypto_helper_never_falls_back_to_json_learning(self):
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "second legacy learning authority"):
            loom_orchestrator._memory_backend(
                self.root / "home", self.root / "install", self.root)


if __name__ == "__main__":
    unittest.main()
