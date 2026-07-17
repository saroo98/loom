import copy
import unittest

import loom_domain
import loom_orchestrator
import loom_plan_contract


class PlanContractMigrationTests(unittest.TestCase):
    def legacy(self, domains):
        body = {
            "schema_version": 1, "request_hash": "a" * 64,
            "survey_hash": "b" * 64, "tier": "M", "domains": domains,
            "pack_baseline_hash": "c" * 64, "pack_root": "plans",
            "allowed_host_write_paths": ["plans/**"], "artifact_matrix": [],
            "required_domain_invariants": [], "current_facts_to_verify": [],
            "verification_media": [], "budget": {"character_ceiling": 1,
                "token_ceiling": 1, "token_metric": "loom-lexical-v1"},
            "work_order_topology": {"minimum": 1, "maximum": 1,
                "dag_required": True, "atomic_outcomes_required": True,
                "acceptance_evidence_required": True},
            "completion_gates": ["g1"],
        }
        return {**body, "contract_hash": loom_orchestrator._hash(body)}

    def test_known_projection_is_idempotent(self):
        route = loom_domain.select_domains("Build a CLI", explicit=["cli"])["domain_contract"]
        first = loom_plan_contract.migrate_v1(
            self.legacy(["cli"]), route=route, created_at="2030-01-01T00:00:00Z")
        second = loom_plan_contract.migrate_v1(
            self.legacy(["cli"]), route=route, created_at="2030-01-01T00:00:00Z")
        self.assertEqual(first, second)
        self.assertEqual("compatible-known", first["migration_receipt"]["status"])

    def test_unknown_projection_cannot_activate_legacy_verified_prose(self):
        route = loom_domain.select_domains(
            "Plan quantum optics", explicit=["quantum-optics"])["domain_contract"]
        result = loom_plan_contract.migrate_v1(
            self.legacy(["quantum-optics"]), route=route,
            created_at="2030-01-01T00:00:00Z")
        self.assertTrue(result["contract"]["domain_discovery"]["required"])
        self.assertEqual("revalidation-required", result["migration_receipt"]["status"])
        self.assertEqual([], result["contract"]["domain_invariants"])

    def test_changed_legacy_contract_hash_is_rejected(self):
        legacy = self.legacy(["cli"]); legacy["tier"] = "L"
        route = loom_domain.select_domains("Build a CLI", explicit=["cli"])["domain_contract"]
        with self.assertRaises(loom_plan_contract.PlanContractMigrationError):
            loom_plan_contract.migrate_v1(
                legacy, route=route, created_at="2030-01-01T00:00:00Z")

    def test_v2_to_v3_adds_content_bound_planning_intelligence(self):
        route = loom_domain.select_domains("Build a CLI", explicit=["cli"])["domain_contract"]
        version_two = loom_plan_contract.migrate_v1(
            self.legacy(["cli"]), route=route,
            created_at="2030-01-01T00:00:00Z")["contract"]
        first = loom_plan_contract.migrate_v2(
            version_two, request="Build a CLI")
        second = loom_plan_contract.migrate_v2(
            version_two, request="Build a CLI")
        self.assertEqual(first, second)
        self.assertEqual(3, first["contract"]["schema_version"])
        self.assertIn("planning-intelligence", first["contract"]["completion_gates"])
        self.assertEqual(
            first["contract"]["planning_intelligence"]["intelligence_digest"],
            first["migration_receipt"]["planning_intelligence_digest"])

    def test_v2_semantic_mutation_is_rejected(self):
        route = loom_domain.select_domains("Build a CLI", explicit=["cli"])["domain_contract"]
        version_two = loom_plan_contract.migrate_v1(
            self.legacy(["cli"]), route=route,
            created_at="2030-01-01T00:00:00Z")["contract"]
        version_two["tier"] = "L"
        with self.assertRaisesRegex(
                loom_plan_contract.PlanContractMigrationError, "hash mismatch"):
            loom_plan_contract.migrate_v2(version_two, request="Build a CLI")


if __name__ == "__main__":
    unittest.main()
