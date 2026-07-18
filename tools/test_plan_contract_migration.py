import copy
import unittest

import loom_domain
import loom_orchestrator
import loom_plan_contract
import loom_project_inspection


class PlanContractMigrationTests(unittest.TestCase):
    def inspection(self, survey_hash="b" * 64, *, unresolved=False):
        unresolved_roots = ([{"path": "unknown", "reason": "ignored-unclassified",
                              "potential_authorities": ["source"]}]
                            if unresolved else [])
        body = {
            "schema_version": 1, "policy_version": "project-inspection-v1",
            "target_identity": "target-sha256:" + "d" * 64,
            "survey_hash": survey_hash,
            "state": "partial-requires-discovery" if unresolved else "complete",
            "source_states": {key: ("partial-requires-discovery" if unresolved and key in {
                "ignored_generated", "manifests"} else "complete") for key in (
                "filesystem_safety", "tracked", "staged", "unstaged", "untracked",
                "ignored_generated", "manifests")},
            "counters": {key: (len(unresolved_roots) if key ==
                "unknown_subtrees_summarized" else 0) for key in (
                "entries_seen", "tracked_paths_seen", "changed_paths_seen",
                "untracked_paths_seen", "ignored_candidate_roots_seen",
                "relevant_files_inspected", "relevant_directories_inspected",
                "manifest_bytes_read", "generated_subtrees_excluded",
                "unknown_subtrees_summarized", "partitions_summarized",
                "detailed_facts_saturated", "elapsed_ms")},
            "facts": {"file_names": [], "extensions": [], "dependencies": [],
                      "manifests": []},
            "partitions": [], "generated_exclusions": [],
            "unresolved_roots": unresolved_roots,
            "relevant_coverage_complete": not unresolved,
            "routing_eligible": True, "draft_planning_eligible": True,
            "g1_eligible": not unresolved, "implementation_eligible": not unresolved,
            "tier_floor": "L" if unresolved else "S",
        }
        return {**body, "receipt_digest": loom_project_inspection._digest(body)}
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

    def test_v3_to_v4_binds_inspection_and_is_idempotent(self):
        route = loom_domain.select_domains("Build a CLI", explicit=["cli"])["domain_contract"]
        version_two = loom_plan_contract.migrate_v1(
            self.legacy(["cli"]), route=route,
            created_at="2030-01-01T00:00:00Z")["contract"]
        version_three = loom_plan_contract.migrate_v2(
            version_two, request="Build a CLI")["contract"]
        receipt = self.inspection(unresolved=True)

        first = loom_plan_contract.migrate_v3(
            version_three, project_inspection=receipt)
        second = loom_plan_contract.migrate_v3(
            version_three, project_inspection=receipt)

        self.assertEqual(first, second)
        self.assertEqual(4, first["contract"]["schema_version"])
        self.assertEqual(2, first["contract"]["domain_route"]["schema_version"])
        self.assertIn("project-inspection", first["contract"]["completion_gates"])
        self.assertEqual(
            receipt["receipt_digest"],
            first["contract"]["project_inspection"]["receipt_digest"])

    def test_v3_to_v4_rejects_wrong_inspection_subject(self):
        route = loom_domain.select_domains("Build a CLI", explicit=["cli"])["domain_contract"]
        version_two = loom_plan_contract.migrate_v1(
            self.legacy(["cli"]), route=route,
            created_at="2030-01-01T00:00:00Z")["contract"]
        version_three = loom_plan_contract.migrate_v2(
            version_two, request="Build a CLI")["contract"]

        with self.assertRaisesRegex(
                loom_plan_contract.PlanContractMigrationError, "does not describe"):
            loom_plan_contract.migrate_v3(
                version_three, project_inspection=self.inspection("e" * 64))


if __name__ == "__main__":
    unittest.main()
