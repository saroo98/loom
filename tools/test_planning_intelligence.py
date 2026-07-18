import copy
import json
import tempfile
import unittest
from pathlib import Path

import loom_domain
import loom_domain_contract
import loom_planning_intelligence


class PlanningIntelligenceTests(unittest.TestCase):
    def compile(self, request, tier="M"):
        route = loom_domain.select_domains(request)["domain_contract"]
        return loom_planning_intelligence.compile_intelligence(
            request, tier=tier, route=route)

    def test_small_irrelevant_change_loads_only_minimal_verification(self):
        result = self.compile("Rename one local CLI flag", tier="S")
        self.assertEqual(["verification-evidence"], [
            item["id"] for item in result["active_modules"]])
        self.assertLessEqual(len(result["atoms"]), 8)
        loom_planning_intelligence.validate(result)
        rendered = loom_planning_intelligence.render_for_host(result)
        self.assertNotIn("interaction-accessibility", json.dumps(rendered))

    def test_reference_material_does_not_activate_interaction_module(self):
        result = self.compile(
            "Read the accessibility research report and implement the Loom planning runtime",
            tier="M")
        self.assertNotIn("interaction-accessibility", [
            item["id"] for item in result["active_modules"]])
        self.assertIn("source-material", {
            item["role"] for item in result["evidence_roles"]})

    def test_negated_clause_is_excluded_and_contrastive_target_remains_active(self):
        result = self.compile(
            "Do not build a website, but implement the CLI planning runtime", tier="M")
        self.assertEqual(["excluded", "target"], [
            item["role"] for item in result["evidence_roles"]])
        self.assertNotIn("interaction-accessibility", {
            item["id"] for item in result["active_modules"]})

    def test_every_specialist_has_positive_source_and_negation_twins(self):
        catalog = loom_planning_intelligence.load_catalog()
        for module in catalog["modules"]:
            if module["activation"]["always"]:
                continue
            pattern = module["activation"]["patterns"][0]
            with self.subTest(module=module["id"], twin="positive"):
                positive = self.compile(f"Implement {pattern} support", tier="M")
                self.assertIn(module["id"], {
                    item["id"] for item in positive["active_modules"]})
            with self.subTest(module=module["id"], twin="source"):
                source = self.compile(
                    f"The research report says '{pattern}'. Implement a CLI flag", tier="M")
                self.assertNotIn(module["id"], {
                    item["id"] for item in source["active_modules"]})
            with self.subTest(module=module["id"], twin="negated"):
                negated = self.compile(
                    f"Do not implement {pattern}. Implement a CLI flag", tier="M")
                self.assertNotIn(module["id"], {
                    item["id"] for item in negated["active_modules"]})

    def test_large_unrelated_program_does_not_load_release_or_operations(self):
        result = self.compile(
            "Plan a year-long literature review with Phase 1 and Phase 2", tier="XL")
        active = {item["id"] for item in result["active_modules"]}
        self.assertNotIn("migration-release", active)
        self.assertNotIn("reliability-operations", active)
        rendered = json.dumps(loom_planning_intelligence.render_for_host(result))
        self.assertNotIn("migration-release", rendered)
        self.assertNotIn("reliability-operations", rendered)

    def test_quoted_source_twin_has_the_same_plan_relevant_route(self):
        clean = loom_domain.select_domains("Implement a single-file CLI flag")
        twin = loom_domain.select_domains(
            "The report says 'build a website'. Implement a single-file CLI flag")
        self.assertEqual(clean["domain_contract"]["route_digest"],
                         twin["domain_contract"]["route_digest"])

    def test_ui_domain_activates_interaction_and_real_medium(self):
        result = self.compile("Build a mobile app", tier="M")
        active = {item["id"] for item in result["active_modules"]}
        self.assertIn("interaction-accessibility", active)
        interaction = [item for item in result["atoms"]
                       if item["module_id"] == "interaction-accessibility"]
        self.assertTrue(all(item["required_real_medium"] for item in interaction))

    def test_large_phase_program_activates_bounded_decision_modules(self):
        request = (
            "Phase 8 and 9 and 10 research is done. Make three plans separately "
            "and then implement Phase 8 with migration, release, and rollback verification."
        )
        result = self.compile(request, tier="L")
        active = {item["id"] for item in result["active_modules"]}
        self.assertTrue({"outcomes-requirements", "architecture-boundaries",
                         "verification-evidence", "migration-release"}.issubset(active))
        self.assertLessEqual(len(result["atoms"]), 24)
        self.assertEqual(["phase-8", "phase-9", "phase-10"], [
            item["id"] for item in result["program"]["milestone_graph"]["milestones"]])

    def test_every_atom_has_non_tautological_structured_verification(self):
        result = self.compile("Build a mobile app with migration and rollback", tier="L")
        for atom in result["atoms"]:
            verification = loom_planning_intelligence.expanded_verification(result, atom)
            self.assertNotEqual(atom["statement"].casefold(),
                                verification["observation_method"].casefold())
            self.assertNotEqual(atom["statement"].casefold(),
                                verification["oracle"].casefold())
            self.assertTrue(verification["evidence_artifact"].startswith("plans/evidence/"))

    def test_digest_mutation_fails(self):
        result = self.compile("Build a CLI tool", tier="M")
        changed = copy.deepcopy(result)
        changed["atoms"][0]["statement"] += " changed"
        with self.assertRaisesRegex(
                loom_planning_intelligence.PlanningIntelligenceError, "digest mismatch"):
            loom_planning_intelligence.validate(changed)

    def test_missing_provenance_edge_fails(self):
        result = self.compile("Build a CLI tool", tier="M")
        changed = copy.deepcopy(result)
        changed["composition"]["edges"].pop()
        body = dict(changed); body.pop("intelligence_digest")
        changed["intelligence_digest"] = loom_domain_contract.digest(
            "planning-intelligence-v1", body)
        with self.assertRaises(loom_planning_intelligence.PlanningIntelligenceError):
            loom_planning_intelligence.validate(changed)

    def test_only_proved_monotone_conflict_resolves_automatically(self):
        monotone = loom_planning_intelligence.resolve_conflict(
            "retain 30 days", "retain 7 days", conflict_type="retention",
            relation="stricter-right", same_scope=True)
        self.assertEqual("stricter-right", monotone["disposition"])
        authority = loom_planning_intelligence.resolve_conflict(
            "owner may approve", "reviewer must approve", conflict_type="authority",
            relation="stricter-right", same_scope=True)
        self.assertEqual("qualified-authority-block", authority["disposition"])

    def test_catalog_rejects_unknown_fields(self):
        catalog = loom_planning_intelligence.load_catalog()
        catalog["modules"][0]["unknown"] = True
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_planning_intelligence.PlanningIntelligenceError, "identity"):
                loom_planning_intelligence.load_catalog(path)

    def test_permutation_is_deterministic(self):
        first = self.compile("Build a mobile app with migration and rollback", tier="L")
        second = self.compile("Build a mobile app with rollback and migration", tier="L")
        self.assertEqual(
            [item["id"] for item in first["active_modules"]],
            [item["id"] for item in second["active_modules"]])


if __name__ == "__main__":
    unittest.main()
