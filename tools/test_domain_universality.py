"""Executable domain-universality benchmarks and structural detection tests."""

import json
import tempfile
import unittest
from pathlib import Path

import loom_domain


class DomainUniversalityTests(unittest.TestCase):
    def test_structural_evidence_is_ambient_without_active_request_words(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"three": "1.0.0"}}), encoding="utf-8")
            (root / "room.glb").write_bytes(b"fixture")
            facts = loom_domain.inspect_project(root)
            result = loom_domain.select_domains("Improve this project", project_facts=facts)
        self.assertEqual(result["memory_domains"], [])
        self.assertIn("realtime-3d", result["ambient_domains"])

    def test_weak_generic_files_do_not_create_unrelated_adapters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "schema.sql").write_text("select 1;\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"react": "1.0.0"}}), encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "name": "ordinary web manifest"}), encoding="utf-8")
            result = loom_domain.select_domains(
                "Improve this existing project",
                project_facts=loom_domain.inspect_project(root))
            self.assertNotIn("data-etl", result["memory_domains"])
            self.assertNotIn("web-app", result["memory_domains"])
            self.assertNotIn("browser-extension", result["memory_domains"])

            (root / "manifest.json").write_text(json.dumps({
                "manifest_version": 3, "name": "Extension", "version": "1"}),
                encoding="utf-8")
            extension = loom_domain.select_domains(
                "Improve this existing project",
                project_facts=loom_domain.inspect_project(root))
            self.assertNotIn("browser-extension", extension["memory_domains"])
            self.assertIn("browser-extension", extension["ambient_domains"])

    def test_composite_domain_loads_only_matching_adapters(self):
        result = loom_domain.select_domains(
            "Build desktop bookkeeping software with double-entry accounting")
        self.assertEqual(set(result["memory_domains"]), {"accounting", "desktop"})
        self.assertNotIn("website", result["memory_domains"])
        self.assertNotIn("web-app", result["memory_domains"])

    def test_standard_library_test_does_not_activate_public_library_domain(self):
        for request in (
                "Plan a tiny Python CLI with one standard-library unittest.",
                "/loom Plan a tiny Python CLI with one standard-library unittest."):
            with self.subTest(request=request):
                result = loom_domain.select_domains(request)
                self.assertEqual(["cli"], result["memory_domains"])
                self.assertNotIn("library-sdk", result["memory_domains"])
                self.assertNotIn("llm-agent", result["memory_domains"])

    def test_embedded_database_research_does_not_activate_hardware(self):
        result = loom_domain.select_domains(
            "Plan a research comparison of local embedded databases, including "
            "source quality and reproducibility checks.")
        self.assertEqual(["research"], result["memory_domains"])
        self.assertNotIn("firmware-hardware", result["memory_domains"])

    def test_research_and_write_request_routes_to_research(self):
        result = loom_domain.select_domains(
            "Research and write a cited comparison of SQLite, DuckDB, and "
            "RocksDB. Deliver only a decision memo.")
        self.assertEqual(["research"], result["memory_domains"])
        self.assertNotIn("unclassified", result["active_task_domains"])

    def test_offline_first_mobile_product_routes_to_mobile(self):
        result = loom_domain.select_domains(
            "Plan an offline-first mobile habit tracker with local notifications.")
        self.assertIn("mobile", result["active_task_domains"])
        self.assertNotEqual(["unclassified"], result["active_task_domains"])
        mobile = next(
            adapter for adapter in result["adapters"]
            if adapter["id"] == "mobile")
        self.assertIn(
            "sync conflict resolution and data integrity",
            mobile["required_invariants"])
        self.assertIn(
            "concurrent-edit conflict transition",
            mobile["verification"])

        embedded_system = loom_domain.select_domains(
            "Plan firmware for an embedded Linux controller.")
        self.assertIn("firmware-hardware", embedded_system["memory_domains"])

    def test_mobile_descriptor_words_before_app_still_route_to_mobile(self):
        result = loom_domain.select_domains(
            "Plan a small mobile offline notes app with conflict handling, "
            "accessibility, lifecycle restoration, and encrypted local storage.")
        self.assertEqual(["mobile"], result["memory_domains"])
        self.assertNotIn("website", result["memory_domains"])

    def test_no_website_leakage_constraint_does_not_activate_website(self):
        result = loom_domain.select_domains(
            "Test a real-time 3D room configurator with coordinate conventions, "
            "an asset pipeline, spatial UX, GPU budgets, and no website-domain leakage.")
        self.assertEqual(["realtime-3d"], result["memory_domains"])
        self.assertNotIn("website", result["memory_domains"])

    def test_firmware_adapter_covers_liveness_endurance_and_brownout(self):
        result = loom_domain.select_domains(
            "Plan sensor firmware with watchdog recovery, flash-wear limits, "
            "and brownout behavior.")
        adapter = next(
            item for item in result["adapters"]
            if item["id"] == "firmware-hardware")
        for invariant in (
                "watchdog and liveness recovery",
                "flash endurance and wear budget",
                "brownout and power-loss behavior"):
            self.assertIn(invariant, adapter["required_invariants"])
        for medium in (
                "watchdog reset and liveness-recovery test",
                "flash endurance and wear-budget stress test",
                "brownout and power-loss fault injection"):
            self.assertIn(medium, adapter["verification"])

    def test_firmware_diagnostic_language_does_not_activate_medical(self):
        firmware = loom_domain.select_domains(
            "Plan firmware diagnostic logging for a sensor controller.")
        self.assertIn("firmware-hardware", firmware["memory_domains"])
        self.assertNotIn("medical", firmware["active_task_domains"])

        for request in (
                "Plan software that records a clinician's diagnosis.",
                "Plan a medical workflow for diagnoses and treatment review.",
                "Plan a clinical tool for diagnosing a documented condition."):
            with self.subTest(request=request):
                medical = loom_domain.select_domains(request)
                self.assertIn(
                    "medical-clinical", medical["active_task_domains"])

    def test_accounting_adapter_covers_filed_tax_period_authority(self):
        result = loom_domain.select_domains(
            "Plan desktop bookkeeping software with tax-period closing.")
        accounting = next(
            adapter for adapter in result["adapters"]
            if adapter["id"] == "accounting")

        self.assertIn(
            "tax-period calendar and filed-period lock/reopen authority",
            accounting["required_invariants"])
        self.assertIn(
            "filed-period lock and authorized reopen proof",
            accounting["release_criteria"])
        self.assertIn(
            "dated jurisdiction, tax-period, and filed-period cases",
            accounting["verification"])

    def test_evidence_path_and_nested_docs_site_do_not_override_agent_runtime_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "plugin.json").write_text("{}", encoding="utf-8")
            (root / "SKILL.md").write_text("# Agent skill\n", encoding="utf-8")
            (root / "sitemap.xml").write_text("<urlset/>", encoding="utf-8")
            facts = loom_domain.inspect_project(root)
            result = loom_domain.select_domains(
                "Now please implement C:\\Reports\\Deep Research\\release engineering.md",
                project_facts=facts)

        self.assertEqual([], result["memory_domains"])
        self.assertIn("llm-agent", result["ambient_domains"])
        self.assertNotIn("research", result["memory_domains"])
        self.assertNotIn("website", result["memory_domains"])

    def test_unknown_domain_blocks_for_invariant_discovery_without_generic_defaults(self):
        result = loom_domain.select_domains("Plan an experimental quantum optics rig")
        self.assertEqual(result["coverage"], "unknown")
        self.assertTrue(result["requires_domain_discovery"])
        self.assertEqual(result["required_artifact"], "domain-discovery.md")
        self.assertEqual(result["memory_domains"], [])
        self.assertIn("do not apply a web/software template", result["note"])

    def test_durable_invariants_are_separate_from_current_facts(self):
        adapter = loom_domain.select_domains("double-entry accounting ledger")["adapters"][0]
        self.assertIn("balanced postings", adapter["durable_invariants"])
        self.assertTrue(all("current" in item for item in adapter["current_facts_to_verify"]))
        self.assertNotEqual(adapter["durable_invariants"], adapter["current_facts_to_verify"])

    def test_requested_accounting_etl_and_mobile_failure_families_are_shipped(self):
        fixtures = {
            "accounting": {
                "reversal and adjusting-entry semantics",
            },
            "data-etl": {
                "quarantine and rejected-record disposition",
                "row-count and reconciliation controls",
            },
            "mobile": {
                "notification denial and recovery behavior",
                "time-zone and daylight-saving scheduling",
                "missed-delivery and delayed-reminder behavior",
                "local private-data lifecycle",
            },
        }
        for domain_id, expected in fixtures.items():
            with self.subTest(domain=domain_id):
                self.assertTrue(
                    expected.issubset(set(loom_domain.CATALOG[domain_id]["invariants"])))

    def test_all_ten_benchmarks_and_every_adapter_fixture_execute(self):
        report = loom_domain.evaluate_benchmarks()
        self.assertEqual(report["benchmark_count"], 10)
        self.assertTrue(report["passed"], report)
        self.assertEqual(set(report["adapter_fixtures"]), set(loom_domain.CATALOG))
        self.assertTrue(all(report["adapter_fixtures"].values()))

    def test_project_inspection_fails_closed_on_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_text("fixture", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            with self.assertRaisesRegex(loom_domain.DomainError, "symlink"):
                loom_domain.inspect_project(root)


if __name__ == "__main__":
    unittest.main()
