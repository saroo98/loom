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
