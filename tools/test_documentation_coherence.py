import json
import tempfile
import unittest
from pathlib import Path

import loom_docs


ROOT = Path(__file__).resolve().parents[1]


class DocumentationCoherenceTests(unittest.TestCase):
    def test_public_surface_teaches_one_command_without_internal_command_sprawl(self):
        report = loom_docs.audit_docs(ROOT)
        self.assertEqual([], report["findings"], report)
        for relative in loom_docs.PUBLIC_SURFACE:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("/loom <request>", text)
            for forbidden in loom_docs.FORBIDDEN_PUBLIC_COMMANDS:
                self.assertNotIn(forbidden, text.lower())

    def test_every_capability_is_mechanical_with_existing_proof_or_advisory(self):
        registry = loom_docs.load_capabilities(ROOT)
        self.assertGreaterEqual(len(registry["capabilities"]), 10)
        for capability in registry["capabilities"]:
            if capability["kind"] == "mechanical":
                self.assertTrue(capability["enforcement"])
                self.assertTrue(capability["tests"])
                for relative in capability["enforcement"] + capability["tests"]:
                    self.assertTrue((ROOT / relative).is_file(), relative)
            else:
                self.assertEqual("advisory", capability["kind"])

    def test_contradiction_scanner_catches_legacy_manual_learning_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text(
                "Run /loom <request>. Then manually update FEEDBACK.md after every run.",
                encoding="utf-8")
            findings = loom_docs.scan_contradictions(root, ["README.md"])
            self.assertTrue(any(item["code"] == "LEGACY_MANUAL_LEARNING" for item in findings))

    def test_generated_evidence_is_derived_from_live_inventory(self):
        evidence = loom_docs.generate_evidence(ROOT)
        discovered = sum(
            1 for path in (ROOT / "tools").glob("test_*.py")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.lstrip().startswith("def test_"))
        self.assertEqual(discovered, evidence["discovered_test_methods"])
        self.assertEqual(
            len(list((ROOT / "schemas").glob("*.schema.json"))),
            evidence["schema_documents"])
        self.assertNotIn("passing_tests", evidence)

    def test_docs_audit_rejects_stale_generated_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "VERSION").write_text("1.0.0\n", encoding="utf-8")
            for relative in loom_docs.PUBLIC_SURFACE + ("docs/architecture.md",):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Loom 1.0.0 /loom <request>\n", encoding="utf-8")
            capabilities = {
                "schema_version": 1, "version": "1.0.0", "capabilities": [],
            }
            (root / "docs" / "capabilities.json").write_text(
                json.dumps(capabilities), encoding="utf-8")
            (root / "tools").mkdir(exist_ok=True)
            (root / "tools" / "loom_sample.py").write_text(
                "VALUE = 1\n", encoding="utf-8")
            (root / "tools" / "test_sample.py").write_text(
                "def test_live_inventory():\n    pass\n", encoding="utf-8")
            (root / "schemas").mkdir()
            (root / "schemas" / "sample.schema.json").write_text(
                "{}\n", encoding="utf-8")
            (root / "docs" / "generated-evidence.json").write_text(
                json.dumps({"schema_version": 1, "discovered_test_methods": 0}),
                encoding="utf-8")

            report = loom_docs.audit_docs(root)

            self.assertIn("GENERATED_EVIDENCE_STALE", {
                item["code"] for item in report["findings"]})

    def test_non_link_repository_document_reference_must_exist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "note.md").write_text(
                "Follow `loom/execution/missing.md` before work.\n",
                encoding="utf-8")
            self.assertEqual([{
                "code": "REPO_REFERENCE_MISSING",
                "path": "note.md",
                "target": "loom/execution/missing.md",
            }], loom_docs._repo_reference_findings(root))

    def test_nested_skill_path_is_not_misread_as_a_missing_loom_document(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            skill = root / "skill" / "loom" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("# Loom skill\n", encoding="utf-8")
            (root / "BUILD-MANIFEST.json").write_text(json.dumps({
                "schema_version": 1,
                "files": [{"path": "skill/loom/SKILL.md"}],
            }), encoding="utf-8")

            self.assertEqual([], loom_docs._repo_reference_findings(root))

    def test_version_is_single_source_and_all_entry_points_match(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual([], loom_docs.check_version_coherence(ROOT, version))


if __name__ == "__main__":
    unittest.main()
