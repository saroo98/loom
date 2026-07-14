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

    def test_version_is_single_source_and_all_entry_points_match(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual([], loom_docs.check_version_coherence(ROOT, version))


if __name__ == "__main__":
    unittest.main()
