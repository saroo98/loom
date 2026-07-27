import json
import shutil
import tempfile
import unittest
from pathlib import Path

import loom_semantic_parity


class SemanticParityTests(unittest.TestCase):
    def fixture(self, root):
        for contract in loom_semantic_parity.ENTITIES.values():
            for relative in (
                    contract["schema"], contract["module"],
                    contract["documentation"], *contract["compatibility_tests"]):
                source = loom_semantic_parity.ROOT / relative
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    shutil.copy2(source, destination)

    def test_current_inventory_compiles_and_future_versions_never_activate(self):
        report = loom_semantic_parity.compile_report()
        self.assertEqual("passed", report["status"])
        self.assertEqual(6, len(report["entities"]))
        self.assertEqual(
            "future-quarantine",
            loom_semantic_parity.classify_version("recovery-receipt", 4))
        self.assertEqual(
            "legacy-readable",
            loom_semantic_parity.classify_version("recovery-receipt", 2))
        self.assertEqual(
            "active",
            loom_semantic_parity.classify_version("recovery-receipt", 3))

    def test_missing_schema_field_is_detected_against_writer_and_validator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            path = root / "schemas" / "owner-message.schema.json"
            schema = json.loads(path.read_text(encoding="utf-8"))
            schema["$defs"]["current"]["allOf"][1]["required"].remove(
                "details_available")
            path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_semantic_parity.ParityError, "owner-message validator drift"):
                loom_semantic_parity.compile_report(root)

    def test_stale_generated_projection_fails_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "semantic.json"
            output.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_semantic_parity.ParityError, "stale"):
                loom_semantic_parity.main([
                    "--root", str(loom_semantic_parity.ROOT),
                    "--output", str(output), "--check"])

    def test_reader_version_branch_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            path = root / "tools" / "loom_message.py"
            source = path.read_text(encoding="utf-8")
            path.write_text(
                source.replace(
                    'value.get("schema_version") not in {3, 4}',
                    'value.get("schema_version") not in {3}'),
                encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_semantic_parity.ParityError,
                    "owner-message reader drift"):
                loom_semantic_parity.compile_report(root)

    def test_compatibility_test_semantics_are_part_of_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            original = loom_semantic_parity.compile_report(root)
            path = root / "tools" / "test_activation_sets_phase3.py"
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "activation_set_id", "activation_identity", 1),
                encoding="utf-8")
            changed = loom_semantic_parity.compile_report(root)
            relative = "tools/test_activation_sets_phase3.py"
            self.assertNotEqual(
                original["source_hashes"][relative],
                changed["source_hashes"][relative])

    def test_documentation_whitespace_does_not_stale_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            original = loom_semantic_parity.compile_report(root)
            path = root / "docs" / "simple-adaptive-experience.md"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n\n",
                encoding="utf-8")
            changed = loom_semantic_parity.compile_report(root)
            relative = "docs/simple-adaptive-experience.md"
            self.assertEqual(
                original["source_hashes"][relative],
                changed["source_hashes"][relative])


if __name__ == "__main__":
    unittest.main()
