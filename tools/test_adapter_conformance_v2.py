"""Disposable multi-host conformance tests."""

import json
import tempfile
import unittest
from pathlib import Path

import loom_adapter_conformance


ROOT = Path(__file__).resolve().parents[1]


class AdapterConformanceV2Tests(unittest.TestCase):
    def test_disposable_profiles_share_one_runtime_and_touch_no_project(self):
        result = loom_adapter_conformance.run(ROOT)
        self.assertEqual("passed", result["status"])
        self.assertEqual("simulated-conformant", result["evidence_status"])
        self.assertTrue(result["project_untouched"])
        self.assertFalse(result["network_listener"])
        self.assertEqual(
            ["claude-code", "codex", "copilot", "gemini-cli", "opencode"],
            [item["id"] for item in result["hosts"]])
        self.assertTrue(all(item["same_runtime"] and item["same_protocol"]
                            and item["adapter_receipt"] for item in result["hosts"]))

    def test_conformance_schema_keeps_simulation_distinct_from_real_host(self):
        schema = json.loads((ROOT / "schemas" / "adapter-conformance.schema.json").read_text(
            encoding="utf-8"))
        self.assertEqual("simulated-conformant",
                         schema["properties"]["evidence_status"]["const"])
        self.assertFalse(schema["additionalProperties"])

    def test_cli_writes_only_explicit_output(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "receipt.json"
            code = loom_adapter_conformance.main([
                "--root", str(ROOT), "--output", str(output)])
            self.assertEqual(0, code)
            self.assertEqual("passed", json.loads(
                output.read_text(encoding="utf-8"))["status"])


if __name__ == "__main__":
    unittest.main()
