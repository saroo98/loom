"""Regression tests for domain selection and honest unknown-domain behavior."""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_domain  # noqa: E402


class DomainSelectionTests(unittest.TestCase):
    def ids(self, description):
        return [item["id"] for item in
                loom_domain.select_domains(description)["adapters"]]

    def test_cli_tool_does_not_receive_web_adapters(self):
        result = loom_domain.select_domains(
            "A command-line developer tool with stable flags and JSON output")
        self.assertEqual(result["coverage"], "adapter")
        self.assertEqual(result["memory_domain"], "cli")
        self.assertNotIn("website", self.ids("command-line developer tool"))

    def test_mobile_project_selects_mobile_reality(self):
        ids = self.ids("Cross-platform mobile app built with Flutter")
        self.assertIn("mobile", ids)
        self.assertNotIn("website", ids)

    def test_etl_and_ml_pipeline_selects_both_adapters(self):
        result = loom_domain.select_domains(
            "ETL and machine learning pipeline with backfills and model training")
        ids = [item["id"] for item in result["adapters"]]
        self.assertIn("data-etl", ids)
        self.assertIn("ml", ids)
        self.assertEqual(result["memory_domains"], ids)

    def test_hyphenated_machine_learning_is_not_silently_missed(self):
        result = loom_domain.select_domains(
            "ETL and machine-learning pipeline with backfills")
        self.assertEqual(
            [item["id"] for item in result["adapters"]], ["data-etl", "ml"])

    def test_research_writeup_is_not_forced_into_software(self):
        result = loom_domain.select_domains(
            "A research writeup and literature review with a reproducible methodology")
        self.assertEqual(result["memory_domain"], "research")
        self.assertNotIn("web-app", [item["id"] for item in result["adapters"]])

    def test_accounting_and_realtime_3d_get_distinct_invariants(self):
        accounting = loom_domain.select_domains(
            "Desktop bookkeeping software with double-entry accounting and tax rules")
        spatial = loom_domain.select_domains(
            "A real-time 3D room configurator with asset and rendering budgets")
        self.assertEqual(accounting["memory_domain"], "accounting")
        self.assertEqual(spatial["memory_domain"], "realtime-3d")
        self.assertIn("balanced postings", accounting["adapters"][0]["required_invariants"])
        self.assertIn("frame budget", spatial["adapters"][0]["required_invariants"])

    def test_firmware_gets_physical_safety_invariants(self):
        result = loom_domain.select_domains("Firmware for a custom microcontroller board")
        self.assertEqual(result["memory_domain"], "firmware-hardware")
        self.assertIn("fail-safe state", result["adapters"][0]["required_invariants"])

    def test_unknown_domain_blocks_g1_and_requires_discovery(self):
        result = loom_domain.select_domains("Choreograph a site-specific community ritual")
        self.assertEqual(result["coverage"], "unknown")
        self.assertTrue(result["requires_domain_discovery"])
        self.assertEqual(result["g1_status"], "blocked")
        self.assertEqual(result["required_artifact"], "domain-discovery.md")
        self.assertEqual(result["adapters"], [])

    def test_explicit_unknown_domain_stays_unknown(self):
        result = loom_domain.select_domains("", ["marine-navigation"])
        self.assertEqual(result["coverage"], "unknown")
        self.assertEqual(result["adapters"][0]["id"], "marine-navigation")

    def test_unsafe_explicit_domain_id_is_rejected(self):
        with self.assertRaises(loom_domain.DomainError):
            loom_domain.select_domains("", ["../../private"])

    def test_cli_emits_truthful_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = loom_domain.main(["--description", "command-line tool"])
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"]["memory_domain"], "cli")


if __name__ == "__main__":
    unittest.main()
