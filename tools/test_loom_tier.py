"""Tiering regressions: small work stays small; real risk promotes."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_tier  # noqa: E402


class TierTests(unittest.TestCase):
    def test_single_file_ui_and_static_landing_page_are_s(self):
        for description in (
            "Build a single-file settings UI",
            "Build a static landing page for a neighborhood coffee shop",
        ):
            with self.subTest(description=description):
                self.assertEqual(loom_tier.classify(description)["tier"], "S")

    def test_small_cli_flag_is_s(self):
        self.assertEqual(loom_tier.classify(
            "Add one command-line flag to an existing developer tool")["tier"], "S")

    def test_auth_or_irreversible_work_promotes_to_m(self):
        self.assertEqual(loom_tier.classify("Add authentication")["tier"], "M")
        self.assertEqual(loom_tier.classify(
            "small change", irreversible=True)["tier"], "M")

    def test_full_accounting_or_realtime_3d_product_is_l(self):
        self.assertEqual(loom_tier.classify(
            "Build full accounting software from scratch")["tier"], "L")
        self.assertEqual(loom_tier.classify(
            "Build a real-time 3D room configurator")["tier"], "L")

    def test_new_mobile_etl_and_firmware_products_are_not_misrouted_to_small(self):
        for description in (
            "Build a cross-platform mobile app",
            "Build and release a new mobile app",
            "Create an ETL pipeline",
            "Build an ETL and ML pipeline",
            "Develop firmware for a new controller",
        ):
            with self.subTest(description=description):
                self.assertEqual(loom_tier.classify(description)["tier"], "L")

    def test_full_cli_and_research_deliverables_receive_a_real_pack(self):
        self.assertEqual(loom_tier.classify(
            "Build a command-line developer tool")["tier"], "M")
        self.assertEqual(loom_tier.classify(
            "Produce a research writeup with reproducible evidence")["tier"], "M")

    def test_observed_scope_promotes_without_keyword_guessing(self):
        self.assertEqual(loom_tier.classify(
            "change copy", files=8)["tier"], "M")
        self.assertEqual(loom_tier.classify(
            "feature", new_components=3)["tier"], "L")


if __name__ == "__main__":
    unittest.main()
