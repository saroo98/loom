"""Behavioral tests for consumer-driven, proportional planning."""

import tempfile
import unittest
import json
from pathlib import Path

import loom_memory
import loom_planning
import loom_tier


class ConsumerPlanningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)
        self.optimizer = loom_planning.PlanningOptimizer(self.home, self.instance)

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_consumer_means_no_artifact_and_small_work_gets_contract_not_pack(self):
        decision = self.optimizer.decide(
            description="Rename one CLI flag", domain="cli",
            facts={"files": 1, "days": 0.2, "new_components": 0,
                   "new_boundaries": 0, "implementers": 1, "irreversible": False},
            implementation_chars=900,
            artifacts=[
                {"id": "architecture", "consumer": "", "decision": "module boundaries",
                 "estimated_chars": 800},
                {"id": "work-contract", "consumer": "implementer",
                 "decision": "exact rename and acceptance evidence", "estimated_chars": 500},
            ],
            sections={"acceptance": "flag is renamed", "ceremony": "   "},
            verification=[{"id": "cli-help", "target": "renamed flag",
                           "medium": "real cli process"},
                          {"id": "generic-quality", "target": "", "medium": "checklist"}],
        )
        self.assertEqual(decision["tier"], "S")
        self.assertEqual(decision["mode"], "compact-work-contract")
        self.assertFalse(decision["create_pack"])
        self.assertEqual([item["id"] for item in decision["artifacts"]], ["work-contract"])
        self.assertIn("architecture", decision["omitted_artifacts"])
        self.assertLessEqual(decision["planning_char_budget"], 900)
        self.assertEqual(decision["sections"], {"acceptance": "flag is renamed"})
        self.assertEqual([item["id"] for item in decision["verification"]], ["cli-help"])

    def test_repeated_non_use_demotes_only_same_domain_and_defect_prevention_strengthens(self):
        for index in range(3):
            self.optimizer.record_usage(
                domain="web", artifact_id="journey-map",
                project_id=f"p-{index + 1:032x}", opened=False, cited=False,
                work_order_used=False, prevented_defect=False)
        for index in range(2):
            self.optimizer.record_usage(
                domain="firmware", artifact_id="hazard-analysis",
                project_id=f"p-{index + 10:032x}", opened=True, cited=True,
                work_order_used=True, prevented_defect=True)

        common = dict(
            description="Add one low-risk view", facts={"files": 2, "days": 0.5,
                "new_components": 0, "new_boundaries": 0, "implementers": 1,
                "irreversible": False}, implementation_chars=1500, sections={},
            verification=[],
        )
        web = self.optimizer.decide(domain="web", artifacts=[{
            "id": "journey-map", "consumer": "designer", "decision": "navigation",
            "estimated_chars": 500}], **common)
        firmware = self.optimizer.decide(domain="firmware", artifacts=[{
            "id": "hazard-analysis", "consumer": "verification owner",
            "decision": "unsafe states", "estimated_chars": 900}], **common)
        other = self.optimizer.decide(domain="accounting", artifacts=[{
            "id": "journey-map", "consumer": "designer", "decision": "navigation",
            "estimated_chars": 500}], **common)
        self.assertEqual(web["artifacts"], [])
        self.assertEqual(web["artifact_reasons"]["journey-map"], "demoted-repeatedly-unused")
        self.assertEqual(firmware["artifact_reasons"]["hazard-analysis"],
                         "strengthened-prevented-defects")
        self.assertEqual([item["id"] for item in other["artifacts"]], ["journey-map"])

    def test_labels_alone_do_not_inflate_tier_but_observed_scope_and_risk_do(self):
        base = dict(domain="mobile", implementation_chars=2000, artifacts=[],
                    sections={}, verification=[])
        small = self.optimizer.decide(
            description="Make a tiny mobile app copy change",
            facts={"files": 1, "days": 0.2, "new_components": 0,
                   "new_boundaries": 0, "implementers": 1, "irreversible": False}, **base)
        large = self.optimizer.decide(
            description="Build an app",
            facts={"files": 40, "days": 20, "new_components": 4,
                   "new_boundaries": 3, "implementers": 3, "irreversible": True}, **base)
        portfolio = self.optimizer.decide(
            description="Coordinate a year-long multi-product program",
            facts={"files": 400, "days": 90, "new_components": 9,
                   "new_boundaries": 8, "implementers": 7, "irreversible": True}, **base)
        self.assertEqual(small["tier"], "S")
        self.assertEqual(large["tier"], "L")
        self.assertEqual(portfolio["tier"], "XL")
        self.assertIn("observed-portfolio-scope", portfolio["tier_evidence"])
        self.assertIn("observed-scope", large["tier_evidence"])
        self.assertEqual(loom_tier.classify("Build a command-line developer tool")["tier"], "S")
        self.assertEqual(loom_tier.classify("Write a research paper")["tier"], "S")
        self.assertEqual(loom_tier.classify("Make a tiny mobile app copy change")["tier"], "S")
        self.assertEqual(loom_tier.classify("Build tax accounting rules")["tier"], "M")
        self.assertEqual(loom_tier.classify(
            "Build an app", days=20, new_components=4, new_boundaries=3,
            implementers=3)["tier"], "L")
        self.assertEqual(loom_tier.classify(
            "Coordinate a year-long multi-product program", days=90,
            new_components=9, new_boundaries=8, implementers=7)["tier"], "XL")

    def test_store_is_bounded_and_invalid_usage_fails_without_write(self):
        with self.assertRaisesRegex(loom_planning.PlanningError, "usage requires"):
            self.optimizer.record_usage(
                domain="cli", artifact_id="contract",
                project_id="not-a-project", opened=True, cited=False,
                work_order_used=False, prevented_defect=False)
        self.assertEqual(self.optimizer.utility(), [])
        for index in range(300):
            self.optimizer.record_usage(
                domain="cli", artifact_id=f"artifact-{index}",
                project_id=f"p-{index + 1:032x}", opened=True, cited=False,
                work_order_used=False, prevented_defect=False)
        self.assertLessEqual(len(self.optimizer.utility()), 256)

    def test_output_gate_blocks_over_budget_or_undeclared_planning(self):
        decision = self.optimizer.decide(
            description="Rename one flag", domain="cli",
            facts={"files": 1, "days": 0.2, "new_components": 0,
                   "new_boundaries": 0, "implementers": 1, "irreversible": False},
            implementation_chars=600,
            artifacts=[{"id": "work-contract", "consumer": "implementer",
                "decision": "rename acceptance", "estimated_chars": 400}],
            sections={"acceptance": "renamed"}, verification=[])
        with self.assertRaisesRegex(loom_planning.PlanningError, "budget"):
            self.optimizer.verify_output(
                decision, actual_chars=601, artifact_ids=["work-contract"],
                sections={"acceptance": "renamed"})
        with self.assertRaisesRegex(loom_planning.PlanningError, "undeclared"):
            self.optimizer.verify_output(
                decision, actual_chars=400, artifact_ids=["architecture"],
                sections={"acceptance": "renamed"})
        verified = self.optimizer.verify_output(
            decision, actual_chars=400, artifact_ids=["work-contract"],
            sections={"acceptance": "renamed"})
        self.assertEqual(verified["status"], "verified")

    def test_tampered_artifact_utility_store_fails_closed(self):
        self.optimizer.record_usage(
            domain="cli", artifact_id="contract",
            project_id="p-00000000000000000000000000000001",
            opened=True, cited=False, work_order_used=False, prevented_defect=False)
        store = json.loads(self.optimizer.path.read_text(encoding="utf-8"))
        store["records"][0]["private_project_name"] = "must not exist"
        self.optimizer.path.write_text(json.dumps(store), encoding="utf-8")
        with self.assertRaisesRegex(loom_planning.PlanningError, "contract"):
            self.optimizer.utility()

    def test_usage_batch_is_atomic_and_tracks_each_consumption_channel(self):
        project = "p-00000000000000000000000000000002"
        with self.assertRaisesRegex(loom_planning.PlanningError, "usage requires"):
            self.optimizer.record_usage_batch(domain="cli", project_id=project, usages=[
                {"artifact_id": "contract", "opened": True, "cited": False,
                 "work_order_used": False, "prevented_defect": False},
                {"artifact_id": "bad id", "opened": True, "cited": False,
                 "work_order_used": False, "prevented_defect": False}])
        self.assertEqual(self.optimizer.utility(), [])
        self.optimizer.record_usage_batch(domain="cli", project_id=project, usages=[
            {"artifact_id": "contract", "opened": True, "cited": False,
             "work_order_used": False, "prevented_defect": False},
            {"artifact_id": "decision-log", "opened": False, "cited": True,
             "work_order_used": True, "prevented_defect": True}])
        records = {item["artifact_id"]: item for item in self.optimizer.utility()}
        self.assertEqual(records["contract"]["opened_count"], 1)
        self.assertEqual(records["decision-log"]["cited_count"], 1)
        self.assertEqual(records["decision-log"]["work_order_used_count"], 1)
        self.assertEqual(records["decision-log"]["prevented_defect_count"], 1)


if __name__ == "__main__":
    unittest.main()
