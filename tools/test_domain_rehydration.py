"""Behavioral tests for bounded exact-domain return and rehydration."""

import tempfile
import unittest
from pathlib import Path

import loom_memory
import loom_session
import loom_learning


class DomainRehydrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)
        self.project = "p-00000000000000000000000000000071"
        self.project_root = self.root / "project"
        self.project_root.mkdir()
        (self.project_root / "README.md").write_text("fixture\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_returning_domain_reactivates_useful_rule_and_flags_stale_rule(self):
        useful = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="three-d")
        loom_memory.select(
            self.home, self.instance, domain="three-d",
            now="2026-01-01T00:00:00Z")
        loom_memory.record_application(
            self.home, self.instance, useful["id"], outcome="helped",
            project_id=self.project, now="2026-01-01T00:05:00Z")
        stale = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="effort-error", future_decision="effort-calibration",
            evidence_count=3, confidence=1.0, domain="three-d",
            verify_by="2026-02-01T00:00:00Z")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-01-01T00:00:00Z")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, useful["id"])["status"], "dormant")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, stale["id"])["status"], "stale")
        result = loom_memory.rehydrate_domain(
            self.home, self.instance, domain="three-d", project_id=self.project,
            max_records=2, max_chars=2000, now="2027-01-02T00:00:00Z")
        self.assertEqual(result["reactivated_ids"], [useful["id"]])
        self.assertEqual(result["verification_required_ids"], [stale["id"]])
        self.assertEqual(result["archive_records_scanned"], 0)
        self.assertLessEqual(result["record_count"], 2)
        self.assertLessEqual(result["character_count"], 2000)
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, useful["id"])["status"], "active")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, stale["id"])["status"], "stale")

    def test_unrelated_domain_loads_zero_and_archived_rule_never_rehydrates(self):
        stale = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="effort-error", future_decision="effort-calibration",
            evidence_count=3, confidence=1.0, domain="three-d",
            verify_by="2026-02-01T00:00:00Z")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-01-01T00:00:00Z")
        accounting = loom_memory.rehydrate_domain(
            self.home, self.instance, domain="accounting", project_id=self.project,
            now="2027-01-02T00:00:00Z")
        self.assertEqual(accounting["record_count"], 0)
        self.assertEqual(accounting["reactivated_ids"], [])
        self.assertEqual(accounting["archive_records_scanned"], 0)

        loom_memory.rehydrate_domain(
            self.home, self.instance, domain="three-d", project_id=self.project,
            now="2027-01-02T00:00:00Z")
        rejected = loom_memory.record_verification(
            self.home, self.instance, stale["id"], verified=False,
            now="2027-01-02T01:00:00Z")
        self.assertEqual(rejected["status"], "archived")
        returned = loom_memory.rehydrate_domain(
            self.home, self.instance, domain="three-d", project_id=self.project,
            now="2027-01-03T00:00:00Z")
        self.assertEqual(returned["record_count"], 0)
        self.assertEqual(returned["archive_records_scanned"], 0)
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, stale["id"])["status"], "archived")

    def test_verified_stale_rule_reactivates_with_a_new_deadline(self):
        stale = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="firmware",
            verify_by="2026-01-01T00:00:00Z")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-01-01T00:00:00Z")
        loom_memory.rehydrate_domain(
            self.home, self.instance, domain="firmware", project_id=self.project,
            now="2027-01-02T00:00:00Z")
        verified = loom_memory.record_verification(
            self.home, self.instance, stale["id"], verified=True,
            verify_by="2027-06-01T00:00:00Z",
            now="2027-01-02T01:00:00Z")
        self.assertEqual(verified["status"], "active")
        self.assertEqual(verified["verify_by"], "2027-06-01T00:00:00Z")
        self.assertEqual(verified["application_count"], 1)

    def test_session_automatically_returns_only_matching_domain_capsule(self):
        cli = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="cli",
            verify_by="2026-01-01T00:00:00Z")
        three_d = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="effort-error", future_decision="effort-calibration",
            evidence_count=3, confidence=1.0, domain="three-d",
            verify_by="2026-01-01T00:00:00Z")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-01-01T00:00:00Z")
        observed = []

        def plan(context):
            observed.extend(item["id"] for item in context.selected_memory)
            return {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": ["verification-evidence"],
                "reversible_action_ids": [],
                "verified_memory_ids": [cli["id"]],
            }

        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": plan}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000701",
            cwd=self.project_root, now="2027-01-02T00:00:00Z")
        self.assertEqual(observed, [cli["id"]])
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, cli["id"])["status"], "active")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, three_d["id"])["status"], "stale")

    def test_rehydration_is_hard_bounded_and_does_not_open_archive(self):
        for index in range(8):
            loom_memory.add_record(
                self.home, self.instance, scope="domain", category="process",
                statement=f"bounded dormant rule {index}", provenance="observed",
                evidence_count=1, confidence=0.5, domain="research")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-07-14T00:00:00Z")
        archive = self.home / "instances" / self.instance / "archive.jsonl"
        archive.write_text("this archive is deliberately unreadable\n", encoding="utf-8")

        result = loom_memory.rehydrate_domain(
            self.home, self.instance, domain="research", project_id=self.project,
            max_records=2, max_chars=1200, now="2027-07-15T00:00:00Z")
        self.assertLessEqual(result["record_count"], 2)
        self.assertLessEqual(result["character_count"], 1200)
        self.assertEqual(result["archive_records_scanned"], 0)
        self.assertLess(result["record_count"], 8)

    def test_candidate_provenance_tracks_reactivated_memory_state(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        for index in range(3):
            engine.capture(
                kind="verification-catch", scope="project",
                signal="verification-caught-defect",
                decision_target="verification-strategy",
                evidence_ids=[f"verification-{index}"], domain="three-d",
                project_id=f"p-{index + 80:032x}")
        candidate = engine.candidates()[0]
        memory_id = candidate["admitted_memory_id"]
        loom_memory.select(
            self.home, self.instance, domain="three-d",
            now="2026-01-01T00:00:00Z")
        loom_memory.record_application(
            self.home, self.instance, memory_id, outcome="helped",
            project_id=self.project, now="2026-01-01T00:05:00Z")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-01-01T00:00:00Z")
        engine.housekeeping(now="2027-01-01T00:01:00Z")
        self.assertEqual(engine.candidates()[0]["status"], "dormant")
        engine.rehydrate_domain(
            domain="three-d", project_id=self.project,
            now="2027-01-02T00:00:00Z")
        self.assertEqual(engine.candidates()[0]["status"], "active")

if __name__ == "__main__":
    unittest.main()
