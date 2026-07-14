"""Behavioral tests for automatic private learning and memory admission."""

import tempfile
import unittest
import os
import subprocess
import sys
import json
from pathlib import Path

import loom_learning
import loom_memory
import loom_session


class AutomaticLearningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)

    def tearDown(self):
        self.tmp.cleanup()

    def test_session_automatically_emits_typed_learning_without_raw_request(self):
        adapter = loom_session.LocalMemoryAdapter(
            owner_home=self.home, instance_id=self.instance)
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": lambda _context: {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {"effort-estimate": 0.7, "effort-actual": 0.5},
                "evidence_ids": ["ev-plan-1"], "reversible_action_ids": [],
            }}, memory=adapter)
        controller.run(
            "Build the confidential Moonlight customer importer",
            invocation_id="00000000-0000-4000-8000-000000000201",
            cwd=self.project, now="2026-07-14T12:00:00Z")

        events = loom_learning.LearningEngine(
            self.home, self.instance).events()
        self.assertGreaterEqual(len(events), 2)
        self.assertTrue({"prediction-outcome", "routing-outcome"}.issubset(
            {event["kind"] for event in events}))
        effort = [event for event in events if event["kind"] == "effort-outcome"]
        self.assertEqual(len(effort), 1)
        self.assertEqual((effort[0]["predicted"], effort[0]["actual"]), (0.7, 0.5))
        serialized = str(events)
        self.assertNotIn("Moonlight", serialized)
        self.assertNotIn("customer importer", serialized)
        self.assertTrue(all(event["evidence_ids"] for event in events))

    def test_one_event_stays_candidate_but_repeated_cross_project_evidence_promotes(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        projects = [f"p-{index:032x}" for index in range(1, 4)]
        first = engine.capture(
            kind="decision-delegation", scope="project",
            signal="decision-delegated", decision_target="delegation-strategy",
            evidence_ids=["decision-1"], domain="cli", project_id=projects[0])
        candidates = engine.candidates()
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["status"], "candidate")
        self.assertEqual(candidates[0]["evidence_count"], 1)
        self.assertEqual(loom_memory.select(
            self.home, self.instance, domain="cli", project_id=projects[0]), [])

        for index in range(1, 3):
            engine.capture(
                kind="decision-delegation", scope="project",
                signal="decision-delegated", decision_target="delegation-strategy",
                evidence_ids=[f"decision-{index + 1}"], domain="cli",
                project_id=projects[index])
        promoted = engine.candidates()[0]
        self.assertEqual(promoted["status"], "active")
        self.assertEqual(promoted["evidence_count"], 3)
        self.assertEqual(len(promoted["evidence_projects"]), 3)
        selected = loom_memory.select(
            self.home, self.instance, domain="firmware", project_id=projects[0])
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["scope"], "global")
        self.assertNotIn(first["id"], selected[0]["statement"])

    def test_duplicate_evidence_merges_and_contradiction_blocks_promotion(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        project = "p-00000000000000000000000000000011"
        event = dict(
            kind="routing-outcome", scope="project", signal="route-succeeded",
            decision_target="routing-strategy", evidence_ids=["route-1"],
            domain="web", project_id=project)
        engine.capture(**event)
        engine.capture(**event)
        engine.capture(**dict(event, evidence_ids=["route-2"],
                              polarity="contradicts"))
        engine.capture(**dict(event, evidence_ids=["route-3"]))
        engine.capture(**dict(event, evidence_ids=["route-4"]))

        candidate = engine.candidates()[0]
        self.assertEqual(candidate["evidence_count"], 4)
        self.assertEqual(candidate["supports"], 3)
        self.assertEqual(candidate["contradicts"], 1)
        self.assertEqual(candidate["status"], "candidate")
        self.assertEqual(loom_memory.select(
            self.home, self.instance, domain="web", project_id=project), [])

    def test_uncontrolled_or_protected_inference_is_rejected_without_candidate(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        with self.assertRaisesRegex(loom_learning.LearningError, "uncontrolled vocabulary"):
            engine.capture(
                kind="decision-delegation", scope="project",
                signal="decision-delegated", decision_target="spending-authority",
                evidence_ids=["decision-1"], domain="cli",
                project_id="p-00000000000000000000000000000012")
        self.assertEqual(engine.candidates(), [])
        with self.assertRaisesRegex(loom_memory.MemoryError, "stated provenance"):
            loom_memory.set_preference(
                self.home, self.instance, "hard_stop", "never delete",
                provenance="inferred")

    def test_low_confidence_candidate_expires_without_entering_active_memory(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        project = "p-00000000000000000000000000000013"
        engine.capture(
            kind="routing-outcome", scope="project", signal="route-escalated",
            decision_target="routing-strategy", evidence_ids=["route-1"],
            domain="firmware", project_id=project,
            recorded_at="2026-01-01T00:00:00Z")
        result = engine.housekeeping(now="2026-01-20T00:00:00Z")
        self.assertEqual(result["expired"], 1)
        self.assertEqual(engine.candidates()[0]["status"], "archived")
        self.assertEqual(loom_memory.select(
            self.home, self.instance, domain="firmware", project_id=project), [])

    def test_improvement_claim_requires_comparative_error_evidence(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        empty = engine.improvement_report(metric="confidence", domain="cli")
        self.assertEqual(empty["claim"], "insufficient-evidence")
        for index, actual in enumerate((0.0, 0.2, 0.8, 1.0), 1):
            loom_memory.record_outcome(
                self.home, self.instance, metric="confidence",
                predicted=1.0, actual=actual, domain="cli",
                outcome_id=f"00000000-0000-4000-8000-{index:012d}")
        report = engine.improvement_report(metric="confidence", domain="cli")
        self.assertEqual(report["claim"], "improved")
        self.assertGreater(report["early_mae"], report["recent_mae"])

    def test_lifecycle_gate_success_automatically_emits_learning_event(self):
        pack = self.project / "plans" / "pack"
        pack.mkdir(parents=True)
        (pack / "MANIFEST.md").write_text(
            "---\nschema_version: 1\n---\n# Test pack\n", encoding="utf-8")

        def plan(context):
            result = subprocess.run(
                [sys.executable, "-B", "loom_gate.py", "init", str(pack),
                 "--repo", str(self.project)], cwd=Path(__file__).parent,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                         **context.environment()), capture_output=True, text=True,
                timeout=20, check=False)
            return {
                "status": "completed" if result.returncode == 0 else "blocked",
                "code": "lifecycle-started" if result.returncode == 0 else "lifecycle-failed",
                "success": result.returncode == 0, "metrics": {},
                "evidence_ids": ["gate-init-1"], "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": plan}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        receipt = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000202",
            cwd=self.project, now="2026-07-14T12:00:00Z")
        self.assertEqual(receipt.code, "lifecycle-started")
        lifecycle = [event for event in loom_learning.LearningEngine(
            self.home, self.instance).events() if event["kind"] == "lifecycle-outcome"]
        self.assertEqual(len(lifecycle), 1)
        self.assertEqual(lifecycle[0]["signal"], "gate-passed")

    def test_structured_handler_metrics_cover_all_automatic_learning_signals(self):
        metrics = {
            "rework-observed": 1, "verification-escape": 1,
            "assumption-caught": 1, "assumption-missed": 1,
            "unpredicted-failure": 1, "artifact-unused": 1,
            "artifact-consumed": 1, "question-rejected": 1,
            "decision-delegated": 1, "verification-caught-defect": 1,
            "guidance-wasted-work": 1,
        }
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": lambda _context: {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": metrics, "evidence_ids": ["private-project-token"],
                "reversible_action_ids": [],
            }}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000203",
            cwd=self.project, now="2026-07-14T12:00:00Z")
        events = loom_learning.LearningEngine(self.home, self.instance).events()
        kinds = {event["kind"] for event in events}
        self.assertTrue({
            "rework", "verification-escape", "assumption-outcome",
            "unpredicted-failure", "artifact-utility", "question-response",
            "decision-delegation", "verification-catch", "guidance-waste",
        }.issubset(kinds))
        self.assertNotIn("private-project-token", str(events))

    def test_domain_learning_never_loads_in_an_unrelated_domain(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        for index in range(3):
            engine.capture(
                kind="verification-catch", scope="project",
                signal="verification-caught-defect",
                decision_target="verification-strategy",
                evidence_ids=[f"verification-{index}"], domain="three-d",
                project_id=f"p-{index + 30:032x}")
        candidate = engine.candidates()[0]
        self.assertEqual(candidate["scope"], "domain")
        self.assertEqual(candidate["status"], "active")
        self.assertEqual(len(loom_memory.select(
            self.home, self.instance, domain="three-d",
            project_id="p-00000000000000000000000000000030")), 1)
        self.assertEqual(loom_memory.select(
            self.home, self.instance, domain="accounting",
            project_id="p-00000000000000000000000000000030"), [])

    def test_owner_stated_preference_is_immediate_not_candidate(self):
        record = loom_memory.set_preference(
            self.home, self.instance, "decision_batching", "one gate batch")
        selected = loom_memory.select(self.home, self.instance, domain="cli")
        self.assertEqual([item["id"] for item in selected], [record["id"]])
        self.assertEqual(loom_learning.LearningEngine(
            self.home, self.instance).candidates(), [])

    def test_tampered_learning_event_fails_closed(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        engine.capture(
            kind="routing-outcome", scope="project", signal="route-succeeded",
            decision_target="routing-strategy", evidence_ids=["route-1"],
            domain="cli", project_id="p-00000000000000000000000000000041")
        store = json.loads(engine.path.read_text(encoding="utf-8"))
        store["events"][0]["signal"] = "route-escalated"
        engine.path.write_text(json.dumps(store), encoding="utf-8")
        with self.assertRaisesRegex(loom_learning.LearningError, "modified after capture"):
            engine.events()

    def test_learning_is_isolated_by_owner_home_and_install_instance(self):
        engine = loom_learning.LearningEngine(self.home, self.instance)
        engine.capture(
            kind="routing-outcome", scope="project", signal="route-succeeded",
            decision_target="routing-strategy", evidence_ids=["route-1"],
            domain="cli", project_id="p-00000000000000000000000000000042")
        other_home = self.root / "other-owner"
        other_install = self.root / "other-install"
        other_install.mkdir()
        other_instance = loom_memory.initialize(other_home, other_install)
        self.assertEqual(loom_learning.LearningEngine(
            other_home, other_instance).events(), [])


if __name__ == "__main__":
    unittest.main()
