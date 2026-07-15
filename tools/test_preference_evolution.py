"""Behavioral tests for scoped, drifting owner preferences."""

import tempfile
import unittest
import json
from pathlib import Path

import loom_memory
import loom_preferences
import loom_planning
import loom_session


class PreferenceEvolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)
        self.engine = loom_preferences.PreferenceEngine(self.home, self.instance)

    def tearDown(self):
        self.tmp.cleanup()

    def test_recent_stated_correction_outranks_historical_behavior_and_can_undo(self):
        for index in range(3):
            self.engine.observe(
                key="report_detail", value="detailed", source="observed",
                project_id=f"p-{index + 1:032x}", evidence_id=f"e-report-{index}",
                observed_at=f"2026-06-0{index + 1}T00:00:00Z")
        self.assertEqual(self.engine.select()[0]["effective_value"], "detailed")

        receipt = self.engine.correct("Prefer concise reports",
                                      observed_at="2026-07-14T12:00:00Z")
        selected = self.engine.select()
        self.assertEqual(selected[0]["effective_value"], "concise")
        self.assertEqual(selected[0]["effective_source"], "stated")
        self.assertEqual(selected[0]["stated_confidence"], 1.0)
        self.assertGreater(selected[0]["inferred_confidence"], 0.0)
        self.assertTrue(receipt["material_change"])

        undone = self.engine.correct(
            "Undo my report detail preference",
            observed_at="2026-07-14T12:01:00Z")
        self.assertEqual(self.engine.select()[0]["effective_value"], "detailed")
        self.assertEqual(undone["action"], "undo")

    def test_inferred_preference_drifts_and_old_value_retires(self):
        for index in range(3):
            self.engine.observe(
                key="decision_batch_size", value="gate-batch", source="observed",
                project_id=f"p-{index + 10:032x}", evidence_id=f"e-old-{index}",
                observed_at=f"2026-01-0{index + 1}T00:00:00Z")
        for index in range(4):
            self.engine.observe(
                key="decision_batch_size", value="small-batch", source="observed",
                project_id=f"p-{index + 20:032x}", evidence_id=f"e-new-{index}",
                observed_at=f"2026-07-0{index + 1}T00:00:00Z")
        selected = self.engine.select()
        self.assertEqual(selected[0]["effective_value"], "small-batch")
        self.assertEqual(selected[0]["effective_source"], "inferred")
        self.assertIn("gate-batch", selected[0]["retired_values"])

    def test_stack_is_domain_scoped_and_high_consequence_autonomy_needs_confirmation(self):
        for index in range(3):
            self.engine.observe(
                key="stack", value="rust", source="observed", domain="firmware",
                project_id=f"p-{index + 30:032x}", evidence_id=f"e-stack-{index}")
        self.assertEqual(self.engine.select(domain="accounting"), [])
        self.assertEqual(self.engine.select(domain="firmware")[0]["effective_value"], "rust")

        last = None
        for index in range(3):
            last = self.engine.observe(
                key="autonomy", value="A3", source="observed",
                task_class="migration", risk_class="high",
                project_id=f"p-{index + 40:032x}", evidence_id=f"e-auto-{index}")
        self.assertTrue(last["requires_confirmation"])
        self.assertEqual(self.engine.select(
            task_class="migration", risk_class="high"), [])
        self.engine.confirm(last["preference_id"])
        self.assertEqual(self.engine.select(
            task_class="migration", risk_class="high")[0]["effective_value"], "A3")

    def test_stale_inferred_preference_auto_retires_but_stated_does_not(self):
        for index in range(3):
            self.engine.observe(
                key="verification_expectation", value="focused", source="observed",
                project_id=f"p-{index + 50:032x}", evidence_id=f"e-verify-{index}",
                observed_at=f"2026-01-0{index + 1}T00:00:00Z")
        self.engine.observe(
            key="report_detail", value="balanced", source="stated",
            evidence_id="e-stated", observed_at="2026-01-01T00:00:00Z")
        result = self.engine.housekeeping(now="2026-07-14T00:00:00Z")
        self.assertEqual(result["retired_inferred"], 1)
        self.assertEqual([item["key"] for item in self.engine.select()], ["report_detail"])

    def test_duplicate_evidence_and_unsupported_free_text_fail_closed(self):
        kwargs = dict(
            key="report_detail", value="concise", source="observed",
            project_id="p-00000000000000000000000000000060",
            evidence_id="e-duplicate")
        self.engine.observe(**kwargs)
        self.engine.observe(**kwargs)
        self.assertEqual(self.engine.inspect()[0]["observation_count"], 1)
        with self.assertRaisesRegex(loom_preferences.PreferenceError, "unsupported correction"):
            self.engine.correct("Please learn every private sentence I ever write")

    def test_sessions_automatically_learn_select_and_receipt_material_changes(self):
        selected = []

        def plan(context):
            selected.append(list(context.selected_preferences))
            return {"status": "completed", "code": "plan-ready", "success": True,
                "metrics": {},
                "evidence_ids": [
                    "pref-report-detail-concise-"
                    "8e42455ca927f83814566fb897985642997e3516a5695a6c0bc88d90e61627db"
                ],
                "reversible_action_ids": [],
                "preference_observations": [
                    {"key": "report_detail", "value": "concise"}],
                "artifact_usage": [{"artifact_id": "journey-map", "opened": False,
                    "cited": False, "work_order_used": False,
                    "prevented_defect": False}]}

        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance, handlers={"plan": plan},
            memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        receipts = []
        for index in range(4):
            project = self.root / f"project-{index}"
            project.mkdir()
            (project / "README.md").write_text("fixture\n", encoding="utf-8")
            receipts.append(controller.run(
                "Rename one CLI flag",
                invocation_id=f"00000000-0000-4000-8000-{index + 1:012d}",
                cwd=project, now=f"2026-07-1{index}T12:00:00Z"))

        self.assertEqual(selected[:3], [[], [], []])
        self.assertEqual(selected[3][0]["effective_value"], "concise")
        self.assertEqual(len(receipts[2].adaptation_receipts), 1)
        self.assertEqual(len(receipts[3].selected_preference_ids), 1)
        utility = loom_planning.PlanningOptimizer(
            self.home, self.instance).utility()
        self.assertEqual(utility[0]["unused_count"], 4)

        loom_memory.set_preference(
            self.home, self.instance, "report_style", "detailed")
        explicit_project = self.root / "project-explicit"
        explicit_project.mkdir()
        (explicit_project / "README.md").write_text("fixture\n", encoding="utf-8")
        controller.run(
            "Rename one CLI flag",
            invocation_id="00000000-0000-4000-8000-000000000099",
            cwd=explicit_project, now="2026-07-14T12:00:00Z")
        self.assertEqual(selected[-1][0]["effective_value"], "detailed")
        self.assertEqual(selected[-1][0]["effective_source"], "stated")

    def test_tampered_preference_store_fails_closed(self):
        self.engine.observe(
            key="report_detail", value="concise", source="stated",
            evidence_id="e-stated")
        store = json.loads(self.engine.path.read_text(encoding="utf-8"))
        store["preferences"][0]["observations"][0]["raw_private_text"] = "must not exist"
        self.engine.path.write_text(json.dumps(store), encoding="utf-8")
        with self.assertRaisesRegex(loom_preferences.PreferenceError, "contract"):
            self.engine.inspect()


if __name__ == "__main__":
    unittest.main()
