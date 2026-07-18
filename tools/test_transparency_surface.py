"""Behavioral tests for Loom's compact natural-language transparency surface."""

import json
import tempfile
import unittest
from pathlib import Path

import loom_memory
import loom_preferences
import loom_transparency
import loom_session


class TransparencySurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "home"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)

    def tearDown(self):
        self.tmp.cleanup()

    def test_compact_receipt_reports_six_owner_questions_without_internal_jargon(self):
        receipt = loom_transparency.compact_receipt({
            "intent": "execute", "tier": "M", "domains": ["cli"],
            "status": "completed", "code": "work-complete",
            "reversible_action_ids": ["action-1"], "outcome_ids": ["outcome-1"],
            "adaptation_receipts": ["Adapted report detail."],
            "archived_count": 2, "uncertainty_codes": [],
            "owner_input_required": False, "user_message": "",
        })
        self.assertEqual(set(receipt), {
            "understood", "did", "changed", "learned", "archived",
            "uncertain", "owner_input_needed", "next"})
        self.assertFalse(receipt["owner_input_needed"])
        rendered = loom_transparency.render_compact_receipt(receipt)
        self.assertLessEqual(len(rendered), 800)
        self.assertNotRegex(rendered.lower(), r"\bg[0-9]\b|loom_[a-z]+|\.json|gate")

    def test_why_explanation_returns_sealed_evidence_and_memory_ids(self):
        explanation = loom_transparency.explain_receipt({
            "intent": "plan", "status": "completed", "code": "plan-ready",
            "receipt_hash": "a" * 64, "world_fingerprint": "b" * 64,
            "selected_memory_ids": ["00000000-0000-4000-8000-000000000001"],
            "outcome_ids": ["00000000-0000-4000-8000-000000000002"],
        })
        self.assertIn("a" * 64, explanation)
        self.assertIn("00000000-0000-4000-8000-000000000001", explanation)
        self.assertIn("evidence", explanation.lower())

    def test_forget_reference_writes_before_success_receipt_and_erases_content(self):
        record = loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        result = loom_transparency.forget_memory(
            self.home, self.instance, f"Forget memory {record['id']}", [record])
        self.assertTrue(result["written"])
        self.assertEqual(result["memory_id"], record["id"])
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"]), {
                "id": record["id"], "status": "forgotten", "content_erased": True})

    def test_profile_summary_is_bounded_human_readable_and_excludes_domain_rules(self):
        loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect", future_decision="verification-strategy",
            evidence_count=3, confidence=1.0, domain="three-d")
        summary = loom_transparency.profile_summary(
            self.home, self.instance, max_chars=600)
        self.assertIn("report_style: concise", summary)
        self.assertNotIn("three-d", summary)
        self.assertLessEqual(len(summary), 600)
        self.assertNotIn("{", summary)

    def test_action_ledger_undoes_latest_reversible_preference_once(self):
        preferences = loom_preferences.PreferenceEngine(self.home, self.instance)
        preferences.observe(
            key="report_detail", value="concise", source="stated",
            evidence_id="stated-initial")
        preferences.observe(
            key="report_detail", value="detailed", source="stated",
            evidence_id="stated-change")
        ledger = loom_transparency.ActionLedger(self.home, self.instance)
        ledger.record(
            action_id="action-report-change", kind="preference",
            target={"key": "report_detail", "domain": None,
                    "task_class": None, "risk_class": None, "subject": None},
            evidence_ids=["stated-change"])

        result = ledger.undo_latest(preferences)
        selected = preferences.select(domain="cli", task_class="plan", risk_class="low")
        report = next(item for item in selected if item["key"] == "report_detail")
        self.assertEqual(report["effective_value"], "concise")
        self.assertEqual(result["action_id"], "action-report-change")
        with self.assertRaisesRegex(loom_transparency.TransparencyError, "no reversible"):
            ledger.undo_latest(preferences)

    def test_sealed_session_exposes_compact_owner_view_with_archival_and_uncertainty(self):
        project = self.root / "project"
        project.mkdir()
        (project / "README.md").write_text("fixture\n", encoding="utf-8")

        def plan(_context):
            return {"status": "completed", "code": "plan-ready", "success": True,
                    "metrics": {}, "evidence_ids": ["observed-plan"],
                    "reversible_action_ids": ["action-plan"]}

        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": plan}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        receipt = controller.run(
            "Plan a command-line tool", cwd=project,
            invocation_id="00000000-0000-4000-8000-000000009001",
            now="2026-07-14T10:00:00Z")
        view = receipt.owner_view()
        self.assertEqual(2, len(view.splitlines()))
        self.assertIn("verification: verified", view)
        self.assertIn("freshness: current", view)
        self.assertIn("reversible: yes", view)
        self.assertIn("Receipt: session-", view)
        self.assertLessEqual(len(view), 600)

    def test_natural_profile_request_is_answered_without_a_user_handler(self):
        loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        project = self.root / "profile-project"
        project.mkdir()
        (project / "README.md").write_text("fixture\n", encoding="utf-8")
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance, handlers={},
            memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        receipt = controller.run(
            "Show what you remember about me", cwd=project,
            invocation_id="00000000-0000-4000-8000-000000009002",
            now="2026-07-14T10:05:00Z")
        self.assertEqual(receipt.intent, "status")
        self.assertEqual(receipt.status, "completed")
        self.assertIn("report_style: concise", receipt.user_message)

    def test_natural_why_undo_and_forget_use_builtin_safe_actions(self):
        project = self.root / "actions-project"
        project.mkdir()
        (project / "README.md").write_text("fixture\n", encoding="utf-8")
        adapter = loom_session.LocalMemoryAdapter(
            owner_home=self.home, instance_id=self.instance)
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": lambda _context: {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": ["plan-proof"],
                "reversible_action_ids": [],
            }}, memory=adapter)
        plan = controller.run(
            "Plan a command-line tool", cwd=project,
            invocation_id="00000000-0000-4000-8000-000000009003",
            now="2026-07-14T10:10:00Z")
        why = controller.run(
            "Why did you do that?", cwd=project,
            invocation_id="00000000-0000-4000-8000-000000009004",
            now="2026-07-14T10:11:00Z")
        self.assertEqual(why.intent, "why")
        self.assertIn(plan.receipt_hash, why.user_message)

        adapter.preferences.observe(
            key="report_detail", value="concise", source="stated",
            evidence_id="initial-detail")
        adapter.preferences.observe(
            key="report_detail", value="detailed", source="stated",
            evidence_id="changed-detail")
        adapter.actions.record(
            action_id="natural-undo-action", kind="preference",
            target={"key": "report_detail", "domain": None, "task_class": None,
                    "risk_class": None, "subject": None},
            evidence_ids=["changed-detail"])
        undone = controller.run(
            "Undo that", cwd=project,
            invocation_id="00000000-0000-4000-8000-000000009005",
            now="2026-07-14T10:12:00Z")
        self.assertEqual(undone.status, "completed")
        self.assertIn("Undid", undone.user_message)
        self.assertEqual(adapter.preferences.select()[0]["effective_value"], "concise")

        record = loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        forgotten = controller.run(
            f"Forget memory {record['id']}", cwd=project,
            invocation_id="00000000-0000-4000-8000-000000009006",
            now="2026-07-14T10:13:00Z")
        self.assertEqual(forgotten.status, "completed")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"])["content_erased"], True)


if __name__ == "__main__":
    unittest.main()
