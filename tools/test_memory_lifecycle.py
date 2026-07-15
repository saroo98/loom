"""Behavioral tests for Loom memory lifecycle and utility tracking."""

import tempfile
import unittest
import json
import os
from pathlib import Path

import loom_memory
import loom_session


class MemoryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir()
        self.instance = loom_memory.initialize(self.home, self.install)
        self.project = "p-00000000000000000000000000000051"
        self.project_root = self.root / "project"
        self.project_root.mkdir()
        (self.project_root / "README.md").write_text("fixture\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_project_close_archives_project_memory_without_deleting_it(self):
        record = loom_memory.admit_learning(
            self.home, self.instance, scope="project", category="process",
            signal="artifact-unused", future_decision="artifact-selection",
            evidence_count=2, confidence=1.0, domain="three-d",
            project_id=self.project)
        result = loom_memory.close_project(
            self.home, self.instance, self.project,
            now="2026-07-14T12:00:00Z")

        self.assertEqual(result["archived"], 1)
        self.assertEqual(loom_memory.select(
            self.home, self.instance, domain="three-d",
            project_id=self.project), [])
        preserved = loom_memory.inspect_record(
            self.home, self.instance, record["id"])
        self.assertEqual(preserved["status"], "archived")
        self.assertEqual(preserved["project_id"], self.project)

    def test_inactive_domain_memory_becomes_dormant_but_hard_stop_stays_active(self):
        domain = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="three-d")
        hard_stop = loom_memory.set_preference(
            self.home, self.instance, "hard_stop", "never publish secrets")
        result = loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2027-07-14T12:00:00Z")

        self.assertEqual(result["dormant"], 1)
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, domain["id"])["status"], "dormant")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, hard_stop["id"])["status"], "active")
        selected = loom_memory.select(self.home, self.instance, domain="three-d")
        self.assertEqual([item["id"] for item in selected], [hard_stop["id"]])

    def test_verified_memory_becomes_stale_at_deadline_not_deleted(self):
        record = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="firmware",
            verify_by="2026-08-01T00:00:00Z")
        result = loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2026-08-02T00:00:00Z")
        self.assertEqual(result["stale"], 1)
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"])["status"], "stale")
        self.assertEqual(loom_memory.select(
            self.home, self.instance, domain="firmware"), [])

    def test_selection_and_helpful_application_are_tracked_separately(self):
        record = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=0.8, domain="cli",
            evidence_projects=[self.project])
        selected = loom_memory.select(
            self.home, self.instance, domain="cli", project_id=self.project,
            now="2026-07-14T12:00:00Z")
        after_selection = loom_memory.inspect_record(
            self.home, self.instance, record["id"])

        self.assertEqual([item["id"] for item in selected], [record["id"]])
        self.assertEqual(after_selection["selection_count"], 1)
        self.assertEqual(after_selection["application_count"], 0)
        self.assertIsNone(after_selection["last_applied"])

        applied = loom_memory.record_application(
            self.home, self.instance, record["id"], outcome="helped",
            project_id=self.project, now="2026-07-14T12:05:00Z")
        self.assertEqual(applied["application_count"], 1)
        self.assertEqual(applied["helped_count"], 1)
        self.assertEqual(applied["hurt_count"], 0)
        self.assertGreater(applied["utility_score"], 0)
        for field in (
                "last_selected", "last_applied", "last_confirmed", "last_helped",
                "last_hurt", "selection_count", "application_count", "helped_count",
                "hurt_count", "evidence_projects", "utility_score", "verify_by",
                "scope", "confidence", "provenance"):
            self.assertIn(field, applied)

    def test_repeated_harm_demotes_quickly_while_helped_memory_survives_age(self):
        harmful = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="guidance-wasted-work", future_decision="guidance-selection",
            evidence_count=3, confidence=1.0, domain="web")
        helpful = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="cli")
        for minute in (1, 2):
            loom_memory.select(
                self.home, self.instance, domain="web",
                now=f"2026-07-14T12:0{minute}:00Z")
            loom_memory.record_application(
                self.home, self.instance, harmful["id"], outcome="hurt",
                now=f"2026-07-14T12:1{minute}:00Z")
        loom_memory.select(
            self.home, self.instance, domain="cli", now="2026-07-14T12:20:00Z")
        loom_memory.record_application(
            self.home, self.instance, helpful["id"], outcome="helped",
            now="2026-07-14T12:21:00Z")
        loom_memory.select(
            self.home, self.instance, domain="cli", now="2026-07-14T12:22:00Z")
        loom_memory.record_application(
            self.home, self.instance, helpful["id"], outcome="helped",
            now="2026-07-14T12:23:00Z")
        loom_memory.maintain_lifecycle(
            self.home, self.instance, now="2028-07-14T12:00:00Z")

        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, harmful["id"])["status"], "dormant")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, helpful["id"])["status"], "active")

    def test_changed_preference_is_superseded_and_forget_is_preserved(self):
        first = loom_memory.set_preference(
            self.home, self.instance, "report_style", "detailed")
        second = loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, first["id"])["status"], "superseded")
        self.assertIn(first["id"], second["supersedes"])
        self.assertTrue(loom_memory.forget(self.home, self.instance, second["id"]))
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, second["id"])["status"], "forgotten")

    def test_selection_stops_when_marginal_value_is_below_context_cost(self):
        record = loom_memory.add_record(
            self.home, self.instance, scope="domain", category="process",
            statement="x" * 1000, provenance="observed", evidence_count=1,
            domain="research", confidence=0.0)
        selected = loom_memory.select(
            self.home, self.instance, domain="research", max_chars=8000,
            now="2027-07-14T12:00:00Z")
        self.assertEqual(selected, [])
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"])["selection_count"], 0)

    def test_session_updates_utility_only_for_memory_handler_reports_applied(self):
        applied_record = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="verification-caught-defect",
            future_decision="verification-strategy", evidence_count=3,
            confidence=1.0, domain="cli")
        unused_record = loom_memory.admit_learning(
            self.home, self.instance, scope="domain", category="domain",
            signal="route-succeeded", future_decision="routing-strategy",
            evidence_count=3, confidence=1.0, domain="cli")

        def plan(context):
            self.assertEqual(len(context.selected_memory), 2)
            return {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": ["session-evidence"],
                "reversible_action_ids": [],
                "applied_memory_ids": [applied_record["id"]],
            }

        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": plan}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000601",
            cwd=self.project_root, now="2026-07-14T12:00:00Z")
        applied = loom_memory.inspect_record(
            self.home, self.instance, applied_record["id"])
        unused = loom_memory.inspect_record(
            self.home, self.instance, unused_record["id"])
        self.assertEqual((applied["selection_count"], applied["application_count"],
                          applied["helped_count"]), (1, 1, 1))
        self.assertEqual((unused["selection_count"], unused["application_count"],
                          unused["helped_count"]), (1, 0, 0))

    def test_session_completion_archives_its_project_only_memory(self):
        project_id = loom_memory.project_identity(self.instance, self.project_root)
        record = loom_memory.admit_learning(
            self.home, self.instance, scope="project", category="process",
            signal="artifact-unused", future_decision="artifact-selection",
            evidence_count=2, confidence=1.0, domain="cli",
            project_id=project_id)
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"plan": lambda _context: {
                "status": "completed", "code": "project-ready", "success": True,
                "metrics": {"project-completed": 1},
                "evidence_ids": ["completion-evidence"],
                "reversible_action_ids": [],
            }}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000602",
            cwd=self.project_root, now="2026-07-14T12:00:00Z")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"])["status"], "archived")

    def test_successful_close_intent_archives_without_handler_metric(self):
        project_id = loom_memory.project_identity(self.instance, self.project_root)
        record = loom_memory.admit_learning(
            self.home, self.instance, scope="project", category="process",
            signal="artifact-unused", future_decision="artifact-selection",
            evidence_count=2, confidence=1.0, domain="cli",
            project_id=project_id)
        controller = loom_session.SessionController(
            owner_home=self.home, instance_id=self.instance,
            handlers={"close": lambda _context: {
                "status": "completed", "code": "project-closed", "success": True,
                "metrics": {}, "evidence_ids": ["close-evidence"],
                "reversible_action_ids": [],
            }}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.home, instance_id=self.instance))
        receipt = controller.run(
            "Close this project",
            invocation_id="00000000-0000-4000-8000-000000000603",
            cwd=self.project_root, now="2026-07-14T12:00:00Z")
        self.assertEqual(receipt.intent, "close")
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"])["status"], "archived")

    def test_legacy_active_store_migrates_reversibly_to_new_lifecycle_fields(self):
        record = loom_memory.set_preference(
            self.home, self.instance, "report_style", "concise")
        path = self.home / "instances" / self.instance / "active.json"
        store = json.loads(path.read_text(encoding="utf-8"))
        legacy = store["records"][0]
        for field in loom_memory.UTILITY_FIELDS:
            legacy.pop(field)
        legacy["status"] = "retired"
        path.write_text(json.dumps(store), encoding="utf-8")

        migrated = loom_memory.read_store(self.home, self.instance)["records"][0]
        self.assertEqual(migrated["id"], record["id"])
        self.assertEqual(migrated["status"], "superseded")
        self.assertEqual(migrated["selection_count"], 0)
        self.assertEqual(migrated["evidence_projects"], [])

    def test_archive_redirection_fails_closed_without_losing_active_memory(self):
        record = loom_memory.admit_learning(
            self.home, self.instance, scope="project", category="process",
            signal="artifact-unused", future_decision="artifact-selection",
            evidence_count=2, confidence=1.0, domain="cli",
            project_id=self.project)
        directory = self.home / "instances" / self.instance
        outside = self.root / "outside-archive.jsonl"
        outside.write_text("sentinel\n", encoding="utf-8")
        archive = directory / "archive.jsonl"
        try:
            os.symlink(outside, archive)
        except (OSError, NotImplementedError):
            self.skipTest("file symlinks are unavailable")
        before = (directory / "active.json").read_bytes()
        with self.assertRaisesRegex(loom_memory.MemoryError, "symlink|junction"):
            loom_memory.close_project(
                self.home, self.instance, self.project,
                now="2026-07-14T12:00:00Z")
        self.assertEqual((directory / "active.json").read_bytes(), before)
        self.assertEqual(outside.read_text(encoding="utf-8"), "sentinel\n")
        archive.unlink()
        self.assertEqual(loom_memory.inspect_record(
            self.home, self.instance, record["id"])["status"], "active")

    def test_inactive_archives_garbage_collect_oldest_detail_at_hard_bounds(self):
        archive = self.home / "bounded-archive.jsonl"
        loom_memory._append_archive_lines(archive, [
            {"index": index, "payload": "x" * 1024}
            for index in range(5000)
        ])

        retained = loom_memory._read_archive(archive)
        self.assertLessEqual(archive.stat().st_size, loom_memory.MAX_ARCHIVE_BYTES)
        self.assertLessEqual(len(retained), loom_memory.MAX_ARCHIVE_ENTRIES)
        self.assertEqual(4999, retained[-1]["index"])
        self.assertGreater(retained[0]["index"], 0)

        loom_memory._append_archive_lines(
            archive, [{"index": 5000, "payload": "newest"}])
        retained = loom_memory._read_archive(archive)
        self.assertEqual(5000, retained[-1]["index"])
        self.assertLessEqual(archive.stat().st_size, loom_memory.MAX_ARCHIVE_BYTES)


if __name__ == "__main__":
    unittest.main()
