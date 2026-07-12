"""Tests for scoped, bounded, sovereign owner learning."""

import tempfile
import unittest
import contextlib
import io
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).parent))
import loom_memory  # noqa: E402
import loom_lint  # noqa: E402


class MemoryIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.loom_a = self.root / "loom-a"
        self.loom_b = self.root / "loom-b"
        self.loom_a.mkdir()
        self.loom_b.mkdir()
        self.a = loom_memory.initialize(self.home, self.loom_a)
        self.b = loom_memory.initialize(self.home, self.loom_b)

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, instance, scope, statement, **kwargs):
        if "project_id" in kwargs and not kwargs["project_id"].startswith("p-"):
            project_root = self.root / kwargs.pop("project_id")
            project_root.mkdir(exist_ok=True)
            kwargs["project_id"] = loom_memory.project_identity(
                instance, project_root)
        return loom_memory.add_record(
            self.home, instance, scope=scope, category="process",
            statement=statement, provenance="observed", evidence_count=2,
            **kwargs)

    def test_instances_are_physically_and_logically_isolated(self):
        self.assertNotEqual(self.a, self.b)
        loom_memory.set_preference(
            self.home, self.a, "report_style", "concise", provenance="stated")
        loom_memory.set_preference(
            self.home, self.b, "report_style", "detailed", provenance="stated")
        selected_a = loom_memory.select(self.home, self.a)
        selected_b = loom_memory.select(self.home, self.b)
        self.assertEqual([r["statement"] for r in selected_a],
                         ["report_style=concise"])
        self.assertEqual([r["statement"] for r in selected_b],
                         ["report_style=detailed"])

    def test_selector_loads_global_plus_only_matching_domain_and_project(self):
        ledger_id = loom_memory.project_identity(self.a, self.root / "ledger-app")
        other_id = loom_memory.project_identity(self.a, self.root / "other-app")
        loom_memory.set_preference(
            self.home, self.a, "decision_batching", "batched",
            provenance="stated")
        self.add(self.a, "domain", "web layout observation", domain="web")
        self.add(self.a, "domain", "accounting reconciliation observation",
                 domain="accounting")
        self.add(self.a, "project", "ledger project local observation",
                 domain="accounting", project_id="ledger-app")
        self.add(self.a, "project", "other project local observation",
                 domain="accounting", project_id="other-app")

        selected = loom_memory.select(
            self.home, self.a, domain="accounting", project_id=ledger_id)
        statements = {record["statement"] for record in selected}
        self.assertEqual(statements, {
            "decision_batching=batched",
            "accounting reconciliation observation",
            "ledger project local observation",
        })

    def test_forget_creates_tombstone_and_removes_record_from_selection(self):
        record = loom_memory.set_preference(
            self.home, self.a, "autonomy_default", "A2", provenance="stated")
        self.assertTrue(loom_memory.forget(self.home, self.a, record["id"]))
        self.assertEqual(loom_memory.select(self.home, self.a), [])
        store = loom_memory.read_store(self.home, self.a)
        self.assertTrue(any(item["status"] == "tombstone"
                            for item in store["records"]))

    def test_duplicate_observation_compacts_evidence_not_context(self):
        self.add(self.a, "domain", "same calibrated lesson", domain="accounting")
        self.add(self.a, "domain", "  Same   calibrated lesson  ",
                 domain="accounting")
        result = loom_memory.compact(self.home, self.a)
        selected = loom_memory.select(self.home, self.a, domain="accounting")
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["evidence_count"], 4)
        self.assertGreaterEqual(result["deduplicated"], 1)

    def test_active_memory_and_selected_context_are_hard_bounded(self):
        for index in range(320):
            self.add(self.a, "domain", f"calibration observation {index}",
                     domain="accounting")
        result = loom_memory.compact(self.home, self.a)
        store = loom_memory.read_store(self.home, self.a)
        selected = loom_memory.select(self.home, self.a, max_chars=1200)
        self.assertLessEqual(result["active"], loom_memory.MAX_ACTIVE_RECORDS)
        self.assertLessEqual(len(store["records"]), loom_memory.MAX_ACTIVE_RECORDS + 64)
        self.assertLessEqual(
            len(__import__("json").dumps(selected, ensure_ascii=False)), 1200)
        self.assertTrue((self.home / "instances" / self.a / "archive.jsonl").is_file())

    def test_concurrent_writers_do_not_lose_records(self):
        project_id = loom_memory.project_identity(
            self.a, self.root / "parallel-project")

        def write(index):
            self.add(self.a, "project", f"concurrent observation {index}",
                     domain="accounting", project_id="parallel-project")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(24)))
        records = [record for record in loom_memory.read_store(
            self.home, self.a)["records"]
            if record.get("status") == "active"
            and record.get("domain") == "accounting"
            and record.get("project_id") == project_id]
        self.assertEqual(len(records), 24)

    def test_concurrent_singleton_preference_updates_leave_exactly_one_active(self):
        values = ["A0", "A1", "A2", "A3"] * 4

        def write(value):
            loom_memory.set_preference(
                self.home, self.a, "autonomy_default", value,
                provenance="stated")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, values))
        selected = [record for record in loom_memory.select(self.home, self.a)
                    if record.get("preference_key") == "autonomy_default"]
        self.assertEqual(len(selected), 1)
        self.assertIn(selected[0]["preference_value"], {"A0", "A1", "A2", "A3"})

    def test_concurrent_initialization_creates_one_instance_identity(self):
        root = self.root / "loom-concurrent-init"
        root.mkdir()

        def initialize(_):
            return loom_memory.initialize(self.home, root)

        with ThreadPoolExecutor(max_workers=8) as pool:
            identities = list(pool.map(initialize, range(16)))
        self.assertEqual(len(set(identities)), 1)
        self.assertEqual(
            (root / ".loom-instance-id").read_text(encoding="utf-8").strip(),
            identities[0])

    def test_live_lock_is_never_deleted_by_an_age_timeout(self):
        path = self.root / "live.lock"
        with loom_memory.FileLock(path, timeout=0):
            with self.assertRaisesRegex(loom_memory.MemoryError, "busy"):
                with loom_memory.FileLock(path, timeout=0, stale_after=0):
                    pass
            self.assertTrue(path.is_file())
        self.assertFalse(path.exists())

    def test_transient_windows_style_permission_denial_retries(self):
        path = self.root / "transient.lock"
        real_open = loom_memory.os.open
        calls = 0

        def transient(target, flags, mode=0o777):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise PermissionError("seeded transient sharing denial")
            return real_open(target, flags, mode)

        with mock.patch.object(loom_memory.os, "open", side_effect=transient):
            with loom_memory.FileLock(path, timeout=1):
                self.assertTrue(path.is_file())
        self.assertFalse(path.exists())
        self.assertGreaterEqual(calls, 2)

    def test_project_scope_cannot_be_selected_without_its_domain(self):
        project_id = loom_memory.project_identity(
            self.a, self.root / "shared-name")
        self.add(self.a, "project", "project-local invariant",
                 domain="accounting", project_id="shared-name")
        with self.assertRaisesRegex(loom_memory.MemoryError, "explicit domain"):
            loom_memory.select(self.home, self.a, project_id=project_id)
        self.assertEqual(
            loom_memory.select(
                self.home, self.a, domain="realtime-3d",
                project_id=project_id), [])

    def test_selector_hard_cap_cannot_be_overridden(self):
        with self.assertRaisesRegex(loom_memory.MemoryError, "between 1 and 8000"):
            loom_memory.select(self.home, self.a, max_chars=8001)
        with self.assertRaisesRegex(loom_memory.MemoryError, "safe local identifier"):
            loom_memory.select(self.home, self.a, domain="../accounting")

    def test_project_identity_is_instance_bound_and_path_specific(self):
        first = loom_memory.project_identity(self.a, self.root / "project-one")
        second = loom_memory.project_identity(self.a, self.root / "project-two")
        other_instance = loom_memory.project_identity(
            self.b, self.root / "project-one")
        self.assertRegex(first, r"^p-[0-9a-f]{32}$")
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, other_instance)

    def test_outbox_is_structured_and_cannot_cross_instances(self):
        entry = loom_memory.queue_feedback(
            self.home, self.a, pattern="stale-state",
            action="fail-closed", evidence_count=3)
        self.assertEqual(entry["instance_id"], self.a)
        with self.assertRaises(loom_memory.MemoryError):
            loom_memory.drain_feedback(self.home, self.a, receiver_instance_id=self.b)
        drained = loom_memory.drain_feedback(
            self.home, self.a, receiver_instance_id=self.a)
        self.assertEqual(len(drained), 1)
        self.assertFalse((self.home / "instances" / self.a / "outbox.jsonl").read_text(
            encoding="utf-8").strip())

    def test_outbox_rejects_free_form_project_text(self):
        with self.assertRaises(TypeError):
            loom_memory.queue_feedback(
                self.home, self.a, pattern="stale-state", action="fail-closed",
                evidence_count=1, project_name="private-client")

    def test_outbox_has_a_hard_active_entry_cap(self):
        with mock.patch.object(loom_memory, "MAX_OUTBOX_ENTRIES", 3):
            for _ in range(3):
                loom_memory.queue_feedback(
                    self.home, self.a, pattern="stale-state",
                    action="fail-closed", evidence_count=1)
            with self.assertRaisesRegex(loom_memory.MemoryError, "outbox is full"):
                loom_memory.queue_feedback(
                    self.home, self.a, pattern="stale-state",
                    action="fail-closed", evidence_count=1)

    def test_malformed_outbox_cannot_inject_project_data_into_feedback(self):
        entry = loom_memory.queue_feedback(
            self.home, self.a, pattern="stale-state",
            action="fail-closed", evidence_count=1)
        entry["project_name"] = "Private-Client"
        outbox = self.home / "instances" / self.a / "outbox.jsonl"
        outbox.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        feedback = self.loom_a / "FEEDBACK.md"
        feedback.write_text("# Feedback\n", encoding="utf-8")
        before = feedback.read_bytes()
        with self.assertRaisesRegex(loom_memory.MemoryError, "unknown/missing fields"):
            loom_memory.contribute(self.home, self.a, self.loom_a)
        self.assertEqual(feedback.read_bytes(), before)

    def test_contribute_is_explicit_local_and_instance_bound(self):
        loom_memory.queue_feedback(
            self.home, self.a, pattern="tier-overestimate",
            action="tier-down", evidence_count=2)
        count = loom_memory.contribute(self.home, self.a, self.loom_a)
        self.assertEqual(count, 1)
        feedback = (self.loom_a / "FEEDBACK.md").read_text(encoding="utf-8")
        self.assertIn("tier-overestimate", feedback)
        self.assertNotIn("loom-a", feedback)
        loom_memory.queue_feedback(
            self.home, self.a, pattern="stale-state",
            action="fail-closed", evidence_count=1)
        with self.assertRaises(loom_memory.MemoryError):
            loom_memory.contribute(self.home, self.a, self.loom_b)

    def test_contribute_enforces_feedback_active_cap_in_same_command(self):
        feedback = self.loom_a / "FEEDBACK.md"
        feedback.write_text(
            "# Feedback\n\n"
            "### 2026-01-01 — one — loom-core\n- saw: one\n- fix: one\n\n"
            "### 2026-01-02 — two — loom-core\n- saw: two\n- fix: two\n",
            encoding="utf-8")
        loom_memory.queue_feedback(
            self.home, self.a, pattern="stale-state",
            action="fail-closed", evidence_count=1)
        with mock.patch.object(loom_memory, "MAX_FEEDBACK_ACTIVE", 2):
            self.assertEqual(loom_memory.contribute(
                self.home, self.a, self.loom_a), 1)
        active = feedback.read_text(encoding="utf-8")
        self.assertEqual(len(__import__("re").findall(r"(?m)^###\s+", active)), 2)
        archive = self.loom_a / ".loom-private" / "feedback-archive.jsonl"
        self.assertEqual(len([line for line in archive.read_text(
            encoding="utf-8").splitlines() if line]), 1)

    def test_learning_report_measures_calibration_change(self):
        for predicted, actual in ((0.9, 0.2), (0.8, 0.2), (0.3, 0.2), (0.2, 0.2)):
            loom_memory.record_outcome(
                self.home, self.a, metric="confidence", predicted=predicted,
                actual=actual, domain="general")
        report = loom_memory.learning_report(self.home, self.a, metric="confidence")
        self.assertEqual(report["sample_count"], 4)
        self.assertLess(report["recent_mae"], report["early_mae"])
        self.assertTrue(report["improved"])

    def test_learning_reports_never_mix_general_and_domain_partitions(self):
        for domain, predicted, actual in (
                ("general", 0.9, 0.1), ("general", 0.2, 0.1),
                ("website", 0.1, 0.9)):
            loom_memory.record_outcome(
                self.home, self.a, metric="confidence", predicted=predicted,
                actual=actual, domain=domain)
        general = loom_memory.learning_report(
            self.home, self.a, metric="confidence")
        website = loom_memory.learning_report(
            self.home, self.a, metric="confidence", domain="website")
        self.assertEqual(general["domain"], "general")
        self.assertEqual(general["sample_count"], 2)
        self.assertEqual(website["sample_count"], 1)

    def test_corrupt_outcome_partition_types_fail_closed(self):
        loom_memory.record_outcome(
            self.home, self.a, metric="confidence", predicted=0.8,
            actual=0.2, domain="general")
        path = self.home / "instances" / self.a / "outcomes.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["partitions"]["confidence:general"]["sample_count"] = "1"
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(loom_memory.MemoryError, "windows are invalid"):
            loom_memory.learning_report(
                self.home, self.a, metric="confidence", domain="general")

    def test_outcome_evidence_stays_bounded_while_summary_keeps_history(self):
        for index in range(530):
            actual = 0.1 if index < 64 else 0.85
            loom_memory.record_outcome(
                self.home, self.a, metric="confidence", predicted=0.9,
                actual=actual, domain="general")
        directory = self.home / "instances" / self.a
        store = json.loads((directory / "outcomes.json").read_text(
            encoding="utf-8"))
        archive = [line for line in (directory / "outcomes-archive.jsonl")
                   .read_text(encoding="utf-8").splitlines() if line]
        report = loom_memory.learning_report(
            self.home, self.a, metric="confidence", domain="general")
        self.assertEqual(len(store["records"]), loom_memory.MAX_OUTCOMES_ACTIVE)
        self.assertEqual(len(archive), 18)
        self.assertEqual(report["sample_count"], 530)
        self.assertEqual(report["active_evidence_count"], 512)
        self.assertLessEqual(report["early_sample_count"], loom_memory.OUTCOME_WINDOW)
        self.assertLess(report["recent_mae"], report["early_mae"])

    def test_preference_update_supersedes_old_value_without_ossifying(self):
        loom_memory.set_preference(
            self.home, self.a, "autonomy_default", "A2", provenance="stated")
        loom_memory.set_preference(
            self.home, self.a, "autonomy_default", "A1", provenance="stated")
        selected = loom_memory.select(self.home, self.a)
        preferences = [record for record in selected
                       if record.get("preference_key") == "autonomy_default"]
        self.assertEqual(len(preferences), 1)
        self.assertEqual(preferences[0]["preference_value"], "A1")

    def test_multiple_stated_hard_stops_accumulate_safely(self):
        loom_memory.set_preference(
            self.home, self.a, "hard_stop", "never deploy", provenance="stated")
        loom_memory.set_preference(
            self.home, self.a, "hard_stop", "never delete data", provenance="stated")
        values = {item["preference_value"] for item in loom_memory.select(self.home, self.a)
                  if item.get("preference_key") == "hard_stop"}
        self.assertEqual(values, {"never deploy", "never delete data"})

    def test_hard_stop_cap_refuses_instead_of_silently_archiving_safety_rules(self):
        with mock.patch.object(loom_memory, "MAX_HARD_STOPS", 2):
            loom_memory.set_preference(
                self.home, self.a, "hard_stop", "never deploy", provenance="stated")
            loom_memory.set_preference(
                self.home, self.a, "hard_stop", "never delete", provenance="stated")
            with self.assertRaisesRegex(loom_memory.MemoryError, "hard-stop cap"):
                loom_memory.set_preference(
                    self.home, self.a, "hard_stop", "never publish", provenance="stated")
        values = {item["preference_value"] for item in loom_memory.select(self.home, self.a)
                  if item.get("preference_key") == "hard_stop"}
        self.assertEqual(values, {"never deploy", "never delete"})

    def test_observed_memory_gets_a_real_expiry(self):
        record = self.add(
            self.a, "domain", "observed process preference", domain="accounting")
        self.assertIsNotNone(record["expires_at"])

    def test_arbitrary_global_observation_is_rejected(self):
        with self.assertRaisesRegex(
                loom_memory.MemoryError, "typed stated preferences"):
            self.add(self.a, "global", "web breakpoints transfer everywhere")

    def test_stack_preference_requires_and_respects_domain_scope(self):
        with self.assertRaisesRegex(loom_memory.MemoryError, "explicit domain"):
            loom_memory.set_preference(
                self.home, self.a, "stack_preference", "React")
        loom_memory.set_preference(
            self.home, self.a, "stack_preference", "React",
            provenance="stated", domain="web")
        self.assertEqual(loom_memory.select(self.home, self.a, domain="accounting"), [])
        self.assertEqual(
            [item["preference_value"] for item in
             loom_memory.select(self.home, self.a, domain="web")], ["React"])

    def test_composite_selection_loads_only_the_explicit_matched_domains(self):
        self.add(self.a, "domain", "accounting invariant", domain="accounting")
        self.add(self.a, "domain", "desktop invariant", domain="desktop")
        self.add(self.a, "domain", "website-only rule", domain="website")
        statements = {item["statement"] for item in loom_memory.select(
            self.home, self.a, domain=["accounting", "desktop"])}
        self.assertEqual(statements, {"accounting invariant", "desktop invariant"})

    def test_preferences_cannot_be_inferred_or_silently_observed(self):
        with self.assertRaisesRegex(loom_memory.MemoryError, "stated provenance"):
            loom_memory.set_preference(
                self.home, self.a, "report_style", "concise",
                provenance="observed")

    def test_legacy_calibration_is_quarantined_not_globally_loaded(self):
        self.home.mkdir(parents=True, exist_ok=True)
        (self.home / "calibration.md").write_text(
            "---\nartifact: user-calibration\n---\n"
            "- 2026-01-01 | Synthetic-Project SEO animation behavior\n",
            encoding="utf-8")
        result = loom_memory.migrate_legacy(self.home, self.a)
        self.assertEqual(result["quarantined"], 1)
        self.assertEqual(loom_memory.select(self.home, self.a), [])
        quarantine = self.home / "instances" / self.a / "legacy-quarantine.jsonl"
        self.assertIn("Synthetic-Project", quarantine.read_text(encoding="utf-8"))

    def test_initialization_automatically_quarantines_preexisting_flat_memory(self):
        root = self.root / "auto-legacy-loom"
        root.mkdir()
        home = self.root / "auto-legacy-home"
        home.mkdir()
        (home / "calibration.md").write_text(
            "# old\n- website-only animation preference\n", encoding="utf-8")
        instance = loom_memory.initialize(home, root)
        archive = home / "instances" / instance / "legacy-quarantine.jsonl"
        self.assertTrue(archive.is_file())
        self.assertIn("website-only animation preference", archive.read_text(encoding="utf-8"))
        self.assertEqual(loom_memory.select(home, instance), [])
        self.assertEqual(loom_lint.lint_home(home).findings, [])
        (home / "calibration.md").write_text(
            "# old\n- website-only animation preference\n- later legacy edit\n",
            encoding="utf-8")
        rep = loom_lint.lint_home(home)
        self.assertTrue(any(item["code"] == "W20" and item["sev"] == "WARN"
                            for item in rep.findings), rep.findings)
        self.assertEqual(loom_memory.select(home, instance), [])

    def test_cli_emits_one_truthful_json_result(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = loom_memory.main([
                "--home", str(self.home), "select", "--instance", self.a,
            ])
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["result"], [])

    def test_typed_home_lints_clean_and_cross_instance_corruption_blocks(self):
        self.assertEqual(loom_lint.lint_home(self.home).findings, [])
        path = self.home / "instances" / self.a / "active.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["instance_id"] = self.b
        path.write_text(json.dumps(data), encoding="utf-8")
        rep = loom_lint.lint_home(self.home)
        self.assertTrue(any(item["code"] == "E21" for item in rep.errors), rep.findings)

    def test_feedback_compaction_bounds_active_queue_without_losing_history(self):
        entries = []
        for index in range(130):
            resolution = "\n- ✔ 2026-01-02 tooling-bug: fixed" if index < 120 else ""
            entries.append(
                f"### 2026-01-01 — source-{index} — tools/file.md\n"
                f"- saw: generic failure {index}\n- fix: generic correction{resolution}\n")
        feedback = self.loom_a / "FEEDBACK.md"
        feedback.write_text("# Feedback\n\n---\n\n" + "\n".join(entries),
                            encoding="utf-8")
        result = loom_memory.compact_feedback(
            self.loom_a, max_active=20, keep_resolved=5)
        active = feedback.read_text(encoding="utf-8")
        archive = self.loom_a / ".loom-private" / "feedback-archive.jsonl"
        archived = [json.loads(line) for line in archive.read_text(
            encoding="utf-8").splitlines() if line]
        self.assertLessEqual(active.count("\n### "), 20)
        self.assertEqual(result["total_entries"], 130)
        self.assertEqual(result["archived_now"], 115)
        self.assertEqual(len(archived), 115)
        second = loom_memory.compact_feedback(
            self.loom_a, max_active=20, keep_resolved=5)
        self.assertEqual(second["archived_now"], 0)

    def test_feedback_active_cap_cannot_be_overridden(self):
        (self.loom_a / "FEEDBACK.md").write_text("# Feedback\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_memory.MemoryError, "max_active"):
            loom_memory.compact_feedback(
                self.loom_a, max_active=loom_memory.MAX_FEEDBACK_ACTIVE + 1)


if __name__ == "__main__":
    unittest.main()
