"""Regression tests for machine-enforced lifecycle chronology."""

import json
import datetime as dt
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import loom_gate  # noqa: E402
import loom_kickoff  # noqa: E402
from test_loom_lint import good_pack  # noqa: E402


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        (self.repo / "src.txt").write_text("baseline", encoding="utf-8")
        self.pack = self.repo / "plans"
        good_pack(self.pack)
        (self.pack / loom_gate.LIFECYCLE_FILE).unlink()
        if git(self.repo, "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "baseline")

    def tearDown(self):
        self.tmp.cleanup()

    def authorize(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 0)
        self.assertEqual(loom_gate.authorize(self.pack, self.repo), 0)

    def mark_done(self, wo=None):
        wo = wo or self.pack / "work-orders" / "WO-001-build-ui.md"
        text = wo.read_text(encoding="utf-8")
        text = text.replace("status: ready", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            "Pending implementation evidence.",
            "Evidence: declared verification command exit 0 observed.")
        wo.write_text(text, encoding="utf-8")
        return wo

    def add_second_work_order(self):
        first = self.pack / "work-orders" / "WO-001-build-ui.md"
        second = self.pack / "work-orders" / "WO-002-build-api.md"
        text = first.read_text(encoding="utf-8")
        text = text.replace("WO-001", "WO-002")
        text = text.replace("Build UI", "Build API")
        text = text.replace("src/ui.py", "src/api.py")
        second.write_text(text, encoding="utf-8")
        manifest = self.pack / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| WO-001 | ready | strong-coding | — | — | — |",
                "| WO-001 | ready | strong-coding | — | — | — |\n"
                "| WO-002 | ready | strong-coding | — | — | — |"),
            encoding="utf-8")
        return second

    def test_valid_chain_reaches_implementation_authorized(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 0)
        self.assertEqual(loom_gate.authorize(self.pack, self.repo), 0)
        self.assertEqual(
            loom_gate.verify(self.pack, self.repo, require_authorized=True), [])
        prompt, code = loom_kickoff.build(
            self.pack / "work-orders" / "WO-001-build-ui.md", repo_path=self.repo)
        self.assertEqual(code, 0)
        self.assertIn("Execute work order WO-001", prompt)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [event["event"] for event in data["events"]],
            ["planning-started", "g1-sealed", "implementation-authorized"])

    def test_repo_change_between_planning_and_g1_is_refused(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        (self.repo / "src.txt").write_text("implemented too early", encoding="utf-8")
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 1)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual([event["event"] for event in data["events"]],
                         ["planning-started"])

    def test_authorize_before_g1_is_refused(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        self.assertEqual(loom_gate.authorize(self.pack, self.repo), 1)

    def test_build_first_history_can_never_authorize_or_receive_plan_credit(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "build-first"), 0)
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 1)
        self.assertEqual(loom_gate.authorize(self.pack, self.repo), 1)
        prompt, code = loom_kickoff.build(
            self.pack / "work-orders" / "WO-001-build-ui.md", repo_path=self.repo)
        self.assertIsNone(prompt)
        self.assertEqual(code, 1)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual([event["event"] for event in data["events"]],
                         ["planning-started"])

    def test_work_order_plan_mutation_after_g1_blocks_authorization(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 0)
        wo = self.pack / "work-orders" / "WO-001-build-ui.md"
        wo.write_text(
            wo.read_text(encoding="utf-8").replace(
                "Produce the fixture UI outcome", "Produce a post-G1 outcome"),
            encoding="utf-8")
        self.assertEqual(loom_gate.authorize(self.pack, self.repo), 1)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual([event["event"] for event in data["events"]],
                         ["planning-started", "g1-sealed"])

    def test_review_mutation_breaks_chain(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 0)
        review.write_text(review.read_text(encoding="utf-8") + "\ntampered\n",
                          encoding="utf-8")
        findings = loom_gate.verify(self.pack, self.repo)
        self.assertTrue(any("review hash" in finding for finding in findings), findings)

    def test_event_tampering_breaks_hash_chain(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        path = self.pack / "lifecycle.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["events"][0]["repo_state_hash"] = "0" * 64
        path.write_text(json.dumps(data), encoding="utf-8")
        findings = loom_gate.verify(self.pack, self.repo)
        self.assertTrue(any("event hash" in finding for finding in findings), findings)

    def test_malformed_event_returns_blocking_findings_instead_of_raising(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        path = self.pack / "lifecycle.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["events"][0] = "not-an-event-object"
        path.write_text(json.dumps(data), encoding="utf-8")
        findings = loom_gate.verify(self.pack, self.repo)
        self.assertTrue(any("must be an object" in item for item in findings), findings)

    def test_tampered_review_traversal_is_rejected_without_reading_outside_pack(self):
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 0)
        path = self.pack / "lifecycle.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        event = data["events"][1]
        event["review"] = "reviews/../../outside.md"
        event["event_hash"] = loom_gate._event_hash(event)
        path.write_text(json.dumps(data), encoding="utf-8")
        findings = loom_gate.verify(self.pack)
        self.assertIn("G1 review path is unsafe or missing", findings)

    def test_preexisting_unchanged_deliverable_gets_no_causal_credit(self):
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("already existed\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "preexisting deliverable")
        self.authorize()
        wo = self.mark_done()
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 1)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(data["work_order_completions"], [])

    def test_post_authorization_change_seals_work_order_completion(self):
        self.authorize()
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("implemented later\n", encoding="utf-8")
        wo = self.mark_done()
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 0)
        self.assertEqual(loom_gate.verify(self.pack), [])
        self.assertEqual(loom_gate.verify(self.pack, self.repo), [])
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(data["work_order_completions"][0]["work_order"], "WO-001")
        self.assertEqual(data["work_order_completions"][0]["changed_paths"], ["src/ui.py"])
        manifest = (self.pack / "MANIFEST.md").read_text(encoding="utf-8")
        self.assertRegex(manifest, r"(?m)^\| WO-001 \| done \|")
        self.assertIn(f'repo_state_hash: "{data["work_order_completions"][0]["repo_state_hash"]}"',
                      manifest)

    def test_post_g1_plan_rewrite_cannot_receive_causal_credit(self):
        self.authorize()
        wo = self.pack / "work-orders" / "WO-001-build-ui.md"
        wo.write_text(
            wo.read_text(encoding="utf-8").replace(
                "Produce the fixture UI outcome", "Invent criteria after implementation"),
            encoding="utf-8")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("implemented later\n", encoding="utf-8")
        self.mark_done(wo)
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 1)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(data["work_order_completions"], [])

    def test_sequential_integration_closes_two_parallelizable_work_orders(self):
        second = self.add_second_work_order()
        self.authorize()
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("first branch merged\n", encoding="utf-8")
        first = self.mark_done()
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, first), 0)
        (self.repo / "src" / "api.py").write_text("second branch merged\n", encoding="utf-8")
        self.mark_done(second)
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, second), 0)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [item["work_order"] for item in data["work_order_completions"]],
            ["WO-001", "WO-002"])
        self.assertEqual(loom_gate.verify(self.pack, self.repo), [])

    def test_close_checkpoint_rolls_back_lifecycle_if_manifest_write_fails(self):
        self.authorize()
        before = (self.pack / "lifecycle.json").read_bytes()
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("implemented later\n", encoding="utf-8")
        wo = self.mark_done()
        with mock.patch.object(
                loom_gate, "_atomic_write_text", side_effect=OSError("seeded manifest failure")):
            self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 2)
        self.assertEqual((self.pack / "lifecycle.json").read_bytes(), before)
        manifest = (self.pack / "MANIFEST.md").read_text(encoding="utf-8")
        self.assertRegex(manifest, r"(?m)^\| WO-001 \| ready \|")

    def test_work_order_close_refuses_changes_outside_declared_touches(self):
        self.authorize()
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("implemented later\n", encoding="utf-8")
        (self.repo / "unrelated.txt").write_text("parallel mutation\n", encoding="utf-8")
        wo = self.mark_done()
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 1)
        data = json.loads((self.pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(data["work_order_completions"], [])

    def test_parent_traversal_in_touches_cannot_be_normalized_into_credit(self):
        self.authorize()
        wo = self.pack / "work-orders" / "WO-001-build-ui.md"
        wo.write_text(
            wo.read_text(encoding="utf-8").replace(
                "touches: [src/ui.py]", "touches: [../../src/ui.py]"),
            encoding="utf-8")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("implemented later\n", encoding="utf-8")
        wo = self.mark_done()
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 1)

    def test_work_order_evidence_mutation_breaks_completion_chain(self):
        self.authorize()
        (self.repo / "src").mkdir()
        (self.repo / "src" / "ui.py").write_text("implemented later\n", encoding="utf-8")
        wo = self.mark_done()
        self.assertEqual(loom_gate.close_wo(self.pack, self.repo, wo), 0)
        wo.write_text(wo.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")
        findings = loom_gate.verify(self.pack)
        self.assertTrue(any("work-order evidence hash" in item for item in findings),
                        findings)

    def test_stable_snapshot_fails_when_state_moves_during_measurement(self):
        first = loom_gate.loom_survey.RepoState(
            False, state_hash="1" * 64, untracked=("src.txt",))
        second = loom_gate.loom_survey.RepoState(
            False, state_hash="2" * 64, untracked=("src.txt",))
        with mock.patch.object(loom_gate, "_state", side_effect=[first, second]), \
                mock.patch.object(loom_gate, "_snapshot_files", return_value={}):
            with self.assertRaisesRegex(
                    loom_gate.loom_survey.SurveyError, "changed while"):
                loom_gate._stable_snapshot(self.repo, self.pack)

    def test_second_writer_cannot_acquire_lifecycle_lock(self):
        lock_path = self.pack / ".test-lifecycle.lock"
        with loom_gate.LifecycleLock(lock_path, timeout=0):
            with self.assertRaises(loom_gate.LifecycleBusy):
                with loom_gate.LifecycleLock(lock_path, timeout=0):
                    pass


class SmallLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        (self.repo / "base.txt").write_text("baseline\n", encoding="utf-8")
        if git(self.repo, "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "baseline")
        self.private = self.repo / "plans" / "small"
        self.record = self.private / "S-001.lifecycle.json"
        self.wo = self.private / "WO-001-small.md"

    def tearDown(self):
        self.tmp.cleanup()

    def write_wo(self, status="ready"):
        checked = "x" if status == "done" else " "
        closeout = ("Evidence: `python -m unittest` exit 0 observed."
                    if status == "done" else "Pending implementation evidence.")
        self.wo.write_text(f"""---
id: WO-001
title: Add small module
status: {status}
depends_on: []
blocks: []
routing: strong-coding
size: S
touches: [src/small.py]
last_verified: {dt.date.today().isoformat()}
---
## Intent
Add one low-risk module.
## Context
Repository baseline recorded by Tier-S lifecycle.
## Preconditions
Target state unchanged.
## Task
Create `src/small.py`.
## Acceptance criteria
- [{checked}] `python -m unittest` exits 0.
- [{checked}] Negative: `git diff --stat` contains only `src/small.py`.
## Out of scope
No architecture changes.
## Escalation triggers
Stop if another component is required.
## Epistemic notes
[FACT — lifecycle baseline] target state was recorded.
## Close-out
{closeout}
""", encoding="utf-8")

    def authorize(self):
        self.assertEqual(loom_gate.small_start(
            self.record, self.repo, self.wo), 0)
        self.write_wo("ready")
        self.assertEqual(loom_gate.small_authorize(
            self.record, self.repo, self.wo), 0)

    def test_small_flow_proves_plan_before_change_without_pack(self):
        self.authorize()
        (self.repo / "src").mkdir()
        (self.repo / "src" / "small.py").write_text("VALUE = 1\n", encoding="utf-8")
        self.write_wo("done")
        self.assertEqual(loom_gate.small_close(
            self.record, self.repo, self.wo), 0)
        self.assertEqual(loom_gate.verify_small(self.record), [])

    def test_small_flow_refuses_unchanged_preexisting_deliverable(self):
        (self.repo / "src").mkdir()
        (self.repo / "src" / "small.py").write_text("VALUE = 1\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "preexisting")
        self.authorize()
        self.write_wo("done")
        self.assertEqual(loom_gate.small_close(
            self.record, self.repo, self.wo), 1)

    def test_small_flow_refuses_target_change_before_authorization(self):
        self.assertEqual(loom_gate.small_start(
            self.record, self.repo, self.wo), 0)
        self.write_wo("ready")
        (self.repo / "base.txt").write_text("changed early\n", encoding="utf-8")
        self.assertEqual(loom_gate.small_authorize(
            self.record, self.repo, self.wo), 1)

    def test_small_flow_refuses_a_planning_essay(self):
        self.assertEqual(loom_gate.small_start(
            self.record, self.repo, self.wo), 0)
        self.write_wo("ready")
        self.wo.write_text(
            self.wo.read_text(encoding="utf-8") + "\n" + "x" * 6000,
            encoding="utf-8")
        self.assertEqual(loom_gate.small_authorize(
            self.record, self.repo, self.wo), 1)


if __name__ == "__main__":
    unittest.main()
