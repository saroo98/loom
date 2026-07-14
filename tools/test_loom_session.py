"""Acceptance tests for Loom's automatic one-command session runtime."""

import tempfile
import unittest
import json
import os
import subprocess
import sys
import time
from unittest import mock
from pathlib import Path

import loom_memory
import loom_improvement
import loom_session


class SessionRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "README.md").write_text("fixture\n", encoding="utf-8")
        self.owner_home = self.root / "owner-home"
        self.instance_id = "00000000-0000-4000-8000-000000000101"

    def tearDown(self):
        self.tmp.cleanup()

    def test_one_request_dispatches_and_seals_a_receipt(self):
        observed = []

        def plan(context):
            observed.append((context.intent, context.project_id, context.session_id))
            return {
                "status": "completed",
                "code": "plan-ready",
                "success": True,
                "metrics": {},
                "evidence_ids": [],
                "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.owner_home,
            instance_id=self.instance_id,
            handlers={"plan": plan},
            memory=loom_session.NoopMemoryAdapter(),
        )
        receipt = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000102",
            cwd=self.project,
            now="2026-07-14T12:00:00Z",
        )

        self.assertEqual(receipt.intent, "plan")
        self.assertEqual(receipt.status, "completed")
        self.assertFalse(receipt.repeated)
        self.assertRegex(receipt.receipt_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0], (
            "plan", receipt.project_id, receipt.session_id))

    def test_repeated_request_returns_existing_receipt_without_duplicate_execution(self):
        calls = []

        def plan(_context):
            calls.append("executed")
            return {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.owner_home,
            instance_id=self.instance_id,
            handlers={"plan": plan},
            memory=loom_session.NoopMemoryAdapter(),
        )
        first = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000103",
            cwd=self.project,
            now="2026-07-14T12:00:00Z",
        )
        second = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000104",
            cwd=self.project,
            now="2026-07-14T12:01:00Z",
        )

        self.assertEqual(calls, ["executed"])
        self.assertEqual(second.session_id, first.session_id)
        self.assertEqual(second.receipt_hash, first.receipt_hash)
        self.assertTrue(second.repeated)

    def test_interrupted_handler_is_reconciled_on_the_next_invocation(self):
        calls = []

        def plan(_context):
            calls.append("called")
            if len(calls) == 1:
                raise RuntimeError("seeded handler crash")
            return {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.owner_home,
            instance_id=self.instance_id,
            handlers={"plan": plan},
            memory=loom_session.NoopMemoryAdapter(),
        )
        with self.assertRaisesRegex(
                loom_session.SessionInterrupted, "HANDLER_INTERRUPTED"):
            controller.run(
                "Build a command-line tool",
                invocation_id="00000000-0000-4000-8000-000000000105",
                cwd=self.project,
                now="2026-07-14T12:00:00Z",
            )
        receipt = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000106",
            cwd=self.project,
            now="2026-07-14T12:01:00Z",
        )

        self.assertEqual(calls, ["called", "called"])
        self.assertEqual(receipt.status, "completed")
        self.assertEqual(receipt.reconciled_session_id, receipt.session_id)

    def test_local_memory_is_selected_compacted_and_records_one_outcome(self):
        loom_root = self.root / "loom-install"
        loom_root.mkdir()
        instance_id = loom_memory.initialize(self.owner_home, loom_root)
        loom_memory.set_preference(
            self.owner_home, instance_id, "report_style", "concise")
        observed_memory = []

        def plan(context):
            observed_memory.extend(item["id"] for item in context.selected_memory)
            return {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.owner_home,
            instance_id=instance_id,
            handlers={"plan": plan},
            memory=loom_session.LocalMemoryAdapter(
                owner_home=self.owner_home, instance_id=instance_id),
        )
        first = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000107",
            cwd=self.project,
            now="2026-07-14T12:00:00Z",
        )
        second = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000108",
            cwd=self.project,
            now="2026-07-14T12:01:00Z",
        )
        report = loom_memory.learning_report(
            self.owner_home, instance_id, metric="confidence", domain="cli")

        self.assertEqual(observed_memory, list(first.selected_memory_ids))
        self.assertEqual(len(first.selected_memory_ids), 1)
        self.assertEqual(len(first.outcome_ids), 1)
        self.assertTrue(second.repeated)
        self.assertEqual(report["sample_count"], 1)

    def test_session_automatically_records_domain_and_general_improvement_evidence(self):
        loom_root = self.root / "loom-install"
        loom_root.mkdir()
        instance_id = loom_memory.initialize(self.owner_home, loom_root)

        def plan(_context):
            return {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {
                    "rework-observed": 0.25,
                    "verification-escape": 0.0,
                    "incorrect-tier": 0.0,
                    "planning-overhead-ratio": 0.3,
                    "human-decision-round-trips": 2,
                    "artifact-unused": 0.1,
                    "wo-reopen": 0.0,
                    "drift-caught-before-execution": 1.0,
                    "release-rollback": 0.0,
                },
                "evidence_ids": ["real-session-evidence"],
                "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.owner_home, instance_id=instance_id,
            handlers={"plan": plan}, memory=loom_session.LocalMemoryAdapter(
                owner_home=self.owner_home, instance_id=instance_id))
        receipt = controller.run(
            "Plan a command-line developer tool",
            invocation_id="00000000-0000-4000-8000-000000000187",
            cwd=self.project, now="2026-07-14T12:00:00Z")

        self.assertEqual(11, len(receipt.improvement_evidence_ids))
        tracker = loom_improvement.ImprovementTracker(self.owner_home, instance_id)
        domain = tracker.report(
            metric="prediction-calibration-error", domain="cli")
        general = tracker.report(
            metric="prediction-calibration-error", domain="general")
        round_trips = tracker.audit_bundle(
            metric="human-decision-round-trips", domain="cli")
        self.assertEqual(1, domain["longitudinal"]["sample_count"])
        self.assertEqual(1, general["longitudinal"]["sample_count"])
        self.assertEqual(2.0, round_trips["evidence"]["longitudinal"]["recent"][0]["value"])
        self.assertEqual("exact-domain", domain["scope"])
        self.assertEqual("general-calibration", general["scope"])

    def test_concurrent_invocations_execute_the_operation_once(self):
        marker = self.root / "handler-marker.txt"
        script = r'''
import json, os, sys, time
from pathlib import Path
import loom_session

owner, project, marker, instance_id, invocation_id = sys.argv[1:]
def plan(_context):
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write("executed\n")
        stream.flush()
        os.fsync(stream.fileno())
    time.sleep(0.4)
    return {"status":"completed","code":"plan-ready","success":True,
            "metrics":{},"evidence_ids":[],"reversible_action_ids":[]}

controller = loom_session.SessionController(
    owner_home=Path(owner), instance_id=instance_id,
    handlers={"plan": plan}, memory=loom_session.NoopMemoryAdapter())
receipt = controller.run(
    "Build a command-line tool", invocation_id=invocation_id,
    cwd=Path(project), now="2026-07-14T12:00:00Z")
print(json.dumps(receipt.to_dict(), sort_keys=True))
'''
        base = [
            sys.executable, "-B", "-c", script,
            str(self.owner_home), str(self.project), str(marker), self.instance_id,
        ]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        first = subprocess.Popen(
            [*base, "00000000-0000-4000-8000-000000000109"],
            cwd=Path(__file__).parent, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.05)
        second = subprocess.Popen(
            [*base, "00000000-0000-4000-8000-000000000110"],
            cwd=Path(__file__).parent, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        first_out, first_err = first.communicate(timeout=20)
        second_out, second_err = second.communicate(timeout=20)

        self.assertEqual(first.returncode, 0, first_err)
        self.assertEqual(second.returncode, 0, second_err)
        receipts = [json.loads(first_out), json.loads(second_out)]
        self.assertEqual(sorted(item["repeated"] for item in receipts), [False, True])
        self.assertEqual(marker.read_text(encoding="utf-8"), "executed\n")

    def test_hard_process_death_is_reconciled_by_next_invocation(self):
        script = r'''
import os, sys
from pathlib import Path
import loom_session
owner, project, instance_id = sys.argv[1:]
def plan(_context): os._exit(91)
controller = loom_session.SessionController(
    owner_home=Path(owner), instance_id=instance_id,
    handlers={"plan": plan}, memory=loom_session.NoopMemoryAdapter())
controller.run("Build a command-line tool",
    invocation_id="00000000-0000-4000-8000-000000000111",
    cwd=Path(project), now="2026-07-14T12:00:00Z")
'''
        dead = subprocess.run(
            [sys.executable, "-B", "-c", script, str(self.owner_home),
             str(self.project), self.instance_id],
            cwd=Path(__file__).parent,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(dead.returncode, 91, dead.stderr)

        calls = []
        controller = loom_session.SessionController(
            owner_home=self.owner_home, instance_id=self.instance_id,
            handlers={"plan": lambda _context: calls.append("recovered") or {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            }}, memory=loom_session.NoopMemoryAdapter())
        receipt = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000112",
            cwd=self.project, now="2026-07-14T12:01:00Z")

        self.assertEqual(calls, ["recovered"])
        self.assertEqual(receipt.reconciled_session_id, receipt.session_id)

    def test_tampered_journal_blocks_before_handler_execution(self):
        calls = []
        controller = loom_session.SessionController(
            owner_home=self.owner_home, instance_id=self.instance_id,
            handlers={"plan": lambda _context: calls.append("executed") or {
                "status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            }}, memory=loom_session.NoopMemoryAdapter())
        receipt = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000113",
            cwd=self.project, now="2026-07-14T12:00:00Z")
        journal = controller._journal_path(receipt.project_id)
        data = json.loads(journal.read_text(encoding="utf-8"))
        data["events"][0]["payload"]["intent"] = "execute"
        journal.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaisesRegex(loom_session.SessionBlocked, "SESSION_CORRUPT"):
            controller.run(
                "Build a command-line tool",
                invocation_id="00000000-0000-4000-8000-000000000114",
                cwd=self.project, now="2026-07-14T12:01:00Z")
        self.assertEqual(calls, ["executed"])

    def test_owner_home_is_mandatory_and_never_falls_back_to_real_home(self):
        with self.assertRaisesRegex(loom_session.SessionBlocked, "SESSION_HOME_REQUIRED"):
            loom_session.SessionController(
                owner_home=None, instance_id=self.instance_id,
                handlers={}, memory=loom_session.NoopMemoryAdapter())

    def test_failed_atomic_replace_preserves_previous_journal_bytes(self):
        path = self.root / "atomic" / "journal.json"
        loom_session._atomic_json(path, {"generation": 1})
        before = path.read_bytes()
        with mock.patch.object(
                loom_session.os, "replace", side_effect=OSError("seeded replace failure")):
            with self.assertRaisesRegex(loom_session.SessionBlocked, "SESSION_WRITE_FAILED"):
                loom_session._atomic_json(path, {"generation": 2})
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_runtime_schema_required_fields_match_emitted_records(self):
        schema_root = Path(__file__).parent.parent / "schemas"
        journal_schema = json.loads(
            (schema_root / "session-journal.schema.json").read_text(encoding="utf-8"))
        receipt_schema = json.loads(
            (schema_root / "session-receipt.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(journal_schema["required"]), {
            "schema_version", "instance_id", "project_id", "events"})
        self.assertEqual(set(receipt_schema["required"]), set(
            loom_session.SessionReceipt.__dataclass_fields__))
        self.assertEqual(
            set(journal_schema["$defs"]["event"]["properties"]), {
                "schema_version", "event_id", "kind", "session_id", "operation_id",
                "recorded_at", "payload", "previous_hash", "event_hash"})

    def test_mutating_lifecycle_cli_requires_active_session_identity(self):
        pack = self.project / "plans" / "pack"
        result = subprocess.run(
            [sys.executable, "-B", "loom_gate.py", "init", str(pack),
             "--repo", str(self.project)],
            cwd=Path(__file__).parent,
            env={key: value for key, value in os.environ.items()
                 if not key.startswith("LOOM_SESSION_")},
            capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("active Loom session identity is required", result.stderr)
        self.assertFalse((pack / "lifecycle.json").exists())

    def test_active_session_can_authorize_lifecycle_mutation_for_its_project(self):
        pack = self.project / "plans" / "pack"
        pack.mkdir(parents=True)
        (pack / "MANIFEST.md").write_text(
            "---\nschema_version: 1\n---\n# Test pack\n", encoding="utf-8")
        diagnostics = []

        def plan(context):
            result = subprocess.run(
                [sys.executable, "-B", "loom_gate.py", "init", str(pack),
                 "--repo", str(self.project)],
                cwd=Path(__file__).parent,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                         **context.environment()),
                capture_output=True, text=True, timeout=20, check=False)
            diagnostics.append((result.returncode, result.stdout, result.stderr))
            return {
                "status": "completed" if result.returncode == 0 else "blocked",
                "code": "lifecycle-started" if result.returncode == 0 else "lifecycle-failed",
                "success": result.returncode == 0,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
            }

        controller = loom_session.SessionController(
            owner_home=self.owner_home, instance_id=self.instance_id,
            handlers={"plan": plan}, memory=loom_session.NoopMemoryAdapter())
        receipt = controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000115",
            cwd=self.project, now="2026-07-14T12:00:00Z")
        self.assertEqual(receipt.code, "lifecycle-started", diagnostics)
        self.assertTrue((pack / "lifecycle.json").is_file())


if __name__ == "__main__":
    unittest.main()
