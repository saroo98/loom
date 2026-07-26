import tempfile
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

import loom_operation_envelope


class OperationEnvelopeTests(unittest.TestCase):
    def begin(self, root, subject="1" * 64):
        return loom_operation_envelope.begin(
            root, operation_class="exact-cut", subject_digest=subject,
            sidecar_type="exact-cut-receipt", sidecar_id="receipt.json",
            sidecar_digest="2" * 64,
            operation_id=str(uuid.uuid4()))

    def test_write_ahead_precedes_effect_and_terminal_state_is_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, created = self.begin(Path(temporary).resolve())
            self.assertEqual(["created"], [
                item["phase"] for item in created["events"]])
            started = loom_operation_envelope.transition(
                path, phase="started", side_effect_boundary="before-build",
                state_may_have_changed=False)
            effect = loom_operation_envelope.transition(
                path, phase="effect", side_effect_boundary="cut-staging-created",
                state_may_have_changed=True)
            passed = loom_operation_envelope.transition(
                path, phase="passed", side_effect_boundary="receipt-committed",
                state_may_have_changed=True, cleanup_disposition="completed")
            self.assertEqual(["created", "started", "effect", "passed"], [
                item["phase"] for item in passed["events"]])
            self.assertNotEqual(started["envelope_sha256"], effect["envelope_sha256"])
            loom_operation_envelope.validate(passed)

    def test_tampering_future_transition_and_second_terminal_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.begin(Path(temporary).resolve())
            loom_operation_envelope.transition(
                path, phase="started", side_effect_boundary="before-build",
                state_may_have_changed=False)
            terminal = loom_operation_envelope.transition(
                path, phase="failed", side_effect_boundary="build-failed",
                state_may_have_changed=True, primary_failure="injected",
                cleanup_disposition="preserved")
            with self.assertRaises(loom_operation_envelope.EnvelopeError):
                loom_operation_envelope.transition(
                    path, phase="passed", side_effect_boundary="forged",
                    state_may_have_changed=True)
            terminal["subject_digest"] = "3" * 64
            with self.assertRaises(loom_operation_envelope.EnvelopeError):
                loom_operation_envelope.validate(terminal)

    def test_incomplete_operation_reconciles_once_and_wrong_world_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = self.begin(Path(temporary).resolve())
            loom_operation_envelope.transition(
                path, phase="started", side_effect_boundary="before-build",
                state_may_have_changed=False)
            with self.assertRaises(loom_operation_envelope.EnvelopeError):
                loom_operation_envelope.reconcile_incomplete(
                    path, subject_digest="9" * 64, reconciler=lambda _: {})
            reconciled = loom_operation_envelope.reconcile_incomplete(
                path, subject_digest="1" * 64,
                reconciler=lambda _: {
                    "state_may_have_changed": False,
                    "cleanup_disposition": "completed",
                    "secondary_failures": [],
                })
            self.assertEqual("reconciled", reconciled["events"][-1]["phase"])
            self.assertEqual(
                reconciled,
                loom_operation_envelope.reconcile_incomplete(
                    path, subject_digest="1" * 64, reconciler=lambda _: None))

    def test_unchanged_world_reuses_operation_and_changed_world_creates_new_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first_path, first, reused = loom_operation_envelope.begin_or_reuse(
                root, operation_class="exact-cut", subject_digest="1" * 64,
                sidecar_type="exact-cut-receipt", sidecar_id="receipt.json",
                sidecar_digest="2" * 64)
            second_path, second, reused_second = \
                loom_operation_envelope.begin_or_reuse(
                    root, operation_class="exact-cut", subject_digest="1" * 64,
                    sidecar_type="exact-cut-receipt", sidecar_id="receipt.json",
                    sidecar_digest="2" * 64)
            changed_path, changed, changed_reused = \
                loom_operation_envelope.begin_or_reuse(
                    root, operation_class="exact-cut", subject_digest="3" * 64,
                    sidecar_type="exact-cut-receipt", sidecar_id="receipt.json",
                    sidecar_digest="2" * 64)
            self.assertFalse(reused)
            self.assertTrue(reused_second)
            self.assertFalse(changed_reused)
            self.assertEqual(first_path, second_path)
            self.assertEqual(first["operation_id"], second["operation_id"])
            self.assertNotEqual(first_path, changed_path)
            self.assertNotEqual(first["operation_id"], changed["operation_id"])
            self.assertEqual(
                {first_path, changed_path},
                {item[0] for item in loom_operation_envelope.incomplete(root)})

    def test_forced_process_exit_leaves_reconcilable_not_false_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            code = (
                "import os,sys;"
                "from pathlib import Path;"
                "import loom_operation_envelope as e;"
                "p,_,_=e.begin_or_reuse(Path(sys.argv[1]),"
                "operation_class='crash-fixture',subject_digest='1'*64,"
                "sidecar_type='fixture-receipt',sidecar_id='one.json',"
                "sidecar_digest='2'*64);"
                "e.transition(p,phase='started',side_effect_boundary='before-effect',"
                "state_may_have_changed=False);"
                "os._exit(97)"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(root)], cwd=Path(__file__).parent,
                check=False)
            self.assertEqual(97, result.returncode)
            pending = loom_operation_envelope.incomplete(root)
            self.assertEqual(1, len(pending))
            self.assertEqual("started", pending[0][1]["events"][-1]["phase"])


if __name__ == "__main__":
    unittest.main()
