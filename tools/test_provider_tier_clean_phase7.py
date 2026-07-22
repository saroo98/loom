import json
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import loom_provider_evidence
import loom_clean_room
import loom_release
import loom_tier_s_study


def usage_bundle(source="provider", response=True):
    identity = str(uuid.uuid4())
    event = {
        "schema_version": 3, "event_id": str(uuid.uuid4()),
        "owner_vault_id": str(uuid.uuid4()), "project_id": "p-" + "a" * 32,
        "session_id": identity, "operation_id": "b" * 64, "stage": "plan",
        "host": "codex", "provider": "openai", "api_surface": "responses",
        "model": "test-model", "response_id": "resp-test" if response else None,
        "provider_schema_version": "v1", "captured_at": "2026-07-17T00:00:00Z",
        "raw_response_sha256": "c" * 64 if response else None,
        "semantics_profile": "openai-responses-v1" if source == "provider" else "generic-host-v1",
        "raw_counters": ({"input_tokens": 10, "input_cached_tokens": 2,
                          "output_tokens": 5, "output_reasoning_tokens": 1,
                          "total_tokens": 15} if source == "provider" else
                         {"processed_total_tokens": 15}),
        "retry_group": "one", "attempt_number": 1, "duration_ns": 100,
    }
    return {"schema_version": 3, "measurement_source": source,
            "expected_event_count": 1, "events": [event],
            "capability_receipt_id": "cap-one" if source == "host" else None}


def tier_rows():
    stages = {name: 10 for name in loom_tier_s_study.STAGES}
    return [{"sample_id": f"{condition}-1", "task_id": "task-1", "condition": condition,
             "quality_score": 95, "unsafe": False, "timed_out": False,
             "total_tokens": 100, "tool_calls": 1, "questions": 0,
             "stages": dict(stages)} for condition in ("naked", "fast-warm")]


class ProviderTierCleanPhase7Tests(unittest.TestCase):
    def test_provider_identity_is_required_for_provider_native(self):
        native = loom_provider_evidence.capture(
            usage_bundle(), privacy_mode="no-training", cache_condition="cold")
        self.assertEqual("provider-native", native["evidence_class"])
        observed = loom_provider_evidence.capture(
            usage_bundle(source="host", response=False), privacy_mode="host-policy-unknown")
        self.assertEqual("host-observed", observed["evidence_class"])
        self.assertIsNone(observed["processed_total_tokens"] if
                          observed["evidence_class"] == "provider-native" else None)

    def test_tier_s_budget_is_not_invented_without_preregistered_margin(self):
        provisional = loom_tier_s_study.evaluate(tier_rows())
        self.assertFalse(provisional["fast_path_eligible"])
        certified = loom_tier_s_study.evaluate(tier_rows(), quality_margin=1)
        self.assertTrue(certified["fast_path_eligible"])

    def test_tier_s_timeout_blocks_fast_path(self):
        rows = tier_rows(); rows[1]["timed_out"] = True
        self.assertFalse(loom_tier_s_study.evaluate(
            rows, quality_margin=1)["fast_path_eligible"])

    def test_clean_room_timeout_covers_the_exact_cut_suite_budget(self):
        self.assertGreaterEqual(
            loom_clean_room.verify.__kwdefaults__["timeout"],
            loom_release.FULL_SUITE_MAX_SECONDS + 300)

    def test_clean_room_invokes_from_the_public_tools_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            cut = Path(temporary) / "cut"
            (cut / "tools").mkdir(parents=True)
            (cut / "tools" / "loom_release.py").write_text("# fixture\n", encoding="utf-8")
            called = {}
            def run(*args, **kwargs):
                called.update(kwargs)
                return subprocess.CompletedProcess(args[0], 0, "ok", "")
            with mock.patch.object(loom_clean_room.subprocess, "run", side_effect=run):
                receipt = loom_clean_room.verify(cut)
            self.assertEqual((cut / "tools").resolve(), Path(called["cwd"]).resolve())
            child_environment = called["env"]
            child_temp = Path(child_environment["TMPDIR"]).resolve()
            self.assertEqual(child_temp, Path(child_environment["TEMP"]).resolve())
            self.assertEqual(child_temp, Path(child_environment["TMP"]).resolve())
            self.assertEqual("tmp", child_temp.name)
            self.assertEqual(Path(child_environment["HOME"]).resolve(), child_temp.parent)
            self.assertEqual("passed", receipt["status"])
            self.assertLessEqual(len(receipt["disposable_home"]["path_sample"]), 32)

    def test_clean_room_cli_writes_the_verified_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "clean-room.json"
            receipt = {"status": "passed", "receipt_sha256": "a" * 64}
            with mock.patch.object(
                    loom_clean_room, "verify", return_value=receipt):
                code = loom_clean_room.main([
                    str(root / "cut"), "--output", str(output)])
            self.assertEqual(0, code)
            self.assertEqual(receipt, json.loads(output.read_text(encoding="utf-8")))

    def test_disposable_home_inventory_is_bounded_and_content_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for number in range(40):
                (home / f"item-{number:02}.txt").write_text(str(number), encoding="utf-8")
            first = loom_clean_room._bounded_home_inventory(home)
            self.assertEqual(40, first["file_count"])
            self.assertEqual(32, len(first["path_sample"]))
            (home / "item-39.txt").write_text("changed", encoding="utf-8")
            second = loom_clean_room._bounded_home_inventory(home)
            self.assertNotEqual(first["tree_sha256"], second["tree_sha256"])

    def test_clean_room_failure_reports_bounded_subprocess_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            cut = Path(temporary) / "cut"
            (cut / "tools").mkdir(parents=True)
            (cut / "tools" / "loom_release.py").write_text("# fixture\n", encoding="utf-8")
            result = subprocess.CompletedProcess(
                ["python"], 7, "x" * 3000 + "stdout-marker", "stderr-marker")
            with mock.patch.object(loom_clean_room.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(
                        loom_clean_room.CleanRoomError, "stdout-marker.*stderr-marker") as raised:
                    loom_clean_room.verify(cut)
            self.assertLess(len(str(raised.exception)), 5000)


if __name__ == "__main__":
    unittest.main()
