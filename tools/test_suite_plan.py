"""Deterministic inventory and shard-plan contracts for release assurance."""

import json
import tempfile
import unittest
from pathlib import Path

import loom_suite_plan


SUBJECT = {
    "repository": "https://github.com/saroo98/loom",
    "source_commit": "1" * 40,
    "source_tree_sha256": "2" * 64,
    "public_root_sha256": "3" * 64,
    "public_manifest_sha256": "5" * 64,
    "public_file_count": 117,
}
ENVIRONMENT = {
    "requested_label": "ubuntu-24.04",
    "image_os": "ubuntu24",
    "image_version": "20260801.1",
    "os": "linux",
    "os_release": "24.04", "os_version": "24.04.2",
    "architecture": "x86_64",
    "python_implementation": "CPython",
    "python_version": "3.13.7",
    "workflow_path": ".github/workflows/quality.yml",
    "workflow_digest": "a" * 64, "action_manifest_digest": "b" * 64,
    "event_name": "push", "run_id": "1", "run_attempt": "1",
}


class SuitePlanTests(unittest.TestCase):
    def test_inventory_is_complete_ordered_and_fails_on_import_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "test_beta.py").write_text(
                "import unittest\n"
                "class Beta(unittest.TestCase):\n"
                "    def test_two(self): pass\n",
                encoding="utf-8")
            (root / "test_alpha.py").write_text(
                "import unittest\n"
                "class Alpha(unittest.TestCase):\n"
                "    def test_one(self): pass\n",
                encoding="utf-8")
            inventory = loom_suite_plan.inventory(
                root, subject=SUBJECT, environment=ENVIRONMENT,
                harness_sha256="4" * 64)
            self.assertEqual(2, inventory["module_count"])
            self.assertEqual(2, inventory["test_count"])
            self.assertEqual(
                ["test_alpha", "test_beta"],
                [row["module"] for row in inventory["modules"]])
            self.assertEqual(
                ["test_alpha.Alpha.test_one"], inventory["modules"][0]["tests"])
            self.assertEqual(64, len(inventory["inventory_sha256"]))

            (root / "test_broken.py").write_text(
                "raise RuntimeError('not importable')\n", encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_suite_plan.SuitePlanError, "test discovery failed"):
                loom_suite_plan.inventory(
                    root, subject=SUBJECT, environment=ENVIRONMENT,
                    harness_sha256="4" * 64)

    def test_lpt_plan_is_stable_uses_p75_and_reserves_exclusive_lane(self):
        inventory = loom_suite_plan.seal_inventory({
            "schema_version": 1,
            "subject": SUBJECT,
            "environment": ENVIRONMENT,
            "harness_sha256": "4" * 64,
            "modules": [
                {"module": "test_alpha", "tests": ["test_alpha.T.test_a"]},
                {"module": "test_loom_mutation", "tests": [
                    "test_loom_mutation.T.test_mutation"]},
                {"module": "test_unknown", "tests": ["test_unknown.T.test_u"]},
                {"module": "test_aardvark", "tests": [
                    "test_aardvark.T.test_z"]},
            ],
            "module_count": 4,
            "test_count": 4,
        })
        profile = loom_suite_plan.seal_timing_profile({
            "schema_version": 1,
            "default_p75_microseconds": 500,
            "module_microseconds": {
                "test_alpha": 900,
                "test_loom_mutation": 800,
                "test_aardvark": 200,
            },
        })
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1,
            "authority_mode": "serial",
            "exclusive_modules": ["test_loom_mutation"],
        })

        first = loom_suite_plan.plan(
            inventory, timing_profile=profile, policy=policy,
            logical_cpus=4)
        second = loom_suite_plan.plan(
            json.loads(json.dumps(inventory)), timing_profile=profile,
            policy=policy, logical_cpus=4)

        self.assertEqual(first, second)
        self.assertEqual(3, first["max_parallel_workers"])
        self.assertEqual(
            ["test_loom_mutation"], first["shards"][0]["modules"])
        self.assertTrue(first["shards"][0]["exclusive"])
        general = first["shards"][1:]
        self.assertEqual(
            ["test_alpha"], general[0]["modules"])
        self.assertEqual(
            ["test_aardvark", "test_unknown"], general[1]["modules"])
        self.assertEqual(700, general[1]["estimated_microseconds"])
        self.assertEqual(
            sorted(general[1]["modules"]), general[1]["modules"])
        self.assertEqual(64, len(first["plan_sha256"]))

    def test_dynamic_budget_never_commits_an_os_specific_worker_count(self):
        inventory = loom_suite_plan.seal_inventory({
            "schema_version": 1,
            "subject": SUBJECT,
            "environment": ENVIRONMENT,
            "harness_sha256": "4" * 64,
            "modules": [
                {"module": "test_alpha", "tests": ["test_alpha.T.test_a"]},
                {"module": "test_beta", "tests": ["test_beta.T.test_b"]},
            ],
            "module_count": 2,
            "test_count": 2,
        })
        profile = loom_suite_plan.seal_timing_profile({
            "schema_version": 1, "default_p75_microseconds": 100,
            "module_microseconds": {},
        })
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": [],
        })
        one = loom_suite_plan.plan(
            inventory, timing_profile=profile, policy=policy,
            logical_cpus=1)
        eight = loom_suite_plan.plan(
            inventory, timing_profile=profile, policy=policy,
            logical_cpus=8)
        self.assertEqual(1, one["max_parallel_workers"])
        self.assertEqual(2, eight["max_parallel_workers"])
        self.assertNotIn("linux_workers", policy)
        self.assertNotIn("windows_workers", policy)
        self.assertNotIn("macos_workers", policy)


if __name__ == "__main__":
    unittest.main()
