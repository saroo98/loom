"""Stable repeated-qualification workload outside product discovery."""

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import loom_cut_manifest
import loom_qualification_manifest
import loom_qualification_workload


class QualificationWorkloadTests(unittest.TestCase):
    def environment(self):
        return {
            "requested_label": "windows-2025",
            "image_os": "win25-vs2026", "image_version": "20260803.1",
            "os": "windows", "os_release": "2025",
            "os_version": "10.0.26100", "architecture": "x86_64",
            "python_implementation": "CPython", "python_version": "3.11.9",
            "workflow_path": ".github/workflows/qualification-quality.yml",
            "workflow_digest": "1" * 64,
            "action_manifest_digest": "2" * 64,
            "event_name": "workflow_dispatch", "run_id": "1",
            "run_attempt": "1",
        }

    def checked_in_inputs(self):
        root = Path(__file__).resolve().parents[1]
        boundary = json.loads((
            root / "contracts" / "release-qualification-boundary-v2.json"
        ).read_text(encoding="utf-8"))
        manifest = json.loads((
            root / "contracts" / "release-qualification-manifest-v2.json"
        ).read_text(encoding="utf-8"))
        manifest = loom_qualification_manifest.verify(root, boundary, manifest)
        return root, manifest

    def test_workload_is_outside_product_discovery_and_builds_minimal_cut(self):
        root, manifest = self.checked_in_inputs()
        product_modules = {
            path.stem for path in (root / "tools").glob("test_*.py")
        }
        self.assertFalse(any(name.startswith("test_qual_")
                             for name in product_modules))

        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            identity = loom_qualification_workload.build_fixture(
                fixture, manifest=manifest, root=root)
            self.assertEqual(
                identity["public_root_sha256"],
                loom_cut_manifest.verify(fixture)["root_sha256"])
            fixture_modules = {
                path.stem for path in (fixture / "tools").glob("test_*.py")
            }
            policy = loom_qualification_workload.load_policy(root)
            self.assertEqual(set(policy["modules"]), fixture_modules)
            self.assertFalse((fixture / "tools" / "loom_vault.py").exists())
            self.assertFalse((fixture / "tools" / "test_loom_vault_v11.py").exists())

    def test_unrelated_product_edit_does_not_change_workload_identity(self):
        root, manifest = self.checked_in_inputs()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            first = loom_qualification_workload.build_fixture(
                temporary / "first", manifest=manifest, root=root)
            copied = temporary / "repository"
            copied.mkdir()
            shutil.copytree(root / "qualification", copied / "qualification")
            (copied / "tools").mkdir()
            (copied / "tools" / "test_unrelated_product.py").write_text(
                "PRODUCT_ONLY = True\n", encoding="utf-8")
            second = loom_qualification_workload.build_fixture(
                temporary / "second", manifest=manifest, root=copied,
                mechanism_root=root)
            self.assertEqual(first, second)

            changed = copy.deepcopy(manifest)
            workload = copied / "qualification" / "workload-v2" \
                / "test_qual_general_b.py"
            workload.write_text(
                workload.read_text(encoding="utf-8") + "\n# semantic change\n",
                encoding="utf-8")
            third = loom_qualification_workload.build_fixture(
                temporary / "third", manifest=changed, root=copied,
                mechanism_root=root)
            self.assertNotEqual(
                first["workload_source_sha256"],
                third["workload_source_sha256"])

    def test_serial_and_isolated_shadow_cover_the_fixed_inventory_exactly(self):
        root, manifest = self.checked_in_inputs()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            fixture = temporary / "fixture"
            identity = loom_qualification_workload.build_fixture(
                fixture, manifest=manifest, root=root)
            policy = loom_qualification_workload.load_policy(root)
            profile = loom_qualification_workload.load_timing_profile(root)
            serial = loom_qualification_workload.run_serial(fixture, policy)
            shadow = loom_qualification_workload.run_shadow(
                fixture, policy, profile, temporary / "shadow",
                environment=self.environment(), fixture_identity=identity,
                logical_cpus=4, timeout=120)

            self.assertTrue(serial["successful"])
            self.assertEqual("matched", shadow["comparison"]["status"])
            self.assertEqual("certified", shadow["cell_certificate"]["status"])
            self.assertEqual(
                policy["expected_tests"],
                sorted(row["test"] for row in shadow[
                    "cell_certificate"]["outcomes"]))
            self.assertEqual(
                set(policy["modules"]),
                {row["module"] for row in shadow["inventory"]["modules"]})
            self.assertEqual(3, shadow["plan"]["max_parallel_workers"])
            self.assertEqual(
                ["test_qual_exclusive"],
                next(row["modules"] for row in shadow["plan"]["shards"]
                     if row["shard_id"] == "exclusive"))
            self.assertEqual(
                policy["policy_sha256"], shadow["workload_policy_sha256"])
            self.assertEqual(
                identity["workload_source_sha256"],
                shadow["workload_source_sha256"])
            self.assertTrue(all(
                receipt["runtime_roots_clean"]
                and receipt["mutation_clean"]
                and receipt["privacy_clean"]
                and receipt["operation"]["survivors_confirmed_zero"]
                for receipt in shadow["worker_receipts"]))

    def test_product_report_cannot_be_mislabelled_as_mechanism_workload(self):
        root, _manifest = self.checked_in_inputs()
        policy = loom_qualification_workload.load_policy(root)
        product_report = {
            "mode": "modules", "selected_modules": ["test_test_runner"],
            "successful": True, "failures": 0, "errors": 0, "skipped": 0,
            "capability_complete": True, "within_budget": True,
            "timings": [{
                "test": "test_test_runner.TestRunnerTests.test_fixture",
                "status": "passed", "seconds": 0.001,
            }],
        }
        with self.assertRaises(loom_qualification_workload.WorkloadError):
            loom_qualification_workload.validate_serial_report(
                product_report, policy)


if __name__ == "__main__":
    unittest.main()
