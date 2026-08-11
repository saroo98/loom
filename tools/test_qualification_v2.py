"""Separated mechanism qualification and exact candidate evidence v2."""

import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import loom_qualification_manifest
import loom_qualification_v2
import loom_qualification_workload
import loom_lint
import loom_suite_certificate_core
import loom_suite_plan
import loom_suite_worker


class QualificationV2Tests(unittest.TestCase):
    def inputs(self):
        root = Path(__file__).resolve().parents[1]
        boundary = json.loads((
            root / "contracts" / "release-qualification-boundary-v2.json"
        ).read_text(encoding="utf-8"))
        manifest = json.loads((
            root / "contracts" / "release-qualification-manifest-v2.json"
        ).read_text(encoding="utf-8"))
        manifest = loom_qualification_manifest.verify(root, boundary, manifest)
        workload = loom_qualification_workload.load_policy(root)
        timing = loom_qualification_workload.load_timing_profile(root)
        authority = loom_suite_plan.load_authority_policy(
            root / "contracts" / "release-authority-policy-v2.json")
        return root, manifest, workload, timing, authority

    def evidence(self, manifest, workload, timing, *, consumer="quality",
                 label="ubuntu-latest", image_os="ubuntu24",
                 architecture="x86_64", python_minor="3.10", index=1,
                 event_name="workflow_dispatch", timing_digest=None):
        workflow = f".github/workflows/qualification-{consumer}.yml"
        environment = {
            "requested_label": label, "image_os": image_os,
            "image_version": f"202608{index:02d}.1", "os": (
                "windows" if label.startswith("windows") else
                "macos" if label.startswith("macos") else "linux"),
            "os_release": "fixture", "os_version": f"fixture-{index}",
            "architecture": architecture,
            "python_implementation": "CPython",
            "python_version": f"{python_minor}.{index}",
            "workflow_path": workflow, "workflow_digest": "a" * 64,
            "action_manifest_digest": "b" * 64,
            "event_name": event_name,
            "run_id": f"{consumer}-{label}-{python_minor}-{index}",
            "run_attempt": "1",
        }
        subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": f"{index:040x}",
            "source_tree_sha256": manifest["manifest_sha256"],
            "public_root_sha256": "c" * 64,
            "public_manifest_sha256": "d" * 64,
            "public_file_count": 32,
        }
        tests_by_module = {module: [] for module in workload["modules"]}
        for test_id in workload["expected_tests"]:
            tests_by_module[test_id.split(".", 1)[0]].append(test_id)
        inventory = loom_suite_plan.seal_inventory({
            "schema_version": 1, "subject": subject,
            "environment": environment, "harness_sha256": "e" * 64,
            "modules": [{"module": module, "tests": tests_by_module[module]}
                        for module in workload["modules"]],
            "module_count": len(workload["modules"]),
            "test_count": len(workload["expected_tests"]),
        })
        v1_profile = loom_suite_plan.seal_timing_profile({
            "schema_version": 1,
            "default_p75_microseconds": timing[
                "default_p75_microseconds"],
            "module_microseconds": timing["module_microseconds"],
        })
        v1_policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": workload["exclusive_modules"],
        })
        plan = loom_suite_plan.plan(
            inventory, timing_profile=v1_profile, policy=v1_policy,
            logical_cpus=4)
        receipts = []
        for shard in plan["shards"]:
            expected = sorted(
                test for module in shard["modules"]
                for test in tests_by_module[module])
            receipts.append(loom_suite_worker._seal({
                "schema_version": 1, "status": "passed",
                "primary_reason": None, "findings": [],
                "subject": subject, "environment": environment,
                "inventory_sha256": inventory["inventory_sha256"],
                "policy_sha256": v1_policy["policy_sha256"],
                "timing_profile_sha256": v1_profile["profile_sha256"],
                "plan_sha256": plan["plan_sha256"],
                "shard_id": shard["shard_id"],
                "exclusive": shard["exclusive"],
                "expected_modules": shard["modules"],
                "expected_tests": expected,
                "observed_tests": [
                    {"test": test, "status": "passed"} for test in expected],
                "test_count": len(expected), "failure_count": 0,
                "error_count": 0, "skip_count": 0,
                "duration_microseconds": 250 + index,
                "pre_manifest_sha256": subject["public_manifest_sha256"],
                "post_manifest_sha256": subject["public_manifest_sha256"],
                "mutation_clean": True, "privacy_clean": True,
                "runtime_roots_clean": True,
                "operation": {
                    "status": "passed", "returncode": 0,
                    "primary_failure": None,
                    "survivors_confirmed_zero": True,
                    "protected_roots_unchanged": True,
                    "network_isolation_proven": False,
                    "containment_provider": "fixture",
                    "receipt_sha256": f"{index + len(receipts) + 100:064x}",
                },
            }))
        cell = loom_suite_certificate_core.compile_cell(
            inventory, plan, receipts, policy=v1_policy)
        serial = {
            "schema_version": 1, "mode": "modules",
            "selected_modules": workload["modules"],
            "tests_run": len(workload["expected_tests"]),
            "failures": 0, "errors": 0, "skipped": 0,
            "elapsed_seconds": (900 + index) / 1_000_000,
            "elapsed_microseconds": 900 + index,
            "suppressed_stdout_chars": 0, "max_seconds": None,
            "within_budget": True, "capability_complete": True,
            "status": "passed", "successful": True,
            "skip_receipts": [], "failure_diagnostics": [],
            "timings": [{"test": test, "seconds": 0.0001, "status": "passed"}
                        for test in workload["expected_tests"]],
        }
        comparison = loom_suite_certificate_core.compare_shadow(serial, cell)
        shadow = {
            "schema_version": 2, "workload_kind": "mechanism-v2",
            "workload_policy_sha256": workload["policy_sha256"],
            "timing_profile_sha256": timing["profile_sha256"]
            if timing_digest is None else timing_digest,
            "mechanism_manifest_sha256": manifest["manifest_sha256"],
            "workload_source_sha256": workload["workload_source_sha256"],
            "fixture_sha256": "f" * 64, "serial_report": serial,
            "inventory": inventory, "plan": plan,
            "worker_receipts": receipts, "cell_certificate": cell,
            "comparison": comparison,
        }
        context = {
            "consumer": consumer,
            "qualification_workflow_path": workflow,
            "qualification_workflow_digest": environment["workflow_digest"],
            "action_manifest_digest": environment["action_manifest_digest"],
            "repository_source_tree_sha256": f"{index + 500:064x}",
        }
        return serial, shadow, comparison, context

    def observation(self, manifest, workload, timing, **kwargs):
        serial, shadow, comparison, context = self.evidence(
            manifest, workload, timing, **kwargs)
        return loom_qualification_v2.compile_observation(
            serial, shadow, comparison, manifest=manifest,
            workload=workload, context=context)

    def test_observation_reverifies_closed_evidence_and_allows_product_tree_change(self):
        _root, manifest, workload, timing, _authority = self.inputs()
        first = self.observation(
            manifest, workload, timing, index=1)
        second = self.observation(
            manifest, workload, timing, index=2)
        self.assertNotEqual(first["source_commit"], second["source_commit"])
        self.assertNotEqual(
            first["repository_source_tree_sha256"],
            second["repository_source_tree_sha256"])
        self.assertEqual(
            first["mechanism_manifest_sha256"],
            second["mechanism_manifest_sha256"])
        self.assertEqual(
            first, loom_qualification_v2.verify_observation(
                first, manifest=manifest, workload=workload))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "qualification-observation", first,
            "release-qualification-observation-v2.schema.json")
        self.assertEqual([], report.errors)
        forged = copy.deepcopy(first)
        forged["mechanism_manifest_sha256"] = "0" * 64
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_observation(
                forged, manifest=manifest, workload=workload)

    def test_family_requires_ten_unique_observations_and_reports_honest_statistics(self):
        _root, manifest, workload, timing, _authority = self.inputs()
        observations = [self.observation(
            manifest, workload, timing, index=index)
            for index in range(1, 11)]
        family = loom_qualification_v2.compile_family(
            observations, manifest=manifest, workload=workload)
        self.assertEqual(10, family["observation_count"])
        self.assertEqual(910, family["serial_observed_max_microseconds"])
        self.assertNotIn("p95", json.dumps(family).casefold())
        self.assertEqual(
            family, loom_qualification_v2.verify_family(
                family, manifest=manifest, workload=workload))
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_family(
                observations[:9], manifest=manifest, workload=workload)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_family(
                observations[:9] + [observations[0]],
                manifest=manifest, workload=workload)

        mixed_timing = list(observations)
        mixed_timing[-1] = self.observation(
            manifest, workload, timing, index=11, timing_digest="7" * 64)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_family(
                mixed_timing, manifest=manifest, workload=workload)

    def test_observation_transport_is_bounded_strict_and_canonical(self):
        _root, manifest, workload, timing, _authority = self.inputs()
        observation = self.observation(manifest, workload, timing, index=1)
        reordered = dict(reversed(list(observation.items())))
        self.assertEqual(
            observation,
            loom_qualification_v2.verify_observation(
                reordered, manifest=manifest, workload=workload))

        unknown = dict(observation, unexpected=True)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_observation(
                unknown, manifest=manifest, workload=workload)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "observation.json"
            valid.write_text(
                json.dumps(observation, indent=2), encoding="utf-8")
            self.assertEqual(
                observation,
                loom_qualification_v2.load_observation(
                    valid, manifest=manifest, workload=workload))

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":2,"schema_version":2}',
                encoding="utf-8")
            with self.assertRaises(loom_qualification_v2.QualificationV2Error):
                loom_qualification_v2.load_observation(
                    duplicate, manifest=manifest, workload=workload)

            invalid_utf8 = root / "invalid-utf8.json"
            invalid_utf8.write_bytes(b"\xff")
            with self.assertRaises(loom_qualification_v2.QualificationV2Error):
                loom_qualification_v2.load_observation(
                    invalid_utf8, manifest=manifest, workload=workload)

            oversize = root / "oversize.json"
            oversize.write_bytes(b" " * 65)
            with mock.patch.object(
                    loom_qualification_v2, "MAX_OBSERVATION_BYTES", 64):
                with self.assertRaises(
                        loom_qualification_v2.QualificationV2Error):
                    loom_qualification_v2.load_observation(
                        oversize, manifest=manifest, workload=workload)

    def test_observation_rejects_untrusted_execution_identity(self):
        _root, manifest, workload, timing, _authority = self.inputs()
        serial, shadow, comparison, context = self.evidence(
            manifest, workload, timing, index=1, event_name="pull_request")
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_observation(
                serial, shadow, comparison, manifest=manifest,
                workload=workload, context=context)

        serial, shadow, comparison, context = self.evidence(
            manifest, workload, timing, index=2)
        context["action_manifest_digest"] = "9" * 64
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_observation(
                serial, shadow, comparison, manifest=manifest,
                workload=workload, context=context)

        serial, shadow, comparison, context = self.evidence(
            manifest, workload, timing, consumer="quality",
            label="ubuntu-24.04", index=3)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_observation(
                serial, shadow, comparison, manifest=manifest,
                workload=workload, context=context)

    def test_observation_rejects_nested_unknown_fields(self):
        _root, manifest, workload, timing, _authority = self.inputs()
        serial, shadow, _comparison, context = self.evidence(
            manifest, workload, timing, index=1)
        serial = dict(serial, raw_exception_text="must-not-cross")
        shadow["serial_report"] = serial
        comparison = loom_suite_certificate_core.compare_shadow(
            serial, shadow["cell_certificate"])
        shadow["comparison"] = comparison
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_observation(
                serial, shadow, comparison, manifest=manifest,
                workload=workload, context=context)

    def test_observation_cli_revalidates_current_graph(self):
        root, manifest, workload, timing, _authority = self.inputs()
        observation = self.observation(manifest, workload, timing, index=1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = loom_qualification_v2.main([
                    "verify-observation", "--root", str(root),
                    "--observation", str(path),
                ])
            self.assertEqual(0, result)
            self.assertEqual(
                observation["observation_sha256"],
                json.loads(output.getvalue())["observation_sha256"])

    def test_complete_mechanism_record_requires_all_families_faults_and_current_graph(self):
        _root, manifest, workload, timing, authority = self.inputs()
        labels = {
            "quality": (
                ("ubuntu-latest", "ubuntu24", "x86_64"),
                ("macos-latest", "macos-26", "arm64"),
                ("windows-latest", "win25-vs2026", "x86_64"),
            ),
            "compatibility": (
                ("ubuntu-24.04", "ubuntu24", "x86_64"),
                ("macos-15", "macos-15", "arm64"),
                ("windows-2025", "win25-vs2026", "x86_64"),
            ),
        }
        families = []
        index = 1
        for consumer, environments in labels.items():
            for label, image_os, architecture in environments:
                for python_minor in ("3.10", "3.11", "3.12", "3.13", "3.14"):
                    observations = []
                    for sequence in range(1, 11):
                        observations.append(self.observation(
                            manifest, workload, timing, consumer=consumer,
                            label=label, image_os=image_os,
                            architecture=architecture,
                            python_minor=python_minor,
                            index=index * 100 + sequence))
                    families.append(loom_qualification_v2.compile_family(
                        observations, manifest=manifest, workload=workload))
                    index += 1
        faults = [loom_qualification_v2.compile_fault_receipt(
            platform, {code: True for code in loom_qualification_v2.FAULT_CODES},
            manifest=manifest, workload=workload)
            for platform in ("linux", "macos", "windows")]
        record = loom_qualification_v2.compile_mechanism(
            families, faults, policy=authority, manifest=manifest,
            workload=workload)
        current = [loom_qualification_v2.family_identity(row) for row in families]
        self.assertEqual(30, record["family_count"])
        self.assertEqual(
            record, loom_qualification_v2.verify_mechanism(
                record, policy=authority, manifest=manifest,
                workload=workload, current_families=current))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "mechanism-qualification", record,
            "release-mechanism-qualification-v2.schema.json")
        self.assertEqual([], report.errors)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_mechanism(
                families[:-1], faults, policy=authority, manifest=manifest,
                workload=workload)
        stale = copy.deepcopy(manifest)
        stale["nodes"][0]["sha256"] = "0" * 64
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_mechanism(
                record, policy=authority, manifest=stale,
                workload=workload, current_families=current)

        changed_family = copy.deepcopy(current)
        changed_family[0]["image_os"] = "ubuntu26"
        changed_family[0]["family_id"] = loom_suite_plan.digest({
            key: changed_family[0][key]
            for key in loom_qualification_v2.FAMILY_FIELDS
            if key != "family_id"
        })
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_mechanism(
                record, policy=authority, manifest=manifest,
                workload=workload, current_families=changed_family)


if __name__ == "__main__":
    unittest.main()
