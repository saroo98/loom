"""Separated mechanism qualification and exact candidate evidence v2."""

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import loom_qualification_manifest
import loom_qualification_v2
import loom_qualification_workload
import loom_exact_cut_receipt
import loom_lint
import loom_platform_probe
import loom_release_suite
import loom_suite_certificate_core
import loom_suite_plan
import loom_suite_worker
import loom_subject_identity


class QualificationV2Tests(unittest.TestCase):
    @staticmethod
    def git(root, *args):
        return subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True,
            check=True).stdout.strip()

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
                 event_name="workflow_dispatch", timing_digest=None,
                 source_commit=None, source_tree_sha256=None,
                 public_root_sha256=None, public_manifest_sha256=None,
                 workflow_path=None, run_id=None):
        workflow = (f".github/workflows/qualification-{consumer}.yml"
                    if workflow_path is None else workflow_path)
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
            "run_id": (f"{consumer}-{label}-{python_minor}-{index}"
                       if run_id is None else run_id),
            "run_attempt": "1",
        }
        subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": f"{index:040x}" if source_commit is None
            else source_commit,
            "source_tree_sha256": manifest["manifest_sha256"]
            if source_tree_sha256 is None else source_tree_sha256,
            "public_root_sha256": "c" * 64 if public_root_sha256 is None
            else public_root_sha256,
            "public_manifest_sha256": "d" * 64
            if public_manifest_sha256 is None else public_manifest_sha256,
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

    def candidate_matrix_bundle(self, manifest, workload, timing, *,
                                consumer, source_commit, source_tree_sha256,
                                public_root_sha256, start_index=1):
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
        cells = []
        receipts = []
        clean_suite = None
        index = start_index
        for label, image_os, architecture in labels[consumer]:
            for python_minor in ("3.10", "3.11", "3.12", "3.13", "3.14"):
                serial, shadow, _comparison, _context = self.evidence(
                    manifest, workload, timing, consumer=consumer,
                    label=label, image_os=image_os,
                    architecture=architecture, python_minor=python_minor,
                    index=index, event_name="pull_request",
                    source_commit=source_commit,
                    source_tree_sha256=source_tree_sha256,
                    public_root_sha256=public_root_sha256,
                    workflow_path=f".github/workflows/{consumer}.yml")
                cell = shadow["cell_certificate"]
                environment_body = {
                    "evidence_class": "ci-reproduced", **cell["environment"],
                }
                environment = {
                    **environment_body,
                    "environment_sha256": loom_suite_plan.digest(
                        environment_body),
                }
                normalized_suite = {
                    "schema_version": 2, "passed": True,
                    "capability_complete": True,
                    "capability_status": "complete", "returncode": 0,
                    "primary_failure_sha256": None,
                    "operation_receipt_sha256": f"{index + 800:064x}",
                    "elapsed_microseconds": serial["elapsed_microseconds"],
                    "tests_run": serial["tests_run"], "failure_count": 0,
                    "error_count": 0, "failed_tests": [],
                    "skip_receipts": [],
                    "timings": [{
                        "test": row["test"], "status": row["status"],
                        "duration_microseconds": int(round(
                            row["seconds"] * 1_000_000)),
                    } for row in serial["timings"]],
                    "binding": {
                        "source_commit": source_commit,
                        "public_root_sha256": public_root_sha256,
                        "environment": environment,
                        "platform": image_os + ":" + environment["image_version"],
                        "architecture": architecture,
                        "python": environment["python_version"],
                        "runner": environment["environment_sha256"],
                    },
                }
                receipt = loom_exact_cut_receipt.seal_receipt({
                    "schema_version": 2, "status": "verified",
                    "platform": environment["os"],
                    "architecture": architecture,
                    "python": environment["python_version"],
                    "source_commit": source_commit,
                    "build_root_sha256": public_root_sha256,
                    "verified_root_sha256": public_root_sha256,
                    "public_manifest_sha256": "d" * 64,
                    "public_file_count": 32, "suite": normalized_suite,
                    "error_type": None, "error_sha256": None,
                    "operation_id": f"candidate-{consumer}-{index}",
                    "environment": environment,
                })
                cells.append(cell)
                receipts.append(receipt)
                if consumer == "compatibility" \
                        and label == "ubuntu-24.04" \
                        and python_minor == "3.11":
                    clean_suite = normalized_suite
                index += 1
        matrix = loom_suite_certificate_core.compile_matrix(
            cells, consumer=consumer,
            required_environments=[row["environment_sha256"] for row in cells])
        clean_room = None
        if consumer == "compatibility":
            clean_body = {
                "schema_version": 1, "evidence_class": "mechanical-local",
                "status": "passed", "subject_sha256": "7" * 64,
                "returncode": 0, "stdout_sha256": "8" * 64,
                "stderr_sha256": "9" * 64,
                "disposable_home": {
                    "file_count": 0, "bytes": 0,
                    "tree_sha256": "a" * 64, "path_sample": [],
                },
                "maintainer_state_loaded": False,
                "network_isolation_proven": False,
                "rust_toolchain": {
                    "rustc_sha256": "b" * 64, "cargo_sha256": "c" * 64,
                    "rustc_version_sha256": "d" * 64,
                    "cargo_version_sha256": "e" * 64,
                    "locked_dependencies_vendored": True,
                    "dependency_provisioning_network_blocked": False,
                },
                "operation_receipt_sha256": "f" * 64,
                "containment_provider": "linux-process-group",
                "verification_mode": "serial-evidence",
                "suite_certificate_sha256": None,
                "suite_evidence_sha256": loom_suite_plan.digest(clean_suite),
                "limitations": [
                    "Standard-library execution does not prove host-level network isolation.",
                    "Locked public Rust dependencies may be fetched into the disposable workspace before the verification subprocess is forced offline.",
                ],
            }
            clean_room = {
                "receipt": {**clean_body, "receipt_sha256":
                            loom_suite_plan.digest(clean_body)},
                "suite": clean_suite,
            }
        return {
            "schema_version": 2, "consumer": consumer,
            "exact_cut_receipts": receipts,
            "matrix_certificate": matrix, "clean_room": clean_room,
        }

    @staticmethod
    def native_receipts(source_commit):
        platforms = {
            "linux-arm64": ("ubuntu-24.04-arm", "ubuntu24", "linux", "arm64"),
            "linux-x64": ("ubuntu-24.04", "ubuntu24", "linux", "x86_64"),
            "macos-arm64": ("macos-15", "macos-15", "macos", "arm64"),
            "macos-x64": ("macos-15-intel", "macos-15", "macos", "x86_64"),
            "windows-arm64": ("windows-11-arm", "win11", "windows", "arm64"),
            "windows-x64": ("windows-2025", "win25-vs2026", "windows", "x86_64"),
        }
        values = []
        for index, (platform, identity) in enumerate(platforms.items(), 1):
            label, image_os, os_name, architecture = identity
            environment_body = {
                "evidence_class": "ci-reproduced", "requested_label": label,
                "image_os": image_os, "image_version": f"native-{index}",
                "os": os_name, "os_release": "fixture",
                "os_version": "fixture", "architecture": architecture,
                "python_implementation": "CPython",
                "python_version": "3.11.9",
                "workflow_path": ".github/workflows/build-helper.yml",
                "workflow_digest": "3" * 64,
                "action_manifest_digest": "4" * 64,
                "event_name": "pull_request", "run_id": "native-run",
                "run_attempt": "1",
            }
            environment = {
                **environment_body,
                "environment_sha256": loom_suite_plan.digest(environment_body),
            }
            provenance = {
                "schema_version": 1,
                "repository": "https://github.com/saroo98/loom",
                "commit": source_commit, "platform": platform,
                "binary_sha256": f"{index:064x}",
                "source_sha256": "1" * 64,
                "cargo_lock_sha256": "2" * 64,
                "independent_build": True,
                "builder": {
                    "id": "github-actions-native-helper",
                    "run_id": "native-run",
                },
            }
            provenance_sha256 = hashlib.sha256(
                json.dumps(provenance, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8") + b"\n").hexdigest()
            body = {
                "schema_version": 2, "platform": platform,
                "source_commit": source_commit,
                "binary_sha256": f"{index:064x}",
                "rebuild_sha256": f"{index:064x}",
                "source_sha256": "1" * 64,
                "cargo_lock_sha256": "2" * 64,
                "sbom_sha256": f"{index + 10:064x}",
                "provenance_sha256": provenance_sha256,
                "environment_sha256": environment["environment_sha256"],
                "workflow_digest": "3" * 64,
                "action_manifest_digest": "4" * 64,
            }
            values.append({
                "receipt": {**body, "receipt_sha256":
                            loom_suite_plan.digest(body)},
                "environment": environment, "provenance": provenance,
            })
        return values

    @staticmethod
    def fault_receipts(manifest, workload):
        identities = {
            "linux": ("ubuntu-24.04", "ubuntu24", "x86_64"),
            "macos": ("macos-15", "macos-15", "arm64"),
            "windows": ("windows-2025", "win25-vs2026", "x86_64"),
        }
        receipts = []
        for index, (platform, identity) in enumerate(identities.items(), 1):
            label, image_os, architecture = identity
            body = {
                "evidence_class": "ci-reproduced",
                "requested_label": label, "image_os": image_os,
                "image_version": f"fault-{index}", "os": platform,
                "os_release": "fixture", "os_version": "fixture",
                "architecture": architecture,
                "python_implementation": "CPython",
                "python_version": "3.11.9",
                "workflow_path": ".github/workflows/qualification-faults.yml",
                "workflow_digest": "a" * 64,
                "action_manifest_digest": "b" * 64,
                "event_name": "workflow_dispatch",
                "run_id": f"fault-{platform}", "run_attempt": "1",
            }
            environment = {
                **body, "environment_sha256": loom_suite_plan.digest(body)}
            results = {
                code: f"{index * 100 + offset:064x}"
                for offset, code in enumerate(
                    loom_qualification_v2.FAULT_CODES, 1)
            }
            receipts.append(loom_qualification_v2.compile_fault_receipt(
                environment, results, manifest=manifest,
                workload=workload))
        return receipts

    def mechanism_record(self, manifest, workload, timing, authority):
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
                for python_minor in (
                        "3.10", "3.11", "3.12", "3.13", "3.14"):
                    observations = [self.observation(
                        manifest, workload, timing, consumer=consumer,
                        label=label, image_os=image_os,
                        architecture=architecture,
                        python_minor=python_minor,
                        index=index * 100 + sequence)
                        for sequence in range(1, 11)]
                    families.append(loom_qualification_v2.compile_family(
                        observations, manifest=manifest, workload=workload))
                    index += 1
        faults = self.fault_receipts(manifest, workload)
        record = loom_qualification_v2.compile_mechanism(
            families, faults, policy=authority, manifest=manifest,
            workload=workload)
        return record, families

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

    def test_mechanism_transport_rejects_95mb_plus_one_before_json_parse(self):
        self.assertEqual(95_000_000, loom_qualification_v2.MAX_MECHANISM_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mechanism.json"
            with path.open("wb") as stream:
                stream.truncate(
                    loom_qualification_v2.MAX_MECHANISM_BYTES + 1)
            with mock.patch.object(
                    loom_qualification_v2.json, "loads",
                    side_effect=AssertionError("JSON parser must not run")) \
                    as parser:
                with self.assertRaises(
                        loom_qualification_v2.QualificationV2Error):
                    loom_qualification_v2._load_json(
                        path, loom_qualification_v2.MAX_MECHANISM_BYTES)
            parser.assert_not_called()

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
        record, families = self.mechanism_record(
            manifest, workload, timing, authority)
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
                families[:-1], record["fault_receipts"], policy=authority,
                manifest=manifest,
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

    def test_exact_candidate_admission_rebinds_product_bytes_without_resetting_mechanism(self):
        _root, manifest, workload, timing, authority = self.inputs()
        commit = "5" * 40
        source_tree = "6" * 64
        public_root = "7" * 64
        quality = self.candidate_matrix_bundle(
            manifest, workload, timing, consumer="quality",
            source_commit=commit, source_tree_sha256=source_tree,
            public_root_sha256=public_root, start_index=1)
        compatibility = self.candidate_matrix_bundle(
            manifest, workload, timing, consumer="compatibility",
            source_commit=commit, source_tree_sha256=source_tree,
            public_root_sha256=public_root, start_index=101)
        native = self.native_receipts(commit)
        admission = loom_qualification_v2.compile_candidate(
            quality, compatibility, native, mechanism=None, policy=authority,
            manifest=manifest)
        self.assertEqual("admitted", admission["status"])
        self.assertEqual(30, admission["cell_count"])
        self.assertEqual(6, len(admission["native_subjects"]))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "candidate-admission", admission,
            "release-candidate-admission-v2.schema.json")
        self.assertEqual([], report.errors)
        self.assertEqual(
            admission, loom_qualification_v2.verify_candidate(
                admission, expected_commit=commit,
                expected_tree=source_tree, expected_public_root=public_root,
                mechanism=None, policy=authority, manifest=manifest))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate-admission.json"
            path.write_text(json.dumps(admission), encoding="utf-8")
            self.assertEqual(
                admission, loom_qualification_v2.load_candidate(
                    path, expected_commit=commit, expected_tree=source_tree,
                    expected_public_root=public_root, mechanism=None,
                    policy=authority, manifest=manifest))
        suite = loom_release_suite.certify_candidate_admission(
            admission, mechanism=None, authority_policy=authority,
            manifest=manifest, workload=None, expected_commit=commit,
            expected_tree=source_tree, expected_root=public_root)
        self.assertEqual(
            suite, loom_release_suite.verify_candidate_admission(
                suite, admission=admission, mechanism=None,
                authority_policy=authority, manifest=manifest, workload=None,
                expected_commit=commit, expected_tree=source_tree,
                expected_root=public_root))
        missing_cell = copy.deepcopy(quality)
        missing_cell["exact_cut_receipts"].pop()
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_candidate(
                missing_cell, compatibility, native, mechanism=None,
                policy=authority, manifest=manifest)
        mixed_run = copy.deepcopy(quality)
        mixed_run["exact_cut_receipts"][0] = copy.deepcopy(
            compatibility["exact_cut_receipts"][0])
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_candidate(
                mixed_run, compatibility, native, mechanism=None,
                policy=authority, manifest=manifest)

        corrected_commit = "8" * 40
        corrected_tree = "9" * 64
        corrected_root = "a" * 64
        corrected_quality = self.candidate_matrix_bundle(
            manifest, workload, timing, consumer="quality",
            source_commit=corrected_commit,
            source_tree_sha256=corrected_tree,
            public_root_sha256=corrected_root, start_index=201)
        corrected_compatibility = self.candidate_matrix_bundle(
            manifest, workload, timing, consumer="compatibility",
            source_commit=corrected_commit,
            source_tree_sha256=corrected_tree,
            public_root_sha256=corrected_root, start_index=301)
        corrected = loom_qualification_v2.compile_candidate(
            corrected_quality, corrected_compatibility,
            self.native_receipts(corrected_commit), mechanism=None,
            policy=authority, manifest=manifest)
        self.assertNotEqual(
            admission["candidate_admission_sha256"],
            corrected["candidate_admission_sha256"])
        self.assertEqual(
            manifest["manifest_sha256"],
            corrected["mechanism_manifest_sha256"])
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_candidate(
                admission, expected_commit=corrected_commit,
                expected_tree=corrected_tree,
                expected_public_root=corrected_root,
                mechanism=None, policy=authority, manifest=manifest)

    def test_certificate_candidate_requires_current_mechanism_and_exact_native_evidence(self):
        _root, manifest, workload, timing, serial_authority = self.inputs()
        mechanism, _families = self.mechanism_record(
            manifest, workload, timing, serial_authority)
        certificate_authority = loom_suite_plan.seal_authority_policy({
            key: ("certificate" if key == "authority_mode" else value)
            for key, value in serial_authority.items()
            if key != "policy_sha256"
        })
        commit = "b" * 40
        source_tree = "c" * 64
        public_root = "d" * 64
        quality = self.candidate_matrix_bundle(
            manifest, workload, timing, consumer="quality",
            source_commit=commit, source_tree_sha256=source_tree,
            public_root_sha256=public_root, start_index=401)
        compatibility = self.candidate_matrix_bundle(
            manifest, workload, timing, consumer="compatibility",
            source_commit=commit, source_tree_sha256=source_tree,
            public_root_sha256=public_root, start_index=501)
        admission = loom_qualification_v2.compile_candidate(
            quality, compatibility, self.native_receipts(commit),
            mechanism=mechanism, policy=certificate_authority,
                        manifest=manifest, workload=workload)
        self.assertEqual(
            mechanism["qualification_sha256"],
            admission["mechanism_qualification_sha256"])
        self.assertEqual(
            admission, loom_qualification_v2.verify_candidate(
                admission, expected_commit=commit,
                expected_tree=source_tree, expected_public_root=public_root,
                mechanism=mechanism, policy=certificate_authority,
                manifest=manifest, workload=workload))

        serial_rollback = loom_qualification_v2.compile_candidate(
            quality, compatibility, self.native_receipts(commit),
            mechanism=None, policy=serial_authority, manifest=manifest)
        self.assertEqual("serial", serial_rollback["authority_mode"])
        self.assertIsNone(
            serial_rollback["mechanism_qualification_sha256"])
        self.assertEqual(
            admission["source_commit"], serial_rollback["source_commit"])
        self.assertEqual(
            admission["repository_source_tree_sha256"],
            serial_rollback["repository_source_tree_sha256"])
        self.assertEqual(
            serial_rollback, loom_qualification_v2.verify_candidate(
                serial_rollback, expected_commit=commit,
                expected_tree=source_tree, expected_public_root=public_root,
                mechanism=None, policy=serial_authority,
                manifest=manifest, workload=None))
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_candidate(
                admission, expected_commit=commit,
                expected_tree=source_tree, expected_public_root=public_root,
                mechanism=None, policy=serial_authority,
                manifest=manifest, workload=None)

        damaged_native = self.native_receipts(commit)
        damaged_native[0]["receipt"]["rebuild_sha256"] = "0" * 64
        damaged_body = {
            key: value for key, value in damaged_native[0]["receipt"].items()
            if key != "receipt_sha256"
        }
        damaged_native[0]["receipt"]["receipt_sha256"] = \
            loom_suite_plan.digest(damaged_body)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_candidate(
                quality, compatibility, damaged_native,
                mechanism=mechanism, policy=certificate_authority,
                manifest=manifest, workload=workload)

        wrong_runner = self.native_receipts(commit)
        environment = wrong_runner[0]["environment"]
        environment["requested_label"] = "ubuntu-latest"
        environment_body = {
            key: value for key, value in environment.items()
            if key != "environment_sha256"
        }
        environment["environment_sha256"] = loom_suite_plan.digest(
            environment_body)
        wrong_runner[0]["receipt"]["environment_sha256"] = environment[
            "environment_sha256"]
        receipt_body = {
            key: value for key, value in wrong_runner[0]["receipt"].items()
            if key != "receipt_sha256"
        }
        wrong_runner[0]["receipt"]["receipt_sha256"] = \
            loom_suite_plan.digest(receipt_body)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_candidate(
                quality, compatibility, wrong_runner,
                mechanism=mechanism, policy=certificate_authority,
                manifest=manifest, workload=workload)

    def test_qualification_batch_requires_one_complete_single_run_topology(self):
        _root, manifest, workload, timing, _authority = self.inputs()
        observations = []
        index = 1
        labels = (
            ("ubuntu-latest", "ubuntu24", "x86_64"),
            ("macos-latest", "macos-26", "arm64"),
            ("windows-latest", "win25-vs2026", "x86_64"),
        )
        for label, image_os, architecture in labels:
            for python_minor in loom_qualification_v2.PYTHON_MINORS:
                serial, shadow, comparison, context = self.evidence(
                    manifest, workload, timing, consumer="quality",
                    label=label, image_os=image_os,
                    architecture=architecture, python_minor=python_minor,
                    index=index, source_commit="5" * 40,
                    source_tree_sha256=manifest["manifest_sha256"],
                    run_id="quality-run")
                context["repository_source_tree_sha256"] = "6" * 64
                observations.append(loom_qualification_v2.compile_observation(
                    serial, shadow, comparison, manifest=manifest,
                    workload=workload, context=context))
                index += 1
        batch = loom_qualification_v2.compile_batch(
            observations, consumer="quality", manifest=manifest,
            workload=workload)
        self.assertEqual("certified", batch["status"])
        self.assertEqual(15, batch["observation_count"])
        self.assertEqual(
            batch, loom_qualification_v2.verify_batch(
                batch, manifest=manifest, workload=workload))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "qualification-batch", batch,
            "release-qualification-batch-v2.schema.json")
        self.assertEqual([], report.errors)
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            paths = []
            for number, observation in enumerate(observations):
                path = temporary / f"observation-{number}.json"
                path.write_text(json.dumps(observation), encoding="utf-8")
                paths.append(path)
            output = temporary / "batch.json"
            arguments = [
                "compile-batch", "--root", str(_root),
                "--consumer", "quality", "--output", str(output),
            ]
            for path in paths:
                arguments.extend(("--observation", str(path)))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_qualification_v2.main(arguments))
            self.assertEqual(
                batch, json.loads(output.read_text(encoding="utf-8")))
        for damaged in (
                observations[:-1],
                observations + [copy.deepcopy(observations[0])]):
            with self.assertRaises(loom_qualification_v2.QualificationV2Error):
                loom_qualification_v2.compile_batch(
                    damaged, consumer="quality", manifest=manifest,
                    workload=workload)
        mixed = copy.deepcopy(observations)
        serial, shadow, comparison, context = self.evidence(
            manifest, workload, timing, consumer="quality",
            label="ubuntu-latest", image_os="ubuntu24",
            architecture="x86_64", python_minor="3.10", index=99,
            source_commit="5" * 40,
            source_tree_sha256=manifest["manifest_sha256"],
            run_id="different-run")
        context["repository_source_tree_sha256"] = "6" * 64
        mixed[0] = loom_qualification_v2.compile_observation(
            serial, shadow, comparison, manifest=manifest,
            workload=workload, context=context)
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.compile_batch(
                mixed, consumer="quality", manifest=manifest,
                workload=workload)

    def test_run_observation_uses_only_manual_fixed_workload_identity(self):
        root, manifest, workload, _timing, _authority = self.inputs()
        commit = "1" * 40
        environment = loom_platform_probe.release_environment(
            requested_label="windows-latest", image_os="local-windows",
            image_version="test", workflow_path=(
                ".github/workflows/qualification-quality.yml"),
            workflow_digest="a" * 64, action_manifest_digest="b" * 64,
            event_name="workflow_dispatch", run_id="fixture-run",
            run_attempt="1")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                loom_qualification_v2.loom_platform_probe,
                "release_environment", return_value=environment), \
                mock.patch.object(
                    loom_qualification_v2.loom_subject_identity,
                    "git_tree_inventory", return_value={
                        "tree_sha256": manifest["manifest_sha256"]}):
            output = Path(temporary) / "observation.json"
            observation = loom_qualification_v2.run_observation(
                root, consumer="quality", output=output,
                source_commit=commit, logical_cpus=2, timeout=60)
            self.assertEqual(
                observation, loom_qualification_v2.load_observation(
                    output, manifest=manifest, workload=workload))
        self.assertEqual("mechanism-v2", observation["workload_kind"])
        self.assertEqual("workflow_dispatch",
                         observation["environment"]["event_name"])
        self.assertEqual(workload["expected_tests"], sorted(
            row["test"] for row in observation["shadow"][
                "cell_certificate"]["outcomes"]))

    def test_candidate_cli_assembles_only_closed_matrix_and_native_artifacts(self):
        root, manifest, workload, timing, authority = self.inputs()
        commit = "6" * 40
        source_tree = "7" * 64
        public_root = "8" * 64
        bundles = {
            consumer: self.candidate_matrix_bundle(
                manifest, workload, timing, consumer=consumer,
                source_commit=commit, source_tree_sha256=source_tree,
                public_root_sha256=public_root,
                start_index=1 if consumer == "quality" else 101)
            for consumer in ("quality", "compatibility")
        }
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            bundle_paths = {}
            for consumer, bundle in bundles.items():
                inputs = temporary / consumer
                inputs.mkdir()
                receipt_paths = []
                for index, receipt in enumerate(
                        bundle["exact_cut_receipts"], 1):
                    path = inputs / f"exact-cut-{index}.json"
                    path.write_text(json.dumps(receipt), encoding="utf-8")
                    receipt_paths.append(path)
                matrix = inputs / "matrix.json"
                matrix.write_text(
                    json.dumps(bundle["matrix_certificate"]),
                    encoding="utf-8")
                output = temporary / f"{consumer}-bundle.json"
                arguments = [
                    "compile-candidate-bundle", "--root", str(root),
                    "--consumer", consumer, "--matrix", str(matrix),
                    "--output", str(output),
                ]
                for path in receipt_paths:
                    arguments.extend(("--exact-receipt", str(path)))
                if consumer == "compatibility":
                    clean = inputs / "clean-room.json"
                    clean.write_text(json.dumps(
                        bundle["clean_room"]["receipt"]), encoding="utf-8")
                    arguments.extend(("--clean-room", str(clean)))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(0, loom_qualification_v2.main(arguments))
                self.assertEqual(
                    loom_qualification_v2._candidate_matrix(
                        bundle, consumer=consumer, policy=authority)[0],
                    json.loads(output.read_text(encoding="utf-8")))
                bundle_paths[consumer] = output

            native_directories = []
            for native in self.native_receipts(commit):
                directory = temporary / native["receipt"]["platform"]
                directory.mkdir()
                for name, value in (
                        ("receipt.json", native["receipt"]),
                        ("environment.json", native["environment"]),
                        ("provenance.json", native["provenance"])):
                    (directory / name).write_text(
                        json.dumps(value), encoding="utf-8")
                native_directories.append(directory)
            candidate_path = temporary / "candidate-admission.json"
            arguments = [
                "compile-candidate", "--root", str(root),
                "--quality-bundle", str(bundle_paths["quality"]),
                "--compatibility-bundle",
                str(bundle_paths["compatibility"]),
                "--policy",
                str(root / "contracts" / "release-authority-policy-v2.json"),
                "--output", str(candidate_path),
            ]
            for directory in native_directories:
                arguments.extend(("--native-directory", str(directory)))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_qualification_v2.main(arguments))
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            self.assertEqual(commit, candidate["source_commit"])
            self.assertEqual(6, len(candidate["native_evidence"]))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_qualification_v2.main([
                    "verify-candidate", "--root", str(root),
                    "--candidate", str(candidate_path),
                    "--expected-commit", commit,
                    "--expected-tree", source_tree,
                    "--expected-public-root", public_root,
                    "--policy", str(
                        root / "contracts" /
                        "release-authority-policy-v2.json"),
                ]))

    def test_mechanism_cli_requires_ten_complete_paired_batches_and_faults(self):
        root, manifest, workload, timing, authority = self.inputs()
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
        batches = []
        for sequence in range(1, 11):
            source_commit = f"{sequence:040x}"
            source_tree = f"{sequence + 100:064x}"
            for consumer in ("quality", "compatibility"):
                observations = []
                index = sequence * 100
                for label, image_os, architecture in labels[consumer]:
                    for python_minor in loom_qualification_v2.PYTHON_MINORS:
                        serial, shadow, comparison, context = self.evidence(
                            manifest, workload, timing, consumer=consumer,
                            label=label, image_os=image_os,
                            architecture=architecture,
                            python_minor=python_minor, index=index,
                            source_commit=source_commit,
                            source_tree_sha256=manifest["manifest_sha256"],
                            run_id=f"{consumer}-run-{sequence}")
                        context["repository_source_tree_sha256"] = source_tree
                        observations.append(
                            loom_qualification_v2.compile_observation(
                                serial, shadow, comparison,
                                manifest=manifest, workload=workload,
                                context=context))
                        index += 1
                batches.append(loom_qualification_v2.compile_batch(
                    observations, consumer=consumer, manifest=manifest,
                    workload=workload))
        faults = self.fault_receipts(manifest, workload)
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            arguments = [
                "compile-mechanism", "--root", str(root), "--policy",
                str(root / "contracts" / "release-authority-policy-v2.json"),
                "--output", str(temporary / "qualification.json"),
            ]
            for index, batch in enumerate(batches):
                path = temporary / f"batch-{index}.json"
                path.write_text(json.dumps(batch), encoding="utf-8")
                arguments.extend(("--batch", str(path)))
            for index, fault in enumerate(faults):
                path = temporary / f"fault-{index}.json"
                path.write_text(json.dumps(fault), encoding="utf-8")
                arguments.extend(("--fault-receipt", str(path)))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_qualification_v2.main(arguments))
            record = json.loads((temporary / "qualification.json").read_text(
                encoding="utf-8"))
            self.assertEqual(30, record["family_count"])
            self.assertEqual(10, record["required_observations"])
            missing = list(arguments)
            position = missing.index("--batch")
            del missing[position:position + 2]
            missing[missing.index("--output") + 1] = str(
                temporary / "missing.json")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, loom_qualification_v2.main(missing))

    def test_fault_corpus_executes_real_fail_closed_paths_and_binds_host(self):
        root, manifest, workload, _timing, _authority = self.inputs()
        environment = loom_platform_probe.release_environment(
            requested_label="windows-2025", image_os="win25-vs2026",
            image_version="fixture", workflow_path=(
                ".github/workflows/qualification-faults.yml"),
            workflow_digest="a" * 64, action_manifest_digest="b" * 64,
            event_name="workflow_dispatch", run_id="fault-run",
            run_attempt="1")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                loom_qualification_v2.loom_platform_probe,
                "release_environment", return_value=environment), \
                mock.patch.object(
                    loom_qualification_v2.loom_subject_identity,
                    "_run_git", return_value="1" * 40):
            output = Path(temporary) / "fault-receipt.json"
            receipt = loom_qualification_v2.run_fault_corpus(
                root, platform="windows", output=output,
                logical_cpus=2, timeout=60, fault_timeout=1)
            self.assertEqual(
                receipt, loom_qualification_v2.verify_fault_receipt(
                    json.loads(output.read_text(encoding="utf-8")),
                    manifest=manifest, workload=workload))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_qualification_v2.main([
                    "verify-fault", "--root", str(root),
                    "--receipt", str(output),
                ]))
        self.assertEqual(environment, receipt["environment"])
        self.assertEqual(
            list(loom_qualification_v2.FAULT_CODES),
            [row["code"] for row in receipt["faults"]])
        self.assertTrue(all(
            row["passed"] is True and len(row["evidence_sha256"]) == 64
            for row in receipt["faults"]))
        forged = copy.deepcopy(receipt)
        forged["environment"]["requested_label"] = "windows-latest"
        with self.assertRaises(loom_qualification_v2.QualificationV2Error):
            loom_qualification_v2.verify_fault_receipt(
                forged, manifest=manifest, workload=workload)

    def test_merge_equivalence_reuses_only_an_identical_committed_tree(self):
        _root, manifest, workload, timing, authority = self.inputs()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.git(repository, "init", "-b", "main")
            self.git(repository, "config", "user.email", "loom@example.invalid")
            self.git(repository, "config", "user.name", "Loom Test")
            self.git(repository, "commit", "--allow-empty", "-m", "base")
            self.git(repository, "checkout", "-b", "feature")
            docs = repository / "docs"
            docs.mkdir()
            (docs / "capabilities.json").write_text(
                '{"fixture":1}\n', encoding="utf-8")
            (docs / "generated-evidence.json").write_text(
                '{"fixture":2}\n', encoding="utf-8")
            self.git(repository, "add", "docs")
            self.git(repository, "commit", "-m", "reviewed")
            reviewed = self.git(repository, "rev-parse", "HEAD")
            reviewed_tree = loom_subject_identity.git_tree_inventory(
                repository, reviewed)
            public_root = "e" * 64
            quality = self.candidate_matrix_bundle(
                manifest, workload, timing, consumer="quality",
                source_commit=reviewed,
                source_tree_sha256=reviewed_tree["tree_sha256"],
                public_root_sha256=public_root, start_index=601)
            compatibility = self.candidate_matrix_bundle(
                manifest, workload, timing, consumer="compatibility",
                source_commit=reviewed,
                source_tree_sha256=reviewed_tree["tree_sha256"],
                public_root_sha256=public_root, start_index=701)
            admission = loom_qualification_v2.compile_candidate(
                quality, compatibility, self.native_receipts(reviewed),
                mechanism=None, policy=authority, manifest=manifest)

            self.git(repository, "checkout", "main")
            self.git(repository, "merge", "--no-ff", "feature", "-m", "merge")
            merge_commit = self.git(repository, "rev-parse", "HEAD")
            context = {
                "repository": "https://github.com/saroo98/loom",
                "workflow_path": ".github/workflows/candidate-equivalence.yml",
                "workflow_digest": "1" * 64,
                "action_manifest_digest": "2" * 64,
                "event_name": "push", "run_id": "123", "run_attempt": "1",
            }
            equivalence = loom_qualification_v2.compile_equivalence(
                admission, reviewed_commit=reviewed,
                merge_commit=merge_commit, repository=repository,
                context=context)
            report = loom_lint.Report()
            loom_lint.validate_schema(
                report, "candidate-equivalence", equivalence,
                "release-candidate-equivalence-v2.schema.json")
            self.assertEqual([], report.errors)
            self.assertEqual(
                equivalence, loom_qualification_v2.verify_equivalence(
                    equivalence, admission=admission,
                    expected_commit=merge_commit, repository=repository))
            self.assertEqual(
                equivalence["reviewed_git_tree_oid"],
                equivalence["merge_git_tree_oid"])

            (docs / "generated-evidence.json").write_text(
                '{"fixture":3}\n', encoding="utf-8")
            self.git(repository, "add", "docs/generated-evidence.json")
            self.git(repository, "commit", "-m", "changed bytes")
            changed = self.git(repository, "rev-parse", "HEAD")
            with self.assertRaises(loom_qualification_v2.QualificationV2Error):
                loom_qualification_v2.compile_equivalence(
                    admission, reviewed_commit=reviewed,
                    merge_commit=changed, repository=repository,
                    context=context)


if __name__ == "__main__":
    unittest.main()
