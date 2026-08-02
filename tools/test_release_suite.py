"""Release-suite certification bound to exact cross-platform capability evidence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_release_suite
import loom_suite_certificate
import loom_suite_plan


COMMIT = "1" * 40
ROOT = "2" * 64
TEST_ID = "test_capability.ExampleTests.test_platform_capability"


def report(platform, status, *, exact_environment=False):
    skipped = status == "skipped"
    value = {
        "schema_version": 1,
        "mode": "full",
        "tests_run": 1,
        "failures": 0,
        "errors": 0,
        "skipped": 1 if skipped else 0,
        "elapsed_seconds": 0.1,
        "suppressed_stdout_chars": 0,
        "max_seconds": None,
        "within_budget": True,
        "capability_complete": not skipped,
        "status": "passed-with-capability-skips" if skipped else "passed",
        "successful": not skipped,
        "timings": [{"test": TEST_ID, "status": status, "seconds": 0.1}],
        "skip_receipts": ([{"test": TEST_ID, "reason": "platform fixture"}]
                          if skipped else []),
        "binding": {
            "source_commit": COMMIT,
            "public_root_sha256": ROOT,
            "platform": platform,
            "architecture": "x86_64",
            "python": "3.11.0",
            "runner": f"{platform}-runner",
        },
    }
    if exact_environment:
        environment = {
            "evidence_class": "ci-reproduced",
            "requested_label": ("ubuntu-latest" if platform == "linux"
                                else "windows-latest"),
            "image_os": platform, "image_version": "fixture",
            "os": platform, "os_release": "fixture", "os_version": "fixture",
            "architecture": "x86_64", "python_implementation": "CPython",
            "python_version": "3.11.1",
            "workflow_path": ".github/workflows/quality.yml",
            "workflow_digest": "c" * 64,
            "action_manifest_digest": "d" * 64,
            "event_name": "push", "run_id": "1", "run_attempt": "1",
        }
        environment_sha256 = loom_suite_plan.digest(environment)
        value["binding"]["environment"] = {
            **environment, "environment_sha256": environment_sha256}
        value["binding"]["runner"] = environment_sha256
        value["binding"]["platform"] = platform + ":fixture"
        value["binding"]["python"] = "3.11.1"
    return value


class ReleaseSuiteTests(unittest.TestCase):
    @staticmethod
    def _matrix(consumer, *, commit=COMMIT, root=ROOT, policy_sha="c" * 64):
        subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": commit,
            "source_tree_sha256": "3" * 64,
            "public_root_sha256": root,
            "public_manifest_sha256": "4" * 64,
            "public_file_count": 100,
        }
        labels = loom_suite_certificate.RELEASE_MATRIX_LABELS[consumer]
        cells = []
        for label in labels:
            if label.startswith("windows"):
                image_os, os_name, architecture = "win25", "windows", "x86_64"
            elif label.startswith("macos"):
                image_os, os_name, architecture = "macos15", "macos", "arm64"
            else:
                image_os, os_name, architecture = "ubuntu24", "linux", "x86_64"
            for minor in loom_suite_certificate.RELEASE_MATRIX_PYTHONS:
                environment = {
                    "requested_label": label, "image_os": image_os,
                    "image_version": "fixture", "os": os_name,
                    "os_release": "fixture", "os_version": "fixture",
                    "architecture": architecture,
                    "python_implementation": "CPython",
                    "python_version": minor + ".1",
                    "workflow_path": f".github/workflows/{consumer}.yml",
                    "workflow_digest": "8" * 64,
                    "action_manifest_digest": "9" * 64,
                    "event_name": "push", "run_id": minor.replace(".", ""),
                    "run_attempt": "1",
                }
                fault_tests = set(loom_suite_certificate.FAULT_TESTS.values())
                fault_tests.update(
                    loom_suite_certificate.WINDOWS_FAULT_TESTS.values())
                outcomes = []
                for test_id in sorted({TEST_ID, *fault_tests}):
                    if test_id in loom_suite_certificate.WINDOWS_FAULT_TESTS.values() \
                            and os_name != "windows":
                        outcomes.append({
                            "test": test_id, "status": "skipped",
                            "skip_reason_code": "platform-boundary",
                            "skip_reason_sha256": "7" * 64,
                        })
                    else:
                        outcomes.append({"test": test_id, "status": "passed"})
                skipped_count = sum(
                    row["status"] == "skipped" for row in outcomes)
                cell_body = {
                    "schema_version": 1, "status": "certified", "subject": subject,
                    "environment": environment,
                    "environment_sha256": loom_suite_plan.digest(environment),
                    "inventory_sha256": "a" * 64, "harness_sha256": "b" * 64,
                    "policy_sha256": policy_sha,
                    "timing_profile_sha256": "d" * 64,
                    "plan_sha256": "e" * 64,
                    "worker_receipts": [{"shard_id": "general-000",
                                         "worker_receipt_sha256": "f" * 64,
                                         "duration_microseconds": 1000}],
                    "execution_microseconds": 1000,
                    "outcomes": outcomes,
                    "outcomes_sha256": loom_suite_plan.digest(outcomes),
                    "test_count": len(outcomes),
                    "passed_count": len(outcomes) - skipped_count,
                    "failure_count": 0,
                    "error_count": 0, "skip_count": skipped_count,
                }
                cells.append({
                    **cell_body,
                    "cell_certificate_sha256": loom_suite_plan.digest(cell_body)})
        cells.sort(key=lambda item: item["environment_sha256"])
        body = {
            "schema_version": 1, "status": "certified",
            "consumer": consumer,
            "subject": subject,
            "cells": cells,
            "cell_count": len(cells),
        }
        return {**body, "matrix_certificate_sha256": loom_suite_plan.digest(body)}

    @staticmethod
    def _qualification(matrices, policy):
        cells = {matrix["consumer"]: matrix["cells"] for matrix in matrices}
        first = {consumer: rows[0] for consumer, rows in cells.items()}
        bound = {
            "harness_sha256": first["quality"]["harness_sha256"],
            "timing_profile_sha256": first["quality"]["timing_profile_sha256"],
            "workflow_digests": {
                consumer: cell["environment"]["workflow_digest"]
                for consumer, cell in first.items()},
            "action_manifest_digests": {
                consumer: cell["environment"]["action_manifest_digest"]
                for consumer, cell in first.items()},
            "qualification_code_sha256": (
                loom_suite_certificate.qualification_code_sha256()),
        }
        families = []
        for consumer, rows in cells.items():
            for cell in rows:
                identity = loom_suite_certificate._family(cell, consumer)
                families.append({
                    **identity,
                    "successful_run_ids": [str(index) for index in range(1, 11)],
                    "exact_image_versions": [cell["environment"]["image_version"]],
                    "python_patches": [cell["environment"]["python_version"]],
                    "serial_p50_microseconds": 100, "serial_p95_microseconds": 120,
                    "sharded_p50_microseconds": 90,
                    "sharded_p95_microseconds": 110,
                    "parity_verified": True,
                })
        clean_cell = next(
            cell for cell in cells["compatibility"]
            if cell["environment"]["requested_label"] == "ubuntu-24.04"
            and cell["environment"]["python_version"].startswith("3.11."))
        clean_identity = loom_suite_certificate._family(
            clean_cell, "clean-room")
        families.append({
            **clean_identity, "successful_run_ids": [str(index) for index in range(1, 11)],
            "exact_image_versions": [clean_cell["environment"]["image_version"]],
            "python_patches": [clean_cell["environment"]["python_version"]],
            "serial_p50_microseconds": 100, "serial_p95_microseconds": 120,
            "sharded_p50_microseconds": 90, "sharded_p95_microseconds": 110,
            "parity_verified": True,
        })
        serial = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": policy["exclusive_modules"],
        })
        body = {
            "schema_version": 1, "status": "qualified", "required_successes": 10,
            "serial_policy_sha256": serial["policy_sha256"],
            "certificate_policy_sha256": policy["policy_sha256"],
            "bound_inputs": bound, "bound_inputs_sha256": loom_suite_plan.digest(bound),
            "families": families,
            "fault_injection_receipts": (
                loom_suite_certificate.fault_injection_receipts(matrices)),
            "reproducibility_receipt_sha256s": ["4" * 64, "5" * 64],
            "rollback_receipt_sha256": "6" * 64,
            "workflow_critical_path_improved": True,
            "archive_subjects_agree": True, "privacy_clean": True,
            "mutation_clean": True, "worker_cleanup_verified": True,
        }
        return {**body, "qualification_sha256": loom_suite_plan.digest(body)}

    def test_certificate_authority_compiles_without_running_the_suite(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix("quality", policy_sha=policy["policy_sha256"]),
                    self._matrix("compatibility", policy_sha=policy["policy_sha256"])]
        qualification = self._qualification(matrices, policy)
        with mock.patch.object(
                loom_release_suite.loom_test, "run",
                side_effect=AssertionError("broad suite must not run")):
            result = loom_release_suite.certify_certificates(
                matrices, qualification=qualification, policy=policy,
                expected_commit=COMMIT, expected_root=ROOT)
        self.assertEqual("certified", result["status"])
        self.assertEqual("certificate", result["mode"])
        self.assertEqual(
            ["compatibility", "quality"],
            [row["consumer"] for row in result["matrices"]])
        forged = dict(qualification)
        forged_body = {key: value for key, value in forged.items()
                       if key != "qualification_sha256"}
        forged_body["fault_injection_receipts"] = {
            **forged_body["fault_injection_receipts"], "linux": "0" * 64}
        forged = {**forged_body,
                  "qualification_sha256": loom_suite_plan.digest(forged_body)}
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError,
                "qualification gates are incomplete"):
            loom_release_suite.certify_certificates(
                matrices, qualification=forged, policy=policy,
                expected_commit=COMMIT, expected_root=ROOT)

    def test_serial_cell_evidence_compiles_without_a_release_host_suite(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial", "exclusive_modules": []})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quality = self._write_reports(root, ((
                "quality", report("linux", "passed", exact_environment=True)),))
            compatibility = self._write_reports(
                root, (("compatibility", report(
                    "windows", "passed", exact_environment=True)),))
            with mock.patch.object(
                    loom_release_suite.loom_test, "run",
                    side_effect=AssertionError("release host suite must not run")):
                result = loom_release_suite.certify_serial_evidence(
                    quality, compatibility, policy=policy,
                    expected_commit=COMMIT, expected_root=ROOT, required_cells=1,
                    enforce_release_topology=False)
        self.assertEqual("serial-evidence", result["mode"])
        self.assertEqual(2, len(result["matrices"]))

    def test_serial_cell_evidence_rejects_uncovered_and_unreceipted_skips(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial", "exclusive_modules": []})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skipped = report("linux", "skipped", exact_environment=True)
            quality = self._write_reports(root, (("quality", skipped),))
            compatibility = self._write_reports(root, ((
                "compatibility", report("windows", "passed", exact_environment=True)),))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "uncovered skips"):
                loom_release_suite.certify_serial_evidence(
                    quality, compatibility, policy=policy,
                    expected_commit=COMMIT, expected_root=ROOT, required_cells=1,
                    enforce_release_topology=False)
            skipped["skip_receipts"] = []
            quality = self._write_reports(root, (("quality-unreceipted", skipped),))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "skip or inventory"):
                loom_release_suite.certify_serial_evidence(
                    quality, compatibility, policy=policy,
                    expected_commit=COMMIT, expected_root=ROOT, required_cells=1,
                    enforce_release_topology=False)

    def test_compiled_suite_verifier_rejects_tampering_and_wrong_policy(self):
        serial = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial", "exclusive_modules": []})
        body = {
            "schema_version": 2, "status": "certified", "mode": "serial-evidence",
            "subject": {"source_commit": COMMIT, "public_root_sha256": ROOT},
            "policy_sha256": serial["policy_sha256"],
            "matrices": [
                {"consumer": "quality", "cells": 15, "matrix_sha256": "1" * 64},
                {"consumer": "compatibility", "cells": 15,
                 "matrix_sha256": "2" * 64},
            ],
        }
        value = {**body, "suite_certificate_sha256": loom_suite_plan.digest(body)}
        self.assertEqual(value, loom_release_suite.verify_compiled(
            value, policy=serial, expected_commit=COMMIT, expected_root=ROOT))
        forged = dict(value)
        forged["suite_certificate_sha256"] = "f" * 64
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError, "identity"):
            loom_release_suite.verify_compiled(
                forged, policy=serial, expected_commit=COMMIT, expected_root=ROOT)

    def test_certificate_mode_requires_certificate_policy_and_exact_subject(self):
        serial = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": [],
        })
        certificate = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix("quality", policy_sha=certificate["policy_sha256"]),
                    self._matrix("compatibility", policy_sha=certificate[
                        "policy_sha256"])]
        qualification = self._qualification(matrices, certificate)
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError, "disabled"):
            loom_release_suite.certify_certificates(
                matrices, qualification=qualification, policy=serial,
                expected_commit=COMMIT, expected_root=ROOT)
        wrong = [self._matrix("quality", policy_sha=certificate["policy_sha256"]),
                 self._matrix("compatibility", root="9" * 64,
                              policy_sha=certificate["policy_sha256"])]
        wrong_qualification = self._qualification(wrong, certificate)
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError, "release subject"):
            loom_release_suite.certify_certificates(
                wrong, qualification=wrong_qualification, policy=certificate,
                expected_commit=COMMIT, expected_root=ROOT)

    @staticmethod
    def _write_reports(root, rows):
        paths = []
        for name, value in rows:
            path = root / f"{name}.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            paths.append(path)
        return paths

    def test_exact_matrix_pass_authorizes_local_capability_skip(self):
        local = {
            "tests_run": 1,
            "failures": 0,
            "errors": 0,
            "within_budget": True,
            "skip_receipts": [{"test": TEST_ID, "reason": "unavailable locally"}],
            "timings": [{"test": TEST_ID, "status": "skipped", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._write_reports(root, (
                ("linux", report("linux", "skipped")),
                ("windows", report("windows", "passed")),
            ))
            result = loom_release_suite.certify(
                local, paths, expected_commit=COMMIT, expected_root=ROOT)
        self.assertEqual("certified", result["status"])
        self.assertEqual([TEST_ID], result["covered_local_skips"])
        self.assertEqual(2, result["matrix"]["reports"])

    def test_uncovered_local_skip_is_refused(self):
        local = {
            "tests_run": 1, "failures": 0, "errors": 0, "within_budget": True,
            "skip_receipts": [{"test": TEST_ID, "reason": "unavailable locally"}],
            "timings": [{"test": TEST_ID, "status": "skipped", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = self._write_reports(Path(directory), (
                ("linux", report("linux", "skipped")),
            ))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "not certified|lack"):
                loom_release_suite.certify(
                    local, paths, expected_commit=COMMIT, expected_root=ROOT)

    def test_matrix_for_another_release_subject_is_refused(self):
        local = {
            "tests_run": 1, "failures": 0, "errors": 0, "within_budget": True,
            "skip_receipts": [],
            "timings": [{"test": TEST_ID, "status": "passed", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = self._write_reports(Path(directory), (
                ("windows", report("windows", "passed")),
            ))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "this release subject"):
                loom_release_suite.certify(
                    local, paths, expected_commit="3" * 40, expected_root=ROOT)

    def test_local_failure_cannot_be_hidden_by_a_green_matrix(self):
        local = {
            "tests_run": 1, "failures": 1, "errors": 0, "within_budget": True,
            "skip_receipts": [],
            "timings": [{"test": TEST_ID, "status": "failed", "seconds": 0.1}],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = self._write_reports(Path(directory), (
                ("windows", report("windows", "passed")),
            ))
            with self.assertRaisesRegex(
                    loom_release_suite.ReleaseSuiteError, "did not pass"):
                loom_release_suite.certify(
                    local, paths, expected_commit=COMMIT, expected_root=ROOT)


if __name__ == "__main__":
    unittest.main()
