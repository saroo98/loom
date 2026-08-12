"""Fail-closed suite certificate compilation and shadow comparison."""

import ast
import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import loom_operation_supervisor
import loom_suite_certificate
import loom_suite_plan
import loom_suite_worker
import loom_lint


class SuiteCertificateTests(unittest.TestCase):
    def fixture(self, *, exclusive_modules=(), logical_cpus=4,
                durations=None):
        subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": "1" * 40,
            "source_tree_sha256": "2" * 64,
            "public_root_sha256": "3" * 64,
            "public_manifest_sha256": "4" * 64,
            "public_file_count": 3,
        }
        environment = {
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
        inventory = loom_suite_plan.seal_inventory({
            "schema_version": 1, "subject": subject,
            "environment": environment, "harness_sha256": "5" * 64,
            "modules": [
                {"module": "test_alpha", "tests": ["test_alpha.T.test_a"]},
                {"module": "test_beta", "tests": ["test_beta.T.test_b"]},
            ],
            "module_count": 2, "test_count": 2,
        })
        profile = loom_suite_plan.seal_timing_profile({
            "schema_version": 1, "default_p75_microseconds": 100,
            "module_microseconds": {},
        })
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": list(exclusive_modules),
        })
        plan = loom_suite_plan.plan(
            inventory, timing_profile=profile, policy=policy,
            logical_cpus=logical_cpus)
        durations = {} if durations is None else durations
        receipts = []
        tests_by_module = {
            row["module"]: row["tests"] for row in inventory["modules"]}
        for shard in plan["shards"]:
            expected = sorted(
                test_id for module in shard["modules"]
                for test_id in tests_by_module[module])
            receipts.append(loom_suite_worker._seal({
                "schema_version": 1, "status": "passed", "primary_reason": None,
                "findings": [],
                "subject": dict(subject), "environment": dict(environment),
                "inventory_sha256": inventory["inventory_sha256"],
                "policy_sha256": policy["policy_sha256"],
                "timing_profile_sha256": profile["profile_sha256"],
                "plan_sha256": plan["plan_sha256"],
                "shard_id": shard["shard_id"], "exclusive": shard["exclusive"],
                "expected_modules": shard["modules"], "expected_tests": expected,
                "observed_tests": [
                    {"test": test_id, "status": "passed"} for test_id in expected],
                "test_count": len(expected), "failure_count": 0,
                "error_count": 0, "skip_count": 0,
                "duration_microseconds": durations.get(
                    shard["shard_id"], 1000),
                "pre_manifest_sha256": subject["public_manifest_sha256"],
                "post_manifest_sha256": subject["public_manifest_sha256"],
                "mutation_clean": True, "privacy_clean": True,
                "runtime_roots_clean": True,
                "operation": {
                    "status": "passed", "returncode": 0,
                    "primary_failure": None, "survivors_confirmed_zero": True,
                    "protected_roots_unchanged": True,
                    "network_isolation_proven": False,
                    "containment_provider": "fixture",
                    "receipt_sha256": "6" * 64,
                },
            }))
        return inventory, profile, policy, plan, receipts

    def reseal(self, receipt):
        return loom_suite_worker._seal({
            key: value for key, value in receipt.items()
            if key != "worker_receipt_sha256"})

    def test_generic_certificate_core_has_closed_dependency_boundary_and_parity(self):
        core = importlib.import_module("loom_suite_certificate_core")
        tree = ast.parse(Path(core.__file__).read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue({
            "loom_suite_harness", "loom_suite_plan", "loom_suite_worker",
        }.issubset(imports))
        self.assertTrue({
            "loom_exact_cut_ci", "loom_release", "loom_release_candidate",
            "loom_release_rollback", "loom_test", "loom_vault",
        }.isdisjoint(imports))

        inventory, _profile, policy, plan, receipts = self.fixture()
        wrapper_cell = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)
        core_cell = core.compile_cell(
            inventory, plan, receipts, policy=policy)
        self.assertEqual(wrapper_cell, core_cell)
        self.assertEqual(core_cell, core.verify_cell(core_cell))
        serial = {
            "timings": [
                {"test": row["test"], "status": row["status"]}
                for row in core_cell["outcomes"]
            ],
            "skip_receipts": [],
        }
        self.assertEqual(
            loom_suite_certificate.compare_shadow(serial, wrapper_cell),
            core.compare_shadow(serial, core_cell))
        environment_id = core_cell["environment_sha256"]
        wrapper_matrix = loom_suite_certificate.compile_matrix(
            [wrapper_cell], consumer="release",
            required_environments=[environment_id])
        core_matrix = core.compile_matrix(
            [core_cell], consumer="release",
            required_environments=[environment_id])
        self.assertEqual(wrapper_matrix, core_matrix)
        self.assertEqual(core_matrix, core.verify_matrix(core_matrix))

    def test_shadow_cell_sanitizes_supervisor_failure_as_mismatch_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "shadow"
            private_message = "private C:\\Users\\owner\\secret must not escape"
            failure = loom_operation_supervisor.SupervisorError(private_message)
            with mock.patch.object(
                    loom_suite_certificate, "_execute_cell",
                    side_effect=failure):
                result = loom_suite_certificate.run_shadow_cell(
                    None, None, None, None, None, None, output,
                    source_tree_sha256="1" * 64)

        self.assertEqual("mismatched", result["status"])
        self.assertEqual("OS_OPERATION", result["failure_code"])
        self.assertEqual(
            result["comparison_sha256"],
            loom_suite_plan.digest({
                key: value for key, value in result.items()
                if key != "comparison_sha256"}))
        public = json.dumps(result, sort_keys=True)
        self.assertNotIn("owner", public)
        self.assertNotIn("secret", public)
        self.assertNotIn("Users", public)
        self.assertNotIn(
            hashlib.sha256(private_message.encode()).hexdigest(), public)

    def test_certificate_cell_propagates_supervisor_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "certificate"
            failure = loom_operation_supervisor.SupervisorError(
                "authoritative execution failed closed")
            with mock.patch.object(
                    loom_suite_certificate, "_execute_cell",
                    side_effect=failure), self.assertRaises(
                        loom_operation_supervisor.SupervisorError):
                loom_suite_certificate.run_certificate_cell(
                    None, None, None, None, None, output,
                    source_tree_sha256="1" * 64)

    def test_complete_exact_union_compiles_and_verifies(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)
        self.assertEqual("certified", certificate["status"])
        self.assertEqual(2, certificate["test_count"])
        self.assertEqual(2, certificate["passed_count"])
        self.assertEqual(0, certificate["skip_count"])
        self.assertEqual(
            ["test_alpha.T.test_a", "test_beta.T.test_b"],
            [row["test"] for row in certificate["outcomes"]])
        self.assertEqual(
            certificate,
            loom_suite_certificate.verify_cell(certificate))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "cell-certificate", certificate,
            "suite-cell-certificate-v1.schema.json")
        self.assertEqual([], report.errors)
        failed = copy.deepcopy(receipts)
        failed[0]["status"] = "failed"
        failed[0]["primary_reason"] = "TEST_FAILURE"
        failed[0]["findings"] = ["TEST_FAILURE"]
        failed[0]["observed_tests"][0]["status"] = "failed"
        failed[0]["failure_count"] = 1
        failed[0]["operation"]["status"] = "failed"
        failed[0]["operation"]["returncode"] = 1
        failed[0]["operation"]["primary_failure"] = "nonzero-exit"
        failed[0] = self.reseal(failed[0])
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.compile_cell(
                inventory, plan, failed, policy=policy)
        self.assertEqual("TEST_FAILURE", raised.exception.primary_reason)
        self.assertEqual(
            [failed[0]["observed_tests"][0]["test"]],
            raised.exception.public_details["failed_tests"])
        self.assertEqual([], raised.exception.public_details["missing_tests"])
        self.assertEqual([], raised.exception.public_details["unexpected_tests"])

    def test_two_worker_cell_records_parallel_critical_path(self):
        inventory, _profile, policy, plan, receipts = self.fixture(
            exclusive_modules=("test_alpha",), logical_cpus=3,
            durations={"exclusive": 400, "general-000": 900})

        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)

        self.assertEqual(
            "bounded-parallel-v1", certificate.get("execution_model"))
        self.assertEqual(2, certificate.get("max_parallel_workers"))
        self.assertEqual(900, certificate["execution_microseconds"])
        self.assertEqual(
            certificate, loom_suite_certificate.verify_cell(certificate))
        legacy = copy.deepcopy(certificate)
        legacy.pop("execution_model")
        legacy.pop("max_parallel_workers")
        legacy["execution_microseconds"] = 1300
        legacy_body = {
            key: value for key, value in legacy.items()
            if key != "cell_certificate_sha256"
        }
        legacy["cell_certificate_sha256"] = loom_suite_plan.digest(legacy_body)
        self.assertEqual(legacy, loom_suite_certificate.verify_cell(legacy))
        oversize = copy.deepcopy(certificate)
        oversize["max_parallel_workers"] = 8193
        oversize_body = {
            key: value for key, value in oversize.items()
            if key != "cell_certificate_sha256"
        }
        oversize["cell_certificate_sha256"] = loom_suite_plan.digest(
            oversize_body)
        with self.assertRaises(loom_suite_certificate.CertificateError):
            loom_suite_certificate.verify_cell(oversize)

    def test_fail_closed_precedence_prefers_subject_over_later_test_failure(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        invalid = copy.deepcopy(receipts)
        invalid[0]["subject"]["public_root_sha256"] = "9" * 64
        invalid[0]["observed_tests"][0]["status"] = "failed"
        invalid[0]["failure_count"] = 1
        invalid[0]["status"] = "failed"
        invalid[0]["primary_reason"] = "TEST_FAILURE"
        invalid[0]["findings"] = ["TEST_FAILURE"]
        invalid[0] = self.reseal(invalid[0])
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.compile_cell(
                inventory, plan, invalid, policy=policy)
        self.assertEqual("WRONG_SUBJECT", raised.exception.primary_reason)
        self.assertIn("TEST_FAILURE", raised.exception.findings)
        mixed = copy.deepcopy(receipts)
        mixed[0]["environment"]["run_id"] = "2"
        mixed[0] = self.reseal(mixed[0])
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.compile_cell(
                inventory, plan, mixed, policy=policy)
        self.assertEqual("WRONG_ENVIRONMENT", raised.exception.primary_reason)

    def test_missing_duplicate_mutated_and_private_receipts_refuse(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        cases = []
        cases.append((receipts[:1], "INVENTORY_MISMATCH"))
        cases.append((receipts + [receipts[0]], "INVENTORY_MISMATCH"))
        mutated = copy.deepcopy(receipts)
        mutated[0]["mutation_clean"] = False
        mutated[0]["status"] = "failed"
        mutated[0]["primary_reason"] = "CANDIDATE_MUTATION"
        mutated[0]["findings"] = ["CANDIDATE_MUTATION"]
        mutated[0] = self.reseal(mutated[0])
        cases.append((mutated, "CANDIDATE_MUTATION"))
        private = copy.deepcopy(receipts)
        private[0]["privacy_clean"] = False
        private[0]["status"] = "failed"
        private[0]["primary_reason"] = "PRIVACY_FAILURE"
        private[0]["findings"] = ["PRIVACY_FAILURE"]
        private[0] = self.reseal(private[0])
        cases.append((private, "PRIVACY_FAILURE"))
        for candidate, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(
                        loom_suite_certificate.CertificateError) as raised:
                    loom_suite_certificate.compile_cell(
                        inventory, plan, candidate, policy=policy)
                self.assertEqual(expected, raised.exception.primary_reason)

    def test_cell_records_skips_and_matrix_rejects_uncovered_skip(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        skipped = copy.deepcopy(receipts)
        skipped[0]["observed_tests"][0] = {
            "test": skipped[0]["observed_tests"][0]["test"],
            "status": "skipped", "skip_reason_code": "platform-boundary",
            "skip_reason_sha256": "7" * 64}
        skipped[0]["skip_count"] = 1
        skipped[0] = self.reseal(skipped[0])
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, skipped, policy=policy)
        self.assertEqual(1, certificate["skip_count"])
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.compile_matrix(
                [certificate], consumer="release",
                required_environments=[certificate["environment_sha256"]])
        self.assertEqual("UNAUTHORIZED_SKIP", raised.exception.primary_reason)

    def test_corrupt_receipt_digest_is_distinct_from_semantic_failure(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        corrupt = copy.deepcopy(receipts)
        corrupt[0]["worker_receipt_sha256"] = "0" * 64
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.compile_cell(
                inventory, plan, corrupt, policy=policy)
        self.assertEqual("RECEIPT_DIGEST", raised.exception.primary_reason)

    def test_shadow_comparison_and_consumer_matrices_remain_separate(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)
        serial = {
            "timings": [
                {"test": "test_beta.T.test_b", "status": "passed"},
                {"test": "test_alpha.T.test_a", "status": "passed"},
            ],
            "skip_receipts": [],
        }
        comparison = loom_suite_certificate.compare_shadow(serial, certificate)
        self.assertEqual("matched", comparison["status"])
        environment_id = certificate["environment_sha256"]
        quality = loom_suite_certificate.compile_matrix(
            [certificate], consumer="release",
            required_environments=[environment_id])
        compatibility = loom_suite_certificate.compile_matrix(
            [certificate], consumer="clean-room",
            required_environments=[environment_id])
        self.assertNotEqual(
            quality["matrix_certificate_sha256"],
            compatibility["matrix_certificate_sha256"])
        self.assertEqual(certificate, quality["cells"][0])
        self.assertEqual(quality, loom_suite_certificate.verify_matrix(quality))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "matrix-certificate", quality,
            "suite-matrix-certificate-v1.schema.json")
        self.assertEqual([], report.errors)
        mismatch = copy.deepcopy(serial)
        mismatch["timings"][0]["status"] = "failed"
        with self.assertRaisesRegex(
                loom_suite_certificate.CertificateError, "shadow parity"):
            loom_suite_certificate.compare_shadow(mismatch, certificate)
        self.assertEqual(
            "WORKER_RECEIPT_COUNTS",
            loom_suite_certificate._shadow_failure_code(
                loom_suite_worker.SuiteWorkerError(
                    "worker receipt outcome counts are invalid")))
        self.assertEqual(
            "OS_OPERATION",
            loom_suite_certificate._shadow_failure_code(
                OSError("private path must not cross the public projection")))

    def test_release_consumers_require_the_exact_fifteen_cell_topology(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.compile_matrix(
                [certificate], consumer="quality",
                required_environments=[certificate["environment_sha256"]])
        self.assertEqual("INVENTORY_MISMATCH", raised.exception.primary_reason)

    def test_standalone_matrix_revalidates_nested_cells_and_skip_coverage(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)
        matrix = loom_suite_certificate.compile_matrix(
            [certificate], consumer="release",
            required_environments=[certificate["environment_sha256"]])
        forged = copy.deepcopy(matrix)
        forged["cells"][0]["subject"]["source_commit"] = "9" * 40
        forged_body = {key: value for key, value in forged.items()
                       if key != "matrix_certificate_sha256"}
        forged["matrix_certificate_sha256"] = loom_suite_plan.digest(forged_body)
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.verify_matrix(forged)
        self.assertEqual("RECEIPT_DIGEST", raised.exception.primary_reason)

        skipped_receipts = copy.deepcopy(receipts)
        skipped_receipts[0]["observed_tests"][0] = {
            "test": skipped_receipts[0]["observed_tests"][0]["test"],
            "status": "skipped", "skip_reason_code": "platform-boundary",
            "skip_reason_sha256": "7" * 64,
        }
        skipped_receipts[0]["skip_count"] = 1
        skipped_receipts[0] = self.reseal(skipped_receipts[0])
        skipped = loom_suite_certificate.compile_cell(
            inventory, plan, skipped_receipts, policy=policy)
        skipped_body = {
            "schema_version": 1, "status": "certified", "consumer": "release",
            "subject": skipped["subject"], "cells": [skipped], "cell_count": 1,
        }
        skipped_matrix = {**skipped_body,
                          "matrix_certificate_sha256": loom_suite_plan.digest(
                              skipped_body)}
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.verify_matrix(skipped_matrix)
        self.assertEqual("UNAUTHORIZED_SKIP", raised.exception.primary_reason)

    def test_cell_verifier_refuses_unknown_nested_fields_and_duplicate_tests(self):
        inventory, _profile, policy, plan, receipts = self.fixture()
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, receipts, policy=policy)
        unknown = copy.deepcopy(certificate)
        unknown["environment"]["runner_name"] = "private-runner"
        unknown_body = {key: value for key, value in unknown.items()
                        if key != "cell_certificate_sha256"}
        unknown["cell_certificate_sha256"] = loom_suite_plan.digest(unknown_body)
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.verify_cell(unknown)
        self.assertEqual("SCHEMA", raised.exception.primary_reason)

        duplicate = copy.deepcopy(certificate)
        duplicate["outcomes"].append(copy.deepcopy(duplicate["outcomes"][0]))
        duplicate["test_count"] += 1
        duplicate["passed_count"] += 1
        duplicate["outcomes_sha256"] = loom_suite_plan.digest(duplicate["outcomes"])
        duplicate_body = {key: value for key, value in duplicate.items()
                          if key != "cell_certificate_sha256"}
        duplicate["cell_certificate_sha256"] = loom_suite_plan.digest(duplicate_body)
        with self.assertRaises(loom_suite_certificate.CertificateError) as raised:
            loom_suite_certificate.verify_cell(duplicate)
        self.assertEqual("INVENTORY_MISMATCH", raised.exception.primary_reason)


if __name__ == "__main__":
    unittest.main()
