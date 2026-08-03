"""Release-suite certification bound to exact cross-platform capability evidence."""

import base64
import copy
import gzip
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_exact_cut_ci
import loom_lint
import loom_release_candidate
import loom_release_rollback
import loom_release_suite
import loom_suite_certificate
import loom_suite_plan
import loom_suite_worker


COMMIT = "1" * 40
ROOT = "2" * 64
TEST_ID = "test_capability.ExampleTests.test_platform_capability"
TIMING_PROFILE = loom_suite_plan.seal_timing_profile({
    "schema_version": 1,
    "default_p75_microseconds": 100,
    "module_microseconds": {},
})


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
                    "timing_profile_sha256": TIMING_PROFILE["profile_sha256"],
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

    @staticmethod
    def _pair_evidence(cell, serial_policy, *, run_id, run_attempt="1"):
        environment = {
            **cell["environment"],
            "run_id": str(run_id),
            "run_attempt": str(run_attempt),
        }
        grouped = {}
        for outcome in cell["outcomes"]:
            module = outcome["test"].split(".", 1)[0]
            grouped.setdefault(module, []).append(outcome["test"])
        inventory = loom_suite_plan.seal_inventory({
            "schema_version": 1,
            "subject": copy.deepcopy(cell["subject"]),
            "environment": environment,
            "harness_sha256": cell["harness_sha256"],
            "modules": [
                {"module": module, "tests": sorted(tests)}
                for module, tests in sorted(grouped.items())
            ],
            "module_count": len(grouped),
            "test_count": len(cell["outcomes"]),
        })
        plan = loom_suite_plan.plan(
            inventory, timing_profile=TIMING_PROFILE, policy=serial_policy,
            logical_cpus=2)
        shard = plan["shards"][0]
        expected_tests = sorted(
            test for module in shard["modules"] for test in grouped[module])
        observed = sorted(
            copy.deepcopy(cell["outcomes"]), key=lambda row: row["test"])
        duration = 900 + int(str(run_id)[-2:])
        worker = loom_suite_worker._seal({
            "schema_version": 1, "status": "passed", "primary_reason": None,
            "findings": [], "subject": copy.deepcopy(cell["subject"]),
            "environment": environment,
            "inventory_sha256": inventory["inventory_sha256"],
            "policy_sha256": serial_policy["policy_sha256"],
            "timing_profile_sha256": TIMING_PROFILE["profile_sha256"],
            "plan_sha256": plan["plan_sha256"],
            "shard_id": shard["shard_id"], "exclusive": shard["exclusive"],
            "expected_modules": shard["modules"],
            "expected_tests": expected_tests, "observed_tests": observed,
            "test_count": len(observed), "failure_count": 0,
            "error_count": 0,
            "skip_count": sum(row["status"] == "skipped" for row in observed),
            "duration_microseconds": duration,
            "pre_manifest_sha256": cell["subject"]["public_manifest_sha256"],
            "post_manifest_sha256": cell["subject"]["public_manifest_sha256"],
            "mutation_clean": True, "privacy_clean": True,
            "runtime_roots_clean": True,
            "operation": {
                "status": "passed", "returncode": 0,
                "primary_failure": None, "survivors_confirmed_zero": True,
                "protected_roots_unchanged": True,
                "network_isolation_proven": False,
                "containment_provider": "fixture",
                "receipt_sha256": loom_suite_plan.digest({
                    "run_id": run_id, "run_attempt": run_attempt}),
            },
        })
        certificate = loom_suite_certificate.compile_cell(
            inventory, plan, [worker], policy=serial_policy)
        exact_environment = {
            "evidence_class": "ci-reproduced", **environment}
        exact_environment["environment_sha256"] = loom_suite_plan.digest(
            exact_environment)
        serial_suite = {
            "schema_version": 2, "passed": True,
            "capability_complete": not any(
                row["status"] == "skipped" for row in observed),
            "capability_status": (
                "requires-matrix" if any(
                    row["status"] == "skipped" for row in observed)
                else "complete"),
            "returncode": (1 if any(
                row["status"] == "skipped" for row in observed) else 0),
            "primary_failure_sha256": None,
            "operation_receipt_sha256": loom_suite_plan.digest({
                "serial_run_id": run_id, "serial_run_attempt": run_attempt}),
            "elapsed_microseconds": duration + 1000,
            "tests_run": len(observed), "failure_count": 0,
            "error_count": 0, "failed_tests": [],
            "skip_receipts": [{
                "test": row["test"],
                "reason_code": row["skip_reason_code"],
                "reason_sha256": row["skip_reason_sha256"],
            } for row in observed if row["status"] == "skipped"],
            "timings": [{
                "test": row["test"], "status": row["status"],
                "duration_microseconds": 1,
            } for row in observed],
            "binding": {
                "source_commit": cell["subject"]["source_commit"],
                "public_root_sha256": cell["subject"]["public_root_sha256"],
                "environment": exact_environment,
                "platform": (environment["image_os"] + ":" +
                             environment["image_version"]),
                "architecture": environment["architecture"],
                "python": environment["python_version"],
                "runner": exact_environment["environment_sha256"],
            },
        }
        exact_receipt = loom_exact_cut_ci._seal({
            "schema_version": 2, "status": "verified",
            "platform": environment["os"],
            "architecture": environment["architecture"],
            "python": environment["python_version"],
            "source_commit": cell["subject"]["source_commit"],
            "build_root_sha256": cell["subject"]["public_root_sha256"],
            "verified_root_sha256": cell["subject"]["public_root_sha256"],
            "public_manifest_sha256": cell["subject"][
                "public_manifest_sha256"],
            "public_file_count": cell["subject"]["public_file_count"],
            "suite": serial_suite, "error_type": None, "error_sha256": None,
            "operation_id": f"fixture-{run_id}-{run_attempt}",
            "environment": exact_environment,
        })
        return {
            "exact_cut_receipt": exact_receipt,
            "serial_suite": copy.deepcopy(serial_suite),
            "inventory": inventory, "timing_profile": TIMING_PROFILE,
            "plan": plan,
            "worker_receipts": [worker],
            "cell_certificate": certificate,
            "shadow_comparison": loom_suite_certificate.compare_shadow(
                serial_suite, certificate),
        }

    @staticmethod
    def _reproducibility_receipts(subject):
        platforms = sorted(loom_release_candidate.NATIVE_PLATFORMS)
        binaries = {
            platform: loom_suite_plan.digest({"platform": platform})
            for platform in platforms}
        public_cut = {
            "root_sha256": subject["public_root_sha256"],
            "manifest_sha256": subject["public_manifest_sha256"],
            "file_count": subject["public_file_count"],
        }
        candidate = {
            "sha256": "1" * 64, "bytes": 1, "files": 1,
            "extracted_tree_sha256": "2" * 64,
            "installed_tree_sha256": "3" * 64,
            "archive_metadata_sha256": "4" * 64,
            "public_cut": public_cut, "native_binaries": binaries,
        }
        receipts = []
        for witness in ("first", "second"):
            body = {
                "schema_version": 1, "status": "reproduced",
                "candidate_a": candidate, "candidate_b": candidate,
                "canonical_candidate": "A", "public_cut": public_cut,
                "native_subjects": [{
                    "platform": platform,
                    "binary_sha256": binaries[platform],
                    "sbom_sha256": loom_suite_plan.digest({
                        "platform": platform, "witness": witness}),
                    "provenance_sha256": loom_suite_plan.digest({
                        "provenance": platform, "witness": witness}),
                } for platform in platforms],
            }
            receipts.append(loom_release_candidate._seal(body))
        return receipts

    @staticmethod
    def _rollback_receipt(subject):
        body = {
            "schema_version": 1, "status": "passed",
            "commit": subject["source_commit"],
            "public_root_sha256": subject["public_root_sha256"],
            "tests": list(loom_release_rollback.TESTS),
            "transcript_sha256": "7" * 64,
        }
        return {**body, "result_sha256": loom_suite_plan.digest(body)}

    @staticmethod
    def _reseal_pair(pair):
        return loom_suite_certificate._qualification_pair_envelope(pair)

    @staticmethod
    def _reseal_qualification(qualification):
        body = {key: value for key, value in qualification.items()
                if key != "qualification_sha256"}
        return {**body, "qualification_sha256": loom_suite_plan.digest(body)}

    @classmethod
    def _qualification_evidence(cls, matrices, policy):
        serial_policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": policy["exclusive_modules"],
        })
        families = []
        family_number = 0
        for matrix in sorted(matrices, key=lambda row: row["consumer"]):
            for cell in matrix["cells"]:
                family_number += 1
                families.append({
                    "consumer": matrix["consumer"],
                    "pairs": [cls._pair_evidence(
                        cell, serial_policy,
                        run_id=f"{family_number}{run_number:02d}")
                        for run_number in range(1, 11)],
                })
        compiler = getattr(loom_suite_certificate, "compile_qualification", None)
        if compiler is None:
            return None
        return compiler(
            families, matrices, policy=policy,
            reproducibility_receipts=cls._reproducibility_receipts(
                matrices[0]["subject"]),
            rollback_receipt=cls._rollback_receipt(matrices[0]["subject"]))

    def test_claim_only_qualification_cannot_authorize_certificate_mode(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix(
            "quality", policy_sha=policy["policy_sha256"]), self._matrix(
            "compatibility", policy_sha=policy["policy_sha256"])]
        fabricated = self._qualification(matrices, policy)
        with self.assertRaisesRegex(
                loom_suite_certificate.CertificateError,
                "qualification record is invalid"):
            loom_suite_certificate.verify_qualification(
                fabricated, matrices, policy=policy)

    def test_qualification_loaders_are_bounded_above_worker_receipt_limit(self):
        release_loader = getattr(
            loom_release_suite, "_read_qualification", None)
        certificate_loader = getattr(
            loom_suite_certificate, "_load_qualification", None)
        self.assertIsNotNone(release_loader)
        self.assertIsNotNone(certificate_loader)
        if release_loader is None or certificate_loader is None:
            return
        value = {"padding": "x" * (4 * 1024 * 1024)}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qualification.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(value, release_loader(path))
            self.assertEqual(value, certificate_loader(path))
            with self.assertRaises(loom_release_suite.ReleaseSuiteError):
                release_loader(path, max_bytes=1024)
            with self.assertRaises(loom_suite_worker.SuiteWorkerError):
                certificate_loader(path, max_bytes=1024)
            path.write_text('{"duplicate":1,"duplicate":2}', encoding="utf-8")
            with self.assertRaises(loom_release_suite.ReleaseSuiteError):
                release_loader(path)
            with self.assertRaises(loom_suite_worker.SuiteWorkerError):
                certificate_loader(path)
            path.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            with self.assertRaises(loom_release_suite.ReleaseSuiteError):
                release_loader(path)
            with self.assertRaises(loom_suite_worker.SuiteWorkerError):
                certificate_loader(path)

        deep = "[" * 2000 + "0" + "]" * 2000
        raw = (
            '{"exact_cut_receipt":' + deep
            + ',"serial_suite":{},"inventory":{},"timing_profile":{},'
            + '"plan":{},"worker_receipts":[],"cell_certificate":{},'
            + '"shadow_comparison":{}}').encode("utf-8")
        body = {
            "encoding": "gzip-base64-json-v1",
            "uncompressed_bytes": len(raw),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "payload_base64": base64.b64encode(
                gzip.compress(raw, compresslevel=9, mtime=0)).decode("ascii"),
        }
        envelope = {
            **body, "pair_sha256": loom_suite_plan.digest(body),
        }
        with self.assertRaises(loom_suite_certificate.CertificateError):
            loom_suite_certificate._decode_qualification_pair(envelope)

    def test_exactly_ten_full_pairs_derive_one_valid_qualification(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix(
            "quality", policy_sha=policy["policy_sha256"]), self._matrix(
            "compatibility", policy_sha=policy["policy_sha256"])]
        qualification = self._qualification_evidence(matrices, policy)
        self.assertIsNotNone(
            qualification,
            "compile_qualification must compile full pair evidence")
        self.assertEqual(
            qualification,
            loom_suite_certificate.verify_qualification(
                qualification, matrices, policy=policy))
        self.assertEqual(30, len(qualification["families"]))
        clean_room_family = next(
            family for family in qualification["families"]
            if family["family_id"] == qualification["clean_room_family_id"])
        self.assertEqual("compatibility", clean_room_family["consumer"])
        self.assertEqual("ubuntu-24.04", clean_room_family["requested_label"])
        self.assertEqual("3.11", clean_room_family["python_minor"])
        self.assertTrue(all(
            len(family["pairs"]) == 10
            and len(family["derived"]["successful_runs"]) == 10
            and family["derived"]["workflow_critical_path_improved"] is True
            for family in qualification["families"]))
        schema_report = loom_lint.Report()
        loom_lint.validate_schema(
            schema_report, "suite-qualification", qualification,
            "suite-qualification-v1.schema.json")
        self.assertEqual([], schema_report.errors)

    def test_qualification_rejects_missing_duplicate_and_forged_summaries(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix(
            "quality", policy_sha=policy["policy_sha256"]), self._matrix(
            "compatibility", policy_sha=policy["policy_sha256"])]
        qualification = self._qualification_evidence(matrices, policy)
        cases = []
        missing = copy.deepcopy(qualification)
        missing["families"][0]["pairs"].pop()
        cases.append(missing)
        duplicate = copy.deepcopy(qualification)
        duplicate["families"][0]["pairs"][-1] = copy.deepcopy(
            duplicate["families"][0]["pairs"][0])
        cases.append(duplicate)
        forged_timing = copy.deepcopy(qualification)
        forged_timing["families"][0]["derived"][
            "serial_p50_microseconds"] += 1
        cases.append(forged_timing)
        forged_boolean = copy.deepcopy(qualification)
        forged_boolean["families"][0]["derived"]["privacy_clean"] = False
        cases.append(forged_boolean)
        for candidate in cases:
            with self.subTest(case=len(candidate["families"][0]["pairs"])):
                with self.assertRaises(loom_suite_certificate.CertificateError):
                    loom_suite_certificate.verify_qualification(
                        self._reseal_qualification(candidate), matrices,
                        policy=policy)

    def test_qualification_rejects_mixed_subject_stale_and_unresolved_evidence(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix(
            "quality", policy_sha=policy["policy_sha256"]), self._matrix(
            "compatibility", policy_sha=policy["policy_sha256"])]
        qualification = self._qualification_evidence(matrices, policy)
        mixed_subject = copy.deepcopy(qualification)
        pair = loom_suite_certificate._decode_qualification_pair(
            mixed_subject["families"][0]["pairs"][0])
        exact_body = {key: value for key, value in pair[
            "exact_cut_receipt"].items() if key != "receipt_sha256"}
        exact_body["source_commit"] = "9" * 40
        exact_body["suite"]["binding"]["source_commit"] = "9" * 40
        pair["exact_cut_receipt"] = loom_exact_cut_ci._seal(exact_body)
        pair["serial_suite"] = copy.deepcopy(exact_body["suite"])
        mixed_subject["families"][0]["pairs"][0] = self._reseal_pair(pair)

        stale_timing = copy.deepcopy(qualification)
        pair = loom_suite_certificate._decode_qualification_pair(
            stale_timing["families"][0]["pairs"][0])
        profile_body = {key: value for key, value in pair[
            "timing_profile"].items() if key != "profile_sha256"}
        profile_body["default_p75_microseconds"] += 1
        pair["timing_profile"] = loom_suite_plan.seal_timing_profile(profile_body)
        stale_timing["families"][0]["pairs"][0] = self._reseal_pair(pair)

        unresolved_repro = copy.deepcopy(qualification)
        unresolved_repro["reproducibility_receipts"][0] = {
            "receipt_sha256": "a" * 64}
        forged_rollback = copy.deepcopy(qualification)
        forged_rollback["rollback_receipt"]["transcript_sha256"] = "8" * 64

        for candidate in (
                mixed_subject, stale_timing, unresolved_repro, forged_rollback):
            with self.subTest(candidate=list(candidate)):
                with self.assertRaises(loom_suite_certificate.CertificateError):
                    loom_suite_certificate.verify_qualification(
                        self._reseal_qualification(candidate), matrices,
                        policy=policy)

    def test_qualification_rejects_reproductions_of_different_archives(self):
        subject = self._matrix("quality")["subject"]
        receipts = self._reproducibility_receipts(subject)
        changed = copy.deepcopy(receipts[1])
        body = {
            key: value for key, value in changed.items()
            if key != "receipt_sha256"
        }
        for field in ("candidate_a", "candidate_b"):
            body[field]["sha256"] = "9" * 64
        receipts[1] = loom_release_candidate._seal(body)
        for receipt in receipts:
            self.assertEqual(
                "reproduced",
                loom_release_candidate.verify_reproducibility_receipt(
                    receipt)["status"])

        with self.assertRaisesRegex(
                loom_suite_certificate.CertificateError,
                "qualification release evidence is invalid") as refusal:
            loom_suite_certificate._verify_release_evidence(
                receipts, self._rollback_receipt(subject), subject)

        self.assertIn("WRONG_SUBJECT", refusal.exception.findings)

    def test_certificate_authority_compiles_without_running_the_suite(self):
        policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "certificate",
            "exclusive_modules": [],
        })
        matrices = [self._matrix("quality", policy_sha=policy["policy_sha256"]),
                    self._matrix("compatibility", policy_sha=policy["policy_sha256"])]
        qualification = self._qualification_evidence(matrices, policy)
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
        forged = copy.deepcopy(qualification)
        forged["families"][0]["derived"]["parity_verified"] = False
        forged = self._reseal_qualification(forged)
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError,
                "qualification family is invalid"):
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
        qualification = self._qualification_evidence(matrices, certificate)
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError, "disabled"):
            loom_release_suite.certify_certificates(
                matrices, qualification=qualification, policy=serial,
                expected_commit=COMMIT, expected_root=ROOT)
        wrong = [self._matrix("quality", policy_sha=certificate["policy_sha256"]),
                 self._matrix("compatibility", root="9" * 64,
                              policy_sha=certificate["policy_sha256"])]
        with self.assertRaisesRegex(
                loom_release_suite.ReleaseSuiteError,
                "release subject|qualification matrices mix"):
            loom_release_suite.certify_certificates(
                wrong, qualification=qualification, policy=certificate,
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
