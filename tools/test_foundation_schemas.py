import tempfile
import unittest
import copy
from pathlib import Path

import loom_lint
import loom_activation
import loom_execution_chain
import loom_operation_envelope
import loom_operation_supervisor
import loom_path_authority
import loom_product_interface
import loom_suite_harness
import loom_suite_plan
import loom_test


class FoundationSchemaTests(unittest.TestCase):
    def assert_schema(self, value, schema):
        report = loom_lint.Report()
        loom_lint.validate_schema(report, schema, value, schema)
        self.assertEqual([], report.errors)

    def test_operation_envelope_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, envelope = loom_operation_envelope.begin(
                Path(temporary).resolve(), operation_class="fixture",
                subject_digest="1" * 64, sidecar_type="fixture-receipt",
                sidecar_id="fixture.json", sidecar_digest="2" * 64)
            self.assert_schema(envelope, "operation-envelope.schema.json")

    def test_suite_failure_diagnostic_matches_its_closed_schema(self):
        value = {
            "schema_version": 1,
            "worker_receipt_sha256": "1" * 64,
            "shard_id": "general-000",
            "failures": [{
                "test": "test_fixture.Fixture.test_failed",
                "status": "failed",
                "exception_type": "HostFailure",
                "error_code": "LIFECYCLE_VERIFICATION_CONTAINMENT_FAILED",
            }],
            "failure_diagnostic_sha256": "3" * 64,
        }
        self.assert_schema(value, "suite-failure-diagnostic-v1.schema.json")
        rejected = copy.deepcopy(value)
        rejected["failures"][0]["message"] = "private detail"
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "suite-failure-diagnostic-v1.schema.json", rejected,
            "suite-failure-diagnostic-v1.schema.json")
        self.assertTrue(report.errors)

    def test_serial_suite_failure_diagnostic_matches_its_closed_schema(self):
        value = {
            "schema_version": 1,
            "exact_cut_receipt_sha256": "1" * 64,
            "failures": [{
                "test": "fixture.class.test_fixture.Fixture",
                "status": "error",
                "exception_type": "NativeHelperBuildError",
                "error_code": "NATIVE_HELPER_BUILD_TIMEOUT",
            }],
            "failure_diagnostic_sha256": "2" * 64,
        }
        self.assert_schema(
            value, "serial-suite-failure-diagnostic-v1.schema.json")
        projected = copy.deepcopy(value)
        projected["failures"][0]["operation_projection"] = {
            "operation_receipt_sha256": "3" * 64,
            "status": "failed", "returncode": None,
            "primary_failure": "timed-out",
            "survivors_confirmed_zero": True,
            "protected_roots_unchanged": True,
            "network_isolation_proven": False,
            "containment_provider": "windows-job-object",
            "projection_sha256": "4" * 64,
            "test_association_sha256": "5" * 64,
        }
        self.assert_schema(
            projected, "serial-suite-failure-diagnostic-v1.schema.json")
        raw_child = copy.deepcopy(projected)
        raw_child["failures"][0]["operation_projection"]["cwd"] = \
            r"C:\Users\Private Owner\checkout"
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "serial-suite-failure-diagnostic-v1.schema.json", raw_child,
            "serial-suite-failure-diagnostic-v1.schema.json")
        self.assertTrue(report.errors)
        rejected = copy.deepcopy(value)
        rejected["failures"][0]["traceback"] = "private detail"
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "serial-suite-failure-diagnostic-v1.schema.json", rejected,
            "serial-suite-failure-diagnostic-v1.schema.json")
        self.assertTrue(report.errors)
        expected_codes = sorted({
            *loom_test.PUBLIC_ERROR_CODES,
            loom_test.PUBLIC_ERROR_CODE_REDACTED,
        })
        root = Path(__file__).resolve().parents[1]
        for name in (
                "suite-failure-diagnostic-v1.schema.json",
                "serial-suite-failure-diagnostic-v1.schema.json"):
            schema = __import__("json").loads((
                root / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(
                expected_codes,
                sorted(schema["$defs"]["failure"]["properties"][
                    "error_code"]["enum"]))

    def test_supervisor_receipt_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipt = loom_operation_supervisor.run(
                operation_class="schema-fixture",
                command=["cmd", "/c", "exit", "0"] if __import__("os").name == "nt"
                else ["/bin/sh", "-c", "exit 0"],
                cwd=root, timeout=5, allowed_roots=[root])
            self.assert_schema(
                receipt, "operation-supervisor-receipt.schema.json")

    def test_authority_and_ownership_receipts_match_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            owned = root / "owned"
            ownership = loom_path_authority.create_owned_directory(
                path=owned, root=root)
            authority = loom_path_authority.authorize(
                operation_class="staging", path=owned, root=root,
                expected_type="directory", replacement_policy="owned-exact",
                cleanup_disposition="remove-if-owned",
                ownership_receipt=ownership)
            self.assert_schema(
                ownership, "path-authority-receipt.schema.json")
            self.assert_schema(
                authority, "path-authority-receipt.schema.json")

    def test_execution_chain_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            launcher = root / "loom.py"
            launcher.write_text("print('fixture')\n", encoding="utf-8")
            chain = loom_execution_chain.create(
                root / ".loom", launcher_path=launcher)
            value = loom_execution_chain.read(
                root / ".loom", chain["chain_id"])
            self.assert_schema(value, "execution-chain.schema.json")

    def test_activation_set_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / ".loom"
            runtime = root / "runtime" / "versions" / "1.8.15"
            runtime.mkdir(parents=True)
            content = b"runtime"
            (runtime / "loom-runtime.txt").write_bytes(content)
            pointer = {
                "version": "1.8.15",
                "path": "1.8.15",
                "payload_sha256": __import__("hashlib").sha256(content).hexdigest(),
                "release_sequence": 15,
                "previous": None,
            }
            store = loom_activation.ActivationStore(root)
            activated = store.create(
                pointer, state_source=None,
                schema_range={"minimum": 0, "maximum": 0},
                previous_activation_set_id=None,
                purpose="baseline-adoption")
            receipt = store.read_receipt(activated["activation_set_id"])
            self.assert_schema(receipt, "activation-set.schema.json")

    def test_release_suite_inventory_plan_and_serial_policy_match_closed_schemas(self):
        subject = {
            "repository": "https://github.com/saroo98/loom",
            "source_commit": "1" * 40,
            "source_tree_sha256": "2" * 64,
            "public_root_sha256": "3" * 64,
            "public_manifest_sha256": "5" * 64,
            "public_file_count": 117,
        }
        environment = {
            "requested_label": "local",
            "image_os": "windows",
            "image_version": "fixture",
            "os": "windows",
            "os_release": "11", "os_version": "11",
            "architecture": "x86_64",
            "python_implementation": "CPython",
            "python_version": "3.11.9",
            "workflow_path": ".github/workflows/quality.yml",
            "workflow_digest": "a" * 64, "action_manifest_digest": "b" * 64,
            "event_name": "push", "run_id": "1", "run_attempt": "1",
        }
        inventory = loom_suite_plan.seal_inventory({
            "schema_version": 1, "subject": subject,
            "environment": environment, "harness_sha256": "4" * 64,
            "modules": [{"module": "test_alpha", "tests": [
                "test_alpha.Alpha.test_one"]}],
            "module_count": 1, "test_count": 1,
        })
        root = Path(__file__).resolve().parents[1]
        policy = __import__("json").loads((
            root / "contracts" / "release-suite-policy-v1.json").read_text(
                encoding="utf-8"))
        profile = __import__("json").loads((
            root / "contracts" / "release-suite-timing-profile-v1.json").read_text(
                encoding="utf-8"))
        validated_policy = loom_suite_plan._validate_seal(
            policy, "policy_sha256", loom_suite_plan.seal_policy)
        validated_profile = loom_suite_plan._validate_seal(
            profile, "profile_sha256", loom_suite_plan.seal_timing_profile)
        plan = loom_suite_plan.plan(
            inventory, timing_profile=validated_profile,
            policy=validated_policy, logical_cpus=2)
        qualification_exists = (
            root / "contracts" / "release-suite-qualification-v1.json").is_file()
        self.assertEqual(
            "certificate" if qualification_exists else "serial",
            validated_policy["authority_mode"])
        self.assertEqual(
            sorted(loom_suite_plan.DEFAULT_EXCLUSIVE_MODULES),
            validated_policy["exclusive_modules"])
        self.assertFalse(any(
            key.endswith("_workers") for key in validated_policy))
        self.assert_schema(inventory, "suite-inventory-v1.schema.json")
        self.assert_schema(plan, "suite-shard-plan-v1.schema.json")

    def test_release_authority_policy_v2_matches_its_closed_schema(self):
        root = Path(__file__).resolve().parents[1]
        policy_path = root / "contracts" / "release-authority-policy-v2.json"
        policy = loom_suite_plan.load_authority_policy(policy_path)
        self.assertEqual("serial", policy["authority_mode"])
        self.assert_schema(policy, "release-authority-policy-v2.schema.json")

    def test_release_product_interface_matches_its_closed_schema(self):
        root = Path(__file__).resolve().parents[1]
        value = loom_product_interface.load(root)
        self.assert_schema(value, "release-product-interface-v1.schema.json")

    def test_release_suite_diagnostics_match_their_closed_schema(self):
        root = Path(__file__).resolve().parents[1]
        value = loom_suite_harness.load_diagnostic_policy(root)
        self.assert_schema(value, "release-suite-diagnostics-v1.schema.json")

    def test_serial_suite_progress_diagnostic_matches_closed_schema(self):
        value = {
            "schema_version": 1,
            "authorizing": False,
            "exact_cut_receipt_sha256": "1" * 64,
            "operation": {
                "status": "failed", "returncode": None,
                "primary_failure": "timed-out",
                "survivors_confirmed_zero": True,
                "protected_roots_unchanged": True,
                "network_isolation_proven": False,
                "containment_provider": "windows-job-object",
                "receipt_sha256": "2" * 64,
            },
            "checkpoint": {
                "schema_version": 1, "status": "running",
                "authorizing": False,
                "diagnostic_policy_sha256": "3" * 64,
                "selected_modules_sha256": None,
                "checkpoint_sequence": 8,
                "completed_test_count": 700,
                "last_started_test": "test_owner.OwnerTests.test_current",
                "last_completed_test": "test_owner.OwnerTests.test_previous",
                "checkpoint_sha256": "4" * 64,
            },
            "progress_diagnostic_sha256": "5" * 64,
        }
        self.assert_schema(
            value, "serial-suite-progress-diagnostic-v1.schema.json")

    def test_claim_only_release_suite_qualification_is_outside_closed_schema(self):
        value = {
            "schema_version": 1, "status": "qualified",
            "required_successes": 10, "serial_policy_sha256": "1" * 64,
            "certificate_policy_sha256": "2" * 64,
            "bound_inputs": {
                "harness_sha256": "3" * 64,
                "timing_profile_sha256": "4" * 64,
                "workflow_digests": {"quality": "5" * 64,
                                     "compatibility": "6" * 64},
                "action_manifest_digests": {"quality": "7" * 64,
                                            "compatibility": "8" * 64},
                "qualification_code_sha256": "9" * 64,
            },
            "bound_inputs_sha256": "2" * 64,
            "families": [{
                "family_id": "a" * 64,
                "consumer": "quality",
                "requested_label": "ubuntu-latest",
                "image_os": "ubuntu24",
                "architecture": "x86_64",
                "python_implementation": "CPython",
                "python_minor": "3.13",
                "successful_run_ids": [str(index) for index in range(10, 20)],
                "exact_image_versions": ["20260801.1"],
                "python_patches": ["3.13.7"],
                "serial_p50_microseconds": 100,
                "serial_p95_microseconds": 120,
                "sharded_p50_microseconds": 90,
                "sharded_p95_microseconds": 110,
                "parity_verified": True,
            }],
            "fault_injection_receipts": {"linux": "b" * 64,
                                           "windows": "c" * 64,
                                           "macos": "d" * 64},
            "reproducibility_receipt_sha256s": ["e" * 64, "f" * 64],
            "rollback_receipt_sha256": "0" * 64,
            "workflow_critical_path_improved": True,
            "archive_subjects_agree": True,
            "privacy_clean": True,
            "mutation_clean": True,
            "worker_cleanup_verified": True,
            "qualification_sha256": "4" * 64,
        }
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "suite-qualification", value,
            "suite-qualification-v1.schema.json")
        self.assertTrue(report.errors)


if __name__ == "__main__":
    unittest.main()
