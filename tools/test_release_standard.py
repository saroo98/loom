import base64
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

import loom_install
import loom_docs
import loom_release
import loom_reliability
import loom_lint


TEST_RSA_N = int(
    "b1cd1357c5e657cbcf16a52b6f22f01879a0d4212e43efc974b5915072d64c3c"
    "1bcb4ff689979a4f66b27367b4b7d8b0dd4e46fe78492bd5fbe35b19c1bc71db"
    "4a94e3131420ed7af4bccc62b3898ef906c09fd897504263c99104bc6e0d81c2b"
    "d01ed9a803aa30ed15637e8fe4c26530ffc21d6b08f38348ab8fe5a3d20b4dc3"
    "b60690d7b60bd749d5e79fdae778f5ac3a453639eebc1c02228e436d477895dad"
    "4e6515e5ed61720c3c291ae4885c16fda384be6b1bdb0b14917ac591132c78db5"
    "5f0691babaaf53bb2a4d368dd85c5d99e26f8a73b0bbebb94aea4369c4fadfdba"
    "98dd48f729454c81f66ba75243ffa1937c1ada581d0cab26b3ec768d3345", 16)
TEST_RSA_D = int(
    "1f37e5c48c8fe42c79e0fd0142533d1adf083916d65bc1577af1826140b895cc"
    "1c0937b20ef89a748490a2a8bbd767e9ae01d77f48b97843eb254152a56ca405"
    "1ff44266902b33e759df687790148011037980d773c1f8d632870ef0d2d5f649a"
    "e0c0f9f0812c39c8f6ef70426da520455932c91d8905d0b04ac74a47d85279c1"
    "46618fd2b800b1de8c829780ca120326793e383582178b6fbe868a38c03d53b51"
    "dd926c28a491dfcf5a3d90ef010a8c6632dec99062c4b4b14caa0382a3ab0c8c"
    "bfe0a068683027f755e350c4877f3f5bd33c5644489abbd9a6dbc64002cd60ebb"
    "5ea7b8aaae5bc544ff290b1facc015a0c676bd1587e283b42657d2384fea1", 16)


class ReleaseStandardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def test_verify_cut_output_keeps_stdout_bounded(self):
        output = self.root / "verify-cut.json"
        result = {
            "status": "passed",
            "root_sha256": "a" * 64,
            "suite": {
                "passed": True,
                "tests_run": 5000,
                "failure_count": 0,
                "error_count": 0,
                "capability_complete": True,
                "tests": [{"test": "x" * 2048}] * 400,
            },
        }
        stdout = io.StringIO()
        with mock.patch.object(loom_release, "verify_cut", return_value=result), \
                contextlib.redirect_stdout(stdout):
            code = loom_release.main([
                "verify-cut", str(self.root), "--output", str(output)])
        self.assertEqual(0, code)
        self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))
        rendered = stdout.getvalue()
        self.assertLess(len(rendered.encode("utf-8")), 1024)
        self.assertNotIn('"tests"', rendered)

    def tearDown(self):
        self.tmp.cleanup()

    def test_exhaustive_suite_ceiling_has_supported_runner_headroom(self):
        self.assertEqual(2700, loom_release.FULL_SUITE_MAX_SECONDS)
        root = Path(__file__).resolve().parents[1]
        workflow_timeouts = {
            "quality.yml": 90,
            "compatibility.yml": 90,
            "release.yml": 65,
        }
        for name, minutes in workflow_timeouts.items():
            text = (root / ".github" / "workflows" / name).read_text(
                encoding="utf-8")
            self.assertIn(f"timeout-minutes: {minutes}", text)
            self.assertGreaterEqual(
                minutes * 60,
                loom_release.FULL_SUITE_MAX_SECONDS + 10 * 60)

    def test_public_cut_keeps_the_repository_pinned_rust_toolchain(self):
        self.assertIn("rust-toolchain.toml", loom_release.ROOT_FILES)

    def test_public_cut_keeps_v1_and_v2_qualification_authority_outside_runtime_payload(self):
        source = self._source()
        contracts = source / "contracts"
        contracts.mkdir()
        policy = contracts / "release-suite-policy-v1.json"
        policy.write_text('{"authority_mode":"certificate"}\n', encoding="utf-8")
        qualifications = {
            contracts / "release-suite-qualification-v1.json":
                '{"qualification_sha256":"' + ("a" * 64) + '"}\n',
            contracts / "release-mechanism-qualification-v2.json":
                '{"mechanism_qualification_sha256":"' +
                ("b" * 64) + '"}\n',
        }
        for qualification, content in qualifications.items():
            qualification.write_text(content, encoding="utf-8")
        destination = self.root / "public-cut"

        result = loom_release.build_public(
            source, destination, forbidden_tokens=[],
            source_classification="public-release")

        self.assertTrue(policy.is_file())
        self.assertTrue(all(path.is_file() for path in qualifications))
        self.assertTrue(
            (destination / "contracts" / policy.name).is_file())
        published = {row["path"] for row in result["files"]}
        for qualification in qualifications:
            self.assertFalse(
                (destination / "contracts" / qualification.name).exists())
            self.assertNotIn(
                f"contracts/{qualification.name}", published)

    def test_public_cut_preserves_the_fixed_qualification_workload(self):
        source = self._source()
        workload = source / "qualification" / "workload-v2"
        workload.mkdir(parents=True)
        fixture = workload / "test_qual_serial.py"
        fixture.write_text(
            "import unittest\n\n"
            "class QualificationFixtureTests(unittest.TestCase):\n"
            "    def test_fixed_workload(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8")
        destination = self.root / "qualification-workload-cut"

        result = loom_release.build_public(
            source, destination, forbidden_tokens=[],
            source_classification="public-release")

        relative = "qualification/workload-v2/test_qual_serial.py"
        self.assertEqual(
            fixture.read_bytes(), (destination / relative).read_bytes())
        self.assertIn(relative, {row["path"] for row in result["files"]})

    def test_suite_separates_correctness_from_cross_platform_capability_skips(self):
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "loom_test.py").write_text("# fixture runner\n", encoding="utf-8")
        report = {
            "capability_complete": False,
            "failures": 0,
            "errors": 0,
            "within_budget": True,
            "status": "passed-with-capability-skips",
            "successful": False,
            "skip_receipts": [{"test": "fixture.posix", "reason": "not on Windows"}],
            "elapsed_seconds": 1.25,
            "tests_run": 10,
            "timings": [],
        }
        operation = {
            "returncode": 1, "receipt_sha256": "a" * 64,
            "status": "failed", "primary_failure": "nonzero-exit",
        }
        cargo_home = self.root / "cargo-home"
        rustup_home = self.root / "rustup-home"
        cargo_home.mkdir()
        rustup_home.mkdir()
        with mock.patch.dict(
                loom_release.os.environ,
                {"CARGO_HOME": str(cargo_home),
                 "RUSTUP_HOME": str(rustup_home)}):
            with mock.patch.object(
                    loom_release.loom_operation_supervisor, "run",
                    return_value=(
                        operation, json.dumps(report).encode("utf-8"),
                        b"10 tests passed; 1 skipped")) as run:
                result = loom_release._suite(self.root)

        self.assertTrue(result["passed"])
        self.assertFalse(result["capability_complete"])
        self.assertEqual("nonzero-exit", result["primary_failure"])
        self.assertEqual("requires-matrix", result["capability_status"])
        self.assertEqual(report["skip_receipts"], result["skip_receipts"])
        command = run.call_args.kwargs["command"]
        self.assertNotIn("--max-seconds", command)
        self.assertIn("--output", command)
        self.assertEqual(loom_release.FULL_SUITE_MAX_SECONDS,
                         run.call_args.kwargs["timeout"])
        environment = run.call_args.kwargs["environment"]
        self.assertEqual(environment["HOME"], environment["USERPROFILE"])
        self.assertEqual(
            str(Path(environment["HOME"]) / ".codex"),
            environment["CODEX_HOME"])
        self.assertEqual(environment["TEMP"], environment["TMP"])
        self.assertEqual(environment["TEMP"], environment["TMPDIR"])
        self.assertEqual(
            str(Path(environment["HOME"]) / "c"),
            environment["LOOM_TEST_CACHE_ROOT"])
        self.assertEqual(str(cargo_home), environment["CARGO_HOME"])
        self.assertEqual(str(rustup_home), environment["RUSTUP_HOME"])
        self.assertEqual(2, len(run.call_args.kwargs["allowed_roots"]))

    def test_suite_failure_names_failed_tests_without_full_transcripts(self):
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "loom_test.py").write_text("# fixture runner\n", encoding="utf-8")
        report = {
            "capability_complete": False,
            "failures": 1,
            "errors": 0,
            "within_budget": True,
            "status": "failed",
            "successful": False,
            "skip_receipts": [],
            "elapsed_seconds": 2.0,
            "tests_run": 2,
            "failure_diagnostics": [{
                "test": "tests.Failed", "status": "failed",
                "exception_type": "NativeHelperBuildError",
                "error_code": "NATIVE_HELPER_BUILD_TIMEOUT",
            }],
            "timings": [
                {"test": "tests.Failed", "seconds": 1.0, "status": "failed"},
                {"test": "tests.Passed", "seconds": 1.0, "status": "passed"},
            ],
        }
        operation = {
            "returncode": 1, "receipt_sha256": "a" * 64,
            "status": "failed", "primary_failure": "nonzero-exit",
        }
        with mock.patch.object(
                loom_release.loom_operation_supervisor, "run",
                return_value=(
                    operation, json.dumps(report).encode("utf-8"), b"failure")):
            result = loom_release._suite(self.root)
        self.assertEqual(1, result["failure_count"])
        self.assertEqual(0, result["error_count"])
        self.assertEqual(
            [{"test": "tests.Failed", "status": "failed"}], result["failed_tests"])
        self.assertEqual(
            report["failure_diagnostics"], result["failure_diagnostics"])

    def test_suite_timeout_preserves_progress_before_disposable_root_cleanup(self):
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "loom_test.py").write_text("# fixture runner\n", encoding="utf-8")
        operation = {
            "returncode": None,
            "receipt_sha256": "a" * 64,
            "status": "failed",
            "primary_failure": "timed-out",
            "survivors_confirmed_zero": True,
            "protected_roots_unchanged": True,
            "network_isolation_proven": False,
            "containment_provider": "windows-job-object",
        }

        def timed_out(**kwargs):
            command = kwargs["command"]
            progress_path = Path(command[command.index("--progress-output") + 1])
            body = {
                "schema_version": 1,
                "status": "running",
                "authorizing": False,
                "diagnostic_policy_sha256": (
                    loom_release.loom_suite_harness._POLICY["policy_sha256"]),
                "selected_modules_sha256": None,
                "checkpoint_sequence": 17,
                "completed_test_count": 732,
                "last_started_test": "test_vault.OwnerVaultTests.test_concurrent",
                "last_completed_test": "test_vault.OwnerVaultTests.test_previous",
            }
            checkpoint = loom_release.loom_suite_harness.seal_progress_checkpoint(body)
            progress_path.write_text(json.dumps(checkpoint), encoding="utf-8")
            return operation, b"", b"private timeout transcript"

        with mock.patch.object(
                loom_release.loom_operation_envelope, "run_supervised",
                side_effect=timed_out):
            result = loom_release._suite(self.root)
        self.assertFalse(result["passed"])
        self.assertEqual("timed-out", result["primary_failure"])
        self.assertEqual(732, result["progress_checkpoint"][
            "completed_test_count"])
        self.assertEqual("test_vault.OwnerVaultTests.test_concurrent",
                         result["progress_checkpoint"]["last_started_test"])
        self.assertTrue(result["operation"]["survivors_confirmed_zero"])
        self.assertTrue(result["operation"]["protected_roots_unchanged"])
        static = {
            "root_sha256": "b" * 64, "manifest_sha256": "c" * 64,
            "files_verified": 1,
        }
        with mock.patch.object(
                loom_release, "verify_cut_static", return_value=static), \
                mock.patch.object(loom_release, "_suite", return_value=result):
            with self.assertRaises(loom_release.ReleaseError) as raised:
                loom_release.verify_cut(self.root, forbidden_tokens=[])

        details = raised.exception.details["suite"]
        self.assertEqual(result["progress_checkpoint"],
                         details["progress_checkpoint"])
        self.assertEqual(result["operation"], details["operation"])

    def test_verify_cut_failure_preserves_child_and_outer_operation_bindings(self):
        projections = []
        for index, (code, primary, survivors, protected) in enumerate((
                ("NATIVE_HELPER_BUILD_TIMEOUT", "timed-out", True, True),
                ("NATIVE_HELPER_BUILD_SURVIVOR",
                 "survivor-census-indeterminate", False, True),
                ("NATIVE_HELPER_BUILD_SOURCE_MUTATION",
                 "protected-root-changed", True, False)), start=1):
            test_id = f"tests.Native.test_{index}"
            operation_body = {
                "operation_receipt_sha256": str(index) * 64,
                "status": "failed", "returncode": None,
                "primary_failure": primary,
                "survivors_confirmed_zero": survivors,
                "protected_roots_unchanged": protected,
                "network_isolation_proven": False,
                "containment_provider": "windows-job-object",
            }
            projection_sha256 = hashlib.sha256(json.dumps(
                operation_body, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False).encode(
                    "utf-8")).hexdigest()
            operation = {
                **operation_body,
                "projection_sha256": projection_sha256,
                "test_association_sha256": hashlib.sha256(json.dumps({
                    "test": test_id, "status": "error",
                    "operation_projection_sha256": projection_sha256,
                }, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False, allow_nan=False).encode(
                        "utf-8")).hexdigest(),
            }
            projections.append({
                "test": test_id, "status": "error",
                "exception_type": "NativeHelperBuildError",
                "error_code": code, "operation_projection": operation,
            })
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "loom_test.py").write_text(
            "# fixture runner\n", encoding="utf-8")
        timing_report = {
            "capability_complete": False,
            "failures": 0, "errors": 3, "within_budget": True,
            "status": "failed", "successful": False,
            "skip_receipts": [], "elapsed_seconds": 3.0,
            "tests_run": 3, "failure_diagnostics": projections,
            "timings": [{
                "test": row["test"], "seconds": 1.0,
                "status": row["status"],
            } for row in projections],
        }
        operation = {
            "returncode": 1, "receipt_sha256": "f" * 64,
            "status": "failed", "primary_failure": "nonzero-exit",
        }
        with mock.patch.object(
                loom_release.loom_operation_supervisor, "run",
                return_value=(operation, json.dumps(timing_report).encode(
                    "utf-8"), b"private output")):
            suite = loom_release._suite(self.root)
        self.assertEqual(projections, suite["failure_diagnostics"])
        self.assertEqual("f" * 64, suite["operation_receipt_sha256"])
        static = {
            "root_sha256": "a" * 64, "manifest_sha256": "b" * 64,
            "files_verified": 1,
        }
        with mock.patch.object(
                loom_release, "verify_cut_static", return_value=static), \
                mock.patch.object(loom_release, "_suite", return_value=suite):
            with self.assertRaises(loom_release.ReleaseError) as raised:
                loom_release.verify_cut(self.root, forbidden_tokens=[])

        details = raised.exception.details["suite"]
        self.assertEqual("f" * 64, details["operation_receipt_sha256"])
        self.assertEqual(projections, details["failure_diagnostics"])
        self.assertNotIn("output", details)

    def _source(self):
        source = self.root / "source"
        (source / "tools").mkdir(parents=True)
        (source / "docs").mkdir()
        (source / "skill" / "loom").mkdir(parents=True)
        (source / "README.md").write_text(
            "Loom 1.0.0 /loom <request>\n", encoding="utf-8")
        (source / "START-HERE.md").write_text(
            "Loom 1.0.0 /loom <request>\n", encoding="utf-8")
        (source / "VERSION").write_text("1.0.0\n", encoding="utf-8")
        (source / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.97.1"\nprofile = "minimal"\n',
            encoding="utf-8",
        )
        (source / ".gitignore").write_text("__pycache__/\n*.py[cod]\n", encoding="utf-8")
        (source / ".mcp.json").write_text(
            json.dumps({"mcpServers": {}}) + "\n", encoding="utf-8")
        (source / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (source / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        (source / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
        (source / "PRIVACY.md").write_text("# Privacy\n", encoding="utf-8")
        (source / "TERMS.md").write_text("# Terms\n", encoding="utf-8")
        (source / "tools" / "loom_example.py").write_text("VALUE = 1\n", encoding="utf-8")
        (source / "tools" / "test_smoke.py").write_text(
            "import unittest\n\n"
            "class SmokeTest(unittest.TestCase):\n"
            "    def test_public_cut_runs(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8")
        (source / "docs" / "index.html").write_text(
            "<!doctype html><title>Loom 1.0.0 /loom &lt;request&gt;</title>\n",
            encoding="utf-8")
        (source / "docs" / "architecture.md").write_text(
            "# Loom 1.0.0 architecture\n", encoding="utf-8")
        (source / "docs" / "capabilities.json").write_text(json.dumps({
            "schema_version": 1, "version": "1.0.0", "capabilities": [],
        }), encoding="utf-8")
        (source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\ndescription: Loom 1.0.0 /loom <request>\n---\n",
            encoding="utf-8")
        (source / "docs" / "generated-evidence.json").write_text(
            json.dumps(loom_docs.generate_evidence(source), indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        (source / "private").mkdir()
        (source / "private" / "owner-grounding.txt").write_text(
            "real-owner-token\nowner-token\n", encoding="utf-8")
        return source

    def test_public_builder_never_traverses_excluded_mutating_rust_target(self):
        source = self._source()
        (source / "vault-helper" / "target" / "debug").mkdir(parents=True)
        (source / "vault-helper" / "target" / "debug" / "transient").write_text(
            "compiler scratch", encoding="utf-8")
        destination = self.root / "public-cut"
        real_scandir = loom_release.os.scandir

        def guarded_scandir(path):
            if "target" in Path(path).parts:
                raise FileNotFoundError("simulated concurrent Cargo replacement")
            return real_scandir(path)

        with mock.patch.object(loom_release.os, "scandir", side_effect=guarded_scandir):
            result = loom_release.build_public(
                source, destination, forbidden_tokens=[],
                source_classification="public-release")
        self.assertEqual("built", result["status"])
        self.assertFalse((destination / "vault-helper" / "target").exists())

    @staticmethod
    def _sign_item(item):
        signed = {key: value for key, value in item.items() if key != "attestation"}
        signed["attestation"] = {
            "algorithm": item["attestation"]["algorithm"],
            "key_id": item["attestation"]["key_id"],
        }
        digest_info = loom_release.SHA256_DIGEST_INFO + hashlib.sha256(
            loom_release._canonical_bytes(signed)).digest()
        size = (TEST_RSA_N.bit_length() + 7) // 8
        encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) \
            + b"\x00" + digest_info
        signature = pow(int.from_bytes(encoded, "big"), TEST_RSA_D, TEST_RSA_N)
        item["attestation"]["signature"] = base64.b64encode(
            signature.to_bytes(size, "big")).decode("ascii")

    def _signed_external_evidence(self):
        subject = {
            "repository": "https://github.com/example/loom",
            "commit_sha": "a" * 40,
            "root_sha256": "b" * 64,
        }
        specifications = {
            "cross-platform-ci": ("github-actions", {
                "run_id": 42, "run_url": "https://github.com/example/loom/actions/runs/42",
                "total_jobs": 12, "passed_jobs": 12, "conclusion": "success",
                "jobs": [
                    {"id": 100 + os_index * 4 + python_index,
                     "os": os_name, "python": version, "conclusion": "success",
                     "url": ("https://github.com/example/loom/actions/runs/42/job/"
                             f"{100 + os_index * 4 + python_index}")}
                    for os_index, os_name in enumerate(
                        ("ubuntu-latest", "macos-latest", "windows-latest"))
                    for python_index, version in enumerate(
                        ("3.10", "3.11", "3.12", "3.13"))
                ]}),
            "unfamiliar-user-usability": ("independent-participant", {
                "study_id": "study-7",
                "study_bundle_sha256": "2" * 64,
                "public_build_sha256": "b" * 64,
                "participant_count": 1,
                "unfamiliar_participant_count": 1,
                "clean_environment_count": 1,
                "fresh_install_count": 1,
                "real_request_completion_count": 1,
                "completed_without_maintainer_count": 1,
                "coaching_event_count": 0,
                "install_receipt_bundle_sha256": "3" * 64,
                "request_receipt_bundle_sha256": "4" * 64}),
            "independent-hostile-review": ("independent-reviewer", {
                "report_sha256": "c" * 64,
                "review_bundle_sha256": "5" * 64,
                "reproduced_build_sha256": "b" * 64,
                "critical_findings": 0, "high_findings": 0,
                "scope_complete": True, "reviewer_independent": True}),
            "production-performance": ("independent-benchmark", {
                "provider_attested": True,
                "receipt_bundle_sha256": "d" * 64,
                "measurement_bundle_sha256": "e" * 64,
                "sample_count": 24, "workload_count": 4,
                "workloads": [
                    {"id": "tiny-cli", "tier": "S", "sample_count": 6,
                     "p50_total_tokens": 800, "p95_total_tokens": 1200,
                     "worst_total_tokens": 1500, "token_budget": 2000,
                     "p95_wall_ms": 900, "worst_wall_ms": 1200,
                     "wall_budget_ms": 1500},
                    {"id": "medium-mobile", "tier": "M", "sample_count": 6,
                     "p50_total_tokens": 3000, "p95_total_tokens": 4500,
                     "worst_total_tokens": 5500, "token_budget": 6000,
                     "p95_wall_ms": 1800, "worst_wall_ms": 2400,
                     "wall_budget_ms": 3000},
                    {"id": "large-etl", "tier": "L", "sample_count": 6,
                     "p50_total_tokens": 9000, "p95_total_tokens": 13000,
                     "worst_total_tokens": 15000, "token_budget": 16000,
                     "p95_wall_ms": 3200, "worst_wall_ms": 4000,
                     "wall_budget_ms": 5000},
                    {"id": "portfolio", "tier": "XL", "sample_count": 6,
                     "p50_total_tokens": 24000, "p95_total_tokens": 34000,
                     "worst_total_tokens": 39000, "token_budget": 40000,
                     "p95_wall_ms": 6000, "worst_wall_ms": 7500,
                     "wall_budget_ms": 9000}],
                "successful_samples": 24, "regression_status": "passed"}),
            "production-memory-replay": ("independent-benchmark", {
                "provider_attested": True,
                "session_bundle_sha256": "f" * 64,
                "replay_bundle_sha256": "1" * 64,
                "production_session_count": 32, "pair_count": 16,
                "simulation_count": 0, "exact_domain": True,
                "improvement_reproduced": True,
                "regression_guard_passed": True,
                "claims": [{
                    "metric": "memory-help-rate", "domain": "cli",
                    "scope": "exact-domain", "longitudinal_sample_count": 16,
                    "replay_pair_count": 8, "longitudinal_status": "improved",
                    "replay_status": "improved", "regression_alarm": False},
                    {"metric": "prediction-calibration-error", "domain": "general",
                     "scope": "general-calibration", "longitudinal_sample_count": 16,
                     "replay_pair_count": 8, "longitudinal_status": "improved",
                     "replay_status": "improved", "regression_alarm": False}]}),
        }
        evidence = {}
        issuers = []
        for index, (check_id, (kind, payload)) in enumerate(specifications.items(), 1):
            issuer_id = f"issuer-{index}"
            key_id = f"key-{index}"
            item = {
                "schema_version": 1, "check_id": check_id, "status": "passed",
                "evidence_id": "pending", "subject": subject,
                "issued_at": "2026-07-15T00:00:00Z",
                "expires_at": "2026-08-15T00:00:00Z",
                "issuer": {"id": issuer_id, "kind": kind, "independent": True},
                "payload": payload,
                "payload_sha256": loom_release._canonical_hash(payload),
                "attestation": {"algorithm": "rsa-pkcs1v15-sha256",
                                "key_id": key_id, "signature": "pending"},
            }
            item["evidence_id"] = loom_release._external_evidence_id(item)
            self._sign_item(item)
            evidence[check_id] = item
            issuers.append({
                "id": issuer_id, "kind": kind, "key_id": key_id,
                "algorithm": "rsa-pkcs1v15-sha256",
                "modulus_hex": f"{TEST_RSA_N:x}", "exponent": 65537,
                "checks": [check_id], "independent": True,
            })
        return evidence, {"schema_version": 1, "subject": subject, "issuers": issuers}

    @staticmethod
    def _sealed_local_evidence(subject):
        value = {
            "schema_version": 1, "status": "passed",
            "verification_id": str(uuid.UUID(int=100)), "subject": subject,
            "verified_at": "2026-07-15T00:00:00Z",
            "expires_at": "2026-07-17T00:00:00Z",
            "local_checks": {key: True for key in loom_release.LOCAL_CHECKS},
            "evidence": {"suite": {"passed": True, "returncode": 0}},
        }
        value["evidence_sha256"] = loom_release._canonical_hash(value)
        return value

    def test_public_build_is_reproducible_and_refuses_owner_content(self):
        source = self._source()
        first = loom_release.build_public(
            source, self.root / "first", forbidden_tokens=["real-owner-token"])
        second = loom_release.build_public(
            source, self.root / "second", forbidden_tokens=["real-owner-token"])
        self.assertEqual(first["root_sha256"], second["root_sha256"])
        self.assertTrue(first["firewall"]["clean"])
        self.assertEqual(first["files"], second["files"])
        self.assertEqual({
            "source_classification": "private-owner",
            "configured_count": 1, "grounded_count": 1,
            "grounding_status": "grounded-private-source",
            "protection_claimed": True,
        }, first["owner_token_policy"])
        self.assertEqual(
            "__pycache__/\n*.py[cod]\n",
            (self.root / "first" / ".gitignore").read_text(encoding="utf-8"))

        (source / "docs" / "private.bin").write_bytes(b"prefix REAL-OWNER-TOKEN suffix")
        refused = self.root / "refused"
        with self.assertRaisesRegex(loom_release.ReleaseError, "firewall"):
            loom_release.build_public(
                source, refused, forbidden_tokens=["real-owner-token"])
        self.assertFalse(refused.exists())

    def test_private_build_refuses_owner_policy_that_would_protect_nothing(self):
        source = self._source()
        destination = self.root / "dummy-policy"

        with self.assertRaisesRegex(loom_release.ReleaseError, "protect nothing"):
            loom_release.build_public(
                source, destination,
                forbidden_tokens=["__definitely_not_an_owner_token_9f4c2d__"])

        self.assertFalse(destination.exists())

    def test_public_source_build_does_not_claim_owner_token_grounding(self):
        source = self._source()
        result = loom_release.build_public(
            source, self.root / "public-source",
            forbidden_tokens=["__scan_only_defense_in_depth__"],
            source_classification="public-release")

        self.assertEqual({
            "source_classification": "public-release",
            "configured_count": 1, "grounded_count": 0,
            "grounding_status": "not-applicable-public-source",
            "protection_claimed": False,
        }, result["owner_token_policy"])

    def test_public_source_build_needs_no_dummy_owner_token(self):
        source = self._source()
        cut = self.root / "public-source-no-token"
        result = loom_release.build_public(
            source, cut,
            forbidden_tokens=[], source_classification="public-release")
        self.assertEqual({
            "source_classification": "public-release",
            "configured_count": 0, "grounded_count": 0,
            "grounding_status": "not-applicable-public-source",
            "protection_claimed": False,
        }, result["owner_token_policy"])
        verified = loom_release.verify_cut(cut, forbidden_tokens=[])
        self.assertEqual("verified", verified["status"])
        self.assertTrue(verified["firewall"]["clean"])
        self.assertEqual([], verified["firewall"]["findings"])

    def test_public_local_verification_does_not_demand_fake_owner_tokens(self):
        source = self._source()
        with mock.patch.object(
                loom_release, "_git_release_identity",
                side_effect=loom_release.ReleaseError("identity-probe-reached")) as identity:
            with self.assertRaisesRegex(
                    loom_release.ReleaseError, "private/owner tokens"):
                loom_release.verify_local(
                    source, forbidden_tokens=[], source_classification="private-owner")
            identity.assert_not_called()
            with self.assertRaisesRegex(
                    loom_release.ReleaseError, "identity-probe-reached"):
                loom_release.verify_local(
                    source, forbidden_tokens=[], source_classification="public-release")
            identity.assert_called_once()

    def test_pristine_public_cut_is_independently_verifiable_without_git(self):
        source = self._source()
        built = self.root / "verified-cut"
        build = loom_release.build_public(
            source, built, forbidden_tokens=["scan-only-token"],
            source_classification="public-release")

        result = loom_release.verify_cut(
            built, forbidden_tokens=["scan-only-token"])

        self.assertEqual("verified", result["status"])
        self.assertEqual(build["root_sha256"], result["root_sha256"])
        self.assertTrue(result["firewall"]["clean"])
        self.assertEqual("passed", result["docs"]["status"])
        self.assertTrue(result["offline"]["offline"])

    def test_static_cut_verification_never_executes_behavior(self):
        source = self._source()
        built = self.root / "static-cut"
        build = loom_release.build_public(
            source, built, forbidden_tokens=["scan-only-token"],
            source_classification="public-release")
        with mock.patch.object(
                loom_release, "_suite",
                side_effect=AssertionError("behavior must not run")):
            result = loom_release.verify_cut_static(
                built, forbidden_tokens=["scan-only-token"])
        self.assertEqual("verified-static", result["status"])
        self.assertEqual(1, result["schema_version"])
        self.assertEqual(64, len(result["receipt_sha256"]))
        self.assertEqual(build["root_sha256"], result["root_sha256"])
        self.assertTrue(result["firewall"]["clean"])
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "static-receipt", result,
            "release-static-receipt-v1.schema.json")
        self.assertEqual([], report.errors)

    def test_public_cut_verifier_rejects_undeclared_post_build_bytecode(self):
        source = self._source()
        built = self.root / "contaminated-cut"
        loom_release.build_public(
            source, built, forbidden_tokens=["scan-only-token"],
            source_classification="public-release")
        bytecode = built / "tools" / "__pycache__" / "host-path.pyc"
        bytecode.parent.mkdir()
        bytecode.write_bytes(b"C:\\Users\\Owner\\private-host-path")

        with self.assertRaisesRegex(loom_release.ReleaseError, "sealed manifest"):
            loom_release.verify_cut(
                built, forbidden_tokens=["private-host-path"])

    def test_private_owner_grounding_translates_unsafe_tree_to_release_refusal(self):
        source = self._source()
        with mock.patch.object(
                loom_reliability, "_regular_files",
                side_effect=loom_reliability.ReliabilityError("seeded unsafe tree")):
            with self.assertRaisesRegex(loom_release.ReleaseError, "grounding failed"):
                loom_release.build_public(
                    source, self.root / "unsafe-tree",
                    forbidden_tokens=["real-owner-token"])

    def test_public_source_traversal_error_is_structured_and_leaves_no_destination(self):
        source = self._source()
        destination = self.root / "unsafe-public-tree"
        with mock.patch.object(
                loom_reliability, "_regular_files",
                side_effect=loom_reliability.ReliabilityError("seeded unsafe tree")):
            with self.assertRaisesRegex(loom_release.ReleaseError, "traversal failed"):
                loom_release.build_public(
                    source, destination, forbidden_tokens=["scan-token"],
                    source_classification="public-release")
        self.assertFalse(destination.exists())

    def test_installer_cycle_checks_and_removes_only_receipt_proven_files(self):
        source = self._source()
        built = self.root / "built"
        loom_release.build_public(source, built, forbidden_tokens=["owner-token"])
        target = self.root / "installed"
        installed = loom_install.install(built, target)
        marker = target / ".loom-instance-id"
        self.assertTrue(marker.is_file())
        self.assertEqual(36, len(marker.read_text(encoding="utf-8").strip()))
        checked = loom_install.check(target)
        self.assertEqual("installed", checked["status"])
        self.assertEqual(installed["install_id"], checked["install_id"])
        self.assertEqual((built / "skill" / "loom" / "SKILL.md").read_bytes(),
                         (target / "SKILL.md").read_bytes())
        removed = loom_install.uninstall(
            target, confirmation=installed["install_id"])
        self.assertEqual("uninstalled", removed["status"])
        self.assertFalse(target.exists())

    def test_concurrent_identical_install_reuses_only_verified_matching_bytes(self):
        source = self._source()
        target = self.root / "concurrent-installed"
        first = loom_install.install(source, target)
        second = loom_install.install(source, target)

        self.assertFalse(first["reused_existing"])
        self.assertTrue(second["reused_existing"])
        self.assertEqual(0, second["files_installed"])
        self.assertEqual(first["install_id"], second["install_id"])

        changed = self.root / "changed-source"
        shutil.copytree(source, changed)
        (changed / "README.md").write_text("different bytes\n", encoding="utf-8")
        with self.assertRaisesRegex(
                loom_install.InstallError, "different bytes"):
            loom_install.install(changed, target)

    def test_installer_waits_for_os_released_lock_after_process_termination(self):
        source = self._source()
        target = self.root / "post-termination-install"
        marker = self.root / "lock-held"
        lock_path = loom_install._lock_path(target)
        child_script = (
            "import pathlib,sys,time;"
            "sys.path.insert(0,sys.argv[1]);"
            "import loom_reliability;"
            "lock=loom_reliability.exclusive_file_lock(sys.argv[2],timeout=5);"
            "lock.__enter__();"
            "pathlib.Path(sys.argv[3]).write_text('ready',encoding='utf-8');"
            "time.sleep(60)"
        )
        holder = subprocess.Popen(
            [sys.executable, "-B", "-c", child_script,
             str(Path(loom_install.__file__).parent), str(lock_path), str(marker)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        installer = None
        try:
            deadline = time.monotonic() + 10
            while not marker.is_file():
                if holder.poll() is not None:
                    stdout, stderr = holder.communicate()
                    self.fail(
                        f"lock holder exited early: {stdout!r} {stderr!r}")
                if time.monotonic() >= deadline:
                    self.fail("lock holder did not acquire the install lock")
                time.sleep(0.02)
            installer = subprocess.Popen(
                [sys.executable, "-B", str(Path(loom_install.__file__)),
                 "install", str(source), str(target)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.1)
            self.assertIsNone(installer.poll())
            holder.terminate()
            holder.wait(timeout=10)
            holder.communicate()
            stdout, stderr = installer.communicate(timeout=20)
            self.assertEqual(
                0, installer.returncode,
                f"stdout={stdout!r}; stderr={stderr!r}")
            self.assertEqual("installed", loom_install.check(target)["status"])
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=10)
            holder.communicate()
            if installer is not None and installer.poll() is None:
                installer.kill()
                installer.wait(timeout=10)

    def test_source_installer_excludes_only_known_generated_rust_build_trees(self):
        source = self._source()
        (source / "vault-helper" / "target" / "debug").mkdir(parents=True)
        (source / "vault-helper" / "target" / "debug" / "loom-vault.exe").write_bytes(
            b"generated-root-target")
        (source / "vault-helper" / "fuzz" / "target" / "debug").mkdir(parents=True)
        (source / "vault-helper" / "fuzz" / "target" / "debug" / "fuzzer.exe").write_bytes(
            b"generated-fuzz-target")
        (source / "docs" / "target").mkdir(parents=True)
        (source / "docs" / "target" / "legitimate.txt").write_text(
            "install this\n", encoding="utf-8")

        target = self.root / "installed-source"
        installed = loom_install.install(source, target)
        receipt = json.loads(
            (target / loom_install.RECEIPT).read_text(encoding="utf-8"))
        installed_paths = {item["path"] for item in receipt["files"]}

        self.assertEqual("installed", installed["status"])
        self.assertFalse((target / "vault-helper" / "target").exists())
        self.assertFalse((target / "vault-helper" / "fuzz" / "target").exists())
        self.assertTrue((target / "docs" / "target" / "legitimate.txt").is_file())
        self.assertIn("docs/target/legitimate.txt", installed_paths)
        self.assertFalse(any(
            path.startswith("vault-helper/target/")
            or path.startswith("vault-helper/fuzz/target/")
            for path in installed_paths))

    def test_uninstaller_fails_closed_before_deleting_any_file_when_one_changed(self):
        source = self._source()
        built = self.root / "built"
        loom_release.build_public(source, built, forbidden_tokens=["owner-token"])
        target = self.root / "installed"
        installed = loom_install.install(built, target)
        readme = target / "README.md"
        readme.write_text("changed by owner\n", encoding="utf-8")
        version_before = (target / "VERSION").read_bytes()
        with self.assertRaisesRegex(loom_install.InstallError, "changed"):
            loom_install.uninstall(target, confirmation=installed["install_id"])
        self.assertTrue(readme.is_file())
        self.assertEqual(version_before, (target / "VERSION").read_bytes())

    def test_release_certification_stays_blocked_without_external_evidence(self):
        subject = {"repository": "https://github.com/example/loom",
                   "commit_sha": "a" * 40, "root_sha256": "b" * 64}
        report = loom_release.certification_report(
            local_checks=self._sealed_local_evidence(subject), external_evidence={},
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))
        self.assertEqual("blocked", report["status"])
        self.assertLess(report["score"], 100)
        self.assertEqual({
            "cross-platform-ci", "unfamiliar-user-usability",
            "independent-hostile-review", "production-performance",
            "production-memory-replay",
        }, {item["id"] for item in report["unverified"]})

    def test_external_evidence_contract_rejects_high_findings_and_accepts_proof(self):
        external, trust_policy = self._signed_external_evidence()
        local = self._sealed_local_evidence(trust_policy["subject"])
        instant = dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc)
        passed = loom_release.certification_report(
            local_checks=local, external_evidence=external,
            trust_policy=trust_policy, now=instant)
        self.assertEqual("certified", passed["status"])
        self.assertEqual(100, passed["score"])
        external["independent-hostile-review"]["payload"]["high_findings"] = 1
        blocked = loom_release.certification_report(
            local_checks=local, external_evidence=external,
            trust_policy=trust_policy, now=instant)
        self.assertEqual("blocked", blocked["status"])

    def test_cross_platform_evidence_requires_exact_os_python_matrix(self):
        external, trust_policy = self._signed_external_evidence()
        ci = external["cross-platform-ci"]
        ci["payload"] = {
            "run_id": 42,
            "run_url": "https://github.com/example/loom/actions/runs/42",
            "total_jobs": 3,
            "passed_jobs": 3,
            "conclusion": "success",
            "jobs": [
                {"id": index, "os": "ubuntu-latest", "python": version,
                 "conclusion": "success",
                 "url": f"https://github.com/example/loom/actions/runs/42/job/{index}"}
                for index, version in enumerate(("3.10", "3.11", "3.12"), 1)
            ],
        }
        ci["payload_sha256"] = loom_release._canonical_hash(ci["payload"])
        self._sign_item(ci)
        local = self._sealed_local_evidence(trust_policy["subject"])

        report = loom_release.certification_report(
            local_checks=local, external_evidence=external,
            trust_policy=trust_policy,
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))

        self.assertEqual("blocked", report["status"])
        self.assertIn(
            "cross-platform-ci", {item["id"] for item in report["unverified"]})

    def test_usability_evidence_requires_fresh_install_and_real_request_receipts(self):
        external, trust_policy = self._signed_external_evidence()
        usability = external["unfamiliar-user-usability"]
        usability["payload"] = {
            "participant_count": 1,
            "completed_without_maintainer": True,
        }
        usability["payload_sha256"] = loom_release._canonical_hash(
            usability["payload"])
        self._sign_item(usability)
        local = self._sealed_local_evidence(trust_policy["subject"])

        report = loom_release.certification_report(
            local_checks=local, external_evidence=external,
            trust_policy=trust_policy,
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))

        self.assertEqual("blocked", report["status"])
        self.assertIn(
            "unfamiliar-user-usability",
            {item["id"] for item in report["unverified"]})

    def test_hostile_review_requires_bound_report_bundle_and_complete_scope(self):
        external, trust_policy = self._signed_external_evidence()
        review = external["independent-hostile-review"]
        review["payload"] = {"critical_findings": 0, "high_findings": 0}
        review["payload_sha256"] = loom_release._canonical_hash(review["payload"])
        self._sign_item(review)
        local = self._sealed_local_evidence(trust_policy["subject"])

        report = loom_release.certification_report(
            local_checks=local, external_evidence=external,
            trust_policy=trust_policy,
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))

        self.assertEqual("blocked", report["status"])
        self.assertIn(
            "independent-hostile-review",
            {item["id"] for item in report["unverified"]})

    def test_certification_rejects_self_asserted_unbound_evidence(self):
        subject = {"repository": "https://github.com/example/loom",
                   "commit_sha": "a" * 40, "root_sha256": "b" * 64}
        local = self._sealed_local_evidence(subject)
        fabricated = {
            "cross-platform-ci": {"status": "passed", "evidence": "trust me"},
            "unfamiliar-user-usability": {
                "status": "passed", "evidence": "trust me", "participant_count": 1},
            "independent-hostile-review": {
                "status": "passed", "evidence": "trust me",
                "critical_findings": 0, "high_findings": 0},
            "production-performance": {
                "status": "passed", "evidence": "trust me",
                "provider_attested": True, "sample_count": 100},
            "production-memory-replay": {
                "status": "passed", "evidence": "trust me",
                "provider_attested": True, "pair_count": 100},
        }

        report = loom_release.certification_report(
            local_checks=local, external_evidence=fabricated,
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))

        self.assertEqual("blocked", report["status"])
        self.assertFalse(report["claim_100_allowed"])
        self.assertEqual(
            {"cross-platform-ci", "unfamiliar-user-usability",
             "independent-hostile-review", "production-performance",
             "production-memory-replay"},
            {item["id"] for item in report["unverified"]})

    def test_production_performance_requires_provider_attested_complete_distribution(self):
        external, trust_policy = self._signed_external_evidence()
        local = self._sealed_local_evidence(trust_policy["subject"])
        instant = dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc)
        invalid_values = (
            ("provider_attested", False),
            ("sample_count", 19),
            ("workload_count", 3),
            ("successful_samples", 23),
            ("regression_status", "failed"),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(external)
                item = candidate["production-performance"]
                item["payload"][field] = value
                item["payload_sha256"] = loom_release._canonical_hash(item["payload"])
                self._sign_item(item)
                report = loom_release.certification_report(
                    local_checks=local, external_evidence=candidate,
                    trust_policy=trust_policy, now=instant)
                self.assertEqual("blocked", report["status"])
                self.assertIn("production-performance", {
                    check["id"] for check in report["unverified"]})
        candidate = copy.deepcopy(external)
        item = candidate["production-performance"]
        item["payload"]["workloads"][0]["p95_total_tokens"] = 2100
        item["payload_sha256"] = loom_release._canonical_hash(item["payload"])
        self._sign_item(item)
        report = loom_release.certification_report(
            local_checks=local, external_evidence=candidate,
            trust_policy=trust_policy, now=instant)
        self.assertEqual("blocked", report["status"])

    def test_production_replay_requires_real_provider_attested_paired_sessions(self):
        external, trust_policy = self._signed_external_evidence()
        local = self._sealed_local_evidence(trust_policy["subject"])
        instant = dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc)
        invalid_values = (
            ("provider_attested", False),
            ("production_session_count", 15),
            ("pair_count", 7),
            ("simulation_count", 1),
            ("exact_domain", False),
            ("improvement_reproduced", False),
            ("regression_guard_passed", False),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(external)
                item = candidate["production-memory-replay"]
                item["payload"][field] = value
                item["payload_sha256"] = loom_release._canonical_hash(item["payload"])
                self._sign_item(item)
                report = loom_release.certification_report(
                    local_checks=local, external_evidence=candidate,
                    trust_policy=trust_policy, now=instant)
                self.assertEqual("blocked", report["status"])
                self.assertIn("production-memory-replay", {
                    check["id"] for check in report["unverified"]})

    def test_local_verification_names_mechanical_performance_truthfully(self):
        self.assertIn("performance_contracts", loom_release.LOCAL_CHECKS)
        self.assertNotIn("performance_budgets", loom_release.LOCAL_CHECKS)
        result = loom_release._performance_contracts()
        self.assertTrue(result["passed"], result)
        self.assertFalse(result["certifies_production_usage"])

    def test_certification_rejects_unsealed_local_boolean_map(self):
        external, trust_policy = self._signed_external_evidence()
        local = {key: True for key in loom_release.LOCAL_CHECKS}

        report = loom_release.certification_report(
            local_checks=local, external_evidence=external,
            trust_policy=trust_policy,
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))

        self.assertEqual("blocked", report["status"])
        self.assertFalse(report["claim_100_allowed"])
        self.assertIn("local-verification", {
            item["id"] for item in report["unverified"]})

    def test_signed_evidence_is_content_bound_unique_relevant_and_fresh(self):
        external, trust_policy = self._signed_external_evidence()
        local = self._sealed_local_evidence(trust_policy["subject"])
        instant = dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc)

        tampered = copy.deepcopy(external)
        tampered["independent-hostile-review"]["payload"]["high_findings"] = 1
        duplicate = copy.deepcopy(external)
        duplicate["unfamiliar-user-usability"]["evidence_id"] = \
            duplicate["cross-platform-ci"]["evidence_id"]
        self._sign_item(duplicate["unfamiliar-user-usability"])
        irrelevant_policy = copy.deepcopy(trust_policy)
        irrelevant_policy["issuers"][1]["checks"] = ["independent-hostile-review"]

        for evidence, policy, now in (
                (tampered, trust_policy, instant),
                (external, trust_policy, dt.datetime(
                    2026, 9, 1, tzinfo=dt.timezone.utc)),
                (duplicate, trust_policy, instant),
                (external, irrelevant_policy, instant)):
            with self.subTest(evidence=evidence, policy=policy, now=now):
                report = loom_release.certification_report(
                    local_checks=local, external_evidence=evidence,
                    trust_policy=policy, now=now)
                self.assertEqual("blocked", report["status"])
                self.assertFalse(report["claim_100_allowed"])

    def test_external_evidence_id_cannot_be_reused_for_different_signed_content(self):
        external, trust_policy = self._signed_external_evidence()
        local = self._sealed_local_evidence(trust_policy["subject"])
        reused = copy.deepcopy(external)
        item = reused["unfamiliar-user-usability"]
        original_id = item["evidence_id"]
        item["payload"]["study_id"] = "different-study"
        item["payload_sha256"] = loom_release._canonical_hash(item["payload"])
        self._sign_item(item)

        self.assertEqual(original_id, item["evidence_id"])
        report = loom_release.certification_report(
            local_checks=local, external_evidence=reused,
            trust_policy=trust_policy,
            now=dt.datetime(2026, 7, 16, tzinfo=dt.timezone.utc))
        self.assertEqual("blocked", report["status"])
        self.assertIn("unfamiliar-user-usability", {
            value["id"] for value in report["unverified"]})

    def test_local_release_evidence_is_commit_and_content_bound(self):
        subject = {"repository": "https://github.com/example/loom",
                   "commit_sha": "a" * 40, "root_sha256": "b" * 64}
        instant = dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc)
        sealed = loom_release.seal_local_evidence(
            subject=subject,
            local_checks={key: True for key in loom_release.LOCAL_CHECKS},
            evidence={"suite": {"passed": True, "returncode": 0}}, now=instant)

        self.assertIsNotNone(loom_release._validated_local_evidence(
            sealed, now=instant + dt.timedelta(hours=1)))
        tampered = copy.deepcopy(sealed)
        tampered["subject"]["commit_sha"] = "c" * 40
        self.assertIsNone(loom_release._validated_local_evidence(
            tampered, now=instant + dt.timedelta(hours=1)))
        tampered = copy.deepcopy(sealed)
        tampered["local_checks"]["suite"] = False
        self.assertIsNone(loom_release._validated_local_evidence(
            tampered, now=instant + dt.timedelta(hours=1)))

    def test_release_identity_requires_clean_committed_github_source(self):
        root = self.root / "repository"
        root.mkdir()

        def git(*args):
            return subprocess.run(
                ["git", "-C", str(root), *args], check=True,
                capture_output=True, text=True, encoding="utf-8")

        git("init", "-q")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "test")
        (root / "README.md").write_text("fixture\n", encoding="utf-8")
        git("add", "README.md")
        git("commit", "-qm", "fixture")
        git("remote", "add", "origin", "git@github.com:example/loom.git")

        identity = loom_release._git_release_identity(root)

        self.assertEqual("https://github.com/example/loom", identity["repository"])
        self.assertRegex(identity["commit_sha"], r"^[0-9a-f]{40}$")
        (root / "dirty.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_release.ReleaseError, "clean committed"):
            loom_release._git_release_identity(root)

    def test_public_release_evidence_redacts_local_home_and_repository_paths(self):
        local_home = self.root / "private-home"
        repository = local_home / "private-repository"
        suite = loom_release.sanitize_suite_evidence({
            "passed": True, "returncode": 0,
            "output": f"ERROR {repository}\\pack.md\nowner {local_home}\n",
        }, root=repository, home=local_home)
        self.assertNotIn(str(local_home), suite["output"])
        self.assertNotIn(str(repository), suite["output"])
        self.assertIn("[LOCAL_ROOT]", suite["output"])


if __name__ == "__main__":
    unittest.main()
