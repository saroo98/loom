import base64
import copy
import datetime as dt
import hashlib
import json
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import loom_install
import loom_docs
import loom_release
import loom_reliability


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

    def tearDown(self):
        self.tmp.cleanup()

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
        completed = mock.Mock(
            returncode=1, stdout=json.dumps(report), stderr="10 tests passed; 1 skipped")
        with mock.patch.object(subprocess, "run", return_value=completed):
            result = loom_release._suite(self.root)

        self.assertTrue(result["passed"])
        self.assertFalse(result["capability_complete"])
        self.assertEqual("requires-matrix", result["capability_status"])
        self.assertEqual(report["skip_receipts"], result["skip_receipts"])

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
        (source / ".gitignore").write_text("__pycache__/\n*.py[cod]\n", encoding="utf-8")
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
            local_checks=local, external_evidence=fabricated)

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
