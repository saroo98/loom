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

import loom_install
import loom_release


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

    def _source(self):
        source = self.root / "source"
        (source / "tools").mkdir(parents=True)
        (source / "docs").mkdir()
        (source / "skill" / "loom").mkdir(parents=True)
        (source / "README.md").write_text("/loom <request>\n", encoding="utf-8")
        (source / "START-HERE.md").write_text("/loom <request>\n", encoding="utf-8")
        (source / "VERSION").write_text("1.0.0\n", encoding="utf-8")
        (source / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (source / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        (source / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
        (source / "PRIVACY.md").write_text("# Privacy\n", encoding="utf-8")
        (source / "tools" / "loom_example.py").write_text("VALUE = 1\n", encoding="utf-8")
        (source / "docs" / "index.html").write_text("<!doctype html>\n", encoding="utf-8")
        (source / "skill" / "loom" / "SKILL.md").write_text(
            "---\nname: loom\n---\n", encoding="utf-8")
        return source

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
                "total_jobs": 12, "passed_jobs": 12, "conclusion": "success"}),
            "unfamiliar-user-usability": ("independent-participant", {
                "study_id": "study-7", "participant_count": 1,
                "completed_without_maintainer": True}),
            "independent-hostile-review": ("independent-reviewer", {
                "report_sha256": "c" * 64, "critical_findings": 0,
                "high_findings": 0}),
        }
        evidence = {}
        issuers = []
        for index, (check_id, (kind, payload)) in enumerate(specifications.items(), 1):
            issuer_id = f"issuer-{index}"
            key_id = f"key-{index}"
            item = {
                "schema_version": 1, "check_id": check_id, "status": "passed",
                "evidence_id": str(uuid.UUID(int=index)), "subject": subject,
                "issued_at": "2026-07-15T00:00:00Z",
                "expires_at": "2026-08-15T00:00:00Z",
                "issuer": {"id": issuer_id, "kind": kind, "independent": True},
                "payload": payload,
                "payload_sha256": loom_release._canonical_hash(payload),
                "attestation": {"algorithm": "rsa-pkcs1v15-sha256",
                                "key_id": key_id, "signature": "pending"},
            }
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

        (source / "docs" / "private.bin").write_bytes(b"prefix REAL-OWNER-TOKEN suffix")
        refused = self.root / "refused"
        with self.assertRaisesRegex(loom_release.ReleaseError, "firewall"):
            loom_release.build_public(
                source, refused, forbidden_tokens=["real-owner-token"])
        self.assertFalse(refused.exists())

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
            "independent-hostile-review",
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
        }

        report = loom_release.certification_report(
            local_checks=local, external_evidence=fabricated)

        self.assertEqual("blocked", report["status"])
        self.assertFalse(report["claim_100_allowed"])
        self.assertEqual(
            {"cross-platform-ci", "unfamiliar-user-usability",
             "independent-hostile-review"},
            {item["id"] for item in report["unverified"]})

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
