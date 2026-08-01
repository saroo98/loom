"""Release-specific readiness passport and privacy tests."""

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import loom_release_passport
import loom_release_subject
import loom_subject_identity


class ReleasePassportTests(unittest.TestCase):
    EPOCH = "2026-08-01T12:00:00Z"
    EXPIRES = "2026-08-08T12:00:00Z"

    def fixture(self, root):
        commit = "a" * 40
        tree = "b" * 64
        plugin = root / "loom-plugin-v1.9.0.zip"
        repro = root / "repro.zip"
        plugin.write_bytes(b"plugin")
        repro.write_bytes(b"plugin")
        subjects = [
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "main-source", "subject_id": "main",
                "repository": loom_subject_identity.REPOSITORY,
                "commit": commit, "tree_sha256": tree}),
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "candidate-source",
                "subject_id": "candidate", "repository": loom_subject_identity.REPOSITORY,
                "base_commit": commit, "commit": commit, "tree_sha256": tree,
                "overlay_sha256": loom_subject_identity.EMPTY_OVERLAY_SHA256,
                "dirty": False}),
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "release-tag", "subject_id": "v1.9.0",
                "repository": loom_subject_identity.REPOSITORY, "tag": "v1.9.0",
                "tag_object_id": "c" * 40, "tag_object_sha256": "d" * 64,
                "peeled_commit": commit, "signature_state": "verified"}),
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "plugin-zip",
                "subject_id": plugin.name, "filename": plugin.name,
                "bytes": plugin.stat().st_size,
                "sha256": hashlib.sha256(plugin.read_bytes()).hexdigest()}),
        ]
        native = {}
        for index, platform in enumerate((
                "windows-x64", "windows-arm64", "macos-x64", "macos-arm64",
                "linux-x64", "linux-arm64"), 1):
            directory = root / platform
            directory.mkdir()
            binary = directory / ("loom-vault.exe" if platform.startswith("windows")
                                  else "loom-vault")
            sbom = directory / "loom-vault.spdx.json"
            provenance = directory / "provenance.json"
            binary.write_bytes(f"binary-{index}".encode())
            sbom.write_bytes(f"sbom-{index}".encode())
            provenance.write_bytes(f"provenance-{index}".encode())
            subject = loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "native-helper", "subject_id": platform,
                "platform": platform, "filename": binary.name, "bytes": binary.stat().st_size,
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(),
                "provenance_sha256": hashlib.sha256(provenance.read_bytes()).hexdigest(),
            })
            subjects.append(subject)
            native[platform] = {"binary": binary, "sbom": sbom,
                                "provenance": provenance}
        subject = loom_release_subject.create_typed(subjects=subjects, release_sequence=1)
        cut = {"status": "verified", "root_sha256": tree,
               "firewall": {"clean": True}, "offline": {"offline": True}}
        suite = {"schema_version": 1, "status": "certified",
                 "subject": {"source_commit": commit, "public_root_sha256": tree}}
        rollback_body = {"schema_version": 1, "status": "passed", "commit": commit,
                         "public_root_sha256": tree,
                         "tests": ["test_update", "test_recovery"]}
        rollback = {**rollback_body,
                    "result_sha256": loom_release_passport._digest(rollback_body)}
        attestation = b'{"verification":"passed"}'
        authority = {
            "run_id": "12345", "job_id": "release", "runner": "ubuntu-24.04",
            "workflow_digest": "e" * 64,
            "attestation_sha256": hashlib.sha256(attestation).hexdigest(),
            "attestation_bundle": base64.b64encode(attestation).decode(),
            "issued_at": self.EPOCH, "verified_at": self.EPOCH,
            "expires_at": self.EXPIRES,
        }
        return {"subject": subject, "plugin": plugin, "reproduced_plugin": repro,
                "cut_receipt": cut, "suite_report": suite,
                "rollback_report": rollback, "native_evidence": native,
                "ci_authority": authority, "evaluation_epoch": self.EPOCH}

    def test_exact_release_passport_promotes_only_proven_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            with mock.patch.object(
                    loom_release_passport.loom_release_subject_verify, "verify",
                    return_value={"status": "verified",
                                  "bundle_sha256": fixture["subject"]["bundle_sha256"]}):
                value = loom_release_passport.compile_passport(**fixture)
            readiness = value["readiness"]
            self.assertEqual("release", readiness["report_kind"])
            self.assertEqual(fixture["subject"]["bundle_sha256"],
                             readiness["release_subject_sha256"])
            by_id = {item["id"]: item for item in readiness["claims"]}
            for claim_id in loom_release_passport.RELEASE_PREDICATES.values():
                self.assertEqual("supported", by_id[claim_id]["evidence_status"])
            for platform in fixture["native_evidence"]:
                self.assertEqual("supported",
                                 by_id[f"platform.{platform}"]["evidence_status"])
            self.assertEqual("unverified",
                             by_id["external.hostile-audit"]["evidence_status"])

    def test_native_subject_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.fixture(Path(temporary))
            next(iter(fixture["native_evidence"].values()))["sbom"].write_bytes(b"changed")
            with self.assertRaisesRegex(
                    loom_release_passport.ReleasePassportError,
                    "does not match"):
                loom_release_passport.compile_passport(**fixture)

    def test_public_output_rejects_paths_prompts_and_owner_fields(self):
        for value in (
                {"prompt": "do something"},
                {"safe": "C:\\Users\\owner\\project"},
                {"owner_vault": {"digest": "a" * 64}}):
            with self.subTest(value=value), self.assertRaises(
                    loom_release_passport.ReleasePassportError):
                loom_release_passport._public_value(value, "test output")

    def test_output_is_bounded_and_contains_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self.fixture(root)
            with mock.patch.object(
                    loom_release_passport.loom_release_subject_verify, "verify",
                    return_value={"status": "verified",
                                  "bundle_sha256": fixture["subject"]["bundle_sha256"]}):
                value = loom_release_passport.compile_passport(**fixture)
            output = root / "passport"
            result = loom_release_passport.write_outputs(output, value)
            self.assertEqual(4, result["files"])
            self.assertTrue((output / "RELEASE-READINESS.json").is_file())
            self.assertEqual(3, len((output / "SHA256SUMS").read_text(
                encoding="utf-8").splitlines()))


if __name__ == "__main__":
    unittest.main()
