"""Exact current-candidate release certificate v2."""

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import loom_lint
import loom_qualification_v2
import loom_release_candidate
import loom_release_authority
import loom_release_certificate
import loom_release_promotion
import loom_release_rollback
import loom_release_suite
import loom_suite_plan
import test_qualification_v2


class ReleaseCertificateTests(unittest.TestCase):
    @staticmethod
    def _seal(body):
        return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()}

    def candidate(self):
        helper = test_qualification_v2.QualificationV2Tests()
        _root, manifest, workload, timing, authority = helper.inputs()
        commit = "5" * 40
        tree = "6" * 64
        public_root = "7" * 64
        quality = helper.candidate_matrix_bundle(
            manifest, workload, timing, consumer="quality",
            source_commit=commit, source_tree_sha256=tree,
            public_root_sha256=public_root, start_index=1)
        compatibility = helper.candidate_matrix_bundle(
            manifest, workload, timing, consumer="compatibility",
            source_commit=commit, source_tree_sha256=tree,
            public_root_sha256=public_root, start_index=101)
        admission = loom_qualification_v2.compile_candidate(
            quality, compatibility, helper.native_receipts(commit),
            mechanism=None, policy=authority, manifest=manifest)
        return admission

    def evidence(self, admission, archive_bytes=b"canonical archive"):
        archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        public_cut = {
            "root_sha256": admission["public_root_sha256"],
            "manifest_sha256": admission["public_manifest_sha256"],
            "file_count": admission["public_file_count"],
        }
        natives = [{
            key: row[key] for key in (
                "platform", "binary_sha256", "sbom_sha256",
                "provenance_sha256")
        } for row in admission["native_subjects"]]
        archive = {
            "sha256": archive_sha256, "bytes": len(archive_bytes),
            "files": 100, "extracted_tree_sha256": "8" * 64,
            "installed_tree_sha256": "9" * 64,
            "archive_metadata_sha256": "a" * 64,
            "public_cut": public_cut,
            "native_binaries": {
                row["platform"]: row["binary_sha256"] for row in natives
            },
        }
        reproducibility = loom_release_candidate._seal({
            "schema_version": 1, "status": "reproduced",
            "candidate_a": archive, "candidate_b": copy.deepcopy(archive),
            "canonical_candidate": "A", "public_cut": public_cut,
            "native_subjects": natives,
        })
        rollback_body = {
            "schema_version": 1, "status": "passed",
            "commit": admission["source_commit"],
            "public_root_sha256": admission["public_root_sha256"],
            "tests": list(loom_release_rollback.TESTS),
            "transcript_sha256": "b" * 64,
        }
        rollback = {**rollback_body, "result_sha256": hashlib.sha256(
            json.dumps(rollback_body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")).hexdigest()}
        tag_body = {
            "schema_version": 1, "tag": "v1.9.0",
            "commit": admission["source_commit"],
            "tag_object_sha256": "c" * 64,
            "signature_sha256": "d" * 64,
            "signer_identity_sha256": "e" * 64,
            "attestation_sha256": "f" * 64,
            "signature_verified": True,
        }
        tag = self._seal(tag_body)
        return archive_bytes, reproducibility, rollback, tag

    @staticmethod
    def gate(digest):
        return {
            "signed_tag_verified": True, "passport_verified": True,
            "matrix_certificate_verified": True,
            "native_evidence_verified": True, "rollback_verified": True,
            "attestation_verified": True, "expected_sha256": digest,
            "release_asset_sha256": digest,
        }

    def test_release_certificate_binds_ready_draft_and_public_subjects(self):
        admission = self.candidate()
        archive_bytes, reproducibility, rollback, tag = self.evidence(admission)
        ready = loom_release_certificate.compile_release(
            admission, reproducibility, rollback, tag=tag, promotion=None)
        self.assertEqual("release-ready", ready["status"])
        self.assertEqual(
            admission["candidate_admission_sha256"],
            ready["candidate_admission_sha256"])
        self.assertEqual(
            ready, loom_release_certificate.verify_release(
                ready, candidate_admission=admission,
                expected_tag="v1.9.0", expected_asset=None))
        candidate_suite_body = {
            "schema_version": 3, "status": "certified",
            "mode": admission["authority_mode"],
            "subject": {
                "source_commit": admission["source_commit"],
                "source_tree_sha256": admission[
                    "repository_source_tree_sha256"],
                "public_root_sha256": admission["public_root_sha256"],
            },
            "authority_policy_sha256": admission[
                "authority_policy_sha256"],
            "mechanism_manifest_sha256": admission[
                "mechanism_manifest_sha256"],
            "mechanism_qualification_sha256": admission[
                "mechanism_qualification_sha256"],
            "candidate_admission_sha256": admission[
                "candidate_admission_sha256"],
            "matrices": admission["matrix_certificates"],
        }
        candidate_suite = {
            **candidate_suite_body,
            "suite_certificate_sha256": loom_suite_plan.digest(
                candidate_suite_body),
        }
        helper = test_qualification_v2.QualificationV2Tests()
        _root, manifest, workload, _timing, authority_policy = helper.inputs()
        narrow_suite = loom_release_authority.certify_candidate_admission(
            admission, mechanism=None, authority_policy=authority_policy,
            manifest=manifest, workload=None,
            expected_commit=admission["source_commit"],
            expected_tree=admission["repository_source_tree_sha256"],
            expected_root=admission["public_root_sha256"])
        self.assertEqual(candidate_suite, narrow_suite)
        self.assertEqual(
            narrow_suite, loom_release_authority.verify_candidate_admission(
                narrow_suite, admission=admission, mechanism=None,
                authority_policy=authority_policy, manifest=manifest,
                workload=None, expected_commit=admission["source_commit"],
                expected_tree=admission["repository_source_tree_sha256"],
                expected_root=admission["public_root_sha256"]))
        authority = loom_release_suite.certify_release_authority(
            candidate_suite, ready, candidate_admission=admission,
            expected_tag="v1.9.0")
        self.assertEqual(
            authority, loom_release_suite.verify_release_authority(
                authority, candidate_suite=candidate_suite,
                release_certificate=ready, candidate_admission=admission,
                expected_tag="v1.9.0"))
        narrow_authority = loom_release_authority.certify_release_authority(
            narrow_suite, ready, candidate_admission=admission,
            expected_tag="v1.9.0")
        self.assertEqual(authority, narrow_authority)
        self.assertEqual(
            narrow_authority,
            loom_release_authority.verify_release_authority(
                narrow_authority, candidate_suite=narrow_suite,
                release_certificate=ready, candidate_admission=admission,
                expected_tag="v1.9.0"))
        with self.assertRaises(loom_release_suite.ReleaseSuiteError):
            loom_release_suite.certify_release_authority(
                {"mechanism_qualification_sha256": "0" * 64}, ready,
                candidate_admission=admission, expected_tag="v1.9.0")

        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "loom-plugin-v1.9.0.zip"
            asset.write_bytes(archive_bytes)
            digest = hashlib.sha256(archive_bytes).hexdigest()
            draft_receipt = loom_release_promotion.verify_draft_with_certificate(
                asset, self.gate(digest), ready, admission,
                expected_tag="v1.9.0")
            draft = loom_release_certificate.compile_release(
                admission, reproducibility, rollback, tag=tag,
                promotion=draft_receipt)
            self.assertEqual("draft-verified", draft["status"])
            self.assertEqual(
                draft, loom_release_certificate.verify_release(
                    draft, candidate_admission=admission,
                    expected_tag="v1.9.0",
                    expected_asset={"sha256": digest,
                                    "bytes": len(archive_bytes)}))

            public_receipt = loom_release_promotion.verify_public_with_certificate(
                asset, self.gate(digest), draft, admission,
                expected_tag="v1.9.0",
                installed_subject_sha256=reproducibility[
                    "candidate_a"]["installed_tree_sha256"],
                represented_installed_subjects=[reproducibility[
                    "candidate_a"]["installed_tree_sha256"]])
            public = loom_release_certificate.compile_release(
                admission, reproducibility, rollback, tag=tag,
                promotion=public_receipt)
            self.assertEqual("public-verified", public["status"])
            self.assertEqual(
                public, loom_release_certificate.verify_release(
                    public, candidate_admission=admission,
                    expected_tag="v1.9.0",
                    expected_asset={"sha256": digest,
                                    "bytes": len(archive_bytes)}))

        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, __file__, public, "release-certificate-v2.schema.json")
        self.assertEqual([], report.errors)

    def test_release_certificate_rejects_stale_or_mismatched_evidence(self):
        admission = self.candidate()
        _archive_bytes, reproducibility, rollback, tag = self.evidence(admission)
        stale_cut = copy.deepcopy(reproducibility)
        for candidate in (stale_cut["candidate_a"], stale_cut["candidate_b"]):
            candidate["public_cut"]["root_sha256"] = "0" * 64
        stale_cut["public_cut"]["root_sha256"] = "0" * 64
        stale_cut = loom_release_candidate._seal({
            key: value for key, value in stale_cut.items()
            if key != "receipt_sha256"})
        stale_rollback = copy.deepcopy(rollback)
        stale_rollback["commit"] = "1" * 40
        stale_body = {key: value for key, value in stale_rollback.items()
                      if key != "result_sha256"}
        stale_rollback["result_sha256"] = hashlib.sha256(json.dumps(
            stale_body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        mismatched_native = copy.deepcopy(reproducibility)
        mismatched_native["native_subjects"][0]["binary_sha256"] = "2" * 64
        platform = mismatched_native["native_subjects"][0]["platform"]
        for candidate in (mismatched_native["candidate_a"],
                          mismatched_native["candidate_b"]):
            candidate["native_binaries"][platform] = "2" * 64
        mismatched_native = loom_release_candidate._seal({
            key: value for key, value in mismatched_native.items()
            if key != "receipt_sha256"})
        metadata_mismatch = copy.deepcopy(reproducibility)
        metadata_mismatch["candidate_b"]["archive_metadata_sha256"] = "3" * 64
        metadata_mismatch = loom_release_candidate._seal({
            key: value for key, value in metadata_mismatch.items()
            if key != "receipt_sha256"})
        old_tag = copy.deepcopy(tag)
        old_tag["tag"] = "v1.8.30"
        old_tag = self._seal({key: value for key, value in old_tag.items()
                              if key != "receipt_sha256"})
        cases = (
            (stale_cut, rollback, tag),
            (reproducibility, stale_rollback, tag),
            (mismatched_native, rollback, tag),
            (metadata_mismatch, rollback, tag),
        )
        for repro, rollback_value, tag_value in cases:
            with self.subTest(repro=repro["receipt_sha256"]), \
                    self.assertRaises(loom_release_certificate.ReleaseCertificateError):
                loom_release_certificate.compile_release(
                    admission, repro, rollback_value, tag=tag_value,
                    promotion=None)
        with self.assertRaises(loom_release_certificate.ReleaseCertificateError):
            loom_release_certificate.compile_release(
                {"source_commit": admission["source_commit"]},
                reproducibility, rollback, tag=tag, promotion=None)
        with self.assertRaises(loom_release_certificate.ReleaseCertificateError):
            loom_release_certificate.compile_release(
                admission, reproducibility, rollback, tag=old_tag,
                promotion=None)

    def test_public_release_rejects_wrong_or_unrepresented_installation(self):
        admission = self.candidate()
        archive_bytes, reproducibility, rollback, tag = self.evidence(admission)
        ready = loom_release_certificate.compile_release(
            admission, reproducibility, rollback, tag=tag, promotion=None)
        with tempfile.TemporaryDirectory() as temporary:
            asset = Path(temporary) / "loom-plugin-v1.9.0.zip"
            asset.write_bytes(archive_bytes)
            digest = hashlib.sha256(archive_bytes).hexdigest()
            wrong_asset = Path(temporary) / "overwritten.zip"
            wrong_asset.write_bytes(b"overwritten archive")
            wrong_digest = hashlib.sha256(wrong_asset.read_bytes()).hexdigest()
            with self.assertRaises(loom_release_promotion.PromotionError):
                loom_release_promotion.verify_draft_with_certificate(
                    wrong_asset, self.gate(wrong_digest), {}, admission,
                    expected_tag="v1.9.0")
            with self.assertRaises(loom_release_promotion.PromotionError):
                loom_release_promotion.verify_draft_with_certificate(
                    wrong_asset, self.gate(wrong_digest), ready, admission,
                    expected_tag="v1.9.0")
            wrong = loom_release_promotion.verify_public(
                asset, self.gate(digest),
                installed_subject_sha256="0" * 64)
        with self.assertRaises(loom_release_certificate.ReleaseCertificateError):
            loom_release_certificate.compile_release(
                admission, reproducibility, rollback, tag=tag,
                promotion=wrong)

    def test_release_certificate_cli_compiles_verifies_and_records_tag_evidence(self):
        admission = self.candidate()
        _archive_bytes, reproducibility, rollback, tag = self.evidence(admission)
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            paths = {}
            for name, value in (
                    ("candidate", admission),
                    ("reproducibility", reproducibility),
                    ("rollback", rollback), ("tag", tag)):
                path = temporary / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                paths[name] = path
            certificate = temporary / "release-certificate.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_release_certificate.main([
                    "compile", "--candidate", str(paths["candidate"]),
                    "--reproducibility", str(paths["reproducibility"]),
                    "--rollback", str(paths["rollback"]),
                    "--tag-evidence", str(paths["tag"]),
                    "--output", str(certificate),
                ]))
                self.assertEqual(0, loom_release_certificate.main([
                    "verify", "--candidate", str(paths["candidate"]),
                    "--certificate", str(certificate),
                    "--expected-tag", "v1.9.0",
                ]))
            root = Path(__file__).resolve().parents[1]
            candidate_suite = temporary / "candidate-suite.json"
            release_authority = temporary / "release-authority.json"
            authority_arguments = [
                "--root", str(root), "--candidate", str(paths["candidate"]),
                "--expected-commit", admission["source_commit"],
                "--expected-tree",
                admission["repository_source_tree_sha256"],
                "--expected-public-root", admission["public_root_sha256"],
                "--policy", str(
                    root / "contracts" / "release-authority-policy-v2.json"),
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_release_authority.main([
                    "candidate-suite", *authority_arguments,
                    "--output", str(candidate_suite),
                ]))
                self.assertEqual(0, loom_release_authority.main([
                    "release-authority", *authority_arguments,
                    "--candidate-suite", str(candidate_suite),
                    "--release-certificate", str(certificate),
                    "--expected-tag", "v1.9.0",
                    "--output", str(release_authority),
                ]))
                self.assertEqual(0, loom_release_authority.main([
                    "verify", *authority_arguments,
                    "--candidate-suite", str(candidate_suite),
                    "--release-certificate", str(certificate),
                    "--release-authority", str(release_authority),
                    "--expected-tag", "v1.9.0",
                ]))
            report = loom_lint.Report()
            loom_lint.validate_schema(
                report, __file__, json.loads(candidate_suite.read_text(
                    encoding="utf-8")),
                "release-candidate-suite-v2.schema.json")
            loom_lint.validate_schema(
                report, __file__, json.loads(release_authority.read_text(
                    encoding="utf-8")), "release-authority-v2.schema.json")
            self.assertEqual([], report.errors)
            signer = temporary / "allowed-signers"
            signer.write_text(
                "loom-release@example.invalid ssh-ed25519 fixture\n",
                encoding="utf-8")
            attestation = temporary / "attestation.json"
            attestation.write_text("{}\n", encoding="utf-8")
            recorded = temporary / "recorded-tag.json"
            raw_tag = (
                b"object " + admission["source_commit"].encode("ascii") +
                b"\ntype commit\ntag v1.9.0\n\nrelease\n"
                b"-----BEGIN SSH SIGNATURE-----\nfixture\n"
                b"-----END SSH SIGNATURE-----\n")

            def git_bytes(_repository, *arguments):
                if arguments[:2] == ("rev-parse", "v1.9.0^{commit}"):
                    return admission["source_commit"].encode("ascii") + b"\n"
                if arguments[:2] == ("verify-tag", "v1.9.0"):
                    return b""
                if arguments[:3] == ("cat-file", "tag", "v1.9.0"):
                    return raw_tag
                raise AssertionError(arguments)

            with mock.patch.object(
                    loom_release_certificate, "_git_bytes",
                    side_effect=git_bytes), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, loom_release_certificate.main([
                    "record-tag", "--repository", str(temporary),
                    "--tag", "v1.9.0", "--expected-commit",
                    admission["source_commit"], "--signer-identity",
                    str(signer), "--attestation", str(attestation),
                    "--output", str(recorded),
                ]))
            recorded_value = json.loads(recorded.read_text(encoding="utf-8"))
            self.assertTrue(recorded_value["signature_verified"])
            self.assertEqual(admission["source_commit"],
                             recorded_value["commit"])


if __name__ == "__main__":
    unittest.main()
