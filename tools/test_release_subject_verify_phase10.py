import hashlib
import inspect
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_release_subject
import loom_release_candidate
import loom_release_subject_verify
import loom_subject_identity
import loom_exact_cut_ci
import loom_suite_plan


class ReleaseSubjectVerifyPhase10Tests(unittest.TestCase):
    def _v4_fixture(self, root):
        plugin = root / "loom.zip"
        plugin.write_bytes(b"plugin")
        common = {"schema_version": 1,
                  "repository": loom_subject_identity.REPOSITORY,
                  "tree_sha256": "3" * 64}
        subjects = [
            loom_subject_identity.seal_subject({
                **common, "kind": "main-source", "subject_id": "main",
                "commit": "2" * 40}),
            loom_subject_identity.seal_subject({
                **common, "kind": "candidate-source", "subject_id": "candidate",
                "base_commit": "2" * 40, "commit": "2" * 40,
                "overlay_sha256": loom_subject_identity.EMPTY_OVERLAY_SHA256,
                "dirty": False}),
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "release-tag",
                "subject_id": "v1.9.0", "repository": loom_subject_identity.REPOSITORY,
                "tag": "v1.9.0", "tag_object_id": "4" * 40,
                "tag_object_sha256": "5" * 64, "peeled_commit": "2" * 40,
                "signature_state": "verified"}),
            loom_subject_identity.artifact_subject("plugin-zip", plugin),
            loom_subject_identity.public_cut(
                root_sha256="a" * 64, manifest_sha256="b" * 64,
                file_count=10),
        ]
        native = {}
        native_rows = []
        for index, platform_id in enumerate(sorted(loom_subject_identity.PLATFORMS), 1):
            digest = f"{index:x}" * 64
            native[platform_id] = digest
            native_rows.append({
                "platform": platform_id, "binary_sha256": digest,
                "sbom_sha256": "c" * 64, "provenance_sha256": "d" * 64})
            subjects.append(loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "native-helper",
                "subject_id": platform_id, "platform": platform_id,
                "filename": ("loom-vault.exe" if platform_id.startswith("windows")
                             else "loom-vault"),
                "bytes": index, "sha256": digest,
                "sbom_sha256": "c" * 64, "provenance_sha256": "d" * 64,
            }))
        public_cut = {"root_sha256": "a" * 64,
                      "manifest_sha256": "b" * 64, "file_count": 10}
        candidate = {
            "sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(),
            "bytes": plugin.stat().st_size, "files": 10,
            "extracted_tree_sha256": "6" * 64,
            "installed_tree_sha256": "7" * 64,
            "archive_metadata_sha256": "8" * 64,
            "public_cut": public_cut, "native_binaries": native,
        }
        reproducibility = loom_release_candidate._seal({
            "schema_version": 1, "status": "reproduced",
            "candidate_a": candidate, "candidate_b": dict(candidate),
            "canonical_candidate": "A", "public_cut": public_cut,
            "native_subjects": native_rows,
        })
        suite_policy = loom_suite_plan.seal_policy({
            "schema_version": 1, "authority_mode": "serial",
            "exclusive_modules": [],
        })
        suite_body = {
            "schema_version": 2, "status": "certified",
            "mode": "serial-evidence",
            "subject": {"source_commit": "2" * 40,
                        "public_root_sha256": "a" * 64},
            "policy_sha256": suite_policy["policy_sha256"],
            "matrices": [
                {"consumer": "compatibility", "cells": 15,
                 "matrix_sha256": "9" * 64},
                {"consumer": "quality", "cells": 15,
                 "matrix_sha256": "e" * 64},
            ],
        }
        suite = {**suite_body,
                 "suite_certificate_sha256": loom_suite_plan.digest(suite_body)}
        promotion_policy = root / "publish-release.yml"
        promotion_policy.write_bytes(b"protected-promotion-policy-v1\n")
        environment_body = {
            "evidence_class": "ci-reproduced", "requested_label": "ubuntu-latest",
            "image_os": "ubuntu", "image_version": "fixture", "os": "linux",
            "os_release": "fixture", "os_version": "fixture",
            "architecture": "x86_64", "python_implementation": "CPython",
            "python_version": "3.11.9",
            "workflow_path": ".github/workflows/quality.yml",
            "workflow_digest": "f" * 64, "action_manifest_digest": "1" * 64,
            "event_name": "push", "run_id": "1", "run_attempt": "1",
        }
        environment = {**environment_body,
                       "environment_sha256": loom_suite_plan.digest(environment_body)}
        exact_cut = loom_exact_cut_ci._seal({
            "schema_version": 2, "status": "verified", "platform": "linux",
            "architecture": "x86_64", "python": "3.11.9",
            "source_commit": "2" * 40, "build_root_sha256": "a" * 64,
            "verified_root_sha256": "a" * 64,
            "public_manifest_sha256": "b" * 64, "public_file_count": 10,
            "suite": None, "error_type": None, "error_sha256": None,
            "operation_id": None, "environment": environment,
        })
        bundle = loom_release_subject.create_evidence_v4(
            subjects=subjects, release_sequence=19,
            reproducibility_receipt_sha256=reproducibility["receipt_sha256"],
            matrix_certificate_sha256=suite["suite_certificate_sha256"],
            promotion_policy_sha256=hashlib.sha256(
                promotion_policy.read_bytes()).hexdigest())
        return {
            "plugin": plugin, "bundle": bundle, "archive": {
                "sha256": candidate["sha256"], "bytes": candidate["bytes"],
                "public_cut": public_cut, "native_binaries": native},
            "reproducibility": reproducibility, "suite": suite,
            "suite_policy": suite_policy, "promotion_policy": promotion_policy,
            "exact_cut": exact_cut,
        }

    def _verify_actual_v4(self, fixture, **changes):
        required = {
            "reproducibility_receipt", "suite_certificate", "suite_policy",
            "promotion_policy", "exact_cut_receipt",
        }
        self.assertTrue(required <= set(inspect.signature(
            loom_release_subject_verify.verify).parameters))
        evidence = {
            "reproducibility_receipt": fixture["reproducibility"],
            "suite_certificate": fixture["suite"],
            "suite_policy": fixture["suite_policy"],
            "promotion_policy": fixture["promotion_policy"],
            "exact_cut_receipt": fixture["exact_cut"],
        }
        evidence.update(changes)
        with mock.patch.object(
                loom_release_subject_verify.loom_release_candidate,
                "_archive_subject", return_value=fixture["archive"]):
            return loom_release_subject_verify.verify(
                fixture["bundle"], fixture["plugin"],
                commit="2" * 40, tag="v1.9.0", **evidence)

    def test_reproducibility_validator_refuses_malformed_native_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            body = {
                key: value for key, value in fixture["reproducibility"].items()
                if key != "receipt_sha256"}
            body["native_subjects"] = [None] * 6
            malformed = loom_release_candidate._seal(body)

            with self.assertRaises(loom_release_candidate.CandidateError):
                loom_release_candidate.verify_reproducibility_receipt(malformed)

    def test_typed_bundle_verifies_plugin_without_collapsing_subjects(self):
        with tempfile.TemporaryDirectory() as temporary:
            plugin = Path(temporary) / "loom.zip"
            plugin.write_bytes(b"plugin")
            common = {
                "schema_version": 1,
                "repository": loom_subject_identity.REPOSITORY,
                "tree_sha256": "3" * 64,
            }
            subjects = [
                loom_subject_identity.seal_subject({
                    **common, "kind": "main-source",
                    "subject_id": "main", "commit": "1" * 40,
                }),
                loom_subject_identity.seal_subject({
                    **common, "kind": "candidate-source",
                    "subject_id": "candidate", "base_commit": "1" * 40,
                    "commit": "2" * 40,
                    "overlay_sha256":
                        loom_subject_identity.EMPTY_OVERLAY_SHA256,
                    "dirty": False,
                }),
                loom_subject_identity.seal_subject({
                    "schema_version": 1, "kind": "release-tag",
                    "subject_id": "v1.6.0",
                    "repository": loom_subject_identity.REPOSITORY,
                    "tag": "v1.6.0", "tag_object_id": "4" * 40,
                    "tag_object_sha256": "5" * 64,
                    "peeled_commit": "2" * 40,
                    "signature_state": "verified",
                }),
                loom_subject_identity.artifact_subject(
                    "plugin-zip", plugin),
                loom_subject_identity.seal_subject({
                    "schema_version": 1, "kind": "native-helper",
                    "subject_id": "linux-x64", "platform": "linux-x64",
                    "filename": "loom-vault", "bytes": 4,
                    "sha256": "7" * 64, "sbom_sha256": "8" * 64,
                    "provenance_sha256": "9" * 64,
                }),
            ]
            bundle = loom_release_subject.create_typed(
                subjects=subjects, release_sequence=16)
            result = loom_release_subject_verify.verify(
                bundle, plugin, commit="2" * 40, tag="v1.6.0")
            self.assertEqual("verified", result["status"])
            self.assertIn("plugin_subject_digest", result)
            plugin.write_bytes(b"changed")
            with self.assertRaisesRegex(
                    loom_release_subject_verify.SubjectVerificationError,
                    "plugin bytes"):
                loom_release_subject_verify.verify(bundle, plugin)

    def test_v4_verifier_requires_and_binds_actual_release_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            with mock.patch.object(
                    loom_release_subject_verify.loom_release_candidate,
                    "_archive_subject", return_value=fixture["archive"]):
                with self.assertRaisesRegex(
                        loom_release_subject_verify.SubjectVerificationError,
                        "actual"):
                    loom_release_subject_verify.verify(
                        fixture["bundle"], fixture["plugin"],
                        commit="2" * 40, tag="v1.9.0")
            result = self._verify_actual_v4(fixture)
            self.assertEqual("verified", result["status"])

    def test_v4_verifier_rejects_a_swapped_reproducibility_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            body = {key: value for key, value in fixture["reproducibility"].items()
                    if key != "receipt_sha256"}
            changed = dict(body["candidate_a"])
            changed["archive_metadata_sha256"] = "0" * 64
            body["candidate_a"] = changed
            body["candidate_b"] = dict(changed)
            swapped = loom_release_candidate._seal(body)
            with self.assertRaisesRegex(
                    loom_release_subject_verify.SubjectVerificationError,
                    "reproducibility"):
                self._verify_actual_v4(
                    fixture, reproducibility_receipt=swapped)

    def test_v4_verifier_rejects_a_swapped_aggregate_suite_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            body = {key: value for key, value in fixture["suite"].items()
                    if key != "suite_certificate_sha256"}
            body["matrices"] = [dict(row) for row in body["matrices"]]
            body["matrices"][1]["matrix_sha256"] = "0" * 64
            swapped = {**body,
                       "suite_certificate_sha256": loom_suite_plan.digest(body)}
            with self.assertRaisesRegex(
                loom_release_subject_verify.SubjectVerificationError, "suite"):
                self._verify_actual_v4(fixture, suite_certificate=swapped)

    def test_v4_verifier_rejects_a_swapped_suite_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            swapped = loom_suite_plan.seal_policy({
                "schema_version": 1, "authority_mode": "serial",
                "exclusive_modules": ["test_fixture"],
            })
            with self.assertRaisesRegex(
                    loom_release_subject_verify.SubjectVerificationError, "suite"):
                self._verify_actual_v4(fixture, suite_policy=swapped)

    def test_v4_verifier_rejects_a_swapped_promotion_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            swapped = Path(temporary) / "swapped-publish-release.yml"
            swapped.write_bytes(b"different-protected-promotion-policy\n")
            with self.assertRaisesRegex(
                    loom_release_subject_verify.SubjectVerificationError,
                    "promotion policy"):
                self._verify_actual_v4(fixture, promotion_policy=swapped)

    def test_v4_verifier_rejects_a_swapped_exact_cut_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._v4_fixture(Path(temporary))
            body = {key: value for key, value in fixture["exact_cut"].items()
                    if key != "receipt_sha256"}
            body["build_root_sha256"] = "0" * 64
            body["verified_root_sha256"] = "0" * 64
            swapped = loom_exact_cut_ci._seal(body)
            with self.assertRaisesRegex(
                    loom_release_subject_verify.SubjectVerificationError,
                    "exact-cut|public-cut"):
                self._verify_actual_v4(fixture, exact_cut_receipt=swapped)

    def test_exact_plugin_and_subject_digest_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, cut, schemas, docs = [root / name for name in
                ("source", "cut", "schemas", "docs")]
            for tree in (source, cut, schemas, docs):
                tree.mkdir()
                (tree / "file").write_text(tree.name, encoding="utf-8")
            plugin, helper, sbom, workflow, registry, provenance = [root / name for name in
                ("plugin.zip", "helper", "sbom", "workflow", "registry", "provenance")]
            for path in (plugin, helper, sbom, workflow, registry, provenance):
                path.write_bytes(path.name.encode())
            subject = loom_release_subject.create(
                source=source, public_cut=cut, plugin=plugin,
                helpers={"linux-x64": helper}, sboms={"spdx": sbom},
                workflows={"quality": workflow}, schemas=schemas, docs=docs,
                registry=registry, provenance={"slsa": provenance},
                commit="a" * 40, tag="v1.6.0", release_sequence=16)
            result = loom_release_subject_verify.verify(
                subject, plugin, commit="a" * 40, tag="v1.6.0")
            self.assertEqual("verified", result["status"])
            plugin.write_bytes(b"changed")
            with self.assertRaisesRegex(
                    loom_release_subject_verify.SubjectVerificationError, "plugin bytes"):
                loom_release_subject_verify.verify(subject, plugin)

    def test_redirected_plugin_is_rejected_before_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, cut, schemas, docs = [root / name for name in
                ("source", "cut", "schemas", "docs")]
            for tree in (source, cut, schemas, docs):
                tree.mkdir()
                (tree / "file").write_text(tree.name, encoding="utf-8")
            plugin, helper, sbom, workflow, registry, provenance = [root / name for name in
                ("plugin.zip", "helper", "sbom", "workflow", "registry", "provenance")]
            for path in (plugin, helper, sbom, workflow, registry, provenance):
                path.write_bytes(path.name.encode())
            subject = loom_release_subject.create(
                source=source, public_cut=cut, plugin=plugin,
                helpers={"linux-x64": helper}, sboms={"spdx": sbom},
                workflows={"quality": workflow}, schemas=schemas, docs=docs,
                registry=registry, provenance={"slsa": provenance},
                commit="a" * 40, tag="v1.6.0", release_sequence=16)
            with mock.patch.object(
                    loom_release_subject_verify.loom_reliability, "_is_redirect",
                    side_effect=lambda path: Path(path) == plugin):
                with self.assertRaisesRegex(
                        loom_release_subject_verify.SubjectVerificationError, "symlink|redirect"):
                    loom_release_subject_verify.verify(subject, plugin)


if __name__ == "__main__":
    unittest.main()
