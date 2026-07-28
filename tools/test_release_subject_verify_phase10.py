import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_release_subject
import loom_release_subject_verify
import loom_subject_identity


class ReleaseSubjectVerifyPhase10Tests(unittest.TestCase):
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
