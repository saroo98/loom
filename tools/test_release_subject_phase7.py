import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_release_subject
import loom_subject_identity


class ReleaseSubjectPhase7Tests(unittest.TestCase):
    def typed_subjects(self):
        common_source = {
            "schema_version": 1,
            "repository": loom_subject_identity.REPOSITORY,
            "tree_sha256": "3" * 64,
        }
        return [
            loom_subject_identity.seal_subject({
                **common_source, "kind": "main-source",
                "subject_id": "main", "commit": "1" * 40,
            }),
            loom_subject_identity.seal_subject({
                **common_source, "kind": "candidate-source",
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
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "plugin-zip",
                "subject_id": "loom.zip", "filename": "loom.zip",
                "bytes": 4, "sha256": "6" * 64,
            }),
            loom_subject_identity.seal_subject({
                "schema_version": 1, "kind": "native-helper",
                "subject_id": "linux-x64", "platform": "linux-x64",
                "filename": "loom-vault", "bytes": 4,
                "sha256": "7" * 64, "sbom_sha256": "8" * 64,
                "provenance_sha256": "9" * 64,
            }),
        ]

    def test_v3_bundle_preserves_typed_non_interchangeable_components(self):
        subjects = self.typed_subjects()
        result = loom_release_subject.create_typed(
            subjects=subjects, release_sequence=16)
        self.assertEqual(3, result["schema_version"])
        self.assertNotIn("subject_sha256", result)
        self.assertEqual(
            {item["subject_digest"] for item in subjects},
            {item["subject_digest"] for item in result["relations"]})
        with self.assertRaisesRegex(
                loom_release_subject.ReleaseSubjectError, "incomplete"):
            loom_release_subject.create_typed(
                subjects=subjects[:-1], release_sequence=16)

    def test_one_byte_change_changes_unified_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, cut = root / "source", root / "cut"
            source.mkdir(); cut.mkdir()
            (source / "README.md").write_text("source", encoding="utf-8")
            (cut / "README.md").write_text("cut", encoding="utf-8")
            plugin, helper, sbom, workflow, registry, provenance = [root / name for name in
                ("plugin.zip", "helper", "sbom.json", "quality.yml", "registry.json", "provenance.json")]
            schemas, docs = root / "schemas", root / "docs"
            schemas.mkdir(); docs.mkdir()
            (schemas / "schema.json").write_text("{}", encoding="utf-8")
            (docs / "README.md").write_text("docs", encoding="utf-8")
            for path in (plugin, helper, sbom, workflow, registry, provenance):
                path.write_bytes(path.name.encode())
            kwargs = dict(source=source, public_cut=cut, plugin=plugin,
                          helpers={"linux-x64": helper}, sboms={"linux-x64": sbom},
                          workflows={"quality": workflow}, schemas=schemas, docs=docs,
                          registry=registry, provenance={"slsa": provenance},
                          commit="a" * 40, tag="v1.6.0", release_sequence=16,
                          previous_subject="b" * 64)
            first = loom_release_subject.create(**kwargs)
            self.assertEqual(2, first["schema_version"])
            self.assertEqual("b" * 64, first["previous_subject_sha256"])
            workflow.write_bytes(b"changed")
            second = loom_release_subject.create(**kwargs)
            self.assertNotEqual(first["subject_sha256"], second["subject_sha256"])

    def test_redirected_artifact_fails_closed_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real, link = root / "real", root / "link"
            real.write_bytes(b"x")
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest("symlink privilege unavailable")
            with self.assertRaises(loom_release_subject.ReleaseSubjectError):
                loom_release_subject._artifact(link)

    def test_artifact_beneath_redirected_parent_fails_closed_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real, link = root / "real", root / "link"
            real.mkdir()
            (real / "artifact").write_bytes(b"x")
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlink privilege unavailable")
            with self.assertRaises(loom_release_subject.ReleaseSubjectError):
                loom_release_subject._artifact(link / "artifact")

    def test_tree_rejects_redirected_directory_before_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary) / "tree"
            redirected = tree / "redirected"
            redirected.mkdir(parents=True)
            (tree / "bound.txt").write_text("bound", encoding="utf-8")
            real_redirect = loom_release_subject.loom_reliability._is_redirect

            def redirect_probe(path):
                return Path(path) == redirected or real_redirect(path)

            with mock.patch.object(
                    loom_release_subject.loom_reliability, "_is_redirect",
                    side_effect=redirect_probe):
                with self.assertRaisesRegex(
                        loom_release_subject.ReleaseSubjectError, "redirected"):
                    loom_release_subject._tree(tree)


if __name__ == "__main__":
    unittest.main()
