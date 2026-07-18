import tempfile
import unittest
from pathlib import Path

import loom_release_subject


class ReleaseSubjectPhase7Tests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
