import tempfile
import unittest
from pathlib import Path

import loom_release_subject
import loom_release_subject_verify


class ReleaseSubjectVerifyPhase10Tests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
