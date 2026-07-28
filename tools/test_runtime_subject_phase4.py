import tempfile
import unittest
from pathlib import Path

import loom_activation
import loom_install
import loom_platform_probe


class RuntimeSubjectPhase4Tests(unittest.TestCase):
    def test_installed_runtime_subject_omits_installation_path(self):
        pointer = {
            "version": "1.8.18",
            "path": "1.8.18",
            "payload_sha256": "1" * 64,
            "release_sequence": 18,
            "previous": None,
            "activation_receipt_sha256": "2" * 64,
        }
        subject = loom_activation.installed_runtime_subject(
            pointer, install_receipt_sha256="3" * 64)
        self.assertEqual("installed-runtime", subject["kind"])
        self.assertNotIn("path", subject)

    def test_install_subject_inputs_expose_digests_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source", root / "installed"
            source.mkdir()
            (source / "payload.txt").write_text("payload", encoding="utf-8")
            loom_install.install(source, target)
            inputs = loom_install.subject_inputs(target)
        self.assertEqual(
            {"payload_sha256", "install_receipt_sha256"}, set(inputs))
        self.assertTrue(all(len(value) == 64 for value in inputs.values()))

    def test_platform_receipt_binds_exact_runtime_and_helper_subjects(self):
        bindings = [
            {
                "kind": "native-helper",
                "subject_id": "linux-x64",
                "subject_digest": "1" * 64,
            },
            {
                "kind": "installed-runtime",
                "subject_id": "1.8.18",
                "subject_digest": "2" * 64,
            },
        ]
        result = loom_platform_probe.collect(subject_bindings=bindings)
        self.assertEqual(2, result["schema_version"])
        self.assertEqual(
            sorted(bindings, key=lambda item: item["kind"]),
            result["subject_bindings"])
        with self.assertRaises(ValueError):
            loom_platform_probe.collect(subject_bindings=[{
                "kind": "plugin-zip",
                "subject_id": "loom.zip",
                "subject_digest": "3" * 64,
            }])


if __name__ == "__main__":
    unittest.main()
