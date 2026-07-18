"""Canonical plugin archive reproducibility and independent-verifier tests."""

import json
import io
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path

import loom_plugin_package
import loom_release_verify


class CanonicalReleaseAssetTests(unittest.TestCase):
    def _finalized(self, root):
        package = root / "plugin"
        (package / "release").mkdir(parents=True)
        (package / "release" / "metadata.json").write_text("{}", encoding="utf-8")
        (package / "release" / "trusted-root.json").write_text("{}", encoding="utf-8")
        (package / "skills").mkdir()
        (package / "skills" / "SKILL.md").write_text("public fixture\n", encoding="utf-8")
        files = []
        for path in sorted(item for item in package.rglob("*") if item.is_file()):
            raw = path.read_bytes()
            import hashlib
            files.append({"path": path.relative_to(package).as_posix(), "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
        (package / "FINAL-PACKAGE-RECEIPT.json").write_text(json.dumps({
            "schema_version": 1, "version": "1.2.0", "release_sequence": 3,
            "files": files,
        }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return package

    def test_two_assemblies_are_identical_and_exact_receipt_verifies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self._finalized(root)
            first = loom_plugin_package.archive_finalized(package, root / "first.zip")
            second = loom_plugin_package.archive_finalized(package, root / "second.zip")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual("verified", loom_release_verify.verify(root / "first.zip")["status"])

    def test_extra_member_and_case_alias_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self._finalized(root)
            archive = root / "plugin.zip"
            loom_plugin_package.archive_finalized(package, archive)
            with zipfile.ZipFile(archive, "a") as output:
                output.writestr("SKILLS/skill.md", b"alias")
            with self.assertRaisesRegex(loom_release_verify.VerifyError, "alias"):
                loom_release_verify.verify(archive)

    def test_forbidden_token_inside_nested_zip_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self._finalized(root)
            nested = io.BytesIO()
            with zipfile.ZipFile(
                    nested, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
                output.writestr("opaque.bin", b"owner-only-project-name" * 64)
            (package / "nested.zip").write_bytes(nested.getvalue())
            import hashlib
            receipt_path = package / "FINAL-PACKAGE-RECEIPT.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            raw = (package / "nested.zip").read_bytes()
            receipt["files"].append({"path": "nested.zip", "bytes": len(raw),
                                     "sha256": hashlib.sha256(raw).hexdigest()})
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            archive = root / "plugin.zip"
            loom_plugin_package.archive_finalized(package, archive)
            with self.assertRaisesRegex(loom_release_verify.VerifyError, "nested"):
                loom_release_verify.verify(
                    archive, forbidden_tokens=["owner-only-project-name"])

    def test_redirected_archive_path_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "plugin.zip"
            archive.write_bytes(b"not opened")
            with mock.patch.object(
                    loom_release_verify, "_redirect",
                    side_effect=lambda path: Path(path) == archive):
                with self.assertRaisesRegex(loom_release_verify.VerifyError, "redirected"):
                    loom_release_verify.verify(archive)

    def test_only_exact_macos_root_aliases_are_trusted(self):
        with mock.patch.object(loom_release_verify.sys, "platform", "darwin"):
            with mock.patch.object(Path, "resolve", return_value=Path("/private/var")):
                self.assertTrue(loom_release_verify._trusted_os_alias(Path("/var")))
            with mock.patch.object(Path, "resolve", return_value=Path("/other/var")):
                self.assertFalse(loom_release_verify._trusted_os_alias(Path("/var")))
            self.assertFalse(loom_release_verify._trusted_os_alias(Path("/users")))


if __name__ == "__main__":
    unittest.main()
