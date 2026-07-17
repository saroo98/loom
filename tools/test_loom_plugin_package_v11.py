"""Deterministic marketplace runtime packaging and opaque-artifact firewall tests."""

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_plugin_package
import loom_privacy
from v11_test_support import build_vault_helper, package_evidence, package_source_commit


ROOT = Path(__file__).resolve().parents[1]


class PluginPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def test_opaque_file_requires_exact_provenance_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "helper.exe"
            binary.write_bytes(b"\x00\xff\x11\x80")
            refused = loom_privacy.scan_publication(root, forbidden_tokens=[])
            self.assertFalse(refused["clean"])
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            accepted = loom_privacy.scan_publication(
                root, forbidden_tokens=[], verified_opaque_hashes={digest})
            self.assertTrue(accepted["clean"])
            binary.write_bytes(binary.read_bytes() + b"changed")
            changed = loom_privacy.scan_publication(
                root, forbidden_tokens=[], verified_opaque_hashes={digest})
            self.assertFalse(changed["clean"])

    def test_git_free_fixture_identity_does_not_require_git_executable(self):
        with mock.patch("v11_test_support.subprocess.run", side_effect=FileNotFoundError):
            first = package_source_commit(ROOT)
            second = package_source_commit(ROOT)
        self.assertRegex(first, r"^[0-9a-f]{40}$")
        self.assertEqual(first, second)

    def test_package_requires_reproducible_helpers_and_scans_final_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, temp / "evidence", loom_plugin_package.PLATFORMS)
            output = temp / "plugin"
            result = loom_plugin_package.build(
                ROOT, output, helpers, receipts, evidence,
                version="1.1.0", release_sequence=2,
                source_commit=package_source_commit(ROOT))
            self.assertTrue(result["firewall"]["clean"])
            for platform in loom_plugin_package.PLATFORMS:
                self.assertTrue((output / "runtime-payload" / platform /
                                 "loom-runtime.zip").is_file())
            if os.name != "nt":
                verifier = output / "crypto" / "linux-x64" / "loom-vault"
                self.assertTrue(verifier.stat().st_mode & stat.S_IXUSR)
            bad = {key: dict(value) for key, value in receipts.items()}
            bad["windows-x64"]["rebuild_sha256"] = "0" * 64
            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "reproducible"):
                loom_plugin_package.build(
                    ROOT, temp / "bad", helpers, bad, evidence,
                    version="1.1.0", release_sequence=2,
                    source_commit=package_source_commit(ROOT))
            Path(evidence["windows-x64"]["sbom"]).write_text(
                '{"components":["tampered"]}', encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "evidence"):
                loom_plugin_package.build(
                    ROOT, temp / "bad-evidence", helpers, receipts, evidence,
                    version="1.1.0", release_sequence=2,
                    source_commit=package_source_commit(ROOT))

    def test_package_rejects_hash_valid_but_semantically_incomplete_sbom(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, temp / "evidence", loom_plugin_package.PLATFORMS)
            platform = "windows-x64"
            sbom_path = Path(evidence[platform]["sbom"])
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            removed = sbom["packages"].pop()
            sbom["relationships"] = [
                item for item in sbom["relationships"]
                if item.get("relatedSpdxElement") != removed["SPDXID"]]
            sbom_path.write_text(
                json.dumps(sbom, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            receipts[platform]["sbom_sha256"] = hashlib.sha256(
                sbom_path.read_bytes()).hexdigest()

            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "Cargo.lock"):
                loom_plugin_package.build(
                    ROOT, temp / "incomplete-sbom", helpers, receipts, evidence,
                    version="1.1.0", release_sequence=2,
                    source_commit=package_source_commit(ROOT))

    def test_package_rejects_provenance_for_a_different_source_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, temp / "evidence", loom_plugin_package.PLATFORMS)
            platform = "windows-x64"
            provenance_path = Path(evidence[platform]["provenance"])
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            provenance["commit"] = "0" * 40
            provenance_path.write_text(
                json.dumps(provenance, sort_keys=True, separators=(",", ":")),
                encoding="utf-8")
            receipts[platform]["provenance_sha256"] = hashlib.sha256(
                provenance_path.read_bytes()).hexdigest()

            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "provenance contract"):
                loom_plugin_package.build(
                    ROOT, temp / "wrong-commit", helpers, receipts, evidence,
                    version="1.1.0", release_sequence=2,
                    source_commit=package_source_commit(ROOT))

    def test_package_rejects_a_helper_labelled_as_the_wrong_platform(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, temp / "evidence", loom_plugin_package.PLATFORMS)
            helpers["windows-x64"] = helpers["linux-x64"]
            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "wrong executable target"):
                loom_plugin_package.build(
                    ROOT, temp / "wrong-platform", helpers, receipts, evidence,
                    version="1.1.0", release_sequence=2,
                    source_commit=package_source_commit(ROOT))

    def test_package_rejects_oversized_helper_before_final_firewall(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, temp / "evidence", loom_plugin_package.PLATFORMS)
            helper = Path(helpers["windows-x64"])
            with helper.open("r+b") as stream:
                stream.seek(loom_privacy.MAX_SCAN_FILE_BYTES)
                stream.write(b"x")
            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "exceeds the publication scan limit"):
                loom_plugin_package.build(
                    ROOT, temp / "oversized", helpers, receipts, evidence,
                    version="1.1.0", release_sequence=2,
                    source_commit=package_source_commit(ROOT))


if __name__ == "__main__":
    unittest.main()
