"""Deterministic marketplace runtime packaging and opaque-artifact firewall tests."""

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

import loom_plugin_package
import loom_privacy


ROOT = Path(__file__).resolve().parents[1]


class PluginPackageTests(unittest.TestCase):
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

    def test_package_requires_reproducible_helpers_and_scans_final_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            helper = temp / "loom-vault.bin"
            helper.write_bytes(b"verified helper fixture")
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            sbom = temp / "sbom.json"
            sbom.write_text('{"components":[]}', encoding="utf-8")
            provenance = temp / "provenance.json"
            provenance.write_text('{"builder":"fixture"}', encoding="utf-8")
            helpers = {platform: helper for platform in loom_plugin_package.PLATFORMS}
            evidence = {platform: {
                "rebuild": helper, "sbom": sbom, "provenance": provenance,
            } for platform in loom_plugin_package.PLATFORMS}
            receipts = {platform: {
                "platform": platform, "binary_sha256": digest,
                "rebuild_sha256": digest,
                "source_sha256": loom_plugin_package._source_digest(ROOT),
                "cargo_lock_sha256": hashlib.sha256(
                    (ROOT / "vault-helper" / "Cargo.lock").read_bytes()).hexdigest(),
                "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(),
                "provenance_sha256": hashlib.sha256(provenance.read_bytes()).hexdigest(),
            } for platform in loom_plugin_package.PLATFORMS}
            output = temp / "plugin"
            result = loom_plugin_package.build(
                ROOT, output, helpers, receipts, evidence,
                version="1.1.0", release_sequence=2)
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
                    version="1.1.0", release_sequence=2)
            sbom.write_text('{"components":["tampered"]}', encoding="utf-8")
            with self.assertRaisesRegex(
                    loom_plugin_package.PackageError, "evidence"):
                loom_plugin_package.build(
                    ROOT, temp / "bad-evidence", helpers, receipts, evidence,
                    version="1.1.0", release_sequence=2)


if __name__ == "__main__":
    unittest.main()
