"""Exact signed-package to stable-launcher bootstrap integration test."""

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import loom_plugin_package
import loom_release_sign
from v11_test_support import build_vault_helper


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "vault-helper"


class BootstrapIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def test_signed_fresh_package_activates_and_stable_launcher_verifies_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()
            sbom = root / "sbom.json"
            sbom.write_text('{"components":[]}', encoding="utf-8")
            provenance = root / "provenance.json"
            provenance.write_text('{"builder":"integration-fixture"}', encoding="utf-8")
            helpers = {platform: self.helper for platform in loom_plugin_package.PLATFORMS}
            evidence = {platform: {
                "rebuild": self.helper, "sbom": sbom, "provenance": provenance,
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
            package = root / "plugin-cache" / "loom" / "1.1.0"
            loom_plugin_package.build(
                ROOT, package, helpers, receipts, evidence,
                version="1.1.0", release_sequence=2)
            ceremony = loom_release_sign.create_root_authority(
                self.helper, root / "offline-keys",
                ["bootstrap authority one", "bootstrap authority two",
                 "bootstrap authority three"],
                expires=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
            keys = ceremony["private_key_paths"]
            finalized = loom_release_sign.finalize_package(
                self.helper, package, ceremony["root"],
                [(keys[0], "bootstrap authority one"),
                 (keys[1], "bootstrap authority two")],
                expires=dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
            self.assertTrue(finalized["firewall"]["clean"])
            home = root / "home" / ".loom"
            result = subprocess.run([
                sys.executable, "-B", str(package / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(package), "--home", str(home)],
                capture_output=True, text=True, timeout=60, check=False)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("activated", json.loads(result.stdout)["status"])
            probe = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "adapter-probe"],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(0, probe.returncode, probe.stdout + probe.stderr)
            self.assertEqual("1.1.0", json.loads(probe.stdout)["version"])


if __name__ == "__main__":
    unittest.main()
