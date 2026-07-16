"""Exact signed-package to stable-launcher bootstrap integration test."""

import datetime as dt
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_plugin_package
import loom_release_sign
import loom_reliability
from v11_test_support import build_vault_helper, package_evidence, package_source_commit


ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "vault-helper"

BOOTSTRAP_SPEC = importlib.util.spec_from_file_location(
    "loom_bootstrap_under_test", ROOT / "scripts" / "loom_bootstrap.py")
loom_bootstrap = importlib.util.module_from_spec(BOOTSTRAP_SPEC)
BOOTSTRAP_SPEC.loader.exec_module(loom_bootstrap)


class BootstrapIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = build_vault_helper(ROOT)

    def test_signed_fresh_package_activates_and_stable_launcher_verifies_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helpers = {platform: self.helper for platform in loom_plugin_package.PLATFORMS}
            receipts, evidence = package_evidence(
                ROOT, self.helper, root / "evidence", loom_plugin_package.PLATFORMS)
            package = root / "plugin-cache" / "loom" / "1.1.0"
            loom_plugin_package.build(
                ROOT, package, helpers, receipts, evidence,
                version="1.1.0", release_sequence=2,
                source_commit=package_source_commit(ROOT))
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

    def test_failed_first_legacy_migration_never_activates_blank_vault_and_retry_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home" / ".loom"
            runtime = root / "runtime"
            runtime.mkdir()
            (runtime / ".loom-instance-id").write_text(
                "00000000-0000-4000-8000-000000000111\n", encoding="utf-8")

            class FakeVault:
                def semantic_inventory(self):
                    return {"sha256": "a" * 64}

                def online_backup(self, destination):
                    Path(destination).write_bytes(b"complete migrated vault")

            vault = FakeVault()

            class FakeOwner:
                @staticmethod
                def initialize_owner_vault(staged_home, _helper):
                    path = Path(staged_home) / "vault" / "owner.sqlite3"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"staged vault")
                    return {"vault": vault, "crypto": object()}

                @staticmethod
                def open_owner_vault(open_home, _helper):
                    if not (Path(open_home) / "vault" / "owner.sqlite3").is_file():
                        raise AssertionError("active vault is absent")
                    return vault, object()

            migrate = mock.Mock()
            migrate.migrate_v1.side_effect = [RuntimeError("injected migration failure"), None]

            with self.assertRaisesRegex(RuntimeError, "injected migration failure"):
                loom_bootstrap._migrate_legacy_staged(
                    home, "helper", runtime,
                    "00000000-0000-4000-8000-000000000111",
                    owner_module=FakeOwner, migrate_module=migrate,
                    reliability_module=loom_reliability)
            self.assertFalse((home / "vault" / "owner.sqlite3").exists())
            self.assertTrue((home / "vault" / "bootstrap-journal.json").is_file())

            migrated, _crypto = loom_bootstrap._migrate_legacy_staged(
                home, "helper", runtime,
                "00000000-0000-4000-8000-000000000111",
                owner_module=FakeOwner, migrate_module=migrate,
                reliability_module=loom_reliability)

            self.assertIs(vault, migrated)
            self.assertEqual(b"complete migrated vault", (
                home / "vault" / "owner.sqlite3").read_bytes())
            journal = json.loads((home / "vault" / "bootstrap-journal.json").read_text(
                encoding="utf-8"))
            self.assertEqual("complete", journal["state"])


if __name__ == "__main__":
    unittest.main()
