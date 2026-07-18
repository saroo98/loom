"""Exact signed-package to stable-launcher bootstrap integration test."""

import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import loom_plugin_package
import loom_install
import loom_orchestrator
import loom_release
import loom_release_sign
import loom_reliability
import loom_update
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
        cls.direct_fixture = tempfile.TemporaryDirectory()
        cls.direct_public = Path(cls.direct_fixture.name) / "public"
        loom_release.build_public(
            ROOT, cls.direct_public,
            forbidden_tokens=["-".join(("direct", "owner", "fixture", "token"))],
            source_classification="public-release")
        platform_id = loom_update.platform_id()
        binary_name = "loom-vault.exe" if platform_id.startswith("windows-") \
            else "loom-vault"
        helper = cls.direct_public / "crypto" / platform_id / binary_name
        helper.parent.mkdir(parents=True)
        shutil.copyfile(cls.helper, helper)
        if os.name != "nt":
            os.chmod(helper, 0o755)

    @classmethod
    def tearDownClass(cls):
        cls.direct_fixture.cleanup()

    def _install_direct_fixture(self, root):
        target = Path(root) / "direct-install"
        loom_install.install(self.direct_public, target)
        return target

    def test_receipt_proven_direct_install_bootstraps_without_signed_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"

            result = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                capture_output=True, text=True, timeout=120, check=False)

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual("activated", value["status"])
            self.assertEqual(
                "direct-source-install-unattested", value["delivery_authority"])
            probe = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "adapter-probe"],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(0, probe.returncode, probe.stdout + probe.stderr)
            self.assertEqual(
                "direct-source-install-unattested",
                json.loads((home / "runtime" / "versions" / value["version"] /
                            ".loom-direct-source-receipt.json").read_text(
                                encoding="utf-8"))["delivery_authority"])

    def test_changed_or_unowned_direct_install_never_creates_active_pointer(self):
        for mutation in ("changed", "missing", "unowned"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                direct = self._install_direct_fixture(root)
                if mutation == "changed":
                    (direct / "tools" / "loom_runtime.py").write_text(
                        "changed\n", encoding="utf-8")
                elif mutation == "missing":
                    (direct / "tools" / "loom_runtime.py").unlink()
                else:
                    (direct / "unowned.txt").write_text("unowned\n", encoding="utf-8")
                home = root / "home" / ".loom"

                result = subprocess.run([
                    sys.executable, "-B",
                    str(direct / "scripts" / "loom_bootstrap.py"),
                    "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                    capture_output=True, text=True, timeout=60, check=False)

                self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                self.assertEqual("blocked", json.loads(result.stdout)["status"])
                self.assertFalse((home / "runtime" / "current.json").exists())

    def test_direct_install_redirect_is_rejected_before_installed_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            direct = self._install_direct_fixture(temporary)
            redirected = direct / "tools"
            real_redirect = loom_bootstrap._redirect

            def redirect_probe(path):
                return Path(path) == redirected or real_redirect(path)

            with mock.patch.object(
                    loom_bootstrap, "_redirect", side_effect=redirect_probe):
                with self.assertRaisesRegex(loom_bootstrap.BootstrapError, "redirect"):
                    loom_bootstrap._direct_install_receipt(direct)

    def test_incomplete_signed_metadata_cannot_downgrade_to_direct_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(self.direct_public, source)
            release = source / "release"
            release.mkdir(exist_ok=True)
            (release / "metadata.json").write_text("{}\n", encoding="utf-8")
            direct = root / "direct-install"
            loom_install.install(source, direct)
            home = root / "home" / ".loom"

            result = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                capture_output=True, text=True, timeout=60, check=False)

            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn("signed delivery metadata is incomplete", result.stdout)
            self.assertFalse((home / "runtime" / "current.json").exists())

    def test_interrupted_direct_pointer_commit_recovers_verified_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            command = [
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)]
            first = subprocess.run(
                command, capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(0, first.returncode, first.stdout + first.stderr)
            version = json.loads(first.stdout)["version"]
            (home / "runtime" / "current.json").unlink()
            (home / "runtime" / "update-state.json").unlink(missing_ok=True)
            (home / "runtime" / "usage" / f"{version}.json").unlink(missing_ok=True)

            recovered = subprocess.run(
                command, capture_output=True, text=True, timeout=120, check=False)

            self.assertEqual(0, recovered.returncode, recovered.stdout + recovered.stderr)
            self.assertEqual("activated", json.loads(recovered.stdout)["status"])
            self.assertTrue((home / "runtime" / "current.json").is_file())
            self.assertTrue((home / "runtime" / "usage" / f"{version}.json").is_file())
            self.assertTrue((home / "runtime" / "update-state.json").is_file())

    def test_installed_launcher_routes_oversized_generated_project_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = self._install_direct_fixture(root)
            home = root / "home" / ".loom"
            bootstrap = subprocess.run([
                sys.executable, "-B", str(direct / "scripts" / "loom_bootstrap.py"),
                "--ensure", "--plugin-root", str(direct), "--home", str(home)],
                capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(0, bootstrap.returncode, bootstrap.stdout + bootstrap.stderr)

            project = root / "oversized-project"
            project.mkdir()
            (project / "Cargo.toml").write_text(
                "[package]\nname='oversized'\nversion='0.1.0'\n", encoding="utf-8")
            (project / ".gitignore").write_text("target/\n", encoding="utf-8")
            (project / "agent.py").write_text("print('agent')\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(project), "init"], check=True,
                           capture_output=True, timeout=30)
            subprocess.run(["git", "-C", str(project), "add", "."], check=True,
                           capture_output=True, timeout=30)
            subprocess.run([
                "git", "-C", str(project), "-c", "user.name=Loom Test", "-c",
                "user.email=loom@example.invalid", "commit", "-m", "fixture"],
                check=True, capture_output=True, timeout=30)
            generated = project / "target" / "debug" / "objects"
            generated.mkdir(parents=True)
            for index in range(4100):
                (generated / f"{index:04d}.o").write_bytes(b"generated")

            request = (
                "Plan recurring blocker prevention for this llm-agent runtime. "
                "The Deep Research Reports path is inert source material; do not activate "
                "website or research domains.")
            home.mkdir(parents=True, exist_ok=True)
            (home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
                loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
            environment = {**os.environ, "LOOM_TEST_ALLOW_LEGACY_BACKEND": "1"}
            invoked = subprocess.run([
                sys.executable, "-B", str(home / "bin" / "loom.py"),
                "--home", str(home), "invoke", "--request", request,
                "--cwd", str(project), "--agent", "codex", "--agent-version", "test"],
                capture_output=True, text=True, timeout=120, check=False,
                env=environment)

            self.assertEqual(0, invoked.returncode, invoked.stdout + invoked.stderr)
            result = json.loads(invoked.stdout)
            self.assertEqual("action-required", result["status"])
            self.assertIn("llm-agent", result["domains"])
            self.assertNotIn("website", result["domains"])
            self.assertNotIn("research", result["domains"])
            inspection = result["plan_contract"]["project_inspection"]
            self.assertEqual("complete", inspection["state"])
            self.assertGreater(inspection["counts"]["entries_seen"], 4096)
            self.assertTrue(inspection["g1_eligible"])
            self.assertEqual(
                ["rust-target"],
                inspection["generated_rule_ids"])

    def test_signed_fresh_package_activates_and_stable_launcher_verifies_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helpers, receipts, evidence = package_evidence(
                ROOT, root / "evidence", loom_plugin_package.PLATFORMS,
                native_helper=self.helper)
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

    def test_prebootstrap_runtime_scan_rejects_redirected_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            redirected = runtime / "redirected"
            redirected.mkdir(parents=True)
            (runtime / "file").write_text("bound", encoding="utf-8")
            real_redirect = loom_bootstrap._redirect

            def redirect_probe(path):
                return Path(path) == redirected or real_redirect(path)

            with mock.patch.object(
                    loom_bootstrap, "_redirect", side_effect=redirect_probe):
                with self.assertRaisesRegex(loom_bootstrap.BootstrapError, "redirected"):
                    list(loom_bootstrap._runtime_files(runtime))

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
            self.assertEqual(
                home.resolve(), Path(migrate.migrate_v1.call_args.args[0]).resolve())


if __name__ == "__main__":
    unittest.main()
