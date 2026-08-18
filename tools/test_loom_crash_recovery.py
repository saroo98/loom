"""Real forced-process-termination probes for durable pointer writes."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_fault_harness


ROOT = Path(__file__).resolve().parents[1]


class CrashRecoveryTests(unittest.TestCase):
    def test_process_death_before_and_after_replace_is_old_or_new_never_partial(self):
        result = loom_fault_harness.atomic_pointer_probe(ROOT)
        self.assertEqual("passed", result["status"])
        self.assertEqual(2, len(result["boundaries"]))

    def test_git_fixture_clone_never_traverses_transient_maintenance_lock(self):
        with tempfile.TemporaryDirectory(prefix="loom-git-fixture-") as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "src").mkdir(parents=True)
            (source / "src" / "app.py").write_text(
                "VALUE = 1\n", encoding="utf-8")
            fixture_home = root / "fixture-home"
            loom_fault_harness.initialize_git_fixture(source, fixture_home)
            maintenance_lock = source / ".git" / "objects" / "maintenance.lock"
            maintenance_lock.write_text("transient", encoding="utf-8")

            destination = root / "destination"
            real_run = loom_fault_harness._run_fixture_git
            commands = []

            def observed_run(arguments, **kwargs):
                commands.append(tuple(arguments))
                return real_run(arguments, **kwargs)

            with mock.patch.object(
                    loom_fault_harness, "_run_fixture_git",
                    side_effect=observed_run):
                loom_fault_harness.clone_git_fixture(
                    source, destination, root / "clone-home")

            self.assertEqual(
                "VALUE = 1\n",
                (destination / "src" / "app.py").read_text(encoding="utf-8"))
            self.assertFalse(
                (destination / ".git" / "objects" / "maintenance.lock").exists())
            self.assertEqual(1, len(commands))
            for key, expected in (
                    ("user.email", "test@example.invalid"),
                    ("user.name", "test"),
                    ("maintenance.auto", "false"),
                    ("gc.auto", "0")):
                observed = subprocess.run(
                    ["git", "-C", str(destination), "config", "--local",
                     "--get", key],
                    capture_output=True, text=True, check=True)
                self.assertEqual(expected, observed.stdout.strip())

    def test_disposable_runtime_shortcuts_are_exactly_scoped(self):
        install_builder = getattr(
            loom_fault_harness, "immutable_install_check", None)
        git_builder = getattr(
            loom_fault_harness, "filesystem_fixture_git", None)
        self.assertIsNotNone(install_builder)
        self.assertIsNotNone(git_builder)

        with tempfile.TemporaryDirectory(prefix="loom-runtime-fixture-") as temporary:
            root = Path(temporary)
            installed = root / "installed"
            installed.mkdir()
            other_install = root / "other-install"
            other_install.mkdir()
            verified = {
                "status": "installed",
                "install_id": "11111111-1111-4111-8111-111111111111",
                "files_verified": 17,
                "receipt_hash": "a" * 64,
            }
            checked = []

            def real_check(target):
                checked.append(Path(target))
                return {**verified, "status": "real"}

            with self.assertRaises(loom_fault_harness.FaultError):
                install_builder(
                    real_check, installed,
                    {**verified, "receipt_hash": "not-a-digest"})
            fixture_check = install_builder(
                real_check, installed, verified)
            self.assertEqual(verified, fixture_check(installed))
            self.assertEqual([], checked)
            self.assertEqual("real", fixture_check(other_install)["status"])
            self.assertEqual([other_install], checked)

            project = root / "project"
            project.mkdir()
            git_calls = []

            def real_git(repo, *args, **kwargs):
                git_calls.append((Path(repo), args, kwargs))
                return subprocess.CompletedProcess(
                    ["git", *args], 0, "true\n", "")

            fixture_git = git_builder(real_git, root)
            missing = fixture_git(
                project, "rev-parse", "--is-inside-work-tree",
                allowed=(0, 128))
            self.assertEqual(128, missing.returncode)
            self.assertEqual([], git_calls)

            (project / ".git").mkdir()
            present = fixture_git(
                project, "rev-parse", "--is-inside-work-tree",
                allowed=(0, 128))
            self.assertEqual(0, present.returncode)
            self.assertEqual(1, len(git_calls))


if __name__ == "__main__":
    unittest.main()
