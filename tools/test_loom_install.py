"""Installer ownership, freshness, and reversible-uninstall regressions."""

import os
import shutil
import subprocess
import tempfile
import unittest
import contextlib
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).parent))
import loom_install  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def source_marker_guard():
    """Keep installer wrapper probes from leaving an instance marker in a public test tree."""
    marker = ROOT / ".loom-instance-id"
    existed = marker.is_file()
    original = marker.read_bytes() if existed else None
    try:
        yield
    finally:
        if existed:
            if not marker.is_file() or marker.read_bytes() != original:
                raise AssertionError("installer changed the pre-existing source instance marker")
        elif marker.is_file():
            marker.unlink()


class PythonInstallerTests(unittest.TestCase):
    def make_root(self, base):
        root = Path(base) / "loom root $ literal"
        (root / "skill" / "loom").mkdir(parents=True)
        (root / "skill" / "codex-prompt").mkdir(parents=True)
        shutil.copy2(ROOT / "skill" / "loom" / "SKILL.md",
                     root / "skill" / "loom" / "SKILL.md")
        shutil.copy2(ROOT / "skill" / "codex-prompt" / "loom.md",
                     root / "skill" / "codex-prompt" / "loom.md")
        return root

    def test_cross_platform_install_check_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_root(tmp)
            home = Path(tmp) / "home $ literal"
            self.assertEqual(loom_install.run(home, loom_root=root), 0)
            self.assertEqual(
                loom_install.run(home, mode="check", loom_root=root), 0)
            self.assertEqual(
                loom_install.run(home, mode="uninstall", loom_root=root), 0)
            self.assertFalse((home / ".codex" / "skills" / "loom" / "SKILL.md").exists())
            self.assertTrue((home / ".codex").is_dir())

    def test_foreign_preflight_makes_no_partial_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_root(tmp)
            home = Path(tmp) / "home"
            foreign = home / ".codex" / "skills" / "loom" / "SKILL.md"
            foreign.parent.mkdir(parents=True)
            foreign.write_text("foreign sentinel\n", encoding="utf-8")
            with self.assertRaisesRegex(loom_install.InstallError, "no entry-point files changed"):
                loom_install.run(home, loom_root=root)
            self.assertEqual(foreign.read_text(encoding="utf-8"), "foreign sentinel\n")
            self.assertFalse((home / ".claude" / "skills" / "loom" / "SKILL.md").exists())
            self.assertFalse((home / ".codex" / "prompts" / "loom.md").exists())

    def test_explicit_adoption_handles_recognized_legacy_skill_and_prompt_as_one_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_root(tmp)
            home = Path(tmp) / "home"
            owner = loom_install._owner_id(home, root, may_create=True)
            targets = loom_install._targets(root, home)
            legacy = []
            for target in targets:
                rendered = loom_install._render(target.source, root, owner).decode("utf-8")
                body = loom_install.OWNER_RE.sub("", rendered)
                target.destination.parent.mkdir(parents=True, exist_ok=True)
                target.destination.write_text(body, encoding="utf-8")
                legacy.append(target.destination.read_bytes())
            with self.assertRaisesRegex(loom_install.InstallError, "no entry-point files changed"):
                loom_install.run(home, loom_root=root)
            self.assertEqual(
                [target.destination.read_bytes() for target in targets], legacy)
            self.assertEqual(
                loom_install.run(home, loom_root=root, adopt_legacy=True), 0)
            self.assertEqual(loom_install.run(home, mode="check", loom_root=root), 0)
            self.assertTrue(all(
                loom_install.OWNER_RE.search(
                    target.destination.read_text(encoding="utf-8"))
                for target in targets))

    def test_targets_canonicalize_equivalent_root_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_root(tmp)
            alias = root / ".." / root.name
            home = Path(tmp) / "home"

            targets = loom_install._targets(alias, home)
            owner = "00000000-0000-0000-0000-000000000000"

            self.assertTrue(all(
                target.source.is_relative_to(root.resolve())
                for target in targets))
            self.assertTrue(all(
                target.destination.is_relative_to(home.resolve())
                for target in targets))
            self.assertEqual(
                loom_install._render(targets[0].source, alias, owner),
                loom_install._render(targets[0].source, root.resolve(), owner))

    def test_mid_transaction_io_failure_rolls_back_created_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_root(tmp)
            home = Path(tmp) / "home"
            real_write = loom_install._atomic_write
            calls = 0

            def fail_second(path, content):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("seeded second-write failure")
                return real_write(path, content)

            with mock.patch.object(loom_install, "_atomic_write", side_effect=fail_second):
                with self.assertRaisesRegex(loom_install.InstallError, "prior files were restored"):
                    loom_install.run(home, loom_root=root)
            self.assertFalse((home / ".claude" / "skills" / "loom" / "SKILL.md").exists())
            self.assertFalse((home / ".codex" / "skills" / "loom" / "SKILL.md").exists())
            self.assertFalse((home / ".codex" / "prompts" / "loom.md").exists())


class PowerShellInstallerTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt" and shutil.which("powershell"),
                         "Windows PowerShell required")
    def test_check_and_uninstall_preserve_modified_owned_file(self):
        with source_marker_guard(), tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home $ literal"
            command = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(ROOT / "tools" / "install.ps1"), "-UserHome", str(home),
            ]
            installed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
            checked = subprocess.run(
                command + ["-Check"], capture_output=True, text=True, timeout=30)
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)

            modified = home / ".codex" / "skills" / "loom" / "SKILL.md"
            modified.write_text(
                modified.read_text(encoding="utf-8") + "local owner edit\n",
                encoding="utf-8")
            stale = subprocess.run(
                command + ["-Check"], capture_output=True, text=True, timeout=30)
            self.assertEqual(stale.returncode, 1, stale.stderr + stale.stdout)
            removed = subprocess.run(
                command + ["-Uninstall"], capture_output=True, text=True, timeout=30)
            self.assertEqual(removed.returncode, 1, removed.stderr + removed.stdout)
            self.assertTrue(modified.is_file())
            self.assertIn("local owner edit", modified.read_text(encoding="utf-8"))
            self.assertTrue((home / ".claude" / "skills" / "loom" / "SKILL.md").is_file())
            self.assertTrue((home / ".codex" / "prompts" / "loom.md").is_file())

    @unittest.skipUnless(os.name == "nt" and shutil.which("powershell"),
                         "Windows PowerShell required")
    def test_foreign_destination_is_never_overwritten(self):
        with source_marker_guard(), tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            foreign = home / ".codex" / "skills" / "loom" / "SKILL.md"
            foreign.parent.mkdir(parents=True)
            foreign.write_text("foreign sentinel\n", encoding="utf-8")
            result = subprocess.run([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(ROOT / "tools" / "install.ps1"), "-UserHome", str(home),
            ], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(foreign.read_text(encoding="utf-8"), "foreign sentinel\n")
            self.assertFalse((home / ".claude" / "skills" / "loom" / "SKILL.md").exists())
            self.assertFalse((home / ".codex" / "prompts" / "loom.md").exists())


class ShellInstallerTests(unittest.TestCase):
    @unittest.skipUnless(os.name != "nt" and shutil.which("bash"),
                         "POSIX bash required")
    def test_shell_install_check_and_uninstall(self):
        with source_marker_guard(), tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            command = ["bash", str(ROOT / "tools" / "install.sh"), "--home", str(home)]
            installed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
            checked = subprocess.run(
                command + ["--check"], capture_output=True, text=True, timeout=30)
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
            removed = subprocess.run(
                command + ["--uninstall"], capture_output=True, text=True, timeout=30)
            self.assertEqual(removed.returncode, 0, removed.stderr + removed.stdout)
            self.assertFalse((home / ".codex" / "skills" / "loom" / "SKILL.md").exists())


if __name__ == "__main__":
    unittest.main()
