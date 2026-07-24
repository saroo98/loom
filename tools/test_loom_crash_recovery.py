"""Real forced-process-termination probes for durable pointer writes."""

import subprocess
import tempfile
import unittest
from pathlib import Path

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
            loom_fault_harness.clone_git_fixture(
                source, destination, root / "clone-home")

            self.assertEqual(
                "VALUE = 1\n",
                (destination / "src" / "app.py").read_text(encoding="utf-8"))
            self.assertFalse(
                (destination / ".git" / "objects" / "maintenance.lock").exists())
            for key, expected in (
                    ("maintenance.auto", "false"), ("gc.auto", "0")):
                observed = subprocess.run(
                    ["git", "-C", str(destination), "config", "--local",
                     "--get", key],
                    capture_output=True, text=True, check=True)
                self.assertEqual(expected, observed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
