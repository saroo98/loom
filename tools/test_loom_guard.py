"""Tests for the pack-guard pre-commit template. Needs git; skips cleanly without it."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_loom_lint import good_pack  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = LOOM_ROOT / "templates" / "hooks" / "pre-commit"
HAS_GIT = shutil.which("git") is not None


def run(args, cwd):
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=60)


@unittest.skipUnless(HAS_GIT, "git not available")
class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.email", "t@example.invalid"], self.repo)
        run(["git", "config", "user.name", "guard-test"], self.repo)
        good_pack(self.repo / "plans")
        hook = TEMPLATE.read_text(encoding="utf-8") \
            .replace("{{LOOM_PATH}}", LOOM_ROOT.as_posix()) \
            .replace("{{PACK_DIR}}", "plans")
        hook_path = self.repo / ".git" / "hooks" / "pre-commit"
        hook_path.write_text(hook, encoding="utf-8", newline="\n")
        hook_path.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def _commit(self, msg):
        run(["git", "add", "-A"], self.repo)
        return run(["git", "commit", "-q", "-m", msg], self.repo)

    def test_clean_pack_commit_passes(self):
        r = self._commit("pack in")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_error_pack_commit_blocked(self):
        (self.repo / "plans" / "MANIFEST.md").unlink()  # E01 — error-level
        r = self._commit("broken pack")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("loom guard", r.stdout + r.stderr)

    def test_non_pack_commit_ignores_broken_pack(self):
        self._commit("pack in")
        (self.repo / "plans" / "MANIFEST.md").unlink()  # pack now broken on disk
        (self.repo / "notes.txt").write_text("unrelated", encoding="utf-8")
        run(["git", "add", "notes.txt"], self.repo)
        # only notes.txt staged; the deletion is NOT staged -> guard must stay asleep
        r = run(["git", "commit", "-q", "-m", "unrelated"], self.repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
