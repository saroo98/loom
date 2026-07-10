"""Tests for loom_survey and loom_kickoff. Run: python -m unittest discover -s tools -p "test_*.py" """

import datetime as dt
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_kickoff  # noqa: E402
import loom_survey   # noqa: E402

TODAY = dt.date.today().isoformat()


def sh(cwd, *args):
    return subprocess.run(list(args), cwd=cwd, capture_output=True, text=True)


class SurveyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "src").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "package.json").write_text(
            '{"dependencies": {"a": "1"}, "devDependencies": {"b": "2"}}', encoding="utf-8")
        (self.root / "package-lock.json").write_text("{}", encoding="utf-8")
        (self.root / "src" / "auth_login.js").write_text("// auth", encoding="utf-8")
        (self.root / "tests" / "x.test.js").write_text("test", encoding="utf-8")
        (self.root / "README.md").write_text("# hi", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_survey_without_git(self):
        out = loom_survey.survey(self.root)
        self.assertIn("Not a git repository", out)
        self.assertIn("Node.js / JavaScript", out)
        self.assertIn("package.json: 2 declared", out)
        self.assertIn("package-lock.json", out)
        self.assertIn("auth_login.js", out)          # danger-zone heuristic
        self.assertIn("Test-looking files: 1", out)
        self.assertIn("Judgment TODO", out)
        self.assertIn("artifact: survey", out)        # pack-lintable frontmatter

    def test_survey_with_git_and_delta(self):
        if sh(self.root, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.root, "git", "config", "user.email", "t@t")
        sh(self.root, "git", "config", "user.name", "t")
        sh(self.root, "git", "add", "-A")
        sh(self.root, "git", "commit", "-qm", "one")
        first = sh(self.root, "git", "rev-parse", "HEAD").stdout.strip()

        out = loom_survey.survey(self.root)
        self.assertIn(f"HEAD: `{first}`", out)
        self.assertIn("repo_head:", out)

        (self.root / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")
        (self.root / "src" / "pay_checkout.js").write_text("//", encoding="utf-8")
        sh(self.root, "git", "add", "-A")
        sh(self.root, "git", "commit", "-qm", "two")

        d = loom_survey.delta(self.root, first)
        self.assertIn("Commits in range: 1", d)
        self.assertIn("package.json", d)              # manifest change flagged
        self.assertIn("pay_checkout.js", d)           # danger-zone touch flagged
        self.assertIn("assumption ledger", d)


class KickoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.wo = Path(self.tmp.name) / "WO-007-refresh.md"
        self.wo.write_text(f"""---
id: WO-007
title: Add refresh
status: ready
routing: strong-coding
size: S
touches: [src/auth/**]
last_verified: {TODAY}
---
## Intent
Do the thing.
""", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_prompt_contains_contract(self):
        prompt, code = loom_kickoff.build(self.wo, loom_path="/loom")
        self.assertEqual(code, 0)
        self.assertIn("Execute work order WO-007", prompt)
        self.assertIn("src/auth/**", prompt)
        self.assertIn("pre-WO staleness check", prompt)
        self.assertIn("handoff brief", prompt)
        self.assertIn("## Intent", prompt)             # full WO body embedded
        self.assertIn("/loom/loom/execution/parallel-work.md", prompt)

    def test_missing_file_fails(self):
        prompt, code = loom_kickoff.build(Path(self.tmp.name) / "nope.md")
        self.assertIsNone(prompt)
        self.assertEqual(code, 1)

    def test_no_touches_gets_escalation_wording(self):
        self.wo.write_text(self.wo.read_text(encoding="utf-8").replace(
            "touches: [src/auth/**]\n", ""), encoding="utf-8")
        prompt, code = loom_kickoff.build(self.wo)
        self.assertEqual(code, 0)
        self.assertIn("none declared", prompt)


class W04DriftTests(unittest.TestCase):
    """repo_head drift: attribution, full hashes, pack-only tolerance (2026-07-10 FEEDBACK)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        if sh(self.repo, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.repo, "git", "config", "user.email", "t@t")
        sh(self.repo, "git", "config", "user.name", "t")
        (self.repo / "plans").mkdir()
        (self.repo / "code.txt").write_text("v1", encoding="utf-8")
        self._write_pack("PLACEHOLDER", "PLACEHOLDER")
        sh(self.repo, "git", "add", "-A"); sh(self.repo, "git", "commit", "-qm", "c1")
        self.c1 = sh(self.repo, "git", "rev-parse", "HEAD").stdout.strip()

    def tearDown(self):
        self.tmp.cleanup()

    def _write_pack(self, man_stamp, survey_stamp):
        import loom_lint as ll
        (self.repo / "plans" / "MANIFEST.md").write_text(f"""---
artifact: manifest
project: "w04"
tier: M
status: active
last_verified: {TODAY}
loom_version: "{ll.current_version()}"
repo_head: "{man_stamp}"
---
# Pack [FACT — test]
""", encoding="utf-8")
        (self.repo / "plans" / "survey.md").write_text(f"""---
artifact: survey
status: gated
last_verified: {TODAY}
repo_head: "{survey_stamp}"
---
# Survey [FACT — test]
""", encoding="utf-8")

    def _w04(self):
        import loom_lint as ll
        rep = ll.lint(self.repo / "plans", repo_path=self.repo)
        return [f for f in rep.findings if f["code"] == "W04"]

    def test_pack_only_drift_is_tolerated(self):
        # restamp to c1, commit (touches only plans/) -> HEAD moves past stamp, no W04
        self._write_pack(self.c1, self.c1)
        sh(self.repo, "git", "add", "-A"); sh(self.repo, "git", "commit", "-qm", "restamp")
        self.assertEqual(self._w04(), [])

    def test_outside_drift_fires_with_attribution_and_full_hashes(self):
        self._write_pack(self.c1, self.c1)
        sh(self.repo, "git", "add", "-A"); sh(self.repo, "git", "commit", "-qm", "restamp")
        (self.repo / "code.txt").write_text("v2", encoding="utf-8")
        sh(self.repo, "git", "add", "-A"); sh(self.repo, "git", "commit", "-qm", "code change")
        findings = self._w04()
        self.assertEqual(len(findings), 2)  # MANIFEST and survey.md both stamped stale
        files = {Path(f["path"]).name for f in findings}
        self.assertEqual(files, {"MANIFEST.md", "survey.md"})
        head = sh(self.repo, "git", "rev-parse", "HEAD").stdout.strip()
        for f in findings:
            self.assertIn(self.c1, f["msg"])   # full stamp hash, not truncated
            self.assertIn(head, f["msg"])      # full HEAD hash
            self.assertIn(Path(f["path"]).name, f["msg"])  # file named in message

    def test_only_stale_file_is_flagged(self):
        head_now = sh(self.repo, "git", "rev-parse", "HEAD").stdout.strip()
        (self.repo / "code.txt").write_text("v3", encoding="utf-8")
        sh(self.repo, "git", "add", "-A"); sh(self.repo, "git", "commit", "-qm", "code v3")
        head2 = sh(self.repo, "git", "rev-parse", "HEAD").stdout.strip()
        self._write_pack(head2, self.c1)  # MANIFEST current, survey stale
        sh(self.repo, "git", "add", "-A"); sh(self.repo, "git", "commit", "-qm", "restamp manifest")
        findings = self._w04()
        # MANIFEST's drift (head2..HEAD) is pack-only -> tolerated; survey's (c1..HEAD) is not
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["path"].endswith("survey.md"))


if __name__ == "__main__":
    unittest.main()
