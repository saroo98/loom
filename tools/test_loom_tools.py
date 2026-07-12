"""Tests for loom_survey and loom_kickoff. Run: python -m unittest discover -s tools -p "test_*.py" """

import datetime as dt
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import loom_kickoff  # noqa: E402
import loom_survey   # noqa: E402

TODAY = dt.date.today().isoformat()


def sh(cwd, *args):
    assert args[0] == "git"  # keeps the no-network audit's literal-head guarantee
    return subprocess.run(["git"] + list(args[1:]), cwd=cwd,
                          capture_output=True, text=True)


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
        self.assertIn("Not a Git repository", out)
        self.assertIn("repo_state_hash:", out)
        self.assertIn("Filesystem state hash", out)
        self.assertIn("Node.js / JavaScript", out)
        self.assertIn("package.json: 2 declared", out)
        self.assertIn("package-lock.json", out)
        self.assertIn("auth_login.js", out)          # danger-zone heuristic
        self.assertIn("Test-looking files: 1", out)
        self.assertIn("Judgment TODO", out)
        self.assertIn("artifact: survey", out)        # pack-lintable frontmatter

    def test_non_git_state_hash_tracks_file_content(self):
        first = loom_survey.repo_state(self.root)
        self.assertEqual(first.mode, "filesystem")
        (self.root / "README.md").write_text("changed", encoding="utf-8")
        second = loom_survey.repo_state(self.root)
        self.assertNotEqual(first.state_hash, second.state_hash)

    def test_state_snapshot_never_returns_a_partial_hash_at_safety_limit(self):
        with mock.patch.object(loom_survey, "STATE_FILE_CAP", 1):
            with self.assertRaisesRegex(
                    loom_survey.SurveyError, "no partial state hash was produced"):
                loom_survey.repo_state(self.root)

    def test_missing_git_binary_falls_back_only_for_non_git_workspace(self):
        failure = loom_survey.SurveyError("git unavailable")
        with mock.patch.object(loom_survey, "run_git", side_effect=failure):
            state = loom_survey.repo_state(self.root)
        self.assertEqual(state.mode, "filesystem")
        (self.root / ".git").mkdir()
        with mock.patch.object(loom_survey, "run_git", side_effect=failure):
            with self.assertRaises(loom_survey.SurveyError):
                loom_survey.repo_state(self.root)

    def test_unborn_git_repository_is_valid_state_not_indeterminate(self):
        if sh(self.root, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.root, "git", "add", "README.md")
        state = loom_survey.repo_state(self.root)
        self.assertTrue(state.is_git)
        self.assertEqual(state.head, "")
        self.assertIn("README.md", state.staged)
        rendered = loom_survey.survey(self.root)
        self.assertIn("repo_head: null", rendered)
        self.assertIn("unborn — no commit", rendered)
        with self.assertRaisesRegex(loom_survey.SurveyError, "valid but unborn"):
            loom_survey.delta(self.root, "HEAD")

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

    def test_dot_path_resolves_to_nonempty_project_name(self):
        out = loom_survey.survey(".")
        self.assertNotIn('project: ""', out)

    def test_invalid_delta_base_fails_closed(self):
        if sh(self.root, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.root, "git", "config", "user.email", "t@t")
        sh(self.root, "git", "config", "user.name", "t")
        sh(self.root, "git", "add", "-A")
        sh(self.root, "git", "commit", "-qm", "base")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = loom_survey.main([
                str(self.root), "--since", "definitely-not-a-valid-commit",
            ])
        self.assertEqual(rc, 2)
        self.assertIn("invalid base commit", stderr.getvalue())

    def test_delta_reports_committed_staged_unstaged_and_untracked(self):
        if sh(self.root, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.root, "git", "config", "user.email", "t@t")
        sh(self.root, "git", "config", "user.name", "t")
        sh(self.root, "git", "add", "-A")
        sh(self.root, "git", "commit", "-qm", "base")
        base = sh(self.root, "git", "rev-parse", "HEAD").stdout.strip()

        (self.root / "README.md").write_text("committed", encoding="utf-8")
        sh(self.root, "git", "add", "README.md")
        sh(self.root, "git", "commit", "-qm", "committed change")
        (self.root / "package.json").write_text("{}", encoding="utf-8")
        sh(self.root, "git", "add", "package.json")
        (self.root / "package-lock.json").write_text("staged then changed", encoding="utf-8")
        sh(self.root, "git", "add", "package-lock.json")
        (self.root / "package-lock.json").write_text("unstaged after stage", encoding="utf-8")
        (self.root / "untracked.txt").write_text("new", encoding="utf-8")

        out = loom_survey.delta(self.root, base)

        for heading in ("Committed changes", "Staged changes", "Unstaged changes",
                        "Untracked files", "Repository state hash"):
            self.assertIn(heading, out)
        for name in ("README.md", "package.json", "package-lock.json", "untracked.txt"):
            self.assertIn(name, out)

    def test_state_hash_includes_untracked_file_content(self):
        if sh(self.root, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.root, "git", "config", "user.email", "t@t")
        sh(self.root, "git", "config", "user.name", "t")
        sh(self.root, "git", "add", "-A")
        sh(self.root, "git", "commit", "-qm", "base")
        path = self.root / "untracked.txt"
        path.write_text("one", encoding="utf-8")
        first = loom_survey.repo_state(self.root).state_hash
        path.write_text("two", encoding="utf-8")
        second = loom_survey.repo_state(self.root).state_hash
        self.assertNotEqual(first, second)

    @unittest.skipUnless(os.name == "nt", "Windows console regression")
    def test_windows_cli_emits_utf8_without_environment_override(self):
        if sh(self.root, "git", "init", "-q").returncode != 0:
            self.skipTest("git unavailable")
        sh(self.root, "git", "config", "user.email", "t@t")
        sh(self.root, "git", "config", "user.name", "t")
        sh(self.root, "git", "add", "-A")
        sh(self.root, "git", "commit", "-qm", "base")
        (self.root / "نام.txt").write_text("x", encoding="utf-8")
        env = dict(os.environ)
        env.pop("PYTHONIOENCODING", None)
        result = subprocess.run(
            [sys.executable, str(Path(loom_survey.__file__)), ".", "--since", "HEAD"],
            cwd=self.root, capture_output=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        text = result.stdout.decode("utf-8")
        self.assertIn("نام.txt", text)


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
        text = self.wo.read_text(encoding="utf-8")
        fm, _ = loom_kickoff.loom_lint.parse_frontmatter(text)
        prompt = loom_kickoff._render(text, fm, loom_path="/loom")
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
        text = self.wo.read_text(encoding="utf-8")
        fm, _ = loom_kickoff.loom_lint.parse_frontmatter(text)
        prompt = loom_kickoff._render(text, fm)
        self.assertIn("none declared", prompt)

    def test_standalone_wo_cannot_bypass_pack_and_state_checks(self):
        prompt, code = loom_kickoff.build(self.wo)
        self.assertIsNone(prompt)
        self.assertEqual(code, 1)


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

    def _write_pack(self, man_stamp, survey_stamp, state_hash=""):
        import loom_lint as ll
        state_line = f'repo_state_hash: "{state_hash}"\n' if state_hash else ""
        (self.repo / "plans" / "MANIFEST.md").write_text(f"""---
artifact: manifest
project: "w04"
tier: M
status: active
last_verified: {TODAY}
loom_version: "{ll.current_version()}"
repo_head: "{man_stamp}"
{state_line}---
# Pack [FACT — test]
""", encoding="utf-8")
        (self.repo / "plans" / "survey.md").write_text(f"""---
artifact: survey
status: gated
last_verified: {TODAY}
repo_head: "{survey_stamp}"
{state_line}---
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

    def test_uncommitted_change_outside_pack_is_reported(self):
        self._write_pack(self.c1, self.c1)
        (self.repo / "code.txt").write_text("dirty", encoding="utf-8")
        import loom_lint as ll
        rep = ll.lint(self.repo / "plans", repo_path=self.repo)
        self.assertTrue(any(f["code"] == "W15" for f in rep.findings), rep.findings)

    def test_invalid_repo_stamp_blocks_strict_staleness(self):
        self._write_pack("not-a-valid-commit", "not-a-valid-commit")
        import loom_lint as ll
        rep = ll.lint(
            self.repo / "plans", repo_path=self.repo, strict_staleness=True)
        self.assertTrue(any(f["code"] == "E16" for f in rep.errors), rep.findings)

    def test_two_month_gap_plus_local_drift_blocks_resume(self):
        self._write_pack(self.c1, self.c1)
        for path in (self.repo / "plans").glob("*.md"):
            path.write_text(
                path.read_text(encoding="utf-8").replace(TODAY, "2020-01-01"),
                encoding="utf-8")
        (self.repo / "untracked-after-pause.txt").write_text("drift", encoding="utf-8")
        import loom_lint as ll
        rep = ll.lint(
            self.repo / "plans", repo_path=self.repo, strict_staleness=True)
        messages = "\n".join(f["msg"] for f in rep.errors if f["code"] == "E16")
        self.assertIn("W03", messages)
        self.assertIn("W15", messages)
        self.assertIn("untracked-after-pause.txt", messages)

    def test_matching_state_hash_ignores_pack_only_edits(self):
        state = loom_survey.repo_state(self.repo)
        self._write_pack(self.c1, self.c1, state.state_hash)
        import loom_lint as ll
        rep = ll.lint(self.repo / "plans", repo_path=self.repo)
        self.assertFalse(any(f["code"] == "W15" for f in rep.findings), rep.findings)


if __name__ == "__main__":
    unittest.main()
