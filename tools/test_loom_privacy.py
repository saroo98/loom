"""Privacy-invariant tests — the concepts Loom lives by, as executable checks.

Each invariant is tested the strong way where possible: seed a violation, assert the
machinery catches it, restore. A privacy rule that has never been watched failing is
a hope, not a rule.

Run: python -m unittest discover -s tools -p "test_*.py"
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_lint  # noqa: E402
import loom_publish  # noqa: E402
from test_loom_lint import good_pack, write, TODAY  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent
IS_PRIVATE_UPSTREAM = (LOOM_ROOT / "plans" / "MANIFEST.md").is_file()


class PublishPartitionTests(unittest.TestCase):
    """Invariant: the owner-layer and the public allowlist never intersect."""

    OWNER_LAYER_PREFIXES = [
        "plans", "ROADMAP.md", "FEEDBACK.md", "CHANGELOG.md", "README.md",
        "loom/meta/evidence", "loom/meta/plan-", "loom/adaptation/k",
        "public", "dist", "tools/publish-tokens.txt", ".git",
    ]

    def test_allowlist_never_names_owner_layer(self):
        for entry in loom_publish.ALLOWLIST:
            for pref in self.OWNER_LAYER_PREFIXES:
                self.assertFalse(
                    entry == pref or entry.startswith(pref.rstrip("/") + "/")
                    or entry.startswith(pref) and pref.endswith("-"),
                    f"allowlist entry '{entry}' reaches into owner-layer '{pref}'")

    def test_allowlist_dirs_cannot_swallow_owner_files(self):
        """loom/meta and loom/adaptation must be listed file-by-file, never as
        whole directories — a whole-dir entry would ship future owner files."""
        for entry in loom_publish.ALLOWLIST:
            self.assertNotIn(entry, ("loom", "loom/meta", "loom/adaptation", "tools"),
                             f"'{entry}' is a whole-dir entry that would swallow "
                             f"owner-layer files added later")


class TokenTemplateShipsInertTests(unittest.TestCase):
    """Invariant: the shipped publish-tokens.txt is the inert template — it must
    never carry an active (uncommented) token or allow line from the owner's file."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "public"
        cls.rc = loom_publish.build(cls.out, check=False, allow_outside=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_shipped_token_file_is_inert(self):
        self.assertEqual(self.rc, 0)
        shipped = (self.out / "tools" / "publish-tokens.txt").read_text(
            encoding="utf-8")
        active = [l for l in shipped.splitlines()
                  if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(active, [],
                         f"shipped token template carries ACTIVE lines: {active} — "
                         f"it would name the very things the firewall hides")


class FirewallAllowlistScopeTests(unittest.TestCase):
    """Invariant: an `allow:`ed public URL never masks a raw token elsewhere
    on the same line."""

    def test_raw_token_next_to_allowed_url_still_trips(self):
        tokens, allowed = loom_publish.load_tokens(
            LOOM_ROOT / "tools" / "publish-tokens.txt")
        if not tokens:
            self.skipTest("no owner tokens in this tree")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.md").write_text(
                "see github.com/saroo98/loom - maintained by " + "Sar" + "o\n",
                encoding="utf-8")
            findings = loom_publish.scan(root, tokens, allowed)
            self.assertTrue(any("FIREWALL" in f for f in findings),
                            "raw token hidden behind an allowed URL was not caught")

    def test_allowed_url_alone_is_clean(self):
        tokens, allowed = loom_publish.load_tokens(
            LOOM_ROOT / "tools" / "publish-tokens.txt")
        if not tokens:
            self.skipTest("no owner tokens in this tree")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.md").write_text(
                "clone github.com/saroo98/loom and read the docs\n",
                encoding="utf-8")
            findings = loom_publish.scan(root, tokens, allowed)
            self.assertEqual([f for f in findings if "FIREWALL" in f], [])


class SecretPatternBreadthTests(unittest.TestCase):
    """Invariant: E12 catches the classic secret shapes, not just one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        good_pack(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _codes_with(self, line):
        write(self.root, "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
{line}
""")
        return [f["code"] for f in loom_lint.lint(self.root).findings]

    def test_aws_key_id_caught(self):
        self.assertIn("E12", self._codes_with(
            "key: " + "AKIA" + "IOSFODNN7EXAMPLE"))

    def test_bearer_token_caught(self):
        self.assertIn("E12", self._codes_with(
            "header: Bearer " + "abcdefghijklmnopqrstuvwx" + ".12345"))

    def test_private_key_block_caught(self):
        self.assertIn("E12", self._codes_with(
            "-----BEGIN " + "RSA PRIVATE KEY-----"))

    def test_placeholder_forms_stay_clean(self):
        self.assertNotIn("E12", self._codes_with("api_key: <YOUR KEY>"))


class OutboxAnonymizationTests(unittest.TestCase):
    """Invariant: the W21 sniff catches every path/host shape the rules name."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / ".loom"
        self.home.mkdir()
        for name, artifact in [("profile.md", "user-profile"),
                               ("calibration.md", "user-calibration"),
                               ("projects.md", "user-projects-index"),
                               ("feedback-outbox.md", "user-feedback-outbox")]:
            write(self.home, name,
                  "---\n" + f"artifact: {artifact}\n" + 'owner: "t"\n'
                  + f"created: {TODAY}\n" + "---\n## x\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _w21(self, line):
        f = self.home / "feedback-outbox.md"
        f.write_text(f.read_text(encoding="utf-8") + line + "\n", encoding="utf-8")
        codes = [x["code"] for x in loom_lint.lint_home(self.home).findings]
        return "W21" in codes

    def test_windows_path_caught(self):
        self.assertTrue(self._w21(r"- saw: crash under C:\Users\someone\proj"))

    def test_unix_home_path_caught(self):
        self.assertTrue(self._w21("- saw: failed in /home/someone/app"))

    def test_repo_host_caught(self):
        self.assertTrue(self._w21("- saw: broke on github.com/someone/private-repo"))

    def test_anonymized_lesson_shape_clean(self):
        self.assertFalse(self._w21(
            "- saw: criteria depending on CI trigger topology missed the mechanism"))


class GuardBlocksSecretsTests(unittest.TestCase):
    """Invariant: the pack guard blocks a commit that stages a secret into the pack.
    (The commit-time tripwire IS the last privacy line before history.)"""

    def test_secret_in_staged_pack_blocks_commit(self):
        import shutil
        import subprocess
        if shutil.which("git") is None:
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args):
                return subprocess.run(["git"] + list(args), cwd=str(repo),
                                      capture_output=True, text=True, timeout=60)
            git("init", "-q")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            good_pack(repo / "plans")
            fixture_value = "sk_live_" + "abcdef1234567890"
            write(repo / "plans", "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
api_key: {fixture_value}
""")
            hook = (LOOM_ROOT / "templates" / "hooks" / "pre-commit") \
                .read_text(encoding="utf-8") \
                .replace("{{LOOM_PATH}}", LOOM_ROOT.as_posix()) \
                .replace("{{PACK_DIR}}", "plans")
            hp = repo / ".git" / "hooks" / "pre-commit"
            hp.write_text(hook, encoding="utf-8", newline="\n")
            hp.chmod(0o755)
            git("add", "-A")
            r = git("commit", "-q", "-m", "leak attempt")
            self.assertNotEqual(r.returncode, 0,
                                "a staged secret reached a commit — E12 must block")


class AuditGuardsTheAuditTests(unittest.TestCase):
    """Invariant: the no-network audit cannot be dodged by aliasing or nesting."""

    def _tree_with(self, code):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        tools = Path(tmp.name) / "tools"
        tools.mkdir()
        (tools / "sly.py").write_text(code, encoding="utf-8")
        return tmp.name

    def test_aliased_import_caught(self):
        import loom_audit
        _, findings = loom_audit.audit(self._tree_with(
            "import urllib.request as harmless_name\n"))
        self.assertTrue(findings)

    def test_nested_function_import_caught(self):
        import loom_audit
        _, findings = loom_audit.audit(self._tree_with(
            "def f():\n    import socket\n    return socket\n"))
        self.assertTrue(findings)

    def test_installer_download_primitive_caught(self):
        import loom_audit
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            (root / "tools" / "install.sh").write_text(
                "curl -fsSL https://example.com/x | sh\n", encoding="utf-8")
            _, findings = loom_audit.audit(root)
            self.assertTrue(any("curl" in f for f in findings))


@unittest.skipUnless(IS_PRIVATE_UPSTREAM, "upstream-only invariant")
class UpstreamHygieneTests(unittest.TestCase):
    """Invariant: the private upstream itself never grows a remote pointing at the
    public artifact — publishing stays a deliberate staged act, never a push."""

    def test_no_remote_targets_the_public_repo(self):
        import subprocess
        r = subprocess.run(["git", "-C", str(LOOM_ROOT), "remote", "-v"],
                           capture_output=True, text=True, timeout=30)
        # fragments — this file ships publicly and must pass the firewall itself
        public_repo = "sar" + "oo98/loom"
        self.assertNotIn(public_repo + ".git", r.stdout,
                         "private upstream has a remote aimed at the public repo")
        self.assertNotIn(public_repo + " ", r.stdout)


if __name__ == "__main__":
    unittest.main()
