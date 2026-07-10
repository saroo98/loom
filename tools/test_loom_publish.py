"""Tests for loom_publish. Run: python -m unittest discover -s tools -p "test_*.py" """

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_publish  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent
IS_PRIVATE_UPSTREAM = (LOOM_ROOT / "plans" / "MANIFEST.md").is_file()


class PublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "public"
        cls.rc = loom_publish.build(cls.out, check=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_build_is_clean(self):
        self.assertEqual(self.rc, 0, "firewall/link findings or missing entries")

    def test_core_present(self):
        for rel in ["START-HERE.md", "README.md", "PRIVACY.md", "CONTRIBUTING.md",
                    "LICENSE", "FEEDBACK.md", "CHANGELOG.md",
                    "loom/core/epistemics.md", "loom/core/privacy.md",
                    "loom/adaptation/localization-playbook.md",
                    "loom/meta/evolving-loom.md", "loom/meta/v1-scorecard.md",
                    "templates/work-order.md", "templates/hooks/pre-commit",
                    "skill/loom/SKILL.md", "tools/loom_lint.py",
                    "tools/loom_publish.py", "tools/publish-tokens.txt",
                    "assets/banner-light.svg", "assets/lifecycle-dark.svg",
                    "docs/index.html", "docs/robots.txt", "docs/sitemap.xml",
                    ".github/workflows/verify.yml", "tools/loom_audit.py"]:
            self.assertTrue((self.out / rel).is_file(), f"missing from cut: {rel}")

    def test_owner_layer_absent(self):
        # note: owner-domain paths are built from fragments so this test file itself
        # never contains a forbidden token contiguously (the firewall scans it too)
        deep_dive = "loom/adaptation/k" + "urdish-localization.md"
        for rel in ["plans", "loom/meta/evidence", "ROADMAP.md", deep_dive,
                    "loom/meta/plan-sharpening.md", "loom/meta/plan-public-cut.md",
                    "loom/meta/plan-learner-public.md", "public", "dist"]:
            self.assertFalse((self.out / rel).exists(), f"owner-layer leaked: {rel}")

    @unittest.skipUnless(IS_PRIVATE_UPSTREAM, "overlay assertions need the upstream tree")
    def test_overlay_won_over_root(self):
        readme = (self.out / "README.md").read_text(encoding="utf-8")
        self.assertIn("Sovereign", readme)               # public README, not owner's
        fb = (self.out / "FEEDBACK.md").read_text(encoding="utf-8")
        self.assertIn("This queue is **yours**", fb)     # fresh header, no entries
        self.assertNotIn("2026-07-09", fb)

    def test_fresh_feedback_has_no_entries(self):
        fb = (self.out / "FEEDBACK.md").read_text(encoding="utf-8")
        self.assertNotIn("Resolution (", fb)

    def test_firewall_catches_a_seeded_leak(self):
        leak = self.out / "loom" / "core" / "principles.md"
        original = leak.read_text(encoding="utf-8")
        seeded = "contact: " + "xizir" + "sar" + "o" + "@example.com"  # fragments —
        try:                       # this source file must not carry the token itself
            leak.write_text(original + "\n" + seeded + "\n", encoding="utf-8")
            tokens, allowed = loom_publish.load_tokens(
                LOOM_ROOT / "tools" / "publish-tokens.txt")
            if not tokens:  # public tree ships a placeholder token file
                self.skipTest("no owner tokens in this tree")
            findings = loom_publish.scan(self.out, tokens, allowed)
            self.assertTrue(any("FIREWALL" in f for f in findings))
        finally:
            leak.write_text(original, encoding="utf-8")

    def test_no_pycache_or_reports(self):
        self.assertFalse(list(self.out.rglob("__pycache__")))
        self.assertFalse(list(self.out.rglob("report.html")))


if __name__ == "__main__":
    unittest.main()
