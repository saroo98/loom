"""Tests for loom_report. Run: python -m unittest discover -s tools -p "test_*.py" """

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_report  # noqa: E402
from test_loom_lint import good_pack, write, TODAY  # noqa: E402

LOOM_ROOT = Path(__file__).resolve().parent.parent


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        good_pack(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _html(self, args=None):
        rc = loom_report.main([self.root] + (args or []))
        self.assertEqual(rc, 0)
        out = Path(self.root) / "report.html"
        self.assertTrue(out.is_file())
        return out.read_text(encoding="utf-8")

    def test_report_carries_the_pack(self):
        html = self._html()
        for marker in ("WO-001", "A-001", "D-001", "tier M", "<svg", "Lint (live)"):
            self.assertIn(marker, html, f"missing: {marker}")

    def test_lint_findings_are_embedded(self):
        write(self.root, "work-orders/WO-002-vague.md", f"""---
id: WO-002
title: Vague
status: ready
depends_on: []
routing: fast-cheap
size: S
touches: [docs/**]
last_verified: {TODAY}
---
## Acceptance criteria
- [ ] everything works nicely
""")
        html = self._html()
        self.assertIn("W10", html)

    def test_custom_out_path(self):
        out = Path(self.root) / "elsewhere.html"
        rc = loom_report.main([self.root, "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.is_file())

    def test_missing_pack_is_usage_error(self):
        self.assertEqual(loom_report.main([str(Path(self.root) / "nope")]), 2)

    def test_content_is_escaped(self):
        write(self.root, "work-orders/WO-003-xss.md", f"""---
id: WO-003
title: "<script>alert(1)</script>"
status: ready
depends_on: []
routing: fast-cheap
size: S
touches: [x/**]
last_verified: {TODAY}
---
body
""")
        html = self._html()
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)

    def test_dogfood_self_pack(self):
        """The report must render Loom's own living pack without error.
        Skips in trees without a self-pack (a fresh public cut has none yet)."""
        if not (LOOM_ROOT / "plans" / "MANIFEST.md").is_file():
            self.skipTest("no self-pack in this tree (fresh cut)")
        out = Path(self.root) / "self.html"
        rc = loom_report.main([str(LOOM_ROOT / "plans"), "--repo", str(LOOM_ROOT),
                               "--out", str(out)])
        self.assertEqual(rc, 0)
        html = out.read_text(encoding="utf-8")
        self.assertIn("Loom (self)", html)


if __name__ == "__main__":
    unittest.main()
