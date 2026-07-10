"""Tests for loom_lint. Run: python -m unittest discover -s tools -p "test_*.py" """

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_lint  # noqa: E402

TODAY = dt.date.today().isoformat()


def write(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def good_pack(root):
    write(root, "MANIFEST.md", f"""---
artifact: manifest
project: "test"
tier: M
status: active
last_verified: {TODAY}
loom_version: "{loom_lint.current_version()}"
freshness_window_days: 14
---
# Pack
""")
    write(root, "assumptions.md", f"""---
artifact: assumption-ledger
status: draft
last_verified: {TODAY}
---
# Ledger

## A-001: Users are on mobile
- status: open
- basis: requester said so
- risk_if_wrong: MED — layout rework
- verify_by: G1 exit
- used_in: intake.md, work-orders/WO-001
""")
    write(root, "decisions.md", f"""---
artifact: decision-log
status: draft
last_verified: {TODAY}
---
## D-001: SQLite, not Postgres
- chosen: SQLite
""")
    write(root, "intake.md", f"""---
artifact: intake
status: gated
last_verified: {TODAY}
---
# Intake
Mobile-first per [ASSUMPTION A-001]; storage per D-001.
""")
    write(root, "work-orders/WO-001-build-ui.md", f"""---
id: WO-001
title: Build UI
status: ready
depends_on: []
routing: strong-coding
size: S
last_verified: {TODAY}
---
## Intent
Build it. Rests on A-001.
""")


def codes(rep):
    return [f["code"] for f in rep.findings]


class LintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        good_pack(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def lint(self):
        return loom_lint.lint(self.root)

    def test_good_pack_has_no_errors(self):
        rep = self.lint()
        self.assertEqual(rep.errors, [], f"unexpected: {rep.findings}")

    def test_missing_manifest(self):
        (Path(self.root) / "MANIFEST.md").unlink()
        self.assertIn("E01", codes(self.lint()))

    def test_bad_wo_status_enum(self):
        p = Path(self.root) / "work-orders/WO-001-build-ui.md"
        p.write_text(p.read_text(encoding="utf-8").replace("status: ready", "status: finished"),
                     encoding="utf-8")
        self.assertIn("E04", codes(self.lint()))

    def test_wo_filename_mismatch(self):
        p = Path(self.root) / "work-orders/WO-001-build-ui.md"
        p.rename(Path(self.root) / "work-orders/WO-9-build-ui.md")
        self.assertIn("E06", codes(self.lint()))

    def test_unknown_dependency(self):
        write(self.root, "work-orders/WO-002-more.md", f"""---
id: WO-002
title: More
status: ready
depends_on: [WO-777]
routing: fast-cheap
size: S
last_verified: {TODAY}
---
body
""")
        self.assertIn("E08", codes(self.lint()))

    def test_dependency_cycle(self):
        p = Path(self.root) / "work-orders/WO-001-build-ui.md"
        p.write_text(p.read_text(encoding="utf-8").replace("depends_on: []",
                                                           "depends_on: [WO-002]"),
                     encoding="utf-8")
        write(self.root, "work-orders/WO-002-more.md", f"""---
id: WO-002
title: More
status: ready
depends_on: [WO-001]
routing: fast-cheap
size: S
last_verified: {TODAY}
---
body
""")
        self.assertIn("E09", codes(self.lint()))

    def test_ledger_missing_field(self):
        p = Path(self.root) / "assumptions.md"
        p.write_text(p.read_text(encoding="utf-8").replace("- verify_by: G1 exit\n", ""),
                     encoding="utf-8")
        self.assertIn("E10", codes(self.lint()))

    def test_orphan_assumption_reference(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8") + "\nAlso rests on A-999.\n",
                     encoding="utf-8")
        self.assertIn("E11", codes(self.lint()))

    def test_secret_pattern(self):
        write(self.root, "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
api_key: sk_live_abcdef1234567890
""")
        self.assertIn("E12", codes(self.lint()))

    def test_placeholder_secret_is_ok(self):
        write(self.root, "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
api_key: <PLACEHOLDER>
""")
        self.assertNotIn("E12", codes(self.lint()))

    def test_stale_artifact_warns(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8").replace(TODAY, "2020-01-01"),
                     encoding="utf-8")
        rep = self.lint()
        self.assertIn("W03", codes(rep))
        self.assertEqual(rep.errors, [])  # staleness is a warning, not an error

    def test_hedge_phrase_warns(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8") + "\nThe migration should work.\n",
                     encoding="utf-8")
        self.assertIn("W02", codes(self.lint()))

    def test_broken_assumption_fanout_warns(self):
        p = Path(self.root) / "assumptions.md"
        p.write_text(p.read_text(encoding="utf-8").replace("- status: open",
                                                           "- status: broken"),
                     encoding="utf-8")
        rep = self.lint()
        # intake.md is gated (not stale) and WO-001 is ready (not blocked) -> two W05s
        self.assertGreaterEqual(codes(rep).count("W05"), 2)

    def test_unreferenced_ledger_entry_warns(self):
        p = Path(self.root) / "assumptions.md"
        p.write_text(p.read_text(encoding="utf-8") + f"""
## A-002: Nobody mentions me
- status: open
- basis: guess
- risk_if_wrong: LOW — nothing
- verify_by: G1 exit
- used_in: nowhere.md
""", encoding="utf-8")
        self.assertIn("W01", codes(self.lint()))

    def test_unknown_decision_reference_warns(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8") + "\nSee D-042 for details.\n",
                     encoding="utf-8")
        self.assertIn("W06", codes(self.lint()))

    def test_exit_codes(self):
        self.assertEqual(loom_lint.main([self.root]), 0)
        (Path(self.root) / "MANIFEST.md").unlink()
        self.assertEqual(loom_lint.main([self.root]), 1)

    # --- lint v2 (0.4.0) checks ---

    def _add_wo(self, wid, touches, status="ready", body="body"):
        write(self.root, f"work-orders/{wid}-x.md", f"""---
id: {wid}
title: X
status: {status}
depends_on: []
routing: fast-cheap
size: S
touches: {touches}
last_verified: {TODAY}
---
{body}
""")

    def test_touches_overlap_warns(self):
        self._add_wo("WO-002", "[src/auth/**]")
        self._add_wo("WO-003", "[src/auth/session.py]")
        self.assertIn("W07", codes(self.lint()))

    def test_disjoint_touches_ok(self):
        self._add_wo("WO-002", "[src/auth/**]")
        self._add_wo("WO-003", "[src/billing/**]")
        self.assertNotIn("W07", codes(self.lint()))

    def test_overlap_ignored_when_not_active(self):
        self._add_wo("WO-002", "[src/auth/**]")
        self._add_wo("WO-003", "[src/auth/**]", status="blocked")
        self.assertNotIn("W07", codes(self.lint()))

    def test_unlabeled_artifact_warns(self):
        write(self.root, "product.md", f"""---
artifact: product-plan
status: draft
last_verified: {TODAY}
---
We will build the best app for everyone.
""")
        self.assertIn("W08", codes(self.lint()))

    def test_dead_glossary_term_warns(self):
        p = Path(self.root) / "MANIFEST.md"
        p.write_text(p.read_text(encoding="utf-8") + """
## Glossary
| Term | Means | Not to be confused with |
|---|---|---|
| ZorbFlux | imaginary component | — |
""", encoding="utf-8")
        self.assertIn("W09", codes(self.lint()))

    def test_used_glossary_term_ok(self):
        p = Path(self.root) / "MANIFEST.md"
        p.write_text(p.read_text(encoding="utf-8") + """
## Glossary
| Term | Means | Not to be confused with |
|---|---|---|
| SessionStore | session backend | — |
""", encoding="utf-8")
        q = Path(self.root) / "intake.md"
        q.write_text(q.read_text(encoding="utf-8") + "\nUses SessionStore.\n", encoding="utf-8")
        self.assertNotIn("W09", codes(self.lint()))

    def test_vague_criterion_warns(self):
        self._add_wo("WO-004", "[docs/**]", body="""## Acceptance criteria
- [ ] authentication works correctly and is well tested
""")
        self.assertIn("W10", codes(self.lint()))

    def test_checkable_criterion_ok(self):
        self._add_wo("WO-004", "[docs/**]", body="""## Acceptance criteria
- [ ] `pytest tests/auth -q` green
""")
        self.assertNotIn("W10", codes(self.lint()))

    def test_heads_match_short_forms(self):
        self.assertTrue(loom_lint.heads_match("f47546c567e6bc2980", "f47546c"))
        self.assertTrue(loom_lint.heads_match("f47546c", "f47546c567e6bc2980"))
        self.assertFalse(loom_lint.heads_match("f47546c567e", "a1d4713812"))
        self.assertFalse(loom_lint.heads_match("abc", "abcdef1234"))  # too short: exact only

    def test_old_pack_version_warns(self):
        p = Path(self.root) / "MANIFEST.md"
        p.write_text(p.read_text(encoding="utf-8").replace(
            f'loom_version: "{loom_lint.current_version()}"', 'loom_version: "0.2.0"'),
            encoding="utf-8")
        self.assertIn("W11", codes(self.lint()))


class SweepAndHeftTests(unittest.TestCase):
    """W12 silence sweep + W13 heft (0.6.2, plan-sharpening.md)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        good_pack(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def lint(self):
        return loom_lint.lint(self.root)

    def _add_wo(self, wid, title="X", touches="[]", status="ready", body="body"):
        write(self.root, f"work-orders/{wid}-x.md", f"""---
id: {wid}
title: {title}
status: {status}
depends_on: []
routing: fast-cheap
size: S
touches: {touches}
last_verified: {TODAY}
---
{body}
""")

    def test_m_tier_without_sweep_warns(self):
        self.assertIn("W12", codes(self.lint()))

    def test_sweep_section_silences_w12(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8") +
                     "\n## Silence sweep\nswept — no material silences.\n",
                     encoding="utf-8")
        self.assertNotIn("W12", codes(self.lint()))

    def test_s_tier_skips_sweep(self):
        p = Path(self.root) / "MANIFEST.md"
        p.write_text(p.read_text(encoding="utf-8").replace("tier: M", "tier: S"),
                     encoding="utf-8")
        self.assertNotIn("W12", codes(self.lint()))

    def test_small_wo_has_no_heft_warning(self):
        self.assertNotIn("W13", codes(self.lint()))

    def test_heft_criteria_count_warns(self):
        crits = "\n".join("- [ ] `check %d` green" % i for i in range(9))
        self._add_wo("WO-002", body="## Acceptance criteria\n" + crits)
        self.assertIn("W13", codes(self.lint()))

    def test_heft_touches_breadth_warns(self):
        self._add_wo("WO-002", touches="[a/**, b/**, c/**, d/**, e/**, f/**]")
        self.assertIn("W13", codes(self.lint()))

    def test_heft_body_length_warns(self):
        body = "\n".join("filler line %d" % i for i in range(160))
        self._add_wo("WO-002", body=body)
        self.assertIn("W13", codes(self.lint()))

    def test_heft_and_title_warns(self):
        self._add_wo("WO-002", title="Build UI and API")
        self.assertIn("W13", codes(self.lint()))

    def test_done_wo_heft_ignored(self):
        self._add_wo("WO-002", title="Build UI and API", status="done")
        self.assertNotIn("W13", codes(self.lint()))

    def test_hedged_criterion_warns(self):
        self._add_wo("WO-002", body="""## Acceptance criteria
- [ ] `date --leapyear 2028` returns 366 days
## Epistemic notes
- [SPECULATION] the leapyear flag exists — verify before relying on it
""")
        self.assertIn("W14", codes(self.lint()))

    def test_verified_criterion_no_w14(self):
        self._add_wo("WO-002", body="""## Acceptance criteria
- [ ] `pytest tests/auth -q` green
## Epistemic notes
- [FACT — survey] sessions live in SessionStore
""")
        self.assertNotIn("W14", codes(self.lint()))

    def test_hedge_without_term_overlap_no_w14(self):
        self._add_wo("WO-002", body="""## Acceptance criteria
- [ ] `pytest tests/auth -q` green
## Epistemic notes
- [UNKNOWN] deployment cadence — verify with owner
""")
        self.assertNotIn("W14", codes(self.lint()))

    def test_done_wo_no_w14(self):
        self._add_wo("WO-002", status="done", body="""## Acceptance criteria
- [ ] `date --leapyear 2028` returns 366 days
## Epistemic notes
- [SPECULATION] the leapyear flag exists — verify before relying on it
""")
        self.assertNotIn("W14", codes(self.lint()))


class HomeLintTests(unittest.TestCase):
    """--home mode (v0.6 user memory). All fixtures backslash-free by construction."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / ".loom"
        self.home.mkdir()
        fm = "---" + chr(10)
        def head(artifact):
            return ("---" + chr(10) + f"artifact: {artifact}" + chr(10) +
                    'owner: "t"' + chr(10) + f"created: {TODAY}" + chr(10) +
                    'loom_version: "0.6.0"' + chr(10) + "---" + chr(10))
        write(self.home, "profile.md", head("user-profile") +
              "# Loom profile" + chr(10) + "## Defaults" + chr(10) +
              f"- autonomy_default: A2            # set {TODAY}, source: stated" + chr(10))
        write(self.home, "calibration.md", head("user-calibration") +
              "## Observations" + chr(10) +
              f"- {TODAY} | tier estimates: 1/1 held (n=1)" + chr(10))
        write(self.home, "projects.md", head("user-projects-index") +
              "| Project | Pack path | Status | Last retro |" + chr(10) +
              "|---|---|---|---|" + chr(10))
        write(self.home, "feedback-outbox.md", head("user-feedback-outbox") +
              "## Queue" + chr(10))

    def tearDown(self):
        self.tmp.cleanup()

    def hcodes(self):
        return [f["code"] for f in loom_lint.lint_home(self.home).findings]

    def _append(self, name, line):
        f = self.home / name
        f.write_text(f.read_text(encoding="utf-8") + line + chr(10), encoding="utf-8")

    def test_good_home_is_clean(self):
        self.assertEqual(self.hcodes(), [])

    def test_missing_home_warns_not_errors(self):
        rep = loom_lint.lint_home(Path(self.tmp.name) / "nope")
        self.assertEqual([f["code"] for f in rep.findings], ["W20"])
        self.assertEqual(rep.errors, [])

    def test_secret_in_profile_is_error(self):
        self._append("profile.md", "- api_key: sk_live_abcdef1234567890")
        self.assertIn("E12", self.hcodes())

    def test_profile_entry_without_provenance_warns(self):
        self._append("profile.md", "- languages: en, fa")
        self.assertIn("W22", self.hcodes())

    def test_pathy_outbox_line_warns(self):
        self._append("feedback-outbox.md", "- pattern: failed in /Users/me/proj")
        self.assertIn("W21", self.hcodes())

    def test_cli_home_flag(self):
        self.assertEqual(loom_lint.main(["--home", str(self.home)]), 0)


if __name__ == "__main__":
    unittest.main()
