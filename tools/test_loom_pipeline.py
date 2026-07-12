"""End-to-end pipeline test: survey -> pack -> lint -> kickoff -> migrate on one fixture,
plus the dogfood check that Loom's own plans/ pack lints error-free.
Run: python -m unittest discover -s tools -p "test_*.py" """

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_kickoff  # noqa: E402
import loom_gate     # noqa: E402
import loom_lint     # noqa: E402
import loom_migrate  # noqa: E402
import loom_survey   # noqa: E402
from test_loom_lint import good_pack  # noqa: E402

TODAY = dt.date.today().isoformat()
LOOM_ROOT = Path(__file__).resolve().parent.parent


class PipelineTest(unittest.TestCase):
    """One fixture, the whole toolchain, in lifecycle order."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.repo = root / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "auth_check.py").write_text("def ok():\n    return True\n",
                                                         encoding="utf-8")
        (self.repo / "requirements.txt").write_text("requests\n", encoding="utf-8")
        self.pack = root / "plans"
        self.pack.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pipeline(self):
        # 1. Survey the repo — skeleton must be pack-lintable and carry the facts
        survey_text = loom_survey.survey(self.repo)
        self.assertIn("artifact: survey", survey_text)
        self.assertIn("Python (requirements)", survey_text)
        self.assertIn("auth_check.py", survey_text)      # danger-zone heuristic
        # 2. Record planning start, then author the pack while target state is frozen.
        good_pack(self.pack)
        (self.pack / loom_gate.LIFECYCLE_FILE).unlink()
        self.assertEqual(loom_gate.start(self.pack, self.repo, "planned"), 0)
        (self.pack / "survey.md").write_text(survey_text, encoding="utf-8")
        manifest = self.pack / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| survey.md | skip | fixture has no target repo | — | — |",
                f"| survey.md | produce | target repo surveyed | gated | {TODAY} |")
            .replace("| WO-001 | ready | strong-coding |",
                     "| WO-001 | ready | fast-cheap |"),
            encoding="utf-8")
        (self.pack / "assumptions.md").write_text(f"""---
artifact: assumption-ledger
status: active
last_verified: {TODAY}
---
## A-001: Fixture stands in for a real repo
- status: open
- basis: pipeline test design
- risk_if_wrong: LOW — test scope only
- verify_by: G1 exit
- used_in: work-orders/WO-001
""", encoding="utf-8")
        (self.pack / "work-orders" / "WO-001-build-ui.md").write_text(f"""---
id: WO-001
title: Verify auth check
status: ready
depends_on: []
blocks: []
routing: fast-cheap
size: S
touches: [src/auth_check.py]
last_verified: {TODAY}
---
## Intent
Fixture WO. Rests on A-001.

## Context
- `src/auth_check.py` exists [FACT — survey.md].

## Preconditions
- G1 sealed; repository state verified.

## Task
Verify the existing authentication check through the declared command.

## Acceptance criteria
- [ ] `python -c "from src.auth_check import ok; assert ok()"` exits 0
- [ ] Negative: `git diff --stat` is empty.

## Out of scope
- Authentication redesign.

## Escalation triggers
- Stop if the surveyed path moved.

## Epistemic notes
- Rests on A-001.

## Close-out
Pending implementation evidence.
""", encoding="utf-8")

        review = self.pack / "reviews" / "G1-plan-review.md"
        self.assertEqual(loom_gate.seal_g1(self.pack, self.repo, review), 0)
        self.assertEqual(loom_gate.authorize(self.pack, self.repo), 0)

        # 3. Lint — must be mechanically clean (errors block gates)
        rep = loom_lint.lint(self.pack, repo_path=self.repo, strict_staleness=True)
        self.assertEqual(rep.errors, [], f"lint errors: {rep.findings}")

        # 4. Kickoff generation from the WO
        prompt, code = loom_kickoff.build(
            self.pack / "work-orders" / "WO-001-build-ui.md",
            loom_path=str(LOOM_ROOT), repo_path=self.repo)
        self.assertEqual(code, 0)
        self.assertIn("Execute work order WO-001", prompt)
        self.assertIn("src/auth_check.py", prompt)

        # 5. Migrate — an up-to-date pack is a no-op
        self.assertEqual(loom_migrate.migrate(self.pack, apply=False,
                                              target=loom_lint.current_version()), 0)

        # 6. Survey delta path exists for non-git (graceful survey, delta needs git)
        self.assertIn("Not a Git repository", survey_text)


class DogfoodTest(unittest.TestCase):
    """Loom's own plans/ pack must lint error-free — the repo obeys its own rules."""

    def test_self_pack_lints_clean(self):
        pack = LOOM_ROOT / "plans"
        if not (pack / "MANIFEST.md").is_file():
            self.skipTest("no self-pack in this tree (fresh cut) - nothing to dogfood yet")
        rep = loom_lint.lint(pack, repo_path=LOOM_ROOT)
        self.assertEqual(rep.errors, [],
                         "Loom's own pack has lint errors: "
                         + "; ".join(f'{f["code"]} {f["msg"]}' for f in rep.errors))


if __name__ == "__main__":
    unittest.main()
