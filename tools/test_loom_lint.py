"""Tests for loom_lint. Run: python -m unittest discover -s tools -p "test_*.py" """

import datetime as dt
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import loom_lint  # noqa: E402
import loom_gate  # noqa: E402
import loom_survey  # noqa: E402
import loom_lifecycle  # noqa: E402

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
execution_mode: planned
last_verified: {TODAY}
loom_version: "{loom_lint.current_version()}"
domain_id: mobile
domain_ids: [mobile]
domain_coverage: adapter
freshness_window_days: 14
---
# Pack

## Artifacts
| Artifact | Action | Consumer | Decision | Why (one line) | Status | last_verified |
|---|---|---|---|---|---|---|
| intake.md | produce | planner | scope and constraints | required intake | gated | {TODAY} |
| survey.md | skip | — | — | fixture has no target repo | — | — |
| product.md | skip | — | — | test scope is fixed | — | — |
| architecture.md | skip | — | — | no architecture change | — | — |
| uiux.md | skip | — | — | lint fixture only | — | — |
| contracts.md | skip | — | — | no boundary | — | — |
| testing.md | skip | — | — | acceptance criteria carry the fixture test | — | — |
| release-rollback.md | skip | — | — | fixture is not released | — | — |
| security.md | skip | — | — | no security boundary | — | — |
| maintenance.md | skip | — | — | no operator | — | — |
| scaffold.md | skip | — | — | repo shape already exists | — | — |
| domain-discovery.md | skip | — | — | shipped mobile adapter selected | — | — |
| work orders | produce | implementer | execution and acceptance | executable frontier | ready | {TODAY} |
| routing | skip | — | — | one implementer | — | — |
| project instructions | skip | — | — | fixture does not ship instructions | — | — |

## Work order frontier
| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|---|
| WO-001 | ready | strong-coding | — | — | — |
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

## Domain adaptation
The `mobile` adapter requires real-device and lifecycle evidence.
""")
    write(root, "work-orders/WO-001-build-ui.md", f"""---
id: WO-001
title: Build UI
status: ready
depends_on: []
blocks: []
routing: strong-coding
size: S
touches: [src/ui.py]
last_verified: {TODAY}
---
## Intent
Build it. Rests on A-001.

## Context
- Mobile audience [ASSUMPTION A-001 — assumptions.md].

## Preconditions
- G1 sealed; repository state verified.

## Task
Produce the fixture UI outcome inside the declared scope.

## Acceptance criteria
- [ ] `python -m unittest` exits 0.
- [ ] Negative: `git diff --stat` contains only `src/ui.py`.

## Out of scope
- Storage changes.

## Escalation triggers
- Stop if `src/ui.py` does not exist.

## Epistemic notes
- Rests on A-001.

## Close-out
Pending implementation evidence.
""")
    write(root, "plan-dependencies.json", json.dumps({
        "schema_version": 1,
        "sections": [
            {"id": "architecture", "target_patterns": ["src/ui.py"]},
            {"id": "testing", "target_patterns": ["src/ui.py"]},
        ],
    }, indent=2) + "\n")
    loom_lifecycle.seal_release_policy(
        root, external_users=0, irreversible=False,
        data_migration=False, regulated=False)
    write(root, "reviews/G1-plan-review.md", f"""---
artifact: gate-review
project: "test"
gate: G1
date: {TODAY}
reviewer: "independent-test-reviewer"
reviewer_independence: independent
verdict: pass
open_high_findings: 0
rubric_average: 4.0
rubric_min: 4
loom_version: "{loom_lint.current_version()}"
---
# G1 review

## Rubric scorecard (G1/G4)
| Dimension | Score | Evidence (pack location) |
|---|---|---|
| 1 Goal fidelity | 4 | intake.md |
| 2 Epistemic hygiene | 4 | assumptions.md |
| 3 Right-sizing | 4 | MANIFEST.md |
| 4 Decision quality | 4 | decisions.md |
| 5 Boundary clarity | 4 | MANIFEST.md |
| 6 WO executability | 4 | work-orders/WO-001-build-ui.md |
| 7 Verifiability | 4 | work-orders/WO-001-build-ui.md |
| 8 Failure preparedness | 4 | work-orders/WO-001-build-ui.md |
| 9 Adaptation fit | 4 | intake.md |
| 10 Clarity | 4 | MANIFEST.md |
""")
    state = loom_survey.RepoState(
        is_git=False, mode="filesystem", state_hash="a" * 64)
    pack_path = Path(root).resolve()
    if pack_path.name == "plans" and (pack_path.parent / ".git").exists():
        try:
            state = loom_survey.repo_state(
                pack_path.parent, exclude_prefixes=(pack_path.name,))
        except loom_survey.SurveyError:
            pass
    baseline = {}
    first = loom_gate.make_event(
        "planning-started", state,
        baseline_snapshot_sha256=loom_gate._mapping_hash(baseline))
    review = Path(root) / "reviews" / "G1-plan-review.md"
    second = loom_gate.make_event(
        "g1-sealed", state, first["event_hash"],
        review="reviews/G1-plan-review.md", review_sha256=loom_gate._sha256(review),
        work_order_plans=loom_gate._work_order_plan_snapshot(root),
        work_order_plans_sha256=loom_gate._mapping_hash(
            loom_gate._work_order_plan_snapshot(root)))
    third = loom_gate.make_event(
        "implementation-authorized", state, second["event_hash"],
        g1_event_hash=second["event_hash"])
    write(root, "lifecycle.json", json.dumps({
        "schema_version": loom_gate.SCHEMA_VERSION, "mode": "planned",
        "baseline_files": baseline,
        "events": [first, second, third],
        "work_order_completions": [],
    }, indent=2) + "\n")


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

    def test_missing_or_incomplete_plan_dependency_map_blocks(self):
        path = Path(self.root) / "plan-dependencies.json"
        path.unlink()
        self.assertIn("E23", codes(self.lint()))
        write(self.root, "plan-dependencies.json", json.dumps({
            "schema_version": 1,
            "sections": [{"id": "testing", "target_patterns": ["other/**"]}],
        }))
        rep = self.lint()
        self.assertTrue(any(
            item["code"] == "E23" and "src/ui.py" in item["msg"]
            for item in rep.errors), rep.errors)

    def test_measured_release_exposure_cannot_skip_release_plan(self):
        loom_lifecycle.seal_release_policy(
            self.root, external_users=1, irreversible=False,
            data_migration=False, regulated=False)
        rep = self.lint()
        self.assertTrue(any(
            item["code"] == "E24" and "release-rollback.md" in item["msg"]
            for item in rep.errors), rep.errors)

    def test_missing_manifest(self):
        (Path(self.root) / "MANIFEST.md").unlink()
        self.assertIn("E01", codes(self.lint()))

    def test_bad_wo_status_enum(self):
        p = Path(self.root) / "work-orders/WO-001-build-ui.md"
        p.write_text(p.read_text(encoding="utf-8").replace("status: ready", "status: finished"),
                     encoding="utf-8")
        self.assertIn("E04", codes(self.lint()))

    def test_manifest_schema_const_is_executable(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "artifact: manifest", "artifact: not-a-manifest"), encoding="utf-8")
        self.assertIn("E18", codes(self.lint()))

    def test_work_order_schema_title_limit_is_executable(self):
        wo = Path(self.root) / "work-orders" / "WO-001-build-ui.md"
        wo.write_text(
            wo.read_text(encoding="utf-8").replace(
                "title: Build UI", "title: " + ("x" * 101)), encoding="utf-8")
        self.assertIn("E18", codes(self.lint()))

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

    def test_assumption_schema_shape_is_executable(self):
        ledger = Path(self.root) / "assumptions.md"
        ledger.write_text(
            ledger.read_text(encoding="utf-8").replace(
                "risk_if_wrong: MED — layout rework", "risk_if_wrong: vague"),
            encoding="utf-8")
        self.assertIn("E18", codes(self.lint()))

    def test_orphan_assumption_reference(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8") + "\nAlso rests on A-999.\n",
                     encoding="utf-8")
        self.assertIn("E11", codes(self.lint()))

    def test_missing_assumption_ledger_and_reference_both_block(self):
        (Path(self.root) / "assumptions.md").unlink()
        intake = Path(self.root) / "intake.md"
        intake.write_text(
            intake.read_text(encoding="utf-8") + "\nRests on A-999.\n",
            encoding="utf-8")
        found = codes(self.lint())
        self.assertIn("E13", found)
        self.assertIn("E11", found)

    def test_missing_decision_log_and_reference_both_block(self):
        (Path(self.root) / "decisions.md").unlink()
        intake = Path(self.root) / "intake.md"
        intake.write_text(
            intake.read_text(encoding="utf-8") + "\nBlocked by D-999.\n",
            encoding="utf-8")
        found = codes(self.lint())
        self.assertIn("E13", found)
        self.assertIn("E14", found)

    def test_tier_m_pack_requires_a_work_order(self):
        for path in (Path(self.root) / "work-orders").glob("*.md"):
            path.unlink()
        self.assertIn("E13", codes(self.lint()))

    def test_work_order_requires_scope_and_both_dependency_directions(self):
        wo = Path(self.root) / "work-orders" / "WO-001-build-ui.md"
        text = wo.read_text(encoding="utf-8")
        for line in ("depends_on: []\n", "blocks: []\n", "touches: [src/ui.py]\n"):
            text = text.replace(line, "")
        wo.write_text(text, encoding="utf-8")
        missing = [f for f in self.lint().errors if f["code"] == "E03"]
        self.assertEqual(
            {key for finding in missing for key in ("depends_on", "blocks", "touches")
             if key in finding["msg"]},
            {"depends_on", "blocks", "touches"})

    def test_ready_work_order_requires_all_contract_sections(self):
        wo = Path(self.root) / "work-orders" / "WO-001-build-ui.md"
        text = re.sub(
            r"(?ms)^## Context\n.*?(?=^## Preconditions)", "",
            wo.read_text(encoding="utf-8"))
        wo.write_text(text, encoding="utf-8")
        self.assertIn("E19", codes(self.lint()))

    def test_active_work_order_requires_nonempty_touches(self):
        wo = Path(self.root) / "work-orders" / "WO-001-build-ui.md"
        wo.write_text(
            wo.read_text(encoding="utf-8").replace(
                "touches: [src/ui.py]", "touches: []"), encoding="utf-8")
        self.assertIn("E19", codes(self.lint()))

    def test_done_work_order_requires_checked_criteria_and_closeout_evidence(self):
        wo = Path(self.root) / "work-orders" / "WO-001-build-ui.md"
        wo.write_text(
            wo.read_text(encoding="utf-8").replace(
                "status: ready", "status: done"), encoding="utf-8")
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| WO-001 | ready |", "| WO-001 | done |"), encoding="utf-8")
        self.assertIn("E19", codes(self.lint()))

    def test_terminal_planned_pack_requires_g4_and_g5_records(self):
        wo = Path(self.root) / "work-orders" / "WO-001-build-ui.md"
        text = wo.read_text(encoding="utf-8").replace("status: ready", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            "Pending implementation evidence.", "Evidence: command exited 0; scope observed.")
        wo.write_text(text, encoding="utf-8")
        manifest = Path(self.root) / "MANIFEST.md"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace("status: active", "status: maintenance")
        text = text.replace("| WO-001 | ready |", "| WO-001 | done |")
        manifest.write_text(text, encoding="utf-8")
        found = codes(self.lint())
        self.assertIn("E17", found)
        self.assertIn("E20", found)
        messages = " ".join(f["msg"] for f in self.lint().errors)
        self.assertIn("G4", messages)
        self.assertIn("G5", messages)

    def test_declared_produced_artifact_must_exist(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| architecture.md | skip |", "| architecture.md | produce |"),
            encoding="utf-8")
        self.assertIn("E15", codes(self.lint()))

    def test_produced_artifact_requires_named_consumer_and_decision(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| intake.md | produce | planner | scope and constraints |",
                "| intake.md | produce | — | — |"),
            encoding="utf-8")
        messages = "\n".join(item["msg"] for item in self.lint().errors)
        self.assertIn("must name its consumer", messages)
        self.assertIn("must name the decision it serves", messages)

    def test_produced_routing_uses_substantive_manifest_snapshot(self):
        manifest = Path(self.root) / "MANIFEST.md"
        text = manifest.read_text(encoding="utf-8").replace(
            "| routing | skip | — | — | one implementer | — | — |",
            f"| routing | produce | implementer | model assignment | executable assignment | gated | {TODAY} |")
        text += "\n## Routing snapshot\n\nstrong-coding → WO-001 — current frontier.\n"
        manifest.write_text(text, encoding="utf-8")
        report = self.lint()
        self.assertFalse(any(item["code"] == "E15" for item in report.errors),
                         report.findings)

    def test_produced_routing_requires_manifest_snapshot(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace(
            "| routing | skip | — | — | one implementer | — | — |",
            f"| routing | produce | implementer | model assignment | executable assignment | gated | {TODAY} |"),
            encoding="utf-8")
        report = self.lint()
        self.assertTrue(any(item["code"] == "E15"
                            and "Routing snapshot" in item["msg"]
                            for item in report.errors), report.findings)

    def test_manifest_frontier_status_must_match_work_order(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "| WO-001 | ready |", "| WO-001 | done |"), encoding="utf-8")
        self.assertIn("E15", codes(self.lint()))

    def test_active_pack_requires_passing_g1_record(self):
        (Path(self.root) / "reviews" / "G1-plan-review.md").unlink()
        self.assertIn("E15", codes(self.lint()))

    def test_active_planned_pack_requires_authorized_lifecycle_chain(self):
        (Path(self.root) / "lifecycle.json").unlink()
        self.assertIn("E17", codes(self.lint()))

    def test_tampered_lifecycle_chain_blocks(self):
        lifecycle = Path(self.root) / "lifecycle.json"
        data = json.loads(lifecycle.read_text(encoding="utf-8"))
        data["events"][0]["repo_state_hash"] = "0" * 64
        lifecycle.write_text(json.dumps(data), encoding="utf-8")
        self.assertIn("E17", codes(self.lint()))

    def test_build_first_mode_is_honest_and_blocks_executable_work(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "execution_mode: planned", "execution_mode: build-first"),
            encoding="utf-8")
        (Path(self.root) / "lifecycle.json").unlink()
        (Path(self.root) / "reviews" / "G1-plan-review.md").unlink()
        rep = self.lint()
        self.assertFalse(any(f["code"] == "E15" for f in rep.errors), rep.findings)
        self.assertIn("E17", codes(rep))
        self.assertIn("W16", codes(rep))

    def test_g1_record_must_contain_complete_passing_rubric(self):
        review = Path(self.root) / "reviews" / "G1-plan-review.md"
        text = re.sub(r"(?m)^\| 10 Clarity \|.*\n", "", review.read_text(encoding="utf-8"))
        review.write_text(text, encoding="utf-8")
        self.assertIn("E15", codes(self.lint()))

    def test_g1_declared_scores_must_match_measured_rows(self):
        review = Path(self.root) / "reviews" / "G1-plan-review.md"
        review.write_text(
            review.read_text(encoding="utf-8").replace(
                "rubric_average: 4.0", "rubric_average: 3.5"), encoding="utf-8")
        self.assertIn("E15", codes(self.lint()))

    def test_g1_rubric_evidence_paths_must_exist(self):
        review = Path(self.root) / "reviews" / "G1-plan-review.md"
        review.write_text(
            review.read_text(encoding="utf-8").replace(
                "| 1 Goal fidelity | 4 | intake.md |",
                "| 1 Goal fidelity | 4 | missing-evidence.md |"),
            encoding="utf-8")
        report = self.lint()
        self.assertTrue(any("evidence path does not exist" in item["msg"]
                            for item in report.errors), report.findings)

    def test_manifest_must_account_for_every_matrix_row(self):
        manifest = Path(self.root) / "MANIFEST.md"
        text = manifest.read_text(encoding="utf-8")
        text = re.sub(r"(?m)^\| security\.md \|.*\n", "", text)
        manifest.write_text(text, encoding="utf-8")
        self.assertIn("E15", codes(self.lint()))

    def test_historical_pack_has_explicit_safe_exemption(self):
        manifest = Path(self.root) / "MANIFEST.md"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace("status: active", "status: maintenance")
        text = text.replace("execution_mode: planned", "execution_mode: historical")
        text = text.replace(
            "| work orders | produce | implementer | execution and acceptance | executable frontier | ready | " + TODAY + " |",
            "| work orders | skip | — | — | historical outcomes-only pack | — | — |")
        text = re.sub(r"(?m)^\| WO-001 \|.*\n", "", text)
        manifest.write_text(text, encoding="utf-8")
        for path in (Path(self.root) / "work-orders").glob("*.md"):
            path.unlink()
        for path in (Path(self.root) / "reviews").glob("*.md"):
            path.unlink()
        rep = self.lint()
        self.assertFalse(any(f["code"] in {"E13", "E15"} for f in rep.errors),
                         rep.findings)

    def test_secret_pattern(self):
        fixture_value = "sk_live_" + "abcdef1234567890"
        write(self.root, "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
{"api" + "_key"}: {fixture_value}
""")
        self.assertIn("E12", codes(self.lint()))

    def test_placeholder_secret_is_ok(self):
        write(self.root, "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
{"api" + "_key"}: EXAMPLE
""")
        self.assertNotIn("E12", codes(self.lint()))

    def test_real_secret_is_not_hidden_by_placeholder_on_same_line(self):
        fixture = "pass" + "word: fake-but-secret-shaped-12345 <VALUE>"
        write(self.root, "contracts.md", f"""---
artifact: contracts
status: draft
last_verified: {TODAY}
---
{fixture}
""")
        self.assertIn("E12", codes(self.lint()))

    def test_stale_artifact_warns(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8").replace(TODAY, "2020-01-01"),
                     encoding="utf-8")
        rep = self.lint()
        self.assertIn("W03", codes(rep))
        self.assertEqual(rep.errors, [])  # staleness is a warning, not an error

    def test_age_check_covers_every_authoritative_artifact(self):
        for path in Path(self.root).rglob("*.md"):
            path.write_text(
                path.read_text(encoding="utf-8").replace(TODAY, "2020-01-01"),
                encoding="utf-8")
        findings = [f for f in self.lint().findings if f["code"] == "W03"]
        names = {Path(f["path"]).name for f in findings}
        self.assertEqual(
            names,
            {"MANIFEST.md", "assumptions.md", "decisions.md", "intake.md",
             "WO-001-build-ui.md"})

    def test_strict_staleness_turns_expired_state_into_errors(self):
        manifest = Path(self.root) / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(TODAY, "2020-01-01"),
            encoding="utf-8")
        rep = loom_lint.lint(self.root, strict_staleness=True)
        self.assertTrue(any(f["code"] == "E16" for f in rep.errors), rep.findings)

    def test_strict_staleness_requires_repository_path_even_when_dates_are_current(self):
        rep = loom_lint.lint(self.root, strict_staleness=True)
        messages = "\n".join(f["msg"] for f in rep.errors if f["code"] == "E16")
        self.assertIn("repository path was not supplied", messages)

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

    def test_unknown_decision_reference_blocks(self):
        p = Path(self.root) / "intake.md"
        p.write_text(p.read_text(encoding="utf-8") + "\nSee D-042 for details.\n",
                     encoding="utf-8")
        self.assertIn("E14", codes(self.lint()))

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


class DomainCoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pack = Path(self.tmp.name)
        good_pack(self.pack)

    def tearDown(self):
        self.tmp.cleanup()

    def set_manifest(self, domain_id, coverage, decision):
        path = self.pack / "MANIFEST.md"
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"(?m)^domain_id: .+$", f"domain_id: {domain_id}", text)
        text = re.sub(r"(?m)^domain_ids: .+$", f"domain_ids: [{domain_id}]", text)
        text = re.sub(
            r"(?m)^domain_coverage: .+$", f"domain_coverage: {coverage}", text)
        text = re.sub(
            r"(?m)^\| domain-discovery\.md \| .+$",
            (f"| domain-discovery.md | produce | planner | domain invariants and real medium | "
             f"custom domain evidence | gated | {TODAY} |") if decision == "produce" else
            "| domain-discovery.md | skip | — | — | adapter coverage is sufficient | — | — |",
            text)
        path.write_text(text, encoding="utf-8")

    def write_discovery(self, domain_id, status="verified", row_status="verified"):
        write(self.pack, "domain-discovery.md", f"""---
artifact: domain-discovery
domain_id: {domain_id}
status: {status}
last_verified: {TODAY}
loom_version: "{loom_lint.current_version()}"
---
# Domain discovery
## Coverage statement
[FACT — source below] Coverage reviewed.
## Authoritative sources and qualified reviewers
| Source/reviewer | Authority for | Current/version evidence | Accessed | Limits |
|---|---|---|---|---|
| governing standard | safety invariant | current edition | {TODAY} | one jurisdiction |
## Invariant ledger
| Invariant | Evidence | Failure if wrong | Required real medium | Status |
|---|---|---|---|---|
| safe state | governing standard | unsafe operation | hardware review | {row_status} |
## Forbidden default transfers
No web defaults.
## Artifact and gate adaptation
Hardware review is the release medium.
""")

    def test_unknown_domain_cannot_pass_g1(self):
        self.set_manifest("marine-navigation", "unknown", "produce")
        self.write_discovery("marine-navigation", status="draft", row_status="unknown")
        report = loom_lint.lint(self.pack)
        self.assertTrue(any(item["code"] == "E22" and "G1 is blocked" in item["msg"]
                            for item in report.errors), report.findings)

    def test_verified_custom_domain_requires_complete_discovery(self):
        self.set_manifest("marine-navigation", "verified", "produce")
        self.write_discovery("marine-navigation")
        report = loom_lint.lint(self.pack)
        self.assertEqual([], report.errors, report.findings)
        self.assertFalse(any(item["code"] == "E22" for item in report.errors),
                         report.findings)

    def test_verified_status_is_reserved_for_domain_discovery(self):
        write(self.pack, "product.md", f"""---
artifact: product
status: verified
last_verified: {TODAY}
loom_version: "{loom_lint.current_version()}"
---
# Product
[FACT — fixture] Ordinary plan artifact.
""")
        report = loom_lint.lint(self.pack)
        self.assertTrue(any(item["code"] == "E04"
                            and Path(item["path"]).name == "product.md"
                            for item in report.errors), report.findings)

    def test_unknown_adapter_claim_is_rejected(self):
        self.set_manifest("marine-navigation", "adapter", "skip")
        report = loom_lint.lint(self.pack)
        self.assertTrue(any(item["code"] == "E22" and "no shipped adapter" in item["msg"]
                            for item in report.errors), report.findings)

    def test_project_config_domain_mismatch_is_blocking(self):
        repo = self.pack / "target-repo"
        repo.mkdir()
        (repo / "loom.config.json").write_text(json.dumps({
            "loom_version": loom_lint.current_version(),
            "domain_id": "accounting",
            "domain_ids": ["accounting"],
            "use_profile": True,
        }), encoding="utf-8")
        manifest = self.pack / "MANIFEST.md"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "execution_mode: planned", "execution_mode: build-first"),
            encoding="utf-8")
        (self.pack / "lifecycle.json").unlink()
        report = loom_lint.lint(self.pack, repo_path=repo)
        self.assertTrue(any(item["code"] == "E22" and "config domain_id" in item["msg"]
                            for item in report.errors), report.findings)


class NestedPackStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        loom_survey.run_git(self.repo, "init")
        write(self.repo, "tracked.txt", "baseline\n")
        write(self.repo, "plans/MANIFEST.md", "# sibling plan history\n")
        loom_survey.run_git(self.repo, "add", ".")
        loom_survey.run_git(
            self.repo, "-c", "user.name=Loom Test", "-c",
            "user.email=loom@example.invalid", "commit", "-m", "baseline")
        write(self.repo, "plans/sibling/notes.md", "untracked sibling plan\n")
        self.pack = self.repo / "plans" / "feature"
        good_pack(self.pack)
        (self.pack / "lifecycle.json").unlink()
        self.assertEqual(0, loom_gate.start(self.pack, self.repo))

    def tearDown(self):
        self.tmp.cleanup()

    def test_strict_lint_matches_nested_pack_lifecycle_boundary(self):
        report = loom_lint.lint(
            self.pack, repo_path=self.repo, strict_staleness=True)
        self.assertFalse(any(item["code"] == "E16"
                             and "repo_state_hash" in item["msg"]
                             for item in report.errors), report.findings)

    def test_strict_lint_detects_sibling_plan_drift(self):
        write(self.repo, "plans/sibling/notes.md", "changed sibling plan\n")
        report = loom_lint.lint(
            self.pack, repo_path=self.repo, strict_staleness=True)
        self.assertTrue(any(item["code"] == "E16"
                            and "repo_state_hash" in item["msg"]
                            for item in report.errors), report.findings)


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
                    f'loom_version: "{loom_lint.current_version()}"' + chr(10) +
                    "---" + chr(10))
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
        self._append("profile.md", "- api" + "_key: sk_live_" + "abcdef1234567890")
        self.assertIn("E12", self.hcodes())

    def test_profile_entry_without_provenance_warns(self):
        self._append("profile.md", "- languages: en, fa")
        self.assertIn("W22", self.hcodes())

    def test_pathy_outbox_line_warns(self):
        self._append("feedback-outbox.md", "- pattern: failed in /Users/me/proj")
        self.assertIn("W21", self.hcodes())

    def test_named_project_outbox_line_is_rejected(self):
        self._append(
            "feedback-outbox.md",
            "- Synthetic-Project, tier M, dataset generation worked")
        self.assertIn("W21", self.hcodes())

    def test_duplicate_profile_key_is_error(self):
        self._append(
            "profile.md",
            f"- autonomy_default: A1 # set {TODAY}, source: stated")
        self.assertIn("E21", self.hcodes())

    def test_invalid_profile_provenance_is_error(self):
        self._append(
            "profile.md",
            f"- report_style: concise # set {TODAY}, source: guessed")
        self.assertIn("E21", self.hcodes())

    def test_six_year_old_profile_entry_warns(self):
        self._append(
            "profile.md",
            "- report_style: verbose # set 2020-01-01, source: inferred")
        self.assertIn("W24", self.hcodes())

    def test_old_home_version_warns(self):
        profile = self.home / "profile.md"
        profile.write_text(
            profile.read_text(encoding="utf-8").replace(
                loom_lint.current_version(), "0.1.0"), encoding="utf-8")
        self.assertIn("W11", self.hcodes())

    def test_cli_home_flag(self):
        self.assertEqual(loom_lint.main(["--home", str(self.home)]), 0)


if __name__ == "__main__":
    unittest.main()
