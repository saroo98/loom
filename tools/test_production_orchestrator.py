"""Black-box coverage for the installed one-surface production orchestrator."""

import datetime as dt
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import loom_gate  # noqa: E402
import loom_install  # noqa: E402
import loom_improvement  # noqa: E402
import loom_lifecycle  # noqa: E402
import loom_lint  # noqa: E402
import loom_memory  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_performance  # noqa: E402
import loom_release  # noqa: E402


TODAY = dt.date.today().isoformat()


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _author_medium_pack(pack, version):
    """Act as the host agent; production code must not import test helpers."""
    _write(pack / "MANIFEST.md", f"""---
artifact: manifest
project: "orchestrator fixture"
tier: M
status: active
execution_mode: planned
last_verified: {TODAY}
loom_version: "{version}"
domain_id: accounting
domain_ids: [accounting]
domain_coverage: adapter
freshness_window_days: 14
---
# Planning pack

Original request (verbatim, do not paraphrase):
> "Plan a financial double-entry accounting change to src/app.py"

## Artifacts
| Artifact | Action | Consumer | Decision | Why (one line) | Status | last_verified |
|---|---|---|---|---|---|---|
| intake.md | produce | planner | scope and constraints | establishes the contract | gated | {TODAY} |
| survey.md | skip | — | — | the sealed machine survey supplies current world state | — | — |
| product.md | skip | — | — | no independent product-policy consumer was selected | — | — |
| architecture.md | skip | — | — | no multi-component architecture decision was observed | — | — |
| uiux.md | skip | — | — | no interface-state consumer was selected | — | — |
| contracts.md | skip | — | — | no durable external boundary was observed | — | — |
| testing.md | produce | verifier | acceptance evidence | invariants need tests | gated | {TODAY} |
| release-rollback.md | skip | — | — | release exposure does not require a separate artifact | — | — |
| security.md | skip | — | — | no independent security-boundary consumer was selected | — | — |
| maintenance.md | skip | — | — | no separate operator decision was observed | — | — |
| scaffold.md | skip | — | — | scaffolding belongs in atomic work orders, not a planning essay | — | — |
| domain-discovery.md | skip | — | — | shipped domain adapters cover the selected invariants | — | — |
| work orders | produce | implementer | execution and acceptance | executable frontier | ready | {TODAY} |
| routing | skip | — | — | one ordered implementer frontier is sufficient | — | — |
| project instructions | skip | — | — | no new repository instruction consumer was observed | — | — |

## Work order frontier
| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|---|
| WO-001 | ready | strong-coding | — | — | — |
""")
    _write(pack / "assumptions.md", f"""---
artifact: assumption-ledger
status: draft
last_verified: {TODAY}
---
# Assumptions

## A-001: Existing ledger boundary remains stable
- status: open
- basis: request names one existing target
- risk_if_wrong: HIGH — accounting invariants could be incomplete
- verify_by: before implementation
- used_in: intake.md, work-orders/WO-001-accounting.md
""")
    _write(pack / "decisions.md", f"""---
artifact: decision-log
status: draft
last_verified: {TODAY}
---
## D-001: Preserve double-entry balance
- chosen: every accepted posting keeps total debits equal to total credits
""")
    _write(pack / "intake.md", f"""---
artifact: intake
status: gated
last_verified: {TODAY}
---
# Intake
Change only `src/app.py`; verify A-001 before implementation and preserve D-001.

## Domain adaptation
Accounting requires balanced postings, exact currency precision, audit history, reconciliation,
period-close behavior, and dated jurisdiction rules.

## Domain invariant contract
| Domain | Invariant | Evidence target | Required real medium | Status |
|---|---|---|---|---|
| accounting | balanced postings | testing.md and WO-001 | double-entry property tests | verified |
| accounting | currency precision | testing.md and WO-001 | dated jurisdiction edge cases | verified |
| accounting | immutable audit trail | decisions.md and WO-001 | double-entry property tests | verified |
| accounting | reconciliation | testing.md and WO-001 | dated jurisdiction edge cases | verified |
| accounting | period close | testing.md and WO-001 | double-entry property tests | verified |
| accounting | jurisdiction/effective-date rules | testing.md and WO-001 | dated jurisdiction edge cases | verified |

## Current facts to verify
| Domain | Fact | Source | Status |
|---|---|---|---|
| accounting | current platform/tool versions and limits | repository and runtime inventory | verified |
| accounting | current governing policies, standards, or regulations | request excludes policy changes | verified |
| accounting | current target environment and release channel | local non-release target | verified |
""")
    _write(pack / "testing.md", f"""---
artifact: testing-plan
status: gated
last_verified: {TODAY}
---
# Testing
Use property tests for balanced postings and explicit rounding, reversal, and period-close cases.
The work order names the real process evidence required for acceptance.

## Verification media contract
| Domain | Medium | Target | Status |
|---|---|---|---|
| accounting | double-entry property tests | prove a release-relevant domain invariant | planned |
| accounting | dated jurisdiction edge cases | prove a release-relevant domain invariant | planned |
""")
    _write(pack / "work-orders" / "WO-001-accounting.md", f"""---
id: WO-001
title: Preserve accounting invariants
status: ready
depends_on: []
blocks: []
routing: strong-coding
size: S
touches: [src/app.py]
last_verified: {TODAY}
---
## Intent
Implement the requested change without violating D-001.

## Context
- The existing boundary is assumed stable [ASSUMPTION A-001 — assumptions.md].

## Preconditions
- G1 is sealed and the repository state is unchanged.

## Task
Change `src/app.py` while preserving balanced postings and exact currency behavior.

## Acceptance criteria
- [ ] `python -m unittest` exits 0 in a real process.
- [ ] Negative: an unbalanced posting is rejected without a partial write.

## Out of scope
- Tax-policy changes and data migration.

## Escalation triggers
- Stop if currency, period, or jurisdiction rules are not evidenced.

## Epistemic notes
- A-001 remains open until the implementer surveys the target boundary.

## Close-out
Pending implementation evidence.
""")
    _write(pack / "plan-dependencies.json", json.dumps({
        "schema_version": 1,
        "sections": [
            {"id": "testing", "target_patterns": ["src/app.py"]},
            {"id": "accounting", "target_patterns": ["src/app.py"]},
        ],
    }, indent=2) + "\n")
    loom_lifecycle.seal_release_policy(
        pack, external_users=0, irreversible=False,
        data_migration=False, regulated=False)
    _write(pack / "reviews" / "G1-plan-review.md", f"""---
artifact: gate-review
project: "orchestrator fixture"
gate: G1
date: {TODAY}
reviewer: "independent-fixture-reviewer"
reviewer_independence: independent
verdict: pass
open_high_findings: 0
rubric_average: 4.0
rubric_min: 4
loom_version: "{version}"
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
| 6 WO executability | 4 | work-orders/WO-001-accounting.md |
| 7 Verifiability | 4 | testing.md |
| 8 Failure preparedness | 4 | work-orders/WO-001-accounting.md |
| 9 Adaptation fit | 4 | intake.md |
| 10 Clarity | 4 | MANIFEST.md |
""")


def _author_small_wo(pack):
    _write(pack / "WO-001.md", f"""---
id: WO-001
title: Add one CLI flag
status: ready
depends_on: []
blocks: []
routing: strong-coding
size: S
touches: [src/app.py]
last_verified: {TODAY}
---
## Intent
Add the requested low-risk command-line flag.
## Context
Repository baseline is sealed by the Tier-S lifecycle.
## Preconditions
Target state remains unchanged.
## Task
Change only `src/app.py` and preserve existing exit and stream contracts.
## Acceptance criteria
- [ ] `python -m unittest` exits 0.
- [ ] Negative: an unknown flag exits nonzero without writing normal output.
## Out of scope
No architecture or packaging change.
## Escalation triggers
Stop if a second component or irreversible effect is required.
## Epistemic notes
[FACT — lifecycle baseline] target state was recorded before this work order.
## Close-out
Pending implementation evidence.
""")


def _mark_medium_wo_done(pack):
    work_order = pack / "work-orders" / "WO-001-accounting.md"
    text = work_order.read_text(encoding="utf-8")
    text = text.replace("status: ready", "status: done")
    text = text.replace("- [ ]", "- [x]")
    text = text.replace(
        "Pending implementation evidence.",
        "Evidence: isolated real-process verification exited 0.")
    work_order.write_text(text, encoding="utf-8")
    return work_order


def _mark_small_wo_done(pack):
    work_order = pack / "WO-001.md"
    text = work_order.read_text(encoding="utf-8")
    text = text.replace("status: ready", "status: done")
    text = text.replace("- [ ]", "- [x]")
    text = text.replace(
        "Pending implementation evidence.",
        "Evidence: isolated real-process verification exited 0.")
    work_order.write_text(text, encoding="utf-8")
    return work_order


class ProductionOrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_temp = tempfile.TemporaryDirectory()
        cls.fixture_root = Path(cls.fixture_temp.name)
        cls.source = Path(__file__).resolve().parents[1]
        cls.public = cls.fixture_root / "public"
        cls.installed_fixture = cls.fixture_root / "installed"
        loom_release.build_public(
            cls.source, cls.public,
            forbidden_tokens=[
                "-".join(("private", "fixture", "token")),
                "-".join(("owner", "fixture", "token")),
            ], source_classification="public-release")
        loom_install.install(cls.public, cls.installed_fixture)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.installed = self.installed_fixture
        self.home = self.root / "home"
        self.repo = self.root / "target"
        (self.repo / "src").mkdir(parents=True)
        _write(self.repo / "src" / "app.py", "VALUE = 1\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email",
                        "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "test"],
                       check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "baseline"],
                       check=True)
        self.request = "Plan a financial double-entry accounting change to src/app.py"

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B",
             str(self.installed / "tools" / "loom_orchestrator.py"),
             *map(str, args)], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60)

    def test_installed_invoke_drives_real_gate_and_seals_receipt(self):
        opened = self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed,
            "--timeout-seconds", "300")
        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        action = json.loads(opened.stdout)
        self.assertEqual("action-required", action["status"])
        self.assertEqual("plan", action["intent"])
        self.assertEqual("M", action["tier"])
        self.assertEqual(["accounting"], action["domains"])
        contract = action["plan_contract"]
        self.assertEqual(1, contract["schema_version"])
        self.assertEqual(15, len(contract["artifact_matrix"]))
        self.assertEqual(
            contract["contract_hash"],
            loom_orchestrator._hash({
                key: value for key, value in contract.items()
                if key != "contract_hash"
            }),
        )
        self.assertEqual(
            {"balanced postings", "currency precision", "immutable audit trail",
             "reconciliation", "period close", "jurisdiction/effective-date rules"},
            {item["invariant"] for item in contract["required_domain_invariants"]},
        )
        sealed_action = json.loads(
            Path(action["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual(contract, sealed_action["plan_contract"])
        self.assertTrue((self.repo / "plans" / "lifecycle.json").is_file())

        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        completed = self.cli(
            "complete", "--action", action["action_path"], "--usage", usage)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual("completed", result["status"])
        self.assertEqual("plan-complete", result["code"])
        self.assertEqual("measured", result["usage"]["measurement_status"])
        self.assertEqual(900, result["usage"]["total_tokens"])
        self.assertEqual([], loom_gate.verify(
            self.repo / "plans", self.repo, require_authorized=True))
        self.assertTrue(result["outcome_ids"])
        self.assertTrue(result["improvement_evidence_ids"])
        instance_id = (self.installed / loom_install.INSTANCE_MARKER).read_text(
            encoding="utf-8").strip()
        performance = loom_performance.usage_report(self.home, instance_id)
        self.assertEqual(1, performance["retained_sample_count"])
        self.assertEqual(900, performance["p95_total_tokens"])
        self.assertEqual("caller-reported", performance["measurement_source"])
        status_result = self.cli(
            "invoke", "--request", "Show my token usage", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, status_result.returncode,
                         status_result.stderr + status_result.stdout)
        status = json.loads(status_result.stdout)
        visible = json.loads(status["user_message"])
        self.assertEqual(900, visible["p95_total_tokens"])
        self.assertEqual("caller-reported-only", visible["certification_status"])
        cycle_install = self.root / "cycle-install"
        loom_install.install(self.public, cycle_install)
        self.assertEqual("installed", loom_install.check(cycle_install)["status"])
        receipt = loom_install.check(cycle_install)
        removed = loom_install.uninstall(
            cycle_install, confirmation=receipt["install_id"])
        self.assertTrue(removed["target_removed"])

    def test_invoke_supplies_bounded_owner_context_before_host_work(self):
        instance_id = loom_memory.initialize(self.home, self.installed)
        preference = loom_memory.set_preference(
            self.home, instance_id, "report_style", "concise")

        opened = self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        result = json.loads(opened.stdout)
        memory_ids = [item["id"] for item in result["context"]["memory"]]
        self.assertIn(preference["id"], memory_ids)
        selected = [item for item in result["context"]["preferences"]
                    if item["key"] == "report_detail"]
        self.assertEqual("concise", selected[0]["effective_value"])
        self.assertLessEqual(
            len(json.dumps(result["context"], ensure_ascii=False)), 32 * 1024)
        action = json.loads(Path(result["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual(result["context"]["memory"], action["context"]["memory"])
        self.assertEqual(
            result["context"]["preferences"], action["context"]["preferences"])
        self.assertEqual(result["context_manifest"], action["context_manifest"])
        self.assertEqual(
            {"skill/loom/SKILL.md", "START-HERE.md"},
            {item["path"] for item in action["context_manifest"]["entries"]})
        self.assertEqual(2, action["context_manifest"]["load_metrics"]["disk_reads"])
        self.assertEqual(2, action["context_manifest"]["load_metrics"]["cache_hits"])

        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        host_outcome = self.root / "host-outcome.json"
        host_outcome.write_text(json.dumps({
            "schema_version": 1,
            "applied_memory_ids": ["00000000-0000-4000-8000-000000000999"],
            "verified_memory_ids": [], "rejected_memory_ids": [],
            "metrics": {}, "preference_observations": [], "artifact_usage": [],
        }), encoding="utf-8")
        refused = self.cli(
            "complete", "--action", result["action_path"], "--usage", usage,
            "--result", host_outcome)
        self.assertEqual(2, refused.returncode)
        self.assertEqual("HOST_OUTCOME_INVALID", json.loads(refused.stdout)["code"])
        host_outcome.write_text(json.dumps({
            "schema_version": 1,
            "applied_memory_ids": [preference["id"]],
            "verified_memory_ids": [], "rejected_memory_ids": [],
            "metrics": {}, "preference_observations": [], "artifact_usage": [],
        }), encoding="utf-8")
        completed = self.cli(
            "complete", "--action", result["action_path"], "--usage", usage,
            "--result", host_outcome)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        recorded = loom_memory.inspect_record(
            self.home, instance_id, preference["id"])
        self.assertEqual(1, recorded["application_count"])
        self.assertEqual(1, recorded["helped_count"])

    def test_unknown_domain_is_promoted_out_of_the_small_lifecycle(self):
        opened = self.cli(
            "invoke", "--request",
            "Develop a museum conservation protocol for water-damaged manuscripts",
            "--cwd", self.repo, "--home", self.home,
            "--install-root", self.installed)

        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        action = json.loads(opened.stdout)
        self.assertEqual("M", action["tier"])
        self.assertEqual(["unclassified"], action["domains"])
        self.assertTrue((self.repo / "plans" / "MANIFEST.md").is_file())
        self.assertFalse((self.repo / "plans" / ".loom-small-lifecycle.json").exists())

    def test_whole_domain_deliverables_receive_domain_aware_tiers(self):
        cases = (
            ("Build a cross-platform command-line developer tool with config discovery, "
             "plugin loading, shell completion, package installers, and compatibility tests.",
             "cli", "L"),
            ("Build an offline-first Android and iOS field inspection app with camera, GPS, "
             "sync conflict resolution, accessibility, and signed store releases.",
             "android", "L"),
            ("Build a streaming ETL and machine-learning pipeline with schema evolution, "
             "backfills, data quality, drift monitoring, reproducible training, and rollback.",
             "data-etl", "L"),
            ("Build desktop bookkeeping software with double-entry correctness, currency "
             "precision, tax rules, reconciliation, immutable audit trails, period close, "
             "migrations, and signed releases.", "accounting", "L"),
            ("Design and validate firmware for a battery-powered sensor node with bootloader "
             "rollback, secure updates, power-loss recovery, hardware-in-loop tests, and "
             "manufacturing calibration.", "firmware-hardware", "L"),
            ("Produce a publishable research study with three methods, statistical analysis, "
             "source provenance, reproducible notebooks, limitations, and publication package.",
             "research", "L"),
            ("Build a real-time 3D room configurator with renderer, spatial UX, asset pipeline, "
             "materials, collision, autosave, and a device performance matrix.",
             "realtime-3d", "L"),
        )
        for index, (request, domain, expected_tier) in enumerate(cases):
            with self.subTest(domain=domain):
                target = self.root / f"domain-target-{index}"
                target.mkdir()
                (target / "seed.txt").write_text("baseline\n", encoding="utf-8")
                opened = self.cli(
                    "invoke", "--request", request, "--cwd", target,
                    "--home", self.home, "--install-root", self.installed)
                self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
                action = json.loads(opened.stdout)
                self.assertEqual(expected_tier, action["tier"])
                self.assertIn(domain, action["domains"])
                self.assertTrue((target / "plans" / "MANIFEST.md").is_file())

    def test_plan_completion_rejects_artifact_rows_outside_the_sealed_contract(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        manifest = self.repo / "plans" / "MANIFEST.md"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace(
            "\n## Work order frontier",
            "\n| extra.md | skip | — | — | outside sealed selection | — | — |\n"
            "\n## Work order frontier",
        )
        manifest.write_text(text, encoding="utf-8")
        usage = self.root / "contract-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "PLAN_CONTRACT_MISMATCH"):
            loom_orchestrator.complete(opened["action_path"], usage)

    def test_plan_contract_requires_invariants_current_facts_and_real_media(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        loom_orchestrator._validate_authored_plan(action)
        cases = (
            (self.repo / "plans" / "intake.md", "| accounting | balanced postings |",
             "required domain invariants"),
            (self.repo / "plans" / "intake.md",
             "| accounting | current platform/tool versions and limits |",
             "required current facts"),
            (self.repo / "plans" / "testing.md",
             "| accounting | double-entry property tests |",
             "required verification media"),
        )
        for path, marker, error in cases:
            original = path.read_text(encoding="utf-8")
            altered = "\n".join(
                line for line in original.splitlines() if marker not in line) + "\n"
            path.write_text(altered, encoding="utf-8")
            try:
                with self.assertRaisesRegex(
                        loom_orchestrator.OrchestratorError, error):
                    loom_orchestrator._validate_authored_plan(action)
            finally:
                path.write_text(original, encoding="utf-8")

    def test_plan_contract_enforces_budget_and_work_order_topology(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        decisions = self.repo / "plans" / "decisions.md"
        original = decisions.read_text(encoding="utf-8")
        decisions.write_text(original + ("x" * 30000), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "sealed planning budget"):
            loom_orchestrator._validate_authored_plan(action)
        decisions.write_text(original, encoding="utf-8")

        template = self.repo / "plans" / "work-orders" / "WO-001-accounting.md"
        for index in range(2, 10):
            (template.parent / f"WO-{index:03d}-extra.md").write_text(
                template.read_text(encoding="utf-8"), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "sealed topology"):
            loom_orchestrator._validate_authored_plan(action)

    def test_rehashed_plan_contract_cannot_change_the_sealed_selection(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        contract = action["plan_contract"]
        contract["artifact_matrix"][0]["action"] = "skip"
        contract["contract_hash"] = loom_orchestrator._hash({
            key: value for key, value in contract.items() if key != "contract_hash"
        })
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "sealed plan contract"):
            loom_orchestrator._read_action(path)

    def test_rehashed_static_context_manifest_cannot_hide_guidance_drift(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        action["context_manifest"]["entries"][0]["sha256"] = "0" * 64
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "static context manifest"):
            loom_orchestrator._read_action(path)

    def test_production_host_outcome_records_controlled_provider_replay_pair(self):
        instance_id = loom_memory.initialize(self.home, self.installed)
        preference = loom_memory.set_preference(
            self.home, instance_id, "report_style", "concise")
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        action_path = Path(opened["action_path"])
        action = json.loads(action_path.read_text(encoding="utf-8"))
        self.assertIn(preference["id"], {
            item["id"] for item in action["context"]["memory"]})
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "replay-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        enabled_evidence = self.repo / "plans" / "evidence" / "enabled-replay.json"
        disabled_evidence = self.repo / "plans" / "evidence" / "disabled-replay.json"
        _write(enabled_evidence, '{"verification_passed":true,"rework":0}\n')
        _write(disabled_evidence, '{"verification_passed":true,"rework":1}\n')

        def cohort(value, response_id, evidence, memory_ids):
            return {
                "value": value, "memory_ids": memory_ids,
                "outcome_evidence_path":
                    evidence.relative_to(self.repo / "plans").as_posix(),
                "outcome_evidence_sha256": hashlib.sha256(
                    evidence.read_bytes()).hexdigest(),
                "provider_receipt": {
                    "source": "provider-response", "provider": "fixture-provider",
                    "model": "fixture-model", "response_id": response_id,
                    "captured_at": action["created_at"],
                    "raw_response_sha256": hashlib.sha256(
                        (response_id + "-raw").encode()).hexdigest(),
                    "usage": {
                        "input_tokens": 100, "cache_read_tokens": 20,
                        "output_tokens": 30, "tool_tokens": 10, "retry_tokens": 0,
                    },
                },
            }

        host_outcome = self.root / "replay-host-outcome.json"
        replay = {
            "schema_version": 1, "replay_id": "production-replay-001",
            "metric": "rework-rate", "domain": "accounting",
            "request_hash": action["prepared"]["request_hash"],
            "world_fingerprint": action["prepared"]["world_fingerprint"],
            "evaluator_id": "real-medium-verifier-v1",
            "production": True, "simulation": False,
            "enabled": cohort(0.0, "response-enabled", enabled_evidence,
                              [preference["id"]]),
            "disabled": cohort(1.0, "response-disabled", disabled_evidence, []),
        }

        def write_outcome(pair):
            host_outcome.write_text(json.dumps({
                "schema_version": 1,
                "applied_memory_ids": [preference["id"]],
                "verified_memory_ids": [], "rejected_memory_ids": [],
                "metrics": {}, "preference_observations": [], "artifact_usage": [],
                "replay_pair": pair,
            }), encoding="utf-8")

        invalid_pairs = []
        duplicate = json.loads(json.dumps(replay))
        duplicate["disabled"]["provider_receipt"]["response_id"] = "response-enabled"
        invalid_pairs.append(duplicate)
        contaminated = json.loads(json.dumps(replay))
        contaminated["disabled"]["memory_ids"] = [preference["id"]]
        invalid_pairs.append(contaminated)
        wrong_world = json.loads(json.dumps(replay))
        wrong_world["world_fingerprint"] = "0" * 64
        invalid_pairs.append(wrong_world)
        simulation = json.loads(json.dumps(replay))
        simulation["production"], simulation["simulation"] = False, True
        invalid_pairs.append(simulation)
        for invalid in invalid_pairs:
            with self.subTest(invalid=invalid):
                write_outcome(invalid)
                with self.assertRaisesRegex(loom_orchestrator.OrchestratorError,
                                            "HOST_OUTCOME_INVALID"):
                    loom_orchestrator.complete(
                        action_path, usage, result_path=host_outcome)

        write_outcome(replay)
        completed = loom_orchestrator.complete(
            action_path, usage, result_path=host_outcome)
        self.assertEqual("recorded", completed["production_replay"]["status"])
        self.assertEqual(
            "requires-independent-attestation",
            completed["production_replay"]["certification_status"])
        report = loom_improvement.ImprovementTracker(
            self.home, instance_id).report(metric="rework-rate", domain="accounting")
        self.assertEqual(1, report["replay"]["pair_count"])
        self.assertEqual("insufficient-evidence", report["replay"]["status"])

    def test_composite_host_outcome_requires_domain_bound_stack_observations(self):
        opened = loom_orchestrator.invoke(
            request="Build an ETL and machine-learning pipeline",
            cwd=self.repo, home=self.home, install_root=self.installed)
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual({"data-etl", "ml"}, set(action["domains"]))
        outcome = self.root / "composite-host-outcome.json"

        def write_observation(observation):
            outcome.write_text(json.dumps({
                "schema_version": 1, "applied_memory_ids": [],
                "verified_memory_ids": [], "rejected_memory_ids": [],
                "metrics": {}, "preference_observations": [observation],
                "artifact_usage": [],
            }), encoding="utf-8")

        write_observation({"key": "stack", "value": "ambiguous"})
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "active domain"):
            loom_orchestrator._read_host_outcome(outcome, action)
        write_observation({"key": "stack", "value": "wrong", "domain": "web"})
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "active domain"):
            loom_orchestrator._read_host_outcome(outcome, action)
        write_observation({"key": "stack", "value": "dbt", "domain": "data-etl"})
        accepted = loom_orchestrator._read_host_outcome(outcome, action)
        self.assertEqual("data-etl", accepted["learning"][
            "preference_observations"][0]["domain"])

    def test_tier_s_uses_one_bounded_work_order_without_a_pack_essay(self):
        request = "Plan a single-file CLI flag in src/app.py"
        opened = self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        action = json.loads(opened.stdout)
        self.assertEqual("S", action["tier"])
        self.assertEqual(["cli"], action["domains"])
        _author_small_wo(self.repo / "plans")
        usage = self.root / "small-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 300, "cache_read_tokens": 50,
            "output_tokens": 150, "tool_tokens": 50, "retry_tokens": 0,
        }), encoding="utf-8")
        completed = self.cli(
            "complete", "--action", action["action_path"], "--usage", usage)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual("completed", result["status"])
        self.assertEqual("plan-complete", result["code"])
        self.assertEqual([], loom_gate.verify_small(
            self.repo / "plans" / ".loom-small-lifecycle.json"))
        self.assertFalse((self.repo / "plans" / "MANIFEST.md").exists())

    def test_tier_s_continue_preserves_cli_route_and_seals_real_change(self):
        request = "Plan a single-file CLI flag in src/app.py"
        opened = json.loads(self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_small_wo(self.repo / "plans")
        usage = self.root / "small-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 300, "cache_read_tokens": 50,
            "output_tokens": 150, "tool_tokens": 50, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)

        continued = self.cli(
            "invoke", "--request", "Continue", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, continued.returncode, continued.stderr + continued.stdout)
        execute = json.loads(continued.stdout)
        self.assertEqual("execute", execute["intent"])
        self.assertEqual("S", execute["tier"])
        self.assertEqual(["cli"], execute["domains"])
        self.assertEqual("WO-001", execute["work_order"])
        (self.repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        _mark_small_wo_done(self.repo / "plans")
        loom_lifecycle.capture_acceptance(
            self.repo / "plans", self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('small verification passed')"])
        completed = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        self.assertEqual("completed", json.loads(completed.stdout)["status"])
        self.assertEqual([], loom_gate.verify_small(
            self.repo / "plans" / ".loom-small-lifecycle.json"))

    def test_tier_s_elapsed_staleness_rebaselines_and_reauthorizes_compact_plan(self):
        request = "Plan a single-file CLI flag in src/app.py"
        started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        opened = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed, now=started)
        _author_small_wo(self.repo / "plans")
        usage = self.root / "small-stale-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 300, "cache_read_tokens": 50,
            "output_tokens": 150, "tool_tokens": 50, "retry_tokens": 0,
        }), encoding="utf-8")
        planned = loom_orchestrator.complete(
            opened["action_path"], usage, now=started)
        self.assertEqual("plan-complete", planned["code"])

        future = started + dt.timedelta(days=16)
        repair = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("action-required", repair["status"])
        self.assertEqual("repair", repair["intent"])
        self.assertEqual("S", repair["tier"])
        self.assertEqual("compact", repair["repair_plan"]["regate_scope"])
        self.assertEqual(
            ["compact-plan"], repair["repair_plan"]["affected_plan_sections"])

        record = self.repo / "plans" / ".loom-small-lifecycle.json"
        lifecycle = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(["small-planning-started"], [
            event["event"] for event in lifecycle["events"]])
        history = self.repo / "plans" / lifecycle["events"][0]["rebaseline_record"]
        self.assertTrue(history.is_file())
        self.assertEqual(
            lifecycle["events"][0]["rebaseline_record_sha256"],
            hashlib.sha256(history.read_bytes()).hexdigest())

        result = self.root / "small-repair-result.json"
        result.write_text(json.dumps({
            "schema_version": 2,
            "repair_verification": [{
                "section": "compact-plan", "medium": "cli-process",
                "command": [sys.executable, "-c",
                            "print('compact plan verified against current target')"],
                "timeout_seconds": 30,
            }],
        }), encoding="utf-8")
        source = self.repo / "src" / "app.py"
        original_source = source.read_bytes()
        source.write_text("VALUE = 99\n", encoding="utf-8")
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError, "TARGET_DRIFT"):
            loom_orchestrator.complete(
                repair["action_path"], usage, result_path=result, now=future)
        source.write_bytes(original_source)
        original_lifecycle = record.read_bytes()
        record.write_text(
            record.read_text(encoding="utf-8").replace(
                '"freshness_window_days": 14', '"freshness_window_days": 15'),
            encoding="utf-8")
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError, "TARGET_DRIFT"):
            loom_orchestrator.complete(
                repair["action_path"], usage, result_path=result, now=future)
        record.write_bytes(original_lifecycle)
        repaired = loom_orchestrator.complete(
            repair["action_path"], usage, result_path=result, now=future)
        self.assertEqual("repair-complete", repaired["code"])
        self.assertEqual([], loom_gate.verify_small(record))

        continued = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("execute", continued["intent"])
        self.assertEqual("S", continued["tier"])
        self.assertEqual("WO-001", continued["work_order"])

    def test_continue_executes_one_declared_work_order_and_seals_completion(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        planned = self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage)
        self.assertEqual(0, planned.returncode, planned.stderr + planned.stdout)

        execute = json.loads(self.cli(
            "invoke", "--request", "Continue", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        self.assertEqual("execute", execute["intent"])
        self.assertEqual("WO-001", execute["work_order"])
        (self.repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        work_order = _mark_medium_wo_done(self.repo / "plans")
        loom_lifecycle.capture_acceptance(
            self.repo / "plans", self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('accounting verification passed')"])

        completed = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        receipt = json.loads(completed.stdout)
        self.assertEqual("completed", receipt["status"], receipt)
        self.assertEqual("execute-complete", receipt["code"])
        lifecycle = json.loads(
            (self.repo / "plans" / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual("WO-001", lifecycle["work_order_completions"][0]["work_order"])
        self.assertEqual("done", loom_lint.parse_frontmatter(
            work_order.read_text(encoding="utf-8"))[0]["status"])

    def test_execute_refuses_noop_completion(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)
        execute = json.loads(self.cli(
            "invoke", "--request", "Continue", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _mark_medium_wo_done(self.repo / "plans")
        loom_lifecycle.capture_acceptance(
            self.repo / "plans", self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('no-op probe')"])

        result = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        receipt = json.loads(result.stdout)
        self.assertEqual("blocked", receipt["status"])
        self.assertIn("no declared target changed", receipt["user_message"])
        lifecycle = json.loads(
            (self.repo / "plans" / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual([], lifecycle["work_order_completions"])

    def test_execute_refuses_changes_outside_declared_touches(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)
        execute = json.loads(self.cli(
            "invoke", "--request", "Continue", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _write(self.repo / "undeclared.txt", "not authorized\n")
        _mark_medium_wo_done(self.repo / "plans")
        loom_lifecycle.capture_acceptance(
            self.repo / "plans", self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('scope probe')"])

        result = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        receipt = json.loads(result.stdout)
        self.assertEqual("blocked", receipt["status"])
        self.assertIn("outside this work order's declared touches", receipt["user_message"])
        lifecycle = json.loads(
            (self.repo / "plans" / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual([], lifecycle["work_order_completions"])

    def test_elapsed_freshness_expiry_routes_to_repair_before_execution(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)

        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=62)
        resumed = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("action-required", resumed["status"])
        self.assertEqual("repair", resumed["intent"])
        self.assertEqual("M", resumed["tier"])
        self.assertEqual(["accounting"], resumed["domains"])
        self.assertIsNone(resumed["work_order"])
        self.assertEqual("full", resumed["repair_plan"]["regate_scope"])
        self.assertEqual(["full-pack"], resumed["repair_plan"]["affected_plan_sections"])

        repair_result = self.root / "repair-result.json"
        repair_result.write_text(json.dumps({
            "schema_version": 2,
            "repair_verification": [{
                "section": "full-pack", "medium": "cli-process",
                "command": [sys.executable, "-c",
                            "print('full pack freshness verification passed')"],
                "timeout_seconds": 30,
            }],
        }), encoding="utf-8")
        repaired = loom_orchestrator.complete(
            resumed["action_path"], usage, result_path=repair_result, now=future)
        self.assertEqual("completed", repaired["status"])
        self.assertEqual("repair-complete", repaired["code"])

        continued = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("execute", continued["intent"])

    def test_repair_requires_exact_content_bound_evidence(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        repair = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("selective", repair["repair_plan"]["regate_scope"])
        self.assertEqual(["accounting", "testing"],
                         repair["repair_plan"]["affected_plan_sections"])
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError,
                                    "REPAIR_EVIDENCE_REQUIRED"):
            loom_orchestrator.complete(repair["action_path"], usage)

        result_path = self.root / "repair.json"
        result_path.write_text(json.dumps({
            "schema_version": 1,
            "repair_verification": [
                {"section": section, "passed": True, "medium": "cli-process",
                 "evidence_path": "evidence/fabricated.txt",
                 "evidence_sha256": "a" * 64}
                for section in ["accounting", "testing"]
            ],
        }), encoding="utf-8")
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError,
                                    "REPAIR_EVIDENCE_INVALID"):
            loom_orchestrator.complete(
                repair["action_path"], usage, result_path=result_path)
        result_path.write_text(json.dumps({
            "schema_version": 2,
            "repair_verification": [
                {"section": section, "medium": "cli-process",
                 "command": [sys.executable, "-c", "raise SystemExit(7)"],
                 "timeout_seconds": 30}
                for section in ["accounting", "testing"]
            ],
        }), encoding="utf-8")
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError,
                                    "REPAIR_VERIFICATION_FAILED"):
            loom_orchestrator.complete(
                repair["action_path"], usage, result_path=result_path)
        result_path.write_text(json.dumps({
            "schema_version": 2,
            "repair_verification": [
                {"section": section, "medium": "cli-process",
                 "command": [sys.executable, "-c",
                             "print('balanced posting verification passed')"],
                 "timeout_seconds": 30}
                for section in ["accounting", "testing"]
            ],
        }), encoding="utf-8")
        completed = self.cli(
            "complete", "--action", repair["action_path"], "--usage", usage,
            "--result", result_path)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        repaired = json.loads(completed.stdout)
        self.assertEqual("repair-complete", repaired["code"])
        action = json.loads(Path(repair["action_path"]).read_text(encoding="utf-8"))
        entries = action["host_result"]["repair_verification"]
        self.assertEqual(2, len(entries))
        self.assertTrue(all(item["attestation_status"] == "loom-executed-local"
                            for item in entries))
        self.assertTrue(all(item["evidence_id"].startswith("sha256-")
                            for item in entries))
        for item in entries:
            receipt_path = Path(repair["action_path"]).parent / item["receipt_path"]
            self.assertTrue(receipt_path.is_file())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(item["evidence_id"], receipt["evidence_id"])
            self.assertEqual(item["evidence_hash"], receipt["evidence_hash"])
            unsigned = dict(receipt)
            unsigned.pop("evidence_id")
            unsigned.pop("evidence_hash")
            self.assertEqual(loom_lifecycle._digest(unsigned), receipt["evidence_hash"])
            self.assertEqual("disposable-target-snapshot",
                             receipt["execution_isolation"])
        continued = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("execute", continued["intent"])

    def test_cancel_is_terminal_and_content_bound(self):
        opened = self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        action = json.loads(opened.stdout)
        cancelled = self.cli("cancel", "--action", action["action_path"])
        self.assertEqual(0, cancelled.returncode, cancelled.stderr + cancelled.stdout)
        self.assertEqual("cancelled", json.loads(cancelled.stdout)["status"])
        usage = self.root / "usage.json"
        usage.write_text("{}", encoding="utf-8")
        refused = self.cli(
            "complete", "--action", action["action_path"], "--usage", usage)
        self.assertEqual(2, refused.returncode)
        self.assertEqual("cancelled", json.loads(refused.stdout)["status"])

        action_file = Path(action["action_path"])
        tampered = json.loads(action_file.read_text(encoding="utf-8"))
        tampered["attempts"] = 2
        action_file.write_text(json.dumps(tampered), encoding="utf-8")
        corrupt = self.cli(
            "complete", "--action", action_file, "--usage", usage)
        self.assertEqual(2, corrupt.returncode)
        self.assertEqual("ACTION_CORRUPT", json.loads(corrupt.stdout)["code"])

        legacy = json.loads(action_file.read_text(encoding="utf-8"))
        legacy["schema_version"] = 1
        legacy["action_hash"] = loom_orchestrator._action_hash(legacy)
        action_file.write_text(json.dumps(legacy), encoding="utf-8")
        unsupported = self.cli(
            "complete", "--action", action_file, "--usage", usage)
        self.assertEqual(2, unsupported.returncode)
        self.assertEqual(
            "ACTION_VERSION_UNSUPPORTED", json.loads(unsupported.stdout)["code"])

    def test_timeout_and_retry_ceiling_close_the_action(self):
        opened = self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        action = json.loads(opened.stdout)
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 1, "cache_read_tokens": 0,
            "output_tokens": 1, "tool_tokens": 0, "retry_tokens": 0,
        }), encoding="utf-8")
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
        with self.assertRaisesRegex(loom_orchestrator.OrchestratorError, "ACTION_TIMEOUT"):
            loom_orchestrator.complete(action["action_path"], usage, now=future)
        expired = json.loads(Path(action["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual("expired", expired["status"])

        second = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip())
        with mock.patch.object(
                loom_orchestrator, "_handler_result",
                side_effect=RuntimeError("seeded transient failure")):
            for expected in (1, 2, 3):
                with self.assertRaisesRegex(
                        loom_orchestrator.OrchestratorError, "HANDLER_INTERRUPTED"):
                    loom_orchestrator.complete(second["action_path"], usage)
                current = json.loads(
                    Path(second["action_path"]).read_text(encoding="utf-8"))
                self.assertEqual(expected, current["attempts"])
        self.assertEqual("failed", current["status"])


if __name__ == "__main__":
    unittest.main()
