"""Black-box coverage for the installed one-surface production orchestrator."""

import datetime as dt
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).parent))
import loom_gate  # noqa: E402
import loom_fault_harness  # noqa: E402
import loom_install  # noqa: E402
import loom_improvement  # noqa: E402
import loom_lifecycle  # noqa: E402
import loom_lint  # noqa: E402
import loom_adapter_protocol  # noqa: E402
import loom_domain_discovery  # noqa: E402
import loom_domain  # noqa: E402
import loom_memory  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_plan_author  # noqa: E402
import loom_performance  # noqa: E402
import loom_reliability  # noqa: E402
import loom_release  # noqa: E402
from test_loom_vault_v11 import TestCrypto  # noqa: E402


TODAY = dt.datetime.now(dt.timezone.utc).date().isoformat()


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_planning_assignments(pack, contract, work_order="WO-001", milestone="delivery"):
    atoms = [item for item in contract["planning_intelligence"]["atoms"]
             if item["gate_effect"] != "none"]
    assignments = [{
        "atom_id": item["atom_id"], "work_order": work_order,
        "milestone": milestone,
        "verification": loom_orchestrator.loom_planning_intelligence.expanded_verification(
            contract["planning_intelligence"], item),
    } for item in sorted(atoms, key=lambda value: value["atom_id"])]
    body = {
        "schema_version": 1, "plan_contract_hash": contract["contract_hash"],
        "planning_intelligence_digest": contract["planning_intelligence"][
            "intelligence_digest"],
        "program_digest": (contract["planning_intelligence"]["program"] or {}).get(
            "program_digest"),
        "assignments": assignments,
    }
    value = {**body, "assignment_digest": loom_orchestrator.loom_domain_contract.digest(
        "planning-obligation-assignments-v1", body)}
    _write(pack / "planning-obligations.json", json.dumps(value, indent=2) + "\n")
    return [item["atom_id"] for item in assignments]


def _author_medium_pack(pack, version, contract):
    """Act as the host agent; production code must not import test helpers."""
    _write(pack / "plan-contract.json", json.dumps(contract, indent=2) + "\n")
    obligation_ids = _write_planning_assignments(pack, contract)
    obligation_list = ", ".join(obligation_ids)
    _write(pack / "MANIFEST.md", f"""---
artifact: manifest
project: "orchestrator fixture"
tier: M
status: active
execution_mode: planned
last_verified: {TODAY}
loom_version: "{version}"
plan_contract_version: {contract["schema_version"]}
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
| accounting | currency precision | testing.md and WO-001 | dated jurisdiction, tax-period, and filed-period cases | verified |
| accounting | immutable audit trail | decisions.md and WO-001 | double-entry property tests | verified |
| accounting | reconciliation | testing.md and WO-001 | double-entry property tests | verified |
| accounting | reversal and adjusting-entry semantics | testing.md and WO-001 | double-entry property tests | verified |
| accounting | period close | testing.md and WO-001 | double-entry property tests | verified |
| accounting | tax-period calendar and filed-period lock/reopen authority | testing.md and WO-001 | dated jurisdiction, tax-period, and filed-period cases | verified |
| accounting | jurisdiction/effective-date rules | testing.md and WO-001 | double-entry property tests | verified |

## Current facts to verify
| Domain | Fact | Source | Status |
|---|---|---|---|
| accounting | current platform/tool versions and limits | repository and runtime inventory | verified |
| accounting | current governing policies, standards, or regulations | request excludes policy changes | verified |
| accounting | current target environment and release channel | local non-release target | verified |

## Planning intelligence obligations

- `security-privacy-safety:authority-boundary`
- `security-privacy-safety:fail-closed-harm`
- `verification-evidence:observable-oracle`
- `verification-evidence:negative-recovery`
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
| accounting | dated jurisdiction, tax-period, and filed-period cases | prove a release-relevant domain invariant | planned |
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
milestone: delivery
planning_obligations: [{obligation_list}]
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


def _author_small_wo(pack, contract):
    obligation_ids = [item["atom_id"] for item in contract["planning_intelligence"]["atoms"]
                      if item["gate_effect"] != "none"]
    obligation_list = ", ".join(sorted(obligation_ids))
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
milestone: delivery
planning_obligations: [{obligation_list}]
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
Planning obligations: `verification-evidence:observable-oracle`,
`verification-evidence:negative-recovery`.
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
        cls.repo_fixture = cls.fixture_root / "repo-fixture"
        (cls.repo_fixture / "src").mkdir(parents=True)
        _write(cls.repo_fixture / "src" / "app.py", "VALUE = 1\n")
        cls.fixture_home = cls.fixture_root / "fixture-home"
        loom_fault_harness.initialize_git_fixture(
            cls.repo_fixture, cls.fixture_home)

    @classmethod
    def tearDownClass(cls):
        cls.fixture_temp.cleanup()

    def setUp(self):
        self.prior_legacy_test_backend = os.environ.get("LOOM_TEST_ALLOW_LEGACY_BACKEND")
        os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = "1"
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.installed = self.installed_fixture
        self.home = self.root / "home"
        self.home.mkdir(parents=True)
        (self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
            loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
        self.repo = self.root / "target"
        loom_fault_harness.clone_git_fixture(
            self.repo_fixture, self.repo, self.home / "git-home")
        self.request = "Plan a financial double-entry accounting change to src/app.py"
        self.request_sequence = 0

    def tearDown(self):
        if self.prior_legacy_test_backend is None:
            os.environ.pop("LOOM_TEST_ALLOW_LEGACY_BACKEND", None)
        else:
            os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = self.prior_legacy_test_backend
        self.temp.cleanup()

    def cli(self, *args):
        values = list(map(str, args))
        stdin = None
        if values and values[0] == "invoke":
            if len(values[1:]) % 2:
                raise AssertionError("invoke test arguments must be flag/value pairs")
            options = dict(zip(values[1::2], values[2::2]))
            self.request_sequence += 1
            message = {
                "schema_version": 2, "message_type": "invoke",
                "request_id": options.get(
                    "--request-id", f"req-production-{self.request_sequence}"),
                "request": options["--request"],
                "cwd": options["--cwd"],
            }
            envelope = loom_adapter_protocol.request_envelope(
                message, {"id": "codex", "version": "test"})
            stdin = (loom_adapter_protocol.canonical_bytes(envelope) + b"\n").decode(
                "utf-8")
            values = [
                "invoke-stdio", "--home", options["--home"],
                "--install-root", options["--install-root"],
            ]
            for flag in ("--target", "--timeout-seconds"):
                if flag in options:
                    values.extend([flag, options[flag]])
        return subprocess.run(
            [sys.executable, "-B",
             str(self.installed / "tools" / "loom_orchestrator.py"),
             *values], input=stdin, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60)

    def test_remember_does_not_claim_success_when_tombstone_blocks_reentry(self):
        class RetiredMemoryAdapter:
            @staticmethod
            def remember(_context, _statement):
                return {
                    "id": "965289d2-e2f1-4128-bd2d-a458cf2bca81",
                    "status": "forgotten",
                }

        handler = loom_orchestrator.default_handlers(
            root=self.repo, owner_home=self.home,
            memory_adapter=RetiredMemoryAdapter())["remember"]
        context = types.SimpleNamespace(
            intent="remember",
            request_text="Remember that plans should stay concise.",
            prepared=types.SimpleNamespace(
                instance_id="instance", route_contract={"tier": "S"}),
            project_id="p-" + "1" * 32)

        result = handler(context)

        self.assertEqual("blocked", result["status"])
        self.assertEqual("memory-remains-forgotten", result["code"])
        self.assertFalse(result["success"])
        self.assertIn("remains permanently forgotten", result["user_message"])

    def test_planning_intelligence_failure_is_a_bounded_json_block(self):
        envelope = loom_adapter_protocol.request_envelope({
            "schema_version": 2,
            "message_type": "invoke",
            "request_id": "req-planning-intelligence-block",
            "request": "Plan a project",
            "cwd": str(self.repo),
        }, {"id": "codex", "version": "test"})
        output = io.StringIO()
        with mock.patch.object(
                loom_orchestrator.loom_adapter_protocol,
                "read_single_frame", return_value=envelope), \
                mock.patch.object(
                    loom_orchestrator, "invoke",
                    side_effect=loom_orchestrator.loom_planning_intelligence.
                    PlanningIntelligenceError("active specialist modules exceed the tier bound")), \
                redirect_stdout(output):
            returncode = loom_orchestrator.main([
                "invoke-stdio", "--home", str(self.home),
                "--install-root", str(self.installed),
            ])
        self.assertEqual(2, returncode)
        result = json.loads(output.getvalue())
        self.assertEqual("blocked", result["status"])
        self.assertEqual("RUNTIME_BLOCKED", result["code"])
        self.assertIn("specialist modules", result["error"])

    def complete_machine_authored_plan(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = action["plan_contract"]
        shape = action["semantic_draft_shape"]
        self.assertEqual(
            ["domain", "fact", "source"], shape["current_fact_fields"])
        self.assertNotIn("evidence_sources", shape["current_fact_fields"])
        self.assertEqual(
            sorted(loom_plan_author.WORK_ORDER_FIELDS),
            shape["work_order_fields"])
        self.assertEqual(
            sorted(loom_plan_author.ROUTING), shape["routing_values"])
        self.assertEqual(
            sorted(loom_plan_author.SIZE), shape["size_values"])
        self.assertEqual(
            loom_plan_author.SOURCE_KEY_PATTERN,
            shape["domain_source_key_pattern"])
        self.assertEqual(
            sorted(loom_plan_author.SOURCE_CLASSES),
            shape["domain_source_class_values"])
        self.assertEqual(
            sorted(loom_plan_author.LOCATOR_VISIBILITY),
            shape["domain_locator_visibility_values"])
        self.assertEqual(
            sorted(loom_plan_author.CURRENTNESS),
            shape["domain_currentness_values"])
        self.assertEqual(
            sorted(loom_plan_author.INVARIANT_TYPES),
            shape["domain_invariant_type_values"])
        self.assertEqual(
            sorted(loom_plan_author.CONSEQUENCE_CLASSES),
            shape["domain_consequence_values"])
        self.assertEqual(
            sorted(loom_plan_author.AUTHORITY_REQUIREMENTS),
            shape["domain_authority_requirement_values"])
        self.assertEqual(
            ["owner-authority", "repository-evidence"],
            shape["domain_authority_availability"]["semantic_source_supported"])
        self.assertIn(
            "real-medium-evidence",
            shape["domain_authority_availability"]["receipt_required"])
        self.assertEqual(["accounting"], shape["active_domain_values"])
        self.assertFalse(shape["domain_evidence_required"])
        self.assertEqual(
            8192, shape["domain_limits"]["sources"]["content_bytes"])
        self.assertNotIn(
            "freshness_policy", shape["domain_invariant_fields"])
        self.assertIn(
            "semantic_draft_shape.domain_limits",
            action["required_outcome"])
        self.assertIn("RFC3339", shape["timestamp_contract"])
        self.assertIn(
            "object", shape["collection_contracts"]["answers"])
        self.assertIn(
            "WO-###", shape["collection_contracts"]["depends_on"])
        self.assertIn(
            "implementation target", " ".join(shape["rules"]))
        self.assertIn(
            "overlapping touches", " ".join(shape["rules"]))
        self.assertIn(
            "does not imply the real-medium-evidence authority requirement",
            " ".join(shape["rules"]))
        self.assertIn(
            "use only semantic_draft_shape field names",
            action["required_outcome"].casefold())
        draft = {
            "schema_version": 1,
            "title": "Preserve double-entry correctness",
            "summary": (
                "Plan one bounded change to src/app.py while preserving the shipped "
                "accounting invariants."),
            "assumptions": [
                "The requested change remains limited to the existing src/app.py boundary."],
            "decisions": [
                "Reject any posting path that could leave debits and credits unbalanced."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped accounting adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Preserve double-entry correctness",
                "outcome": "Requested behavior preserves all accounting invariants.",
                "tasks": [
                    "Inspect the existing posting boundary.",
                    "Implement the requested bounded behavior.",
                    "Run executable positive and negative accounting checks.",
                ],
                "acceptance": [
                    "`python -m unittest` exits 0 for balanced postings.",
                    "A precision edge case preserves its exact decimal result.",
                ],
                "negative_acceptance": [
                    "an unbalanced posting fails without a partial write"],
                "out_of_scope": ["Tax policy and data migration."],
                "escalation": ["Stop if a dated jurisdiction rule is required."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }
        loom_orchestrator.author(
            action["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        return action, completed

    def test_legacy_test_backend_requires_exact_disposable_marker(self):
        marker = self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER
        self.assertTrue(loom_orchestrator._disposable_test_legacy_backend_allowed(
            self.home))
        marker.write_text("wrong\n", encoding="utf-8")
        self.assertFalse(loom_orchestrator._disposable_test_legacy_backend_allowed(
            self.home))

    def test_installed_phase_8_request_uses_deep_target_route(self):
        request = (
            "Phase 8 and 9 and 10 research is done and it's in the folders. "
            "Read all of them, omit what is wrong, make a Loom plan for all three "
            "phases separately and then start Phase 8's plan implementation."
        )
        opened = self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed,
            "--timeout-seconds", "300")
        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        action = json.loads(opened.stdout)
        self.assertEqual("L", action["tier"])
        self.assertEqual(["llm-agent"], action["domains"])
        self.assertEqual(
            loom_orchestrator.PLAN_CONTRACT_SCHEMA_VERSION,
            action["plan_contract"]["schema_version"])
        active = {item["id"] for item in action["plan_contract"]
                  ["planning_intelligence"]["active_modules"]}
        self.assertTrue({"outcomes-requirements", "architecture-boundaries",
                         "verification-evidence"}.issubset(active))
        self.assertNotIn("interaction-accessibility", active)
        self.assertNotIn("migration-release", active)

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
        self.assertEqual(
            "explicit-authority", action["continuation_authority"]["mode"])
        self.assertTrue(action["continuation_authority"]["owner_authorized"])
        self.assertEqual(
            "high", action["continuation_authority"]["facts"]["consequence"])
        self.assertTrue(action["continuation_authority"]["facts"][
            "legal_or_safety_judgment"])
        self.assertEqual("progress", action["owner_message"]["state"])
        self.assertTrue(action["owner_message"]["changes_made"])
        self.assertEqual("unavailable", action["owner_message"]["undo_status"])
        self.assertIn(
            "no project deliverable was changed",
            action["owner_message"]["summary"].casefold())
        self.assertEqual(2, len(action["owner_message"]["human"].splitlines()))
        contract = action["plan_contract"]
        self.assertEqual(
            loom_orchestrator.PLAN_CONTRACT_SCHEMA_VERSION,
            contract["schema_version"])
        self.assertEqual(contract["domain_route"]["route_digest"],
                         contract["route_digest"])
        self.assertEqual(contract["domain_route"]["graph_digest"],
                         contract["composition_graph_digest"])
        self.assertEqual(15, len(contract["artifact_matrix"]))
        self.assertIn("verification-evidence", {
            item["id"] for item in contract["planning_intelligence"]["active_modules"]})
        self.assertEqual("project", contract["planning_intelligence"]
                         ["lifecycle_route"]["mode"])
        self.assertEqual(
            contract["contract_hash"],
            loom_orchestrator._hash({
                key: value for key, value in contract.items()
                if key != "contract_hash"
            }),
        )
        self.assertEqual(
            {"balanced postings", "currency precision", "immutable audit trail",
             "reconciliation", "reversal and adjusting-entry semantics", "period close",
             "tax-period calendar and filed-period lock/reopen authority",
             "jurisdiction/effective-date rules"},
            {item["invariant"] for item in contract["required_domain_invariants"]},
        )

        sealed_action = json.loads(
            Path(action["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual(contract, sealed_action["plan_contract"])
        self.assertEqual(action["continuation_authority"],
                         sealed_action["continuation_authority"])
        self.assertTrue((self.repo / "plans" / "lifecycle.json").is_file())

        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            action["plan_contract"])
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
        self.assertEqual("legacy-ambiguous", result["usage"]["measurement_status"])
        self.assertIsNone(result["usage"]["processed_total_tokens"])
        self.assertEqual(900, result["usage"]["legacy_declared_total_tokens"])
        self.assertIsNone(result["usage"]["processed_total_tokens"])
        self.assertEqual([], loom_gate.verify(
            self.repo / "plans", self.repo))
        self.assertIn(
            "implementation is not authorized",
            loom_gate.verify(
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

    def test_firmware_invariants_receive_concern_specific_real_media(self):
        request = (
            "Plan sensor firmware with watchdog recovery, flash-wear limits, "
            "brownout behavior, hardware-in-loop evidence, and safe rollback.")
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        media = {
            item["invariant"]: item["required_real_medium"]
            for item in action["plan_contract"]["required_domain_invariants"]}

        self.assertEqual(
            "watchdog reset and liveness-recovery test",
            media["watchdog and liveness recovery"])
        self.assertEqual(
            "flash endurance and wear-budget stress test",
            media["flash endurance and wear budget"])
        self.assertEqual(
            "brownout and power-loss fault injection",
            media["brownout and power-loss behavior"])
        self.assertEqual(
            "physical rollback and flash-recovery rehearsal",
            media["physical rollback and safety boundary"])
        normalized = {
            item["statement"]: item["verification"]["required_real_medium"]
            for item in action["plan_contract"]["domain_invariants"]
        }
        self.assertEqual(media, normalized)

    def test_firmware_safety_consequence_reaches_continuation_authority(self):
        request = (
            "Plan a fail-safe industrial controller with watchdog firmware, "
            "hardware interlocks, power-loss recovery, and physical rollback tests.")
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual(
            "high",
            action["plan_contract"]["domain_route"]["consequence"]["class"])
        self.assertEqual("high", action["owner_message"]["consequence"])
        authority = action["continuation_authority"]
        self.assertEqual("explicit-authority", authority["mode"])
        self.assertEqual("high", authority["facts"]["consequence"])
        self.assertTrue(authority["facts"]["legal_or_safety_judgment"])
        self.assertIn("consequential", authority["blockers"])
        self.assertIn("legal-or-safety-judgment", authority["blockers"])

    def test_status_and_why_reports_pending_plan_instead_of_no_prior_run(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        status = loom_orchestrator.invoke(
            request=(
                "Report the current Loom action status for this project and explain "
                "why it is in that state. Do not create or modify a plan."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("completed", status["status"])
        self.assertEqual("active-action-reason", status["code"])
        self.assertEqual(["accounting"], status["domains"])
        self.assertIn("project plan is waiting", status["user_message"].casefold())
        self.assertIn("coding has not started", status["user_message"].casefold())
        self.assertIn("only this action is currently authorized",
                      status["user_message"].casefold())
        self.assertNotIn("no prior loom run", status["user_message"].casefold())
        replay = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual(opened["action_id"], replay["action_id"])

    def test_focused_accounting_desktop_plan_is_medium_not_program_scale(self):
        action = loom_orchestrator.invoke(
            request=(
                "Plan a focused desktop bookkeeping tool with double-entry "
                "correctness and tax-period closing."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual(["accounting", "desktop"], action["domains"])
        self.assertEqual("M", action["tier"])

    def test_machine_authoring_produces_a_lint_clean_authorized_medium_plan(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = action["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Preserve double-entry correctness",
            "summary": (
                "Plan one bounded change to src/app.py while preserving the shipped "
                "accounting invariants."),
            "assumptions": [
                "The requested change remains limited to the existing src/app.py boundary."],
            "decisions": [
                "Reject any posting path that could leave debits and credits unbalanced."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": (
                    "sealed project inspection and the shipped accounting adapter; "
                    "implementation must recheck any dated external rule"),
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Preserve double-entry correctness",
                "outcome": (
                    "The requested src/app.py behavior changes without violating balanced "
                    "posting, precision, audit, reconciliation, or close invariants."),
                "tasks": [
                    "Inspect the current src/app.py posting boundary.",
                    "Implement only the requested behavior inside that boundary.",
                    "Add executable positive and negative accounting checks.",
                ],
                "acceptance": [
                    "`python -m unittest` exits 0 and exercises balanced postings.",
                    "A 0.10 plus 0.20 precision edge case returns exactly 0.30.",
                ],
                "negative_acceptance": [
                    "an unbalanced posting exits nonzero without a partial write"],
                "out_of_scope": ["Tax-policy changes and data migration."],
                "escalation": [
                    "Stop if a dated jurisdiction rule or a second component is required."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }

        authored = loom_orchestrator.author(
            action["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("authored", authored["status"])
        self.assertTrue(authored["ready_for_completion"])
        self.assertFalse([
            item for item in authored["diagnostics"] if item["level"] == "ERROR"])
        self.assertFalse([
            item for item in authored["diagnostics"] if item["level"] == "WARN"])
        intake = (self.repo / "plans" / "intake.md").read_text(encoding="utf-8")
        self.assertIn("| required |", intake)
        self.assertIn("| unverified |", intake)
        review = (
            self.repo / "plans" / "reviews" / "G1-plan-review.md"
        ).read_text(encoding="utf-8")
        self.assertIn("loom-deterministic-plan-validator-v2", review)
        report = loom_lint.lint(
            self.repo / "plans", repo_path=self.repo,
            enforce_lifecycle=False, check_repo_state=False)
        self.assertEqual([], report.findings)

        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        self.assertEqual("plan-complete", completed["code"])
        self.assertEqual(
            "plans/MANIFEST.md",
            completed["owner_message"]["result_path"])
        self.assertIn(
            "Review the plan",
            completed["owner_message"]["human"])
        self.assertNotIn(
            "work-order frontier",
            completed["owner_message"]["human"])
        self.assertNotIn(
            "Implementation may proceed",
            completed["owner_message"]["human"])
        self.assertEqual([], loom_gate.verify(
            self.repo / "plans", self.repo))
        self.assertIn(
            "implementation is not authorized",
            loom_gate.verify(
                self.repo / "plans", self.repo, require_authorized=True))

    def test_medium_plan_requires_explicit_continue_before_authorization(self):
        _action, completed = self.complete_machine_authored_plan()
        self.assertEqual("plan-complete", completed["code"])
        manifest = loom_lint.parse_frontmatter(
            (self.repo / "plans" / "MANIFEST.md").read_text(
                encoding="utf-8"))[0]
        self.assertEqual("gated", manifest["status"])
        self.assertIn(
            "implementation is not authorized",
            loom_gate.verify(
                self.repo / "plans", self.repo, require_authorized=True))

        continued = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", continued["status"])
        self.assertEqual("execute", continued["intent"])
        self.assertEqual("WO-001", continued["work_order"])
        manifest = loom_lint.parse_frontmatter(
            (self.repo / "plans" / "MANIFEST.md").read_text(
                encoding="utf-8"))[0]
        self.assertEqual("active", manifest["status"])
        self.assertEqual(
            [], loom_gate.verify(
                self.repo / "plans", self.repo, require_authorized=True))

    def test_machine_authoring_produces_a_lint_clean_large_routing_snapshot(self):
        action = loom_orchestrator.invoke(
            request=(
                "Plan an ETL and machine-learning pipeline with schema evolution, "
                "backfills, lineage, reproducibility, monitoring, and recovery."),
            cwd=self.repo, home=self.home, install_root=self.installed)
        self.assertEqual("L", action["tier"])
        contract = action["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Replay-safe data and model pipeline",
            "summary": (
                "Plan two ordered outcomes for replay-safe data processing and "
                "reproducible model delivery."),
            "assumptions": [
                "The current pipeline boundary remains the target.",
                "No production deployment is authorized by this plan.",
            ],
            "decisions": [
                "Separate ingestion correctness from model verification.",
                "Require recovery evidence before release.",
            ],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "Unknown at planning time; verify against the sealed target.",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Make ingestion replay safe",
                "outcome": "Ingestion preserves schema, lineage, and idempotency.",
                "tasks": [
                    "Define schema evolution and lineage contracts.",
                    "Add duplicate, late-data, and backfill probes.",
                ],
                "acceptance": [
                    "`python -m unittest` exits 0 for replay and duplicate cases."],
                "negative_acceptance": [
                    "a rejected record never enters the accepted dataset"],
                "out_of_scope": ["Model deployment."],
                "escalation": ["Stop if lineage authority is unavailable."],
                "touches": ["src/etl/**", "tests/etl/**"], "depends_on": [],
                "routing": "strong-coding", "size": "M",
            }, {
                "title": "Prove reproducible model behavior",
                "outcome": "Training and inference are reproducible and monitored.",
                "tasks": [
                    "Bind data, code, configuration, and artifact versions.",
                    "Add leakage, drift, recovery, and train-serve parity checks.",
                ],
                "acceptance": [
                    "Two sealed training runs produce the declared reproducibility result."],
                "negative_acceptance": [
                    "leakage or train-serve skew blocks release"],
                "out_of_scope": ["Changing product policy."],
                "escalation": ["Stop on an unexplained evaluation difference."],
                "touches": ["src/ml/**", "tests/ml/**"],
                "depends_on": ["WO-001"], "routing": "specialist", "size": "M",
            }],
            "domain_evidence": None,
        }

        authored = loom_orchestrator.author(
            action["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        self.assertTrue(authored["ready_for_completion"])
        manifest = (self.repo / "plans" / "MANIFEST.md").read_text(
            encoding="utf-8")
        self.assertIn("## Routing snapshot", manifest)
        report = loom_lint.lint(
            self.repo / "plans", repo_path=self.repo,
            enforce_lifecycle=False, check_repo_state=False)
        self.assertEqual([], report.findings)

    def test_completed_machine_authored_plan_is_exactly_reversible(self):
        action, completed = self.complete_machine_authored_plan()
        self.assertEqual([action["action_id"]], completed["reversible_action_ids"])
        sealed = json.loads(
            Path(action["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual(
            "active", sealed["host_result"]["plan_author"]["state"])

        undone = loom_orchestrator.invoke(
            request="Undo the last Loom plan", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", undone["status"])
        self.assertEqual("undo-complete", undone["code"])
        self.assertIn(
            f"undone-plan-{action['action_id']}",
            undone["owner_message"]["human"])
        self.assertNotIn(
            "completed the requested safe frontier",
            undone["owner_message"]["human"])
        self.assertFalse((self.repo / "plans").exists())
        archive = (
            self.repo / ".loom-history" /
            f"undone-plan-{action['action_id']}")
        self.assertTrue(archive.is_dir())
        _path, restored, _security = loom_orchestrator._read_action(
            action["action_path"])
        record = restored["host_result"]["plan_author"]
        self.assertEqual("undone", record["state"])
        self.assertEqual(
            archive.relative_to(self.repo).as_posix(), record["archive_path"])

    def test_completed_plan_replays_only_in_the_exact_unchanged_world(self):
        action, completed = self.complete_machine_authored_plan()
        replayed = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual(completed, {
            key: value for key, value in replayed.items() if key != "assurance"})
        self.assertEqual("standard", replayed["assurance"]["mode"])
        action_directory = Path(action["action_path"]).parent
        self.assertEqual(
            1, len(list(action_directory.glob(
                "????????-????-????-????-????????????.json"))))

        (self.repo / "src" / "app.py").write_text(
            "print('world changed')\n", encoding="utf-8")
        changed = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertNotEqual(action["action_id"], changed["action_id"])
        self.assertEqual("repair", changed["intent"])
        self.assertEqual(
            2, len(list(action_directory.glob(
                "????????-????-????-????-????????????.json"))))

    def test_medium_whole_accounting_plan_requires_architecture_and_security(self):
        contract = loom_orchestrator._artifact_contract(
            "M", ["accounting", "desktop"],
            "Plan desktop bookkeeping software with tax-period closing.",
            False)
        actions = {
            row["artifact"]: row["action"]
            for row in contract
        }

        self.assertEqual("produce", actions["architecture.md"])
        self.assertEqual("produce", actions["contracts.md"])
        self.assertEqual("produce", actions["security.md"])

    def test_medium_data_migration_produces_release_rollback_contract(self):
        contract = loom_orchestrator._artifact_contract(
            "M", ["accounting", "desktop"],
            "Plan desktop bookkeeping software with a customer data migration.",
            False)
        actions = {
            row["artifact"]: row["action"]
            for row in contract
        }

        self.assertEqual("produce", actions["release-rollback.md"])

    def test_medium_ledger_schema_migration_produces_release_rollback_contract(self):
        contract = loom_orchestrator._artifact_contract(
            "M", ["accounting", "desktop"],
            "Plan the migration of a desktop bookkeeping application to a new "
            "ledger schema.",
            False)
        actions = {row["artifact"]: row["action"] for row in contract}
        self.assertEqual("produce", actions["release-rollback.md"])

        ordinary = loom_orchestrator._artifact_contract(
            "M", ["accounting", "desktop"],
            "Plan a desktop bookkeeping application with a ledger report.",
            False)
        ordinary_actions = {
            row["artifact"]: row["action"] for row in ordinary}
        self.assertEqual("skip", ordinary_actions["release-rollback.md"])

    def test_explicit_encrypted_storage_selects_security_artifact_at_tier_m(self):
        request = (
            "Plan a small mobile offline notes app with conflict handling, "
            "accessibility, lifecycle restoration, encrypted local storage, "
            "and release checks.")
        route = loom_domain.select_domains(request)["domain_contract"]
        intelligence = loom_orchestrator.loom_planning_intelligence.compile_intelligence(
            request, tier="M", route=route)
        contract = loom_orchestrator._artifact_contract(
            "M", ["mobile"], request, False,
            intelligence["active_modules"])
        rows = {row["artifact"]: row for row in contract}

        self.assertEqual("produce", rows["security.md"]["action"])
        self.assertEqual("security reviewer", rows["security.md"]["consumer"])

    def test_research_report_uses_research_artifacts_not_software_artifacts(self):
        contract = loom_orchestrator._artifact_contract(
            "M", ["research"],
            "Plan a research comparison of embedded databases and produce a "
            "Markdown report; do not build software.",
            False)
        rows = {row["artifact"]: row for row in contract}

        self.assertEqual("produce", rows["intake.md"]["action"])
        self.assertEqual("skip", rows["testing.md"]["action"])
        self.assertEqual("produce", rows["work orders"]["action"])
        self.assertEqual("researcher", rows["work orders"]["consumer"])
        self.assertEqual(
            "research tasks and report acceptance",
            rows["work orders"]["decision"])
        self.assertNotIn(
            "executable", rows["work orders"]["reason"].casefold())
        self.assertNotIn(
            "software test", rows["testing.md"]["reason"].casefold())

        memo = loom_orchestrator._artifact_contract(
            "M", ["research"],
            "Research and write a cited comparison of SQLite, DuckDB, and "
            "RocksDB. Deliver only a decision memo.",
            False)
        memo_rows = {row["artifact"]: row for row in memo}
        self.assertEqual("researcher", memo_rows["work orders"]["consumer"])
        self.assertEqual("skip", memo_rows["testing.md"]["action"])

    def test_authored_research_pack_matches_produced_artifact_files_exactly(self):
        action = loom_orchestrator.invoke(
            request=(
                "Plan a research comparison of embedded databases and produce a "
                "Markdown report; do not build software."),
            cwd=self.repo, home=self.home, install_root=self.installed)
        contract = action["plan_contract"]
        rows = {
            item["artifact"]: item["action"]
            for item in contract["artifact_matrix"]}
        self.assertEqual("skip", rows["testing.md"])
        draft = {
            "schema_version": 1,
            "title": "Compare embedded databases",
            "summary": (
                "Produce a cited Markdown comparison of embedded databases."),
            "assumptions": [
                "The comparison is limited to the databases named by the owner."],
            "decisions": [
                "Separate sourced findings from recommendations."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "Verify against the cited primary source before writing.",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Write the cited comparison",
                "outcome": (
                    "A Markdown report separates sourced findings, limitations, "
                    "and the final recommendation."),
                "tasks": [
                    "Collect current primary sources for each database.",
                    "Compare the declared criteria with source citations.",
                    "Write the report and record unresolved limitations.",
                ],
                "acceptance": [
                    "Every factual comparison claim cites a collected source.",
                    "The report distinguishes findings from recommendations.",
                ],
                "negative_acceptance": [
                    "an unsupported factual claim blocks report completion"],
                "out_of_scope": [
                    "Building software or benchmarking undeclared workloads."],
                "escalation": [
                    "Stop if a required current primary source is unavailable."],
                "touches": ["report.md"], "depends_on": [],
                "routing": "specialist", "size": "S",
            }],
            "domain_evidence": None,
        }

        authored = loom_orchestrator.author(
            action["action_path"], draft, owner_home=self.home,
            install_root=self.installed)

        self.assertTrue(authored["ready_for_completion"])
        pack = self.repo / "plans"
        self.assertFalse((pack / "testing.md").exists())
        for artifact, action_name in rows.items():
            if action_name != "produce" or artifact in {
                    "work orders", "routing"}:
                continue
            self.assertTrue(
                (pack / artifact).is_file(),
                f"produced artifact is missing: {artifact}")
        self.assertEqual(
            [], loom_lint.lint(
                pack, repo_path=self.repo,
                enforce_lifecycle=False, check_repo_state=False).findings)

    def test_plan_undo_refuses_changed_pack_without_moving_it(self):
        _action, _completed = self.complete_machine_authored_plan()
        decisions = self.repo / "plans" / "decisions.md"
        decisions.write_text(
            decisions.read_text(encoding="utf-8") + "\nowner change\n",
            encoding="utf-8")

        refused = loom_orchestrator.invoke(
            request="Undo the last Loom plan", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("blocked", refused["status"])
        self.assertEqual("plan-undo-changed", refused["code"])
        self.assertTrue((self.repo / "plans").is_dir())
        self.assertFalse((self.repo / ".loom-history").exists())

    def test_plan_undo_refuses_destination_collision_without_overwriting(self):
        action, _completed = self.complete_machine_authored_plan()
        archive = (
            self.repo / ".loom-history" /
            f"undone-plan-{action['action_id']}")
        archive.mkdir(parents=True)
        marker = archive / "unowned.txt"
        marker.write_text("preserve\n", encoding="utf-8")

        refused = loom_orchestrator.invoke(
            request="Undo the last Loom plan", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("blocked", refused["status"])
        self.assertEqual("plan-undo-conflict", refused["code"])
        self.assertTrue((self.repo / "plans").is_dir())
        self.assertEqual("preserve\n", marker.read_text(encoding="utf-8"))

    def test_plan_undo_recovers_move_completed_before_receipt_update(self):
        action, _completed = self.complete_machine_authored_plan()
        history = self.repo / ".loom-history"
        history.mkdir()
        archive = history / f"undone-plan-{action['action_id']}"
        os.replace(self.repo / "plans", archive)

        recovered = loom_orchestrator.invoke(
            request="Undo the last Loom plan", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", recovered["status"])
        self.assertEqual("undo-complete", recovered["code"])
        self.assertFalse((self.repo / "plans").exists())
        self.assertTrue(archive.is_dir())
        _path, restored, _security = loom_orchestrator._read_action(
            action["action_path"])
        self.assertEqual(
            "undone", restored["host_result"]["plan_author"]["state"])

    def test_machine_authoring_seals_semantic_unknown_domain_evidence(self):
        authority_text = (
            "Every glossary definition must cite AUTHORITY.md and retain the "
            "canonical term spelling.\n")
        _write(self.repo / "AUTHORITY.md", authority_text)
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "AUTHORITY.md"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "add authority"],
            check=True)
        request = (
            "Plan a quantum optics glossary research note in src/app.py using "
            "AUTHORITY.md as the governing repository source.")
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("M", action["tier"])
        contract = action["plan_contract"]
        stamp = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z")
        future = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        draft = {
            "schema_version": 1, "title": "Quantum optics glossary",
            "summary": "Plan a source-traceable quantum optics glossary research note.",
            "assumptions": [], "decisions": [
                "Use only definitions traceable to the sealed repository source."],
            "current_facts": [],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Author traceable glossary",
                "outcome": "Every glossary definition is source-traceable.",
                "tasks": ["Write the glossary note in src/app.py."],
                "acceptance": [
                    "Every definition has one AUTHORITY.md citation."],
                "negative_acceptance": [
                    "an uncited definition is rejected before completion"],
                "out_of_scope": ["Laboratory control and safety guidance."],
                "escalation": ["Stop if a definition lacks repository authority."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "specialist", "size": "S",
            }],
            "domain_evidence": {
                "retrieval_rounds": 1,
                "answers": {
                    key: "Bound to the cited research note and rendered glossary."
                    for key, _question in loom_domain_discovery.QUESTIONS
                },
                "sources": [{
                    "key": "authority", "title": "Repository terminology authority",
                    "locator": "AUTHORITY.md",
                    "locator_visibility": "public",
                    "publisher": "Repository",
                    "source_class": "repository",
                    "content": None,
                    "retrieval_method": "runtime repository read",
                    "document_id": "AUTHORITY.md", "version": "1",
                    "published_at": stamp, "effective_at": stamp,
                    "revalidate_by": future, "jurisdiction": None,
                    "product_class": "research-note", "environment": "local",
                    "currentness": "current", "ambiguity": None,
                }],
                "invariants": [{
                    "statement": (
                        "every glossary definition is traceable to AUTHORITY.md"),
                    "invariant_type": "correctness",
                    "domain_ids": contract["domains"],
                    "subsystem_ids": ["domain-quantum-optics"],
                    "scope": {
                        "component": "glossary", "jurisdiction": None,
                        "product_class": "research-note", "environment": "local",
                        "version_range": "1", "effective_period": stamp[:10],
                    },
                    "consequence_class": "ordinary",
                    "failure": "an unsupported definition is published",
                    "authority_requirements": ["repository-evidence"],
                    "supporting_source_keys": ["authority"],
                    "contradicting_source_keys": [],
                    "applicability_evidence": [
                        "topic, source, and verification scope match"],
                    "required_real_medium": "rendered glossary inspection",
                    "acceptance_target": "every definition has one source citation",
                    "as_of": stamp, "revalidate_by": future,
                    "revision_identity": "1",
                }],
            },
        }

        authored = loom_orchestrator.author(
            action["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        self.assertIn("domain-discovery.json", authored["files"])
        self.assertEqual([], authored["diagnostics"])
        bundle = json.loads(
            (self.repo / "plans" / "domain-discovery.json").read_text(
                encoding="utf-8"))
        self.assertEqual("gate-ready", bundle["discovery"]["status"])
        self.assertNotIn("content", bundle["sources"][0])
        self.assertEqual(
            hashlib.sha256((self.repo / "AUTHORITY.md").read_bytes()).hexdigest(),
            bundle["sources"][0]["content_sha256"])
        self.assertEqual(
            "loom-runtime-repository-read",
            bundle["sources"][0]["retrieval_method"])
        self.assertRegex(bundle["invariants"][0]["invariant_id"], r"^inv-")
        report = loom_lint.lint(
            self.repo / "plans", repo_path=self.repo,
            enforce_lifecycle=False, check_repo_state=False)
        self.assertEqual([], report.findings)
        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        self.assertEqual([], loom_gate.verify(
            self.repo / "plans", self.repo))
        self.assertIn(
            "implementation is not authorized",
            loom_gate.verify(
                self.repo / "plans", self.repo, require_authorized=True))

    def test_unknown_domain_semantics_cannot_mint_missing_authority(self):
        request = (
            "Plan a quantum optics glossary research note in src/app.py. "
            "Use this terminology.")
        action = loom_orchestrator.invoke(
            request=request,
            cwd=self.repo, home=self.home, install_root=self.installed)
        contract = action["plan_contract"]
        self.assertTrue(action["semantic_draft_shape"]["domain_evidence_required"])
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        evidence = {
            "retrieval_rounds": 0,
            "answers": {
                key: "Bounded test answer."
                for key, _question in loom_domain_discovery.QUESTIONS
            },
            "sources": [{
                "key": "owner", "title": "Owner statement",
                "locator": "receipt:owner-statement",
                "locator_visibility": "encrypted-private",
                "publisher": "Owner", "source_class": "owner-attestation",
                "content": "Use this terminology.",
                "retrieval_method": "direct owner statement",
                "document_id": "owner-statement", "version": None,
                "published_at": None, "effective_at": None,
                "revalidate_by": None, "jurisdiction": None,
                "product_class": "research-note", "environment": "local",
                "currentness": "current", "ambiguity": None,
            }],
            "invariants": [{
                "statement": "definitions must follow primary research",
                "invariant_type": "correctness",
                "domain_ids": contract["domains"], "subsystem_ids": [],
                "scope": {
                    "component": "glossary", "jurisdiction": None,
                    "product_class": "research-note", "environment": "local",
                    "version_range": None, "effective_period": None,
                },
                "consequence_class": "ordinary",
                "failure": "an unsupported definition is published",
                "authority_requirements": ["primary-research"],
                "supporting_source_keys": ["owner"],
                "contradicting_source_keys": [],
                "applicability_evidence": ["owner statement names the topic"],
                "required_real_medium": "rendered glossary inspection",
                "acceptance_target": "every definition has one citation",
                "as_of": None, "revalidate_by": None,
                "revision_identity": None,
            }],
        }
        with self.assertRaisesRegex(
                loom_plan_author.PlanAuthorError, "missing authority"):
            loom_plan_author._semantic_domain_bundle(
                evidence, contract, now=now, repo=self.repo, request=request)

    def test_owner_defined_no_io_constraint_is_correctness_without_retry(self):
        _write(
            self.repo / "AUTHORITY.md",
            "The local CLI must not access the network or write files.\n")
        request = (
            "Plan a fictional local CLI in src/app.py. Follow AUTHORITY.md exactly.")
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = action["plan_contract"]
        self.assertIn(
            "bounded prohibitions on network access",
            action["semantic_draft_shape"]["domain_invariant_type_guidance"][
                "correctness"])
        self.assertIn(
            "pre-existing sealed governing-authority receipt",
            action["semantic_draft_shape"]["domain_invariant_type_guidance"]["safety"])
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        evidence = {
            "retrieval_rounds": 0,
            "answers": {
                key: "Bound to AUTHORITY.md and a real local process observation."
                for key, _question in loom_domain_discovery.QUESTIONS
            },
            "sources": [{
                "key": "authority", "title": "Repository authority",
                "locator": "AUTHORITY.md", "locator_visibility": "public",
                "publisher": "Repository", "source_class": "repository",
                "content": None, "retrieval_method": "runtime repository read",
                "document_id": "AUTHORITY.md", "version": "1",
                "published_at": None, "effective_at": None,
                "revalidate_by": None, "jurisdiction": None,
                "product_class": "local-cli", "environment": "local",
                "currentness": "current", "ambiguity": None,
            }],
            "invariants": [{
                "statement": "the local CLI never accesses the network or writes files",
                "invariant_type": "correctness",
                "domain_ids": contract["domains"],
                "subsystem_ids": [
                    f"domain-{domain}" for domain in contract["domains"]],
                "scope": {
                    "component": "local-cli", "jurisdiction": None,
                    "product_class": "local-cli", "environment": "local",
                    "version_range": "1", "effective_period": None,
                },
                "consequence_class": "material",
                "failure": "the CLI performs an undeclared external side effect",
                "authority_requirements": ["repository-evidence"],
                "supporting_source_keys": ["authority"],
                "contradicting_source_keys": [],
                "applicability_evidence": [
                    "the request names AUTHORITY.md as governing"],
                "required_real_medium": "isolated real-process observation",
                "acceptance_target": "no network or filesystem mutation is observed",
                "as_of": None, "revalidate_by": None,
                "revision_identity": "1",
            }],
        }
        bundle = loom_plan_author._semantic_domain_bundle(
            evidence, contract, now=now, repo=self.repo, request=request)
        self.assertEqual("gate-ready", bundle["discovery"]["status"])
        self.assertEqual("correctness", bundle["invariants"][0]["invariant_type"])

        safety = json.loads(json.dumps(evidence))
        safety["invariants"][0]["invariant_type"] = "safety"
        with self.assertRaises(loom_plan_author.PlanAuthorError) as caught:
            loom_plan_author._semantic_domain_bundle(
                safety, contract, now=now, repo=self.repo, request=request)
        self.assertEqual("DOMAIN_EVIDENCE_NOT_READY", caught.exception.code)
        self.assertEqual(
            "SAFETY_AUTHORITY_REQUIRED",
            caught.exception.diagnostics[0]["code"])

    def test_unknown_domain_repository_source_is_runtime_bound(self):
        _write(self.repo / "AUTHORITY.md", "canonical source bytes\n")
        request = (
            "Plan a quantum optics glossary in src/app.py using AUTHORITY.md.")
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = action["plan_contract"]
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        evidence = {
            "retrieval_rounds": 0,
            "answers": {
                key: "Bounded answer."
                for key, _question in loom_domain_discovery.QUESTIONS},
            "sources": [{
                "key": "authority", "title": "Repository authority",
                "locator": "AUTHORITY.md", "locator_visibility": "public",
                "publisher": "Agent claim", "source_class": "repository",
                "content": "agent-authored summary",
                "retrieval_method": "agent claim", "document_id": "agent claim",
                "version": None, "published_at": None, "effective_at": None,
                "revalidate_by": None, "jurisdiction": None,
                "product_class": None, "environment": None,
                "currentness": "current", "ambiguity": None,
            }],
            "invariants": [],
        }
        with self.assertRaisesRegex(
                loom_plan_author.PlanAuthorError, "runtime-read"):
            loom_plan_author._semantic_domain_bundle(
                evidence, contract, now=now, repo=self.repo, request=request)

    def test_unknown_domain_cannot_assert_executed_observation(self):
        request = "Plan a quantum optics glossary in src/app.py."
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = action["plan_contract"]
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        evidence = {
            "retrieval_rounds": 0,
            "answers": {
                key: "Bounded answer."
                for key, _question in loom_domain_discovery.QUESTIONS},
            "sources": [{
                "key": "observation", "title": "Claimed execution",
                "locator": "receipt:claimed",
                "locator_visibility": "encrypted-private",
                "publisher": "Agent", "source_class": "executed-observation",
                "content": "A test allegedly ran.",
                "retrieval_method": "agent claim", "document_id": "claimed",
                "version": None, "published_at": None, "effective_at": None,
                "revalidate_by": None, "jurisdiction": None,
                "product_class": None, "environment": None,
                "currentness": "current", "ambiguity": None,
            }],
            "invariants": [],
        }
        with self.assertRaisesRegex(
                loom_plan_author.PlanAuthorError, "unsupported"):
            loom_plan_author._semantic_domain_bundle(
                evidence, contract, now=now, repo=self.repo, request=request)

    def test_medium_semantic_budget_is_machine_enforced(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = action["plan_contract"]
        self.assertEqual(5, contract["semantic_draft_limits"]["tasks"]["maximum_items"])
        draft = {
            "schema_version": 1, "title": "Bounded accounting change",
            "summary": "Plan one accounting change in src/app.py.",
            "assumptions": [], "decisions": [],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Bounded accounting change",
                "outcome": "Preserve balanced postings.",
                "tasks": [f"Task {index}" for index in range(6)],
                "acceptance": ["`python -m unittest` exits 0."],
                "negative_acceptance": ["an unbalanced posting is rejected"],
                "out_of_scope": ["Tax policy."],
                "escalation": ["Stop if another component changes."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }
        with self.assertRaisesRegex(
                loom_plan_author.PlanAuthorError, "sealed semantic limit"):
            loom_plan_author.validate_draft(
                draft, contract, now=dt.datetime.now(dt.timezone.utc))

    def test_machine_authoring_preserves_compact_tier_s_path(self):
        request = "Plan a tiny Python command-line greeting flag in src/app.py."
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("S", action["tier"])
        contract = action["plan_contract"]
        self.assertTrue(contract["semantic_draft_limits"]["copy_current_facts_exactly"])
        self.assertEqual(
            3, contract["semantic_draft_limits"]["tasks"]["maximum_items"])
        self.assertEqual(
            1, contract["semantic_draft_limits"]["touches"]["minimum_items"])
        self.assertEqual(
            0, contract["semantic_draft_limits"]["assumptions"]["minimum_items"])
        self.assertTrue(any(
            "Every work_order must declare at least one touches entry" in rule
            for rule in action["semantic_draft_shape"]["rules"]))
        draft = {
            "schema_version": 1,
            "title": "Add one greeting flag",
            "summary": "Add one bounded CLI greeting flag in src/app.py.",
            "assumptions": [], "decisions": [],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped CLI adapter",
            } for item in contract["current_facts"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Add greeting flag",
                "outcome": "The CLI accepts one greeting flag without changing other behavior.",
                "tasks": ["Implement the one flag in src/app.py."],
                "acceptance": [
                    "`python -m unittest` exits 0 and the new flag prints one greeting."],
                "negative_acceptance": [
                    "an unknown flag exits nonzero without normal output"],
                "out_of_scope": ["Packaging and architecture changes."],
                "escalation": ["Stop if another component must change."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }

        authored = loom_orchestrator.author(
            action["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual([".loom-small-lifecycle.json", "WO-001.md"], authored["files"])
        self.assertEqual(
            [], loom_lint.lint(
                self.repo / "plans", repo_path=self.repo).errors)
        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        self.assertEqual([], loom_gate.verify_small(
            self.repo / "plans" / ".loom-small-lifecycle.json"))
        self.assertEqual(
            [], loom_lint.lint(
                self.repo / "plans", repo_path=self.repo).errors)
        compact_wo = self.repo / "plans" / "WO-001.md"
        compact_wo.write_text(
            compact_wo.read_text(encoding="utf-8").replace(
                "Add greeting flag", "Tampered greeting flag", 1),
            encoding="utf-8")
        self.assertTrue(
            loom_lint.lint(
                self.repo / "plans", repo_path=self.repo).errors)

    def test_machine_authoring_rejects_malformed_draft_without_replacing_seed(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = self.repo / "plans"
        before = loom_orchestrator._pack_hash(pack)
        malformed = {
            "schema_version": 1, "title": "Bad", "summary": "Bad",
            "assumptions": [], "decisions": [], "current_facts": [],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [], "domain_evidence": None,
        }

        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.author(
                action["action_path"], malformed, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("PLAN_DRAFT_INVALID", caught.exception.code)
        self.assertEqual(before, loom_orchestrator._pack_hash(pack))
        self.assertEqual(
            ["MANIFEST.md", "lifecycle.json"],
            sorted(path.relative_to(pack).as_posix()
                   for path in pack.rglob("*") if path.is_file()))
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertEqual([], list(self.repo.glob(".loom-plan-backup-*")))

    def test_machine_authoring_runs_final_contract_validation_before_activation(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = self.repo / "plans"
        before = loom_orchestrator._pack_hash(pack)
        contract = action["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Preserve double-entry correctness",
            "summary": "Plan one bounded accounting change in src/app.py.",
            "assumptions": [], "decisions": [],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped accounting adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Preserve double-entry correctness",
                "outcome": "The requested change preserves balanced posting.",
                "tasks": ["Implement the bounded change in src/app.py."],
                "acceptance": ["The accounting test suite exits 0."],
                "negative_acceptance": [
                    "an unbalanced posting is rejected before any write"],
                "out_of_scope": ["Tax-policy and migration changes."],
                "escalation": ["Stop if a second component must change."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }
        original_validate = loom_orchestrator._validate_authored_plan

        def reject_staged(candidate_action, *, pack_override=None):
            if pack_override is not None:
                raise loom_orchestrator.OrchestratorError(
                    "PLAN_CONTRACT_MISMATCH",
                    "injected final contract validation failure")
            return original_validate(candidate_action)

        with mock.patch.object(
                loom_orchestrator, "_validate_authored_plan",
                side_effect=reject_staged), \
                self.assertRaisesRegex(
                    loom_orchestrator.OrchestratorError,
                    "injected final contract validation failure"):
            loom_orchestrator.author(
                action["action_path"], draft, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual(before, loom_orchestrator._pack_hash(pack))
        self.assertEqual(
            ["MANIFEST.md", "lifecycle.json"],
            sorted(path.relative_to(pack).as_posix()
                   for path in pack.rglob("*") if path.is_file()))
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertEqual([], list(self.repo.glob(".loom-plan-backup-*")))

    def test_machine_authoring_refuses_a_warning_before_activation(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = self.repo / "plans"
        before = loom_orchestrator._pack_hash(pack)
        contract = action["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Preserve double-entry correctness",
            "summary": "Plan one bounded accounting change in src/app.py.",
            "assumptions": [], "decisions": [],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped accounting adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Preserve double-entry correctness",
                "outcome": "The requested change preserves balanced posting.",
                "tasks": ["Implement the bounded change in src/app.py."],
                "acceptance": ["The accounting test suite exits 0."],
                "negative_acceptance": [
                    "an unbalanced posting is rejected before any write"],
                "out_of_scope": ["Tax-policy and migration changes."],
                "escalation": ["Stop if a second component must change."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }
        original_lint = loom_lint.lint

        def warning_lint(*args, **kwargs):
            report = original_lint(*args, **kwargs)
            report.add(
                "WARN", "W99", Path(args[0]) / "MANIFEST.md", 1,
                "injected machine-author warning")
            return report

        with mock.patch.object(loom_plan_author.loom_lint, "lint", warning_lint), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.author(
                action["action_path"], draft, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("PLAN_AUTHOR_VALIDATION_FAILED", caught.exception.code)
        self.assertIn("1 warning", str(caught.exception))
        self.assertEqual(before, loom_orchestrator._pack_hash(pack))
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertEqual([], list(self.repo.glob(".loom-plan-backup-*")))

    def test_machine_authoring_rejects_world_drift_before_any_plan_write(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = self.repo / "plans"
        before = loom_orchestrator._pack_hash(pack)
        _write(self.repo / "unexpected.txt", "drift\n")

        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.author(
                action["action_path"], {}, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("TARGET_DRIFT", caught.exception.code)
        self.assertEqual(before, loom_orchestrator._pack_hash(pack))

    def test_plan_activation_restores_the_seed_if_second_rename_fails(self):
        pack = self.root / "activation-target" / "plans"
        transaction_id = "a" * 32
        stage = self.root / "activation-target" / (
            ".loom-plan-stage-" + transaction_id)
        transaction = self.root / "activation-target" / (
            ".loom-plan-transaction-action.json")
        _write(pack / "MANIFEST.md", "seed\n")
        _write(stage / "WO-001.md", "candidate\n")
        before = loom_reliability.exact_tree_manifest(pack)
        after = loom_reliability.exact_tree_manifest(stage)
        real_replace = os.replace
        def fail_second(source, target):
            if Path(source).resolve() == stage.resolve() \
                    and Path(target).resolve() == pack.resolve():
                raise OSError("injected activation failure")
            return real_replace(source, target)

        with mock.patch.object(os, "replace", side_effect=fail_second):
            with self.assertRaises(loom_plan_author.PlanAuthorError):
                loom_plan_author._safe_replace_pack(
                    pack, stage, transaction, before=before, after=after,
                    transaction_id=transaction_id)

        self.assertEqual("seed\n", (pack / "MANIFEST.md").read_text(encoding="utf-8"))
        self.assertFalse(stage.exists())
        self.assertFalse(transaction.exists())
        self.assertFalse(list(pack.parent.glob(".loom-plan-backup-*")))

    def test_plan_activation_reconciles_process_death_after_source_move(self):
        target = self.root / "source-move-recovery"
        pack = target / "plans"
        transaction_id = "b" * 32
        stage = target / (".loom-plan-stage-" + transaction_id)
        backup = target / (".loom-plan-backup-" + transaction_id)
        transaction = target / ".loom-plan-transaction-action.json"
        _write(pack / "MANIFEST.md", "seed\n")
        _write(stage / "WO-001.md", "candidate\n")
        before = loom_reliability.exact_tree_manifest(pack)
        after = loom_reliability.exact_tree_manifest(stage)
        loom_plan_author._write_transaction(
            transaction, loom_plan_author._transaction_value(
                transaction_id, "prepared", before, after))
        os.replace(pack, backup)

        result = loom_plan_author.reconcile(pack, transaction)

        self.assertEqual("rolled-back", result["status"])
        self.assertEqual("seed\n", (pack / "MANIFEST.md").read_text(encoding="utf-8"))
        self.assertFalse(stage.exists())
        self.assertFalse(backup.exists())
        self.assertFalse(transaction.exists())

    def test_plan_activation_reconciles_process_death_after_candidate_move(self):
        target = self.root / "candidate-move-recovery"
        pack = target / "plans"
        transaction_id = "c" * 32
        stage = target / (".loom-plan-stage-" + transaction_id)
        backup = target / (".loom-plan-backup-" + transaction_id)
        transaction = target / ".loom-plan-transaction-action.json"
        _write(pack / "MANIFEST.md", "seed\n")
        _write(stage / "WO-001.md", "candidate\n")
        before = loom_reliability.exact_tree_manifest(pack)
        after = loom_reliability.exact_tree_manifest(stage)
        loom_plan_author._write_transaction(
            transaction, loom_plan_author._transaction_value(
                transaction_id, "source-moved", before, after))
        os.replace(pack, backup)
        os.replace(stage, pack)

        result = loom_plan_author.reconcile(pack, transaction)

        self.assertEqual("activated", result["status"])
        self.assertEqual(
            "candidate\n", (pack / "WO-001.md").read_text(encoding="utf-8"))
        self.assertFalse(backup.exists())
        self.assertFalse(transaction.exists())

    def test_plan_activation_finishes_interrupted_receipt_owned_cleanup(self):
        target = self.root / "cleanup-recovery"
        pack = target / "plans"
        transaction_id = "d" * 32
        stage = target / (".loom-plan-stage-" + transaction_id)
        backup = target / (".loom-plan-backup-" + transaction_id)
        transaction = target / ".loom-plan-transaction-action.json"
        _write(pack / "MANIFEST.md", "seed\n")
        _write(pack / "old.md", "old\n")
        _write(stage / "WO-001.md", "candidate\n")
        before = loom_reliability.exact_tree_manifest(pack)
        after = loom_reliability.exact_tree_manifest(stage)
        os.replace(pack, backup)
        os.replace(stage, pack)
        (backup / "old.md").unlink()
        loom_plan_author._write_transaction(
            transaction, loom_plan_author._transaction_value(
                transaction_id, "cleanup-backup", before, after))

        result = loom_plan_author.reconcile(pack, transaction)

        self.assertEqual("activated", result["status"])
        self.assertFalse(backup.exists())
        self.assertFalse(transaction.exists())

    def test_plan_activation_refuses_changed_recovery_namespace(self):
        target = self.root / "changed-recovery"
        pack = target / "plans"
        transaction_id = "e" * 32
        stage = target / (".loom-plan-stage-" + transaction_id)
        transaction = target / ".loom-plan-transaction-action.json"
        _write(pack / "MANIFEST.md", "seed\n")
        _write(stage / "WO-001.md", "candidate\n")
        before = loom_reliability.exact_tree_manifest(pack)
        after = loom_reliability.exact_tree_manifest(stage)
        loom_plan_author._write_transaction(
            transaction, loom_plan_author._transaction_value(
                transaction_id, "prepared", before, after))
        _write(stage / "unowned.md", "changed\n")

        with self.assertRaisesRegex(
                loom_plan_author.PlanAuthorError, "no longer matches"):
            loom_plan_author.reconcile(pack, transaction)

        self.assertEqual("seed\n", (pack / "MANIFEST.md").read_text(encoding="utf-8"))
        self.assertTrue((stage / "unowned.md").is_file())
        self.assertTrue(transaction.is_file())

    def test_non_git_plan_reports_missing_authored_contract_before_route_drift(self):
        """Loom's own seed pack must not turn premature completion into target drift."""
        non_git = self.root / "empty-non-git-target"
        non_git.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        opened = self.cli(
            "invoke", "--request", request, "--cwd", non_git,
            "--home", self.home, "--install-root", self.installed,
            "--timeout-seconds", "300")
        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        action = json.loads(opened.stdout)
        self.assertEqual("action-required", action["status"])
        self.assertEqual("plan", action["intent"])

        premature = self.cli("complete", "--action", action["action_path"])
        self.assertNotEqual(0, premature.returncode, premature.stdout)
        error = json.loads(premature.stdout)
        self.assertEqual("PLAN_CONTRACT_MISMATCH", error["code"])
        self.assertNotEqual("TARGET_DRIFT", error["code"])

    def test_duplicate_pending_plan_reuses_exact_frontier_in_unchanged_world(self):
        non_git = self.root / "duplicate-hook-target"
        non_git.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        first = loom_orchestrator.invoke(
            request=request, cwd=non_git, home=self.home,
            install_root=self.installed,
            transport_invocation_id="90a28883-6a01-5ffd-a9d9-4da1f69f1e77")
        second = loom_orchestrator.invoke(
            request=request, cwd=non_git, home=self.home,
            install_root=self.installed,
            transport_invocation_id="90a28883-6a01-5ffd-a9d9-4da1f69f1e77")
        self.assertEqual(first["action_id"], second["action_id"])
        self.assertEqual(first["action_path"], second["action_path"])
        self.assertEqual(first["plan_contract"], second["plan_contract"])
        self.assertNotIn("prior_recovery", second)

    def test_same_pending_plan_reuses_frontier_across_new_transport_request_ids(self):
        target = self.root / "duplicate-standard-target"
        target.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        first = loom_orchestrator.invoke(
            request=request, cwd=target, home=self.home,
            install_root=self.installed,
            transport_invocation_id="90a28883-6a01-5ffd-a9d9-4da1f69f1e70")
        second = loom_orchestrator.invoke(
            request=request, cwd=target, home=self.home,
            install_root=self.installed,
            transport_invocation_id="90a28883-6a01-5ffd-a9d9-4da1f69f1e71")

        self.assertEqual(first["action_id"], second["action_id"])
        self.assertEqual(first["action_path"], second["action_path"])
        self.assertEqual(first["plan_contract"], second["plan_contract"])
        self.assertNotIn("prior_recovery", second)

    def test_verified_hook_action_resolves_once_without_creating_another_action(self):
        target = self.root / "verified-resolve-target"
        target.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        capabilities = {
            key: key in {"invoke", "complete", "cancel", "status", "markdown"}
            for key in loom_adapter_protocol.CAPABILITY_KEYS
        }
        source = {
            "schema_version": 2, "message_type": "invoke",
            "request_id": "verified-resolve-source",
            "request": request, "cwd": str(target),
        }
        envelope = loom_adapter_protocol.request_envelope(
            source, {"id": "codex", "version": "test"},
            adapter={"id": "codex-prompt-hook", "version": "1.0.0"},
            capabilities=capabilities)
        opened = loom_orchestrator.invoke(
            request=request, cwd=target, home=self.home,
            install_root=self.installed,
            transport_invocation_id=loom_orchestrator._transport_invocation_id(envelope),
            assurance=envelope["assurance"])
        action_path = Path(opened["action_path"])
        action_sha256 = hashlib.sha256(action_path.read_bytes()).hexdigest()

        resolved = loom_orchestrator.resolve(
            request=request, cwd=target, action_path=action_path,
            action_sha256=action_sha256, home=self.home,
            install_root=self.installed)

        self.assertEqual(opened["action_id"], resolved["action_id"])
        self.assertEqual(opened["plan_contract"], resolved["plan_contract"])
        self.assertEqual("verified", resolved["assurance"]["mode"])
        self.assertEqual(
            1, len(list(action_path.parent.glob("????????-????-????-????-????????????.json"))))

        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.resolve(
                request=request, cwd=target, action_path=action_path,
                action_sha256="0" * 64, home=self.home,
                install_root=self.installed)
        self.assertEqual("ACTION_CORRUPT", caught.exception.code)

        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.resolve(
                request=request + " changed", cwd=target, action_path=action_path,
                action_sha256=action_sha256, home=self.home,
                install_root=self.installed)
        self.assertEqual("REQUEST_IDENTITY_INVALID", caught.exception.code)

        (target / "world-drift.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.resolve(
                request=request, cwd=target, action_path=action_path,
                action_sha256=action_sha256, home=self.home,
                install_root=self.installed)
        self.assertEqual("TARGET_DRIFT", caught.exception.code)

    def test_standard_action_cannot_be_relabelled_as_verified_by_resolve(self):
        target = self.root / "standard-resolve-target"
        target.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        opened = loom_orchestrator.invoke(
            request=request, cwd=target, home=self.home,
            install_root=self.installed)
        action_path = Path(opened["action_path"])
        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.resolve(
                request=request, cwd=target, action_path=action_path,
                action_sha256=hashlib.sha256(action_path.read_bytes()).hexdigest(),
                home=self.home, install_root=self.installed)
        self.assertEqual("HOST_UNVERIFIED", caught.exception.code)

    def test_same_plan_request_after_world_change_creates_new_frontier(self):
        non_git = self.root / "changed-world-target"
        non_git.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        first = loom_orchestrator.invoke(
            request=request, cwd=non_git, home=self.home,
            install_root=self.installed)
        (non_git / "new-requirement.txt").write_text("changed\n", encoding="utf-8")
        second = loom_orchestrator.invoke(
            request=request, cwd=non_git, home=self.home,
            install_root=self.installed)
        self.assertNotEqual(first["action_id"], second["action_id"])
        self.assertIn("prior_recovery", second)

    def test_replayed_transport_id_after_world_change_fails_closed(self):
        non_git = self.root / "replayed-transport-target"
        non_git.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        transport_id = "90a28883-6a01-5ffd-a9d9-4da1f69f1e78"
        loom_orchestrator.invoke(
            request=request, cwd=non_git, home=self.home,
            install_root=self.installed,
            transport_invocation_id=transport_id)
        (non_git / "changed.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "repeated transport operation") as caught:
            loom_orchestrator.invoke(
                request=request, cwd=non_git, home=self.home,
                install_root=self.installed,
                transport_invocation_id=transport_id)
        self.assertEqual("TARGET_DRIFT", caught.exception.code)

    def test_placeholder_plan_asks_one_scope_question_without_creating_pack(self):
        for index, prefix in enumerate((
                "",
                "[$loom:loom](C:\\Users\\owner\\.codex\\skills\\loom\\SKILL.md) ")):
            with self.subTest(prefix=prefix):
                target = self.root / f"placeholder-plan-target-{index}"
                target.mkdir()

                result = loom_orchestrator.invoke(
                    request=prefix + "Plan a very simple test project.",
                    cwd=target, home=self.home, install_root=self.installed)

                self.assertEqual("blocked", result["status"])
                self.assertEqual("plan_scope_decision_required", result["code"])
                self.assertEqual("S", result["tier"])
                self.assertIn("kind of project", result["user_message"])
                self.assertIn(
                    "What kind of project should Loom plan",
                    result["block_reason"]["next_action"])
                self.assertIn(
                    "Loom needs one project detail",
                    result["owner_message"]["human"])
                self.assertNotIn(
                    "Follow the receipt", result["owner_message"]["human"])
                self.assertFalse((target / "plans").exists())

    def test_missing_unknown_domain_authority_asks_once_without_creating_pack(self):
        target = self.root / "missing-domain-authority"
        target.mkdir()
        result = loom_orchestrator.invoke(
            request=(
                "Plan a release-ready calibration procedure for an Arcturus-Z9 "
                "cryogenic flux sensor. The sensor is fictional and no manufacturer "
                "specifications are available. Planning only."),
            cwd=target, home=self.home, install_root=self.installed)
        self.assertEqual("blocked", result["status"])
        self.assertEqual("domain_authority_required", result["code"])
        self.assertIn("governing specification", result["user_message"])
        self.assertFalse((target / "plans").exists())

    def test_partial_project_inspection_routes_but_cannot_seal_g1(self):
        _write(self.repo / ".gitignore", "unknown-output/\n")
        subprocess.run(["git", "-C", str(self.repo), "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm",
                        "ignore ambiguous output"], check=True)
        _write(self.repo / "unknown-output" / "payload.bin", "ambiguous\n")

        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", opened["status"])
        self.assertEqual("L", opened["tier"])
        self.assertEqual(
            "partial-requires-discovery",
            opened["plan_contract"]["project_inspection"]["state"])
        self.assertIn("project-inspection", opened["plan_contract"]["completion_gates"])
        self.assertEqual(
            "unknown-output",
            opened["plan_contract"]["inspection_obligations"][0]["path"])
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "PROJECT_INSPECTION_INCOMPLETE"):
            loom_orchestrator.complete(opened["action_path"])

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
            {"skill/loom/SKILL.md", "START-HERE.md", "contracts/cache-classes-v1.json"},
            {item["path"] for item in action["context_manifest"]["entries"]})
        self.assertEqual(3, action["context_manifest"]["load_metrics"]["disk_reads"])
        self.assertEqual(3, action["context_manifest"]["load_metrics"]["cache_hits"])

        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            result["plan_contract"])
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
            "memory_effects": [{
                "memory_id": "00000000-0000-4000-8000-000000000999",
                "status": "applied-unverified", "decision_target": "host-outcome",
                "intended_effect": "test invalid reference", "evidence_id": None,
                "serious_harm": False}],
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
            "memory_effects": [{
                "memory_id": preference["id"], "status": "applied-unverified",
                "decision_target": "host-outcome", "intended_effect": "apply preference",
                "evidence_id": None, "serious_harm": False}],
            "metrics": {}, "preference_observations": [], "artifact_usage": [],
        }), encoding="utf-8")
        completed = self.cli(
            "complete", "--action", result["action_path"], "--usage", usage,
            "--result", host_outcome)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        recorded = loom_memory.inspect_record(
            self.home, instance_id, preference["id"])
        self.assertEqual(1, recorded["application_count"])
        # This fixture explicitly exercises the test-only legacy adapter. The production vault
        # path uses content-bound memory_effects and has separate Phase 2 regression coverage.
        self.assertEqual(1, recorded["helped_count"])

    def test_v11_action_envelope_hides_request_and_authenticates_owner_runtime(self):
        opened = self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, opened.returncode, opened.stdout + opened.stderr)
        result = json.loads(opened.stdout)
        path = Path(result["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        crypto = TestCrypto()
        owner = action["instance_id"]
        loom_orchestrator._write_action(path, action, (crypto, owner))
        raw = path.read_bytes()
        self.assertNotIn(self.request.encode("utf-8"), raw)

        class FakeVault:
            def identity(self):
                return {"owner_vault_id": owner}

        with mock.patch.object(loom_orchestrator, "_vault_helper", return_value=Path("helper")), \
                mock.patch.object(
                    loom_orchestrator.loom_owner, "open_owner_vault",
                    return_value=(FakeVault(), crypto)):
            _path, restored, security = loom_orchestrator._read_action(
                path, owner_home=self.home, install_root=self.installed)
            self.assertEqual(self.request, restored["request"])
            self.assertIsNotNone(security)
            with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
                loom_orchestrator._read_action(
                    path, owner_home=self.root / "wrong-home",
                    install_root=self.installed)
            self.assertEqual("ACTION_PATH_MISMATCH", raised.exception.code)

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
        self.assertEqual("unknown", action["plan_contract"]["domain_route"]["coverage_state"])
        self.assertTrue(action["plan_contract"]["domain_discovery"]["required"])
        self.assertEqual("domain-discovery.json",
                         action["plan_contract"]["domain_discovery"]["machine_bundle"])
        self.assertEqual(action["plan_contract"]["survey_hash"],
                         action["plan_contract"]["target_fingerprint"])
        self.assertTrue((self.repo / "plans" / "MANIFEST.md").is_file())
        self.assertFalse((self.repo / "plans" / ".loom-small-lifecycle.json").exists())

    def test_named_opaque_domain_survives_known_cli_routing(self):
        _write(
            self.repo / "AUTHORITY.md",
            "# QuantaLex authority\n\n"
            "Calibration output must preserve the declared unit and tolerance.\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "AUTHORITY.md"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "add domain authority"],
            check=True)

        opened = loom_orchestrator.invoke(
            request=(
                "Plan a release-ready Python CLI for the fictional QuantaLex "
                "calibration engine. Follow the committed AUTHORITY.md exactly. "
                "Planning only; do not implement."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", opened["status"])
        self.assertEqual("M", opened["tier"])
        self.assertEqual(["cli", "unclassified"], opened["domains"])
        self.assertEqual(
            "partial", opened["plan_contract"]["domain_route"]["coverage_state"])
        self.assertTrue(opened["plan_contract"]["domain_discovery"]["required"])
        self.assertTrue((self.repo / "plans" / "MANIFEST.md").is_file())
        self.assertFalse((self.repo / "plans" / ".loom-small-lifecycle.json").exists())
        contract = opened["plan_contract"]
        stamp = dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0).isoformat().replace("+00:00", "Z")
        future = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        draft = {
            "schema_version": 1,
            "title": "QuantaLex calibration CLI",
            "summary": "Plan one authority-bound calibration command-line engine.",
            "assumptions": [],
            "decisions": [
                "Treat AUTHORITY.md as the governing repository source.",
            ],
            "current_facts": [{
                "domain": item["domain"],
                "fact": item["fact"],
                "source": "sealed project inspection and shipped adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0,
                "irreversible": False,
                "data_migration": False,
                "regulated": False,
            },
            "work_orders": [{
                "title": "Plan authority-bound calibration behavior",
                "outcome": "Every calibration result preserves its declared unit and tolerance.",
                "tasks": [
                    "Define the bounded CLI input and output contract in src/app.py.",
                    "Verify unit and tolerance preservation against AUTHORITY.md.",
                ],
                "acceptance": [
                    "A real CLI process proves the declared unit and tolerance are preserved.",
                ],
                "negative_acceptance": [
                    "a result with a changed unit or tolerance is rejected",
                ],
                "out_of_scope": ["Inventing rules absent from AUTHORITY.md."],
                "escalation": [
                    "Stop if AUTHORITY.md does not define an applicable calibration rule.",
                ],
                "touches": ["src/app.py"],
                "depends_on": [],
                "routing": "specialist",
                "size": "S",
            }],
            "domain_evidence": {
                "retrieval_rounds": 1,
                "answers": {
                    key: "Bound to AUTHORITY.md and a real CLI calibration observation."
                    for key, _question in loom_domain_discovery.QUESTIONS
                },
                "sources": [{
                    "key": "authority",
                    "title": "QuantaLex repository authority",
                    "locator": "AUTHORITY.md",
                    "locator_visibility": "public",
                    "publisher": "Repository",
                    "source_class": "repository",
                    "content": None,
                    "retrieval_method": "runtime repository read",
                    "document_id": "AUTHORITY.md",
                    "version": "1",
                    "published_at": stamp,
                    "effective_at": stamp,
                    "revalidate_by": future,
                    "jurisdiction": None,
                    "product_class": "calibration-engine",
                    "environment": "local",
                    "currentness": "current",
                    "ambiguity": None,
                }],
                "invariants": [{
                    "statement": (
                        "every calibration result preserves the declared unit and tolerance"),
                    "invariant_type": "correctness",
                    "domain_ids": contract["domains"],
                    "subsystem_ids": ["domain-cli", "domain-unclassified"],
                    "scope": {
                        "component": "calibration-engine",
                        "jurisdiction": None,
                        "product_class": "calibration-engine",
                        "environment": "local",
                        "version_range": "1",
                        "effective_period": stamp[:10],
                    },
                    "consequence_class": "material",
                    "failure": "a calibration result changes its declared unit or tolerance",
                    "authority_requirements": ["repository-evidence"],
                    "supporting_source_keys": ["authority"],
                    "contradicting_source_keys": [],
                    "applicability_evidence": [
                        "the request names the engine and AUTHORITY.md as governing",
                    ],
                    "required_real_medium": "real CLI calibration observation",
                    "acceptance_target": (
                        "the observed output retains the declared unit and tolerance"),
                    "as_of": stamp,
                    "revalidate_by": future,
                    "revision_identity": "1",
                }],
            },
        }
        authored = loom_orchestrator.author(
            opened["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual([], authored["diagnostics"])
        report = loom_lint.lint(
            self.repo / "plans", repo_path=self.repo,
            enforce_lifecycle=False, check_repo_state=False)
        self.assertEqual([], report.findings)
        completed = loom_orchestrator.complete(
            opened["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])

    def test_tier_s_capsule_overflow_promotes_before_pack_creation(self):
        original = loom_orchestrator._tier_s_host_capsule

        def force_small_overflow(contract):
            if contract["tier"] == "S":
                raise loom_orchestrator.OrchestratorError(
                    "TIER_PROMOTION_REQUIRED",
                    "complete Tier S decision context exceeds the host capsule bound")
            return original(contract)

        target = self.root / "capsule-promotion-target"
        target.mkdir()
        with mock.patch.object(
                loom_orchestrator, "_tier_s_host_capsule",
                side_effect=force_small_overflow):
            opened = loom_orchestrator.invoke(
                request="Plan a tiny Python command-line greeting tool.",
                cwd=target, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", opened["status"])
        self.assertEqual("M", opened["tier"])
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        self.assertIn(
            "tier-s-host-capsule-overflow",
            action["prepared"]["route_contract"]["evidence"])
        self.assertTrue((target / "plans" / "MANIFEST.md").is_file())
        self.assertFalse((target / "plans" / ".loom-small-lifecycle.json").exists())

    def test_research_plan_owner_message_uses_domain_consequence_and_plain_action(self):
        action = loom_orchestrator.invoke(
            request=(
                "Create a research and writing plan for a cited comparison of "
                "embedded databases, including source checks and review checkpoints. "
                "Do not build software."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual(["research"], action["domains"])
        self.assertEqual("M", action["tier"])
        self.assertEqual("ordinary", action["owner_message"]["consequence"])
        self.assertEqual(
            "Have the agent finish the plan, then review it before any project work starts.",
            action["owner_message"]["next_action"])
        self.assertNotIn("frontier", action["owner_message"]["human"].casefold())
        self.assertNotIn("coding", action["owner_message"]["human"].casefold())

    def test_explicit_etl_reconciliation_and_quarantine_are_sealed_obligations(self):
        action = loom_orchestrator.invoke(
            request=(
                "Plan a daily ETL pipeline that quarantines bad records and verifies "
                "row-count and reconciliation invariants. Do not implement."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        required = {
            item["invariant"] for item in
            action["plan_contract"]["required_domain_invariants"]
        }
        self.assertIn("quarantine and rejected-record disposition", required)
        self.assertIn("row-count and reconciliation controls", required)

    def test_plan_contract_preflight_failure_leaves_no_visible_pack(self):
        target = self.root / "preflight-failure-target"
        target.mkdir()
        with mock.patch.object(
                loom_orchestrator, "_make_plan_contract",
                side_effect=loom_orchestrator.OrchestratorError(
                    "PLAN_CONTRACT_INVALID", "seed-independent preflight failed")):
            with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
                loom_orchestrator.invoke(
                    request="Plan a tiny Python command-line greeting tool.",
                    cwd=target, home=self.home, install_root=self.installed)

        self.assertEqual("PLAN_CONTRACT_INVALID", caught.exception.code)
        self.assertFalse((target / "plans").exists())

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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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

    def test_planning_assignment_cannot_change_verification_under_a_new_digest(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        path = self.repo / "plans" / "planning-obligations.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["assignments"][0]["verification"]["oracle"] = "self assertion"
        body = dict(value); body.pop("assignment_digest")
        value["assignment_digest"] = loom_orchestrator.loom_domain_contract.digest(
            "planning-obligation-assignments-v1", body)
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "scope, evidence, or verification"):
            loom_orchestrator._validate_authored_plan(action)

    def test_multi_phase_program_requires_every_milestone_and_atom_assignment(self):
        request = (
            "Phase 8, Phase 9, and Phase 10 research is complete. Make three plans "
            "and then implement Phase 8 in the Loom agent runtime.")
        opened = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = opened["plan_contract"]
        pack = self.repo / "program-assignments"
        milestones = [item["id"] for item in contract["planning_intelligence"]
                      ["program"]["milestone_graph"]["milestones"]]
        atoms = [item for item in contract["planning_intelligence"]["atoms"]
                 if item["gate_effect"] != "none"]
        assignments = []
        by_work_order = {f"WO-{index + 1:03d}": [] for index in range(len(milestones))}
        for index, atom in enumerate(atoms):
            slot = index % len(milestones)
            work_order = f"WO-{slot + 1:03d}"
            by_work_order[work_order].append(atom["atom_id"])
            assignments.append({
                "atom_id": atom["atom_id"], "work_order": work_order,
                "milestone": milestones[slot],
                "verification": loom_orchestrator.loom_planning_intelligence.
                expanded_verification(contract["planning_intelligence"], atom)})
        assignments.sort(key=lambda item: item["atom_id"])
        for index, milestone in enumerate(milestones):
            identity = f"WO-{index + 1:03d}"
            obligations = ", ".join(sorted(by_work_order[identity]))
            _write(pack / "work-orders" / f"{identity}.md", f"""---
id: {identity}
title: Complete {milestone}
status: ready
depends_on: []
blocks: []
routing: strong-coding
size: S
touches: [src/{milestone}.py]
last_verified: {TODAY}
milestone: {milestone}
planning_obligations: [{obligations}]
---
""")
        body = {"schema_version": 1, "plan_contract_hash": contract["contract_hash"],
                "planning_intelligence_digest": contract["planning_intelligence"]
                ["intelligence_digest"], "program_digest": contract["planning_intelligence"]
                ["program"]["program_digest"], "assignments": assignments}
        _write(pack / "planning-obligations.json", json.dumps({
            **body, "assignment_digest": loom_orchestrator.loom_domain_contract.digest(
                "planning-obligation-assignments-v1", body)}, indent=2) + "\n")
        paths = sorted((pack / "work-orders").glob("WO-*.md"))
        loom_orchestrator._validate_planning_assignments(pack, contract, paths)
        _write(pack / "plan-contract.json", json.dumps(contract, indent=2) + "\n")
        downstream = loom_orchestrator._program_impact(pack, ["src/phase-8.py"])
        self.assertEqual(["phase-8", "phase-9", "phase-10"], downstream["affected"])
        isolated = loom_orchestrator._program_impact(pack, ["src/phase-10.py"])
        self.assertEqual(["phase-10"], isolated["affected"])
        self.assertEqual(["phase-8", "phase-9"], isolated["isolated"])
        broken = json.loads((pack / "planning-obligations.json").read_text(encoding="utf-8"))
        broken["assignments"] = [item for item in broken["assignments"]
                                 if item["milestone"] != "phase-10"]
        body = dict(broken); body.pop("assignment_digest")
        broken["assignment_digest"] = loom_orchestrator.loom_domain_contract.digest(
            "planning-obligation-assignments-v1", body)
        (pack / "planning-obligations.json").write_text(
            json.dumps(broken), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "incomplete|fully assigned"):
            loom_orchestrator._validate_planning_assignments(pack, contract, paths)

    def test_plan_contract_enforces_budget_and_work_order_topology(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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

    def test_external_action_path_is_rejected_before_content_is_read(self):
        outside = self.repo / "outside-action.json"
        outside.write_text("not json", encoding="utf-8")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as malformed:
            loom_orchestrator.cancel(
                outside, owner_home=self.home, install_root=self.installed)
        self.assertEqual("ACTION_PATH_MISMATCH", malformed.exception.code)

        outside.write_text("{}", encoding="utf-8")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as valid_json:
            loom_orchestrator.cancel(
                outside, owner_home=self.home, install_root=self.installed)
        self.assertEqual("ACTION_PATH_MISMATCH", valid_json.exception.code)
        self.assertEqual(malformed.exception.message, valid_json.exception.message)

    def test_rehashed_action_cannot_forge_continuation_authority(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        original_mode = action["continuation_authority"]["mode"]
        action["continuation_authority"]["mode"] = (
            "automatic" if original_mode != "automatic" else "decision-needed")
        self.assertNotEqual(
            original_mode, action["continuation_authority"]["mode"],
            "the adversarial fixture must actually change the authority mode")
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "continuation authority"):
            loom_orchestrator._read_action(path)

    def test_legacy_open_action_requires_fresh_preparation_but_terminal_is_readable(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        action["schema_version"] = loom_orchestrator.LEGACY_ACTION_SCHEMA_VERSION
        action.pop("pack_seed")
        action.pop("recovery_receipt")
        action.pop("assurance")
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "cannot resume") as raised:
            loom_orchestrator._read_action(path)
        self.assertEqual("ACTION_REPREPARE_REQUIRED", raised.exception.code)

        action["status"] = "completed"
        action["result"] = {"status": "completed", "code": "legacy-terminal"}
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")
        _path, restored, _security = loom_orchestrator._read_action(path)
        self.assertEqual("completed", restored["status"])

    def test_plan_contract_v4_terminal_is_readable_but_open_action_requires_reprepare(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        contract = dict(action["plan_contract"])
        contract.pop("project_id")
        contract.pop("semantic_draft_limits")
        contract["schema_version"] = (
            loom_orchestrator.LEGACY_PLAN_CONTRACT_SCHEMA_VERSION)
        contract["contract_hash"] = loom_orchestrator._hash({
            key: value for key, value in contract.items()
            if key != "contract_hash"
        })
        action["plan_contract"] = contract
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "cannot resume under plan-contract-v5") as raised:
            loom_orchestrator._read_action(path)
        self.assertEqual("ACTION_REPREPARE_REQUIRED", raised.exception.code)

        action["status"] = "completed"
        action["result"] = {"status": "completed", "code": "legacy-v4-terminal"}
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")
        _path, restored, _security = loom_orchestrator._read_action(path)
        self.assertEqual("completed", restored["status"])
        self.assertEqual(
            loom_orchestrator.LEGACY_PLAN_CONTRACT_SCHEMA_VERSION,
            restored["plan_contract"]["schema_version"])

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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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
                "memory_effects": [{
                    "memory_id": preference["id"], "status": "applied-unverified",
                    "decision_target": "host-outcome", "intended_effect": "apply preference",
                    "evidence_id": None, "serious_harm": False}],
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
                "memory_effects": [],
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
        self.assertEqual(1, action["plan_contract"]["schema_version"])
        self.assertNotIn("artifact_matrix", action["plan_contract"])
        self.assertLessEqual(len(json.dumps(
            action["plan_contract"], sort_keys=True, separators=(",", ":")).encode()), 4096)
        sealed = json.loads(Path(action["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual(15, len(sealed["plan_contract"]["artifact_matrix"]))
        _author_small_wo(self.repo / "plans", sealed["plan_contract"])
        completed = self.cli(
            "complete", "--action", action["action_path"])
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual("completed", result["status"])
        self.assertEqual("plan-complete", result["code"])
        self.assertEqual("plans/WO-001.md", result["owner_message"]["result_path"])
        self.assertIn("Open: plans/WO-001.md.", result["owner_message"]["human"])
        self.assertNotIn("MANIFEST.md", result["owner_message"]["human"])
        self.assertEqual("unavailable", result["usage"]["measurement_status"])
        self.assertEqual([], loom_gate.verify_small(
            self.repo / "plans" / ".loom-small-lifecycle.json"))
        self.assertFalse((self.repo / "plans" / "MANIFEST.md").exists())
        replayed = self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, replayed.returncode, replayed.stderr + replayed.stdout)
        replay = json.loads(replayed.stdout)
        self.assertEqual(result["receipt_hash"], replay["receipt_hash"])
        self.assertEqual(result["invocation_id"], replay["invocation_id"])
        self.assertEqual("plans/WO-001.md", replay["owner_message"]["result_path"])
        action_directory = Path(action["action_path"]).parent
        self.assertEqual(
            1, len(list(action_directory.glob(
                "????????-????-????-????-????????????.json"))))

    def test_tier_s_continue_preserves_cli_route_and_seals_real_change(self):
        request = "Plan a single-file CLI flag in src/app.py"
        opened = json.loads(self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        sealed = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        _author_small_wo(self.repo / "plans", sealed["plan_contract"])
        usage = self.root / "small-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 300, "cache_read_tokens": 50,
            "output_tokens": 150, "tool_tokens": 50, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)
        record = self.repo / "plans" / ".loom-small-lifecycle.json"
        lifecycle = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(loom_gate.SMALL_EVENT_ORDER[:2], [
            event["event"] for event in lifecycle["events"]])
        self.assertIn(
            "small lifecycle is not authorized",
            loom_gate.verify_small(record, require_authorized=True))

        continued = self.cli(
            "invoke", "--request", "Continue", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, continued.returncode, continued.stderr + continued.stdout)
        execute = json.loads(continued.stdout)
        self.assertEqual("execute", execute["intent"])
        self.assertEqual("S", execute["tier"])
        self.assertEqual(["cli"], execute["domains"])
        self.assertEqual("WO-001", execute["work_order"])
        lifecycle = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(loom_gate.SMALL_EVENT_ORDER[:3], [
            event["event"] for event in lifecycle["events"]])
        self.assertEqual(
            [], loom_gate.verify_small(record, require_authorized=True))
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
        sealed = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        _author_small_wo(self.repo / "plans", sealed["plan_contract"])
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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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
            "--home", self.home, "--install-root", self.installed,
            "--request-id", "req-duplicate-execute").stdout)
        self.assertEqual("execute", execute["intent"])
        self.assertEqual("WO-001", execute["work_order"])
        duplicate = json.loads(self.cli(
            "invoke", "--request", "Continue", "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed,
            "--request-id", "req-duplicate-execute").stdout)
        self.assertEqual(execute["action_id"], duplicate["action_id"])
        self.assertEqual("WO-001", duplicate["work_order"])
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

        advanced = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)
        advanced_operation = advanced["session_environment"][
            "LOOM_SESSION_OPERATION_ID"]
        self.assertNotEqual(receipt["operation_id"], advanced_operation)
        self.assertEqual("close", advanced["intent"])
        self.assertNotEqual("execute-complete", advanced.get("code"))
        self.assertFalse(advanced.get("repeated", False))

    def test_execute_refuses_noop_completion(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_pack(
            self.repo / "plans",
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            opened["plan_contract"])
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

    def test_natural_language_cancel_targets_only_the_pending_project_action(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        cancelled = loom_orchestrator.invoke(
            request=(
                "Cancel the current pending Loom action for this project. "
                "Do not implement anything."),
            cwd=self.repo, home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual(opened["action_id"], cancelled["action_id"])
        self.assertTrue(cancelled["success"])
        self.assertIn("No project implementation", cancelled["user_message"])

        replacement = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("action-required", replacement["status"])
        self.assertNotEqual(opened["action_id"], replacement["action_id"])

    def test_natural_language_cancel_rejects_a_different_action_id(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        wrong = str(uuid.uuid4())
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "not the pending action"):
            loom_orchestrator.invoke(
                request=f"Cancel Loom action {wrong}.",
                cwd=self.repo, home=self.home, install_root=self.installed)
        replay = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual(opened["action_id"], replay["action_id"])

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
            (self.installed / "VERSION").read_text(encoding="utf-8").strip(),
            second["plan_contract"])
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
