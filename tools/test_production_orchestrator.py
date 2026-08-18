"""Black-box coverage for the installed one-surface production orchestrator."""

import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from unittest import mock
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).parent))
import loom_gate  # noqa: E402
import loom_fault_harness  # noqa: E402
import loom_install  # noqa: E402
import loom_improvement  # noqa: E402
import loom_lifecycle  # noqa: E402
import loom_lifecycle_kernel  # noqa: E402
import loom_lifecycle_transition  # noqa: E402
import loom_codex_lifecycle  # noqa: E402
import loom_executor_guard  # noqa: E402
import loom_lint  # noqa: E402
import loom_adapter_protocol  # noqa: E402
import loom_domain_discovery  # noqa: E402
import loom_domain  # noqa: E402
import loom_memory  # noqa: E402
import loom_orchestrator  # noqa: E402
import loom_plan_author  # noqa: E402
import loom_plan_store  # noqa: E402
import loom_performance  # noqa: E402
import loom_proofline  # noqa: E402
import loom_reliability  # noqa: E402
import loom_release  # noqa: E402
import loom_session  # noqa: E402
import loom_windows_acl  # noqa: E402
from test_loom_vault_v11 import TestCrypto  # noqa: E402


TODAY = dt.datetime.now(dt.timezone.utc).date().isoformat()

PRE_UX104_PLANNING_CONTROL_V1 = {
    "schema_version": 1,
    "primary_operation": "plan",
    "relation": "new",
    "prohibitions": [],
    "explicitness": "defaulted",
    "evidence": ["safe-new-default"],
    "blocked": False,
    "block_reason": None,
    "control_sha256": (
        "7aaf553efc41778311b4743cb6a1eb0f0f7c424afddca14c95c1a0a15ed0589a"),
}


def _sealed_preference(identifier, key, value, *, domain=None,
                       task_class=None, risk_class=None):
    return {
        "id": identifier,
        "key": key,
        "effective_value": value,
        "effective_source": "stated",
        "stated_confidence": 1.0,
        "inferred_confidence": 0.0,
        "domain": domain,
        "task_class": task_class,
        "risk_class": risk_class,
        "subject": None,
        "retired_values": [],
    }


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _owned_pack(result):
    action = json.loads(Path(result["action_path"]).read_text(encoding="utf-8"))
    return loom_orchestrator._action_pack_root(action)


def _active_pack(project):
    return loom_plan_store.resolve(project).generation_root


def _write_planning_assignments(
        pack, contract, work_order="WO-001", milestone="delivery", *, write=True):
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
    if write:
        _write(pack / "planning-obligations.json", json.dumps(value, indent=2) + "\n")
    return [item["atom_id"] for item in assignments]


def _write_fixture_proofline(pack, *, request, contract, work_order, assignments):
    draft = {"work_orders": [work_order]}
    ledger = loom_proofline.build_material_ledger(
        request=request, plan_contract=contract, semantic_draft=draft)
    graph = loom_proofline.build_graph(
        ledger=ledger, plan_contract=contract, semantic_draft=draft,
        assignments=assignments)
    _write(
        pack / "proofline" / "material-intent-ledger.json",
        json.dumps(ledger, indent=2) + "\n")
    _write(
        pack / "proofline" / "proof-graph.json",
        json.dumps(graph, indent=2) + "\n")


def _author_medium_pack(pack, version, contract, *, request):
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
    assignments = json.loads(
        (pack / "planning-obligations.json").read_text(encoding="utf-8"))
    _write_fixture_proofline(
        pack, request=request, contract=contract,
        work_order={
            "id": "WO-001",
            "title": "Preserve accounting invariants",
            "outcome": "Requested accounting behavior preserves ledger invariants",
            "tasks": ["Change src/app.py within the sealed accounting boundary"],
            "touches": ["src/app.py"],
            "acceptance": [
                "python -m unittest exits 0 in a real process",
                "an unbalanced posting is rejected without a partial write",
            ],
            "negative_acceptance": [
                "an unbalanced posting cannot leave a partial write",
            ],
        },
        assignments=assignments)


def _author_medium_action(opened, *, request):
    """Use the stable author operation so v3 activation has reviewed semantics."""
    action_path = Path(opened["action_path"])
    action = json.loads(action_path.read_text(encoding="utf-8"))
    contract = opened["plan_contract"]
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
            "domain": item["domain"],
            "fact": item["fact"],
            "source": "sealed project inspection and shipped accounting adapter",
        } for item in contract["current_facts_to_verify"]],
        "release_exposure": {
            "external_users": 0,
            "irreversible": False,
            "data_migration": False,
            "regulated": False,
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
            "touches": ["src/app.py"],
            "depends_on": [],
            "routing": "strong-coding",
            "size": "S",
        }],
        "domain_evidence": None,
    }
    return loom_orchestrator.author(
        action_path, draft,
        owner_home=action["owner_home"], install_root=action["install_root"])


def _author_small_action(opened, *, request):
    """Author a Tier-S plan through the same reviewed host boundary as Codex."""
    action_path = Path(opened["action_path"])
    action = json.loads(action_path.read_text(encoding="utf-8"))
    contract = opened["plan_contract"]
    draft = {
        "schema_version": 1,
        "title": "Plan one bounded CLI flag",
        "summary": (
            "Add one command-line flag in src/app.py while preserving existing "
            "exit and output behavior."),
        "assumptions": [],
        "decisions": [],
        "current_facts": [{
            "domain": item["domain"],
            "fact": item["fact"],
            "source": "sealed project inspection and shipped CLI adapter",
        } for item in contract["current_facts"]],
        "release_exposure": {
            "external_users": 0,
            "irreversible": False,
            "data_migration": False,
            "regulated": False,
        },
        "work_orders": [{
            "title": "Add one CLI flag",
            "outcome": (
                "The requested flag works without changing existing exit or "
                "output contracts."),
            "tasks": ["Change only src/app.py."],
            "acceptance": ["`python -m unittest` exits 0."],
            "negative_acceptance": [
                "an unknown flag exits nonzero without normal output"],
            "out_of_scope": ["Architecture and packaging changes."],
            "escalation": ["Stop if a second component must change."],
            "touches": ["src/app.py"],
            "depends_on": [],
            "routing": "strong-coding",
            "size": "S",
        }],
        "domain_evidence": None,
    }
    return loom_orchestrator.author(
        action_path, draft,
        owner_home=action["owner_home"], install_root=action["install_root"])


def _author_small_wo(pack, contract, *, request):
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
    assignment_ids = _write_planning_assignments(
        pack, contract, write=False)
    atoms = [item for item in contract["planning_intelligence"]["atoms"]
             if item["gate_effect"] != "none"]
    assignments = [{
        "atom_id": item["atom_id"], "work_order": "WO-001",
        "milestone": "delivery",
        "verification": loom_orchestrator.loom_planning_intelligence.expanded_verification(
            contract["planning_intelligence"], item),
    } for item in sorted(atoms, key=lambda value: value["atom_id"])]
    assignment_body = {
        "schema_version": 1, "plan_contract_hash": contract["contract_hash"],
        "planning_intelligence_digest": contract["planning_intelligence"][
            "intelligence_digest"],
        "program_digest": (
            contract["planning_intelligence"]["program"] or {}).get(
                "program_digest"),
        "assignments": assignments,
    }
    assignment_value = {
        **assignment_body,
        "assignment_digest": loom_orchestrator.loom_domain_contract.digest(
            "planning-obligation-assignments-v1", assignment_body),
    }
    assert assignment_ids == [item["atom_id"] for item in assignments]
    _write_fixture_proofline(
        pack, request=request, contract=contract,
        work_order={
            "id": "WO-001", "title": "Add one CLI flag",
            "outcome": "The requested CLI flag works without changing existing contracts",
            "tasks": ["Change only src/app.py"],
            "touches": ["src/app.py"],
            "acceptance": [
                "python -m unittest exits 0",
                "an unknown flag exits nonzero without writing normal output",
            ],
            "negative_acceptance": [
                "an unknown flag cannot write normal output",
            ],
        },
        assignments=assignment_value)


def _mark_medium_wo_done(pack):
    candidates = sorted((pack / "work-orders").glob("WO-001*.md"))
    if len(candidates) != 1:
        raise AssertionError("the medium fixture must contain exactly one WO-001 file")
    work_order = candidates[0]
    text = work_order.read_text(encoding="utf-8")
    text = text.replace("status: ready", "status: done")
    text = text.replace("status: in-progress", "status: done")
    text = text.replace("- [ ]", "- [x]")
    text = text.replace(
        "Pending implementation evidence.",
        "Evidence: isolated real-process verification exited 0.")
    text = text.replace(
        "Pending real implementation evidence.",
        "Evidence: isolated real-process verification exited 0.")
    work_order.write_text(text, encoding="utf-8")
    return work_order


def _mark_small_wo_done(pack):
    work_order = pack / "WO-001.md"
    text = work_order.read_text(encoding="utf-8")
    text = text.replace("status: ready", "status: done")
    text = text.replace("status: in-progress", "status: done")
    text = text.replace("- [ ]", "- [x]")
    text = text.replace(
        "Pending implementation evidence.",
        "Evidence: isolated real-process verification exited 0.")
    text = text.replace(
        "Pending real implementation evidence.",
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
        installed = loom_install.install(cls.public, cls.installed_fixture)
        cls.installed_fixture_check = {
            key: installed[key]
            for key in ("status", "install_id", "files_verified", "receipt_hash")
        }
        cls.fixture_dependencies = {
            "install_check": loom_install.check,
            "filter_drivers":
                loom_orchestrator.loom_survey._configured_filter_drivers,
            "run_git": loom_orchestrator.loom_survey.run_git,
        }
        cls.repo_fixture = cls.fixture_root / "repo-fixture"
        (cls.repo_fixture / "src").mkdir(parents=True)
        _write(cls.repo_fixture / "src" / "app.py", "VALUE = 1\n")
        cls.fixture_home = cls.fixture_root / "fixture-home"
        loom_fault_harness.initialize_git_fixture(
            cls.repo_fixture, cls.fixture_home)

    @classmethod
    def tearDownClass(cls):
        if cls.fixture_dependencies["install_check"](cls.installed_fixture) \
                != cls.installed_fixture_check:
            raise AssertionError("the shared installed fixture changed during the test class")
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
        self._copy_filesystem_fixture(self.repo)
        self.runtime_patches = (
            mock.patch.object(
                loom_install, "check",
                side_effect=loom_fault_harness.immutable_install_check(
                    self.fixture_dependencies["install_check"],
                    self.installed_fixture,
                    self.installed_fixture_check)),
            mock.patch.object(
                loom_orchestrator.loom_survey, "_configured_filter_drivers",
                side_effect=loom_fault_harness.filesystem_fixture_filter_drivers(
                    self.fixture_dependencies["filter_drivers"], self.root)),
            mock.patch.object(
                loom_orchestrator.loom_survey, "run_git",
                side_effect=loom_fault_harness.filesystem_fixture_git(
                    self.fixture_dependencies["run_git"], self.root)),
        )
        for patcher in self.runtime_patches:
            patcher.start()
        self.request = "Plan a financial double-entry accounting change to src/app.py"
        self.request_sequence = 0

    def tearDown(self):
        for patcher in reversed(self.runtime_patches):
            patcher.stop()
        if self.prior_legacy_test_backend is None:
            os.environ.pop("LOOM_TEST_ALLOW_LEGACY_BACKEND", None)
        else:
            os.environ["LOOM_TEST_ALLOW_LEGACY_BACKEND"] = self.prior_legacy_test_backend
        self.temp.cleanup()

    @classmethod
    def _copy_filesystem_fixture(cls, destination):
        shutil.copytree(
            cls.repo_fixture, destination,
            ignore=shutil.ignore_patterns(".git"))

    def _enable_git_fixture(self):
        loom_fault_harness.initialize_git_fixture(
            self.repo, self.home / "git-home")

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

    def test_survey_failure_is_a_bounded_json_block(self):
        envelope = loom_adapter_protocol.request_envelope({
            "schema_version": 2,
            "message_type": "invoke",
            "request_id": "req-survey-block",
            "request": "Plan a project",
            "cwd": str(self.repo),
        }, {"id": "codex", "version": "test"})
        output = io.StringIO()
        with mock.patch.object(
                loom_orchestrator.loom_adapter_protocol,
                "read_single_frame", return_value=envelope), \
                mock.patch.object(
                    loom_orchestrator, "invoke",
                    side_effect=loom_orchestrator.loom_survey.SurveyError(
                        "seeded survey failure")), \
                redirect_stdout(output):
            returncode = loom_orchestrator.main([
                "invoke-stdio", "--home", str(self.home),
                "--install-root", str(self.installed),
            ])
        self.assertEqual(2, returncode)
        result = json.loads(output.getvalue())
        self.assertEqual("blocked", result["status"])
        self.assertEqual("RUNTIME_BLOCKED", result["code"])
        self.assertIn("seeded survey failure", result["error"])

    def test_gitless_invoke_binds_filesystem_mode_before_memory_housekeeping(self):
        target = self.root / "gitless-target"
        target.mkdir()
        instance_id = str(uuid.uuid4())

        class BoundMemory(loom_session.NoopMemoryAdapter):
            def __init__(self):
                self.bindings = []

            def bind_project_state(self, project_id, state_mode):
                self.bindings.append((project_id, state_mode))

        memory = BoundMemory()

        def missing_git(*_args, **_kwargs):
            try:
                raise FileNotFoundError(2, "git unavailable")
            except FileNotFoundError as exc:
                raise loom_orchestrator.loom_survey.SurveyError(
                    f"git unavailable: {exc}") from exc

        with mock.patch.object(
                loom_orchestrator, "_memory_backend",
                return_value=(instance_id, memory)), \
                mock.patch.object(
                    loom_orchestrator.loom_survey, "run_git",
                    side_effect=missing_git):
            result = loom_orchestrator.invoke(
                request="Plan a small Python command-line project.",
                cwd=target, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", result["status"])
        self.assertRegex(result["world_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(1, len(memory.bindings))
        self.assertEqual("filesystem", memory.bindings[0][1])
        self.assertTrue(memory.bindings[0][0].startswith("p-"))

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

    def arm_executor_guard(self, started, *, suffix="1"):
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        loom_executor_guard.observe_post(
            path.parent, action, {
                "hook_event_name": "PostToolUse", "cwd": str(self.repo),
                "session_id": "host-session-" + suffix,
                "turn_id": "host-turn-" + suffix,
                "tool_use_id": "start-" + suffix,
                "tool_name": "mcp__loom__start", "tool_input": {},
            }, lifecycle_control=True)
        return path, action

    def test_legacy_test_backend_requires_exact_disposable_marker(self):
        marker = self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER
        self.assertTrue(loom_orchestrator._disposable_test_legacy_backend_allowed(
            self.home))
        marker.write_text("wrong\n", encoding="utf-8")
        self.assertFalse(loom_orchestrator._disposable_test_legacy_backend_allowed(
            self.home))

    def test_installed_phase_8_request_uses_deep_target_route(self):
        request = (
            "Plan three separate Loom implementation phases from the completed Phase 8, "
            "9, and 10 research folders. Cover outcomes and requirements, architecture "
            "boundaries, and verification evidence. Do not implement."
        )
        opened = self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed,
            "--timeout-seconds", "300")
        self.assertEqual(0, opened.returncode, opened.stderr + opened.stdout)
        action = json.loads(opened.stdout)
        self.assertEqual("M", action["tier"])
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

    def test_explicit_no_file_modification_returns_sealed_inline_plan(self):
        self._enable_git_fixture()
        request = (
            "Produce a reviewable plan for adding a short 'Development notes' section "
            "to README.md in this disposable project. Do not implement the plan, modify "
            "files, install anything, publish anything, or contact external services.")
        before_manifest = loom_reliability.deterministic_manifest(self.repo)
        before_status = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=self.repo, capture_output=True, text=True, check=True).stdout

        result = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertIn("NON-AUTHORITATIVE PLAN", result["user_message"])
        self.assertIn("Understood outcome:", result["user_message"])
        self.assertIn("Proposed sequence:", result["user_message"])
        self.assertIn("Known constraints or uncertainty:", result["user_message"])
        self.assertIn("Reason code: PROJECT_WRITES_PROHIBITED", result["user_message"])
        self.assertEqual(1, result["user_message"].count("Safe next action:"))
        self.assertRegex(result["receipt_hash"], r"^[0-9a-f]{64}$")
        self.assertIsNone(result["terminal_authority"]["implementation_authorized"])
        self.assertFalse((self.repo / "plans").exists())
        self.assertEqual(before_manifest, loom_reliability.deterministic_manifest(self.repo))
        self.assertEqual(before_status, subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=self.repo, capture_output=True, text=True, check=True).stdout)

    def test_exact_installed_acceptance_wording_leaves_project_unchanged(self):
        request = (
            "Plan a small local Python command-line tool that reads a JSON task list "
            "and prints overdue items. Do not implement it or modify project files. "
            "Finalize the reviewable plan and present the result in plain language, "
            "including what is authorized, how completion would be verified, and where "
            "the plan can be inspected.")
        before_manifest = loom_reliability.deterministic_manifest(self.repo)

        result = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertFalse((self.repo / "plans").exists())
        self.assertEqual(before_manifest, loom_reliability.deterministic_manifest(self.repo))

    def test_inline_recovery_is_request_specific_without_prompt_or_project_leaks(self):
        """Break caught: safe inline recovery is generic or echoes raw private wording."""
        before = loom_reliability.deterministic_manifest(self.repo)
        cases = (
            (
                "Plan accounting ledger validation with no project writes. "
                "Private case velvet-otter.",
                "accounting", "velvet-otter",
            ),
            (
                "Plan accessible website navigation with no project writes. "
                "Private case amber-lynx.",
                "website", "amber-lynx",
            ),
        )
        messages = []
        for request, domain, private_marker in cases:
            with self.subTest(domain=domain):
                result = loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)
                messages.append(result["user_message"])
                self.assertEqual("non-authoritative-plan", result["code"])
                self.assertIn(domain, result["user_message"])
                self.assertNotIn(private_marker, json.dumps(result, sort_keys=True))
                self.assertEqual(
                    before, loom_reliability.deterministic_manifest(self.repo))
        self.assertNotEqual(messages[0], messages[1])

    def test_inline_recovery_distinguishes_same_domain_semantic_outcomes(self):
        """Break caught: same-domain recovery loses the requested outcome."""
        before = loom_reliability.deterministic_manifest(self.repo)
        cases = (
            (
                "Plan an accounting reconciliation workflow with no project writes. "
                "Private marker cobalt-heron and owner value violet-7.",
                "reconciliation", ("cobalt-heron", "violet-7"),
            ),
            (
                "Plan an accounting tax-period calendar and filed-period lock with no "
                "project writes. Private marker silver-marten and owner value amber-9.",
                "tax-period", ("silver-marten", "amber-9"),
            ),
        )
        messages = []
        for request, expected_focus, private_values in cases:
            with self.subTest(expected_focus=expected_focus):
                result = loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)
                message = result["user_message"]
                messages.append(message)
                self.assertEqual("non-authoritative-plan", result["code"])
                self.assertIn(expected_focus, message.casefold())
                for private_value in private_values:
                    self.assertNotIn(private_value, json.dumps(result, sort_keys=True))
                self.assertEqual(
                    before, loom_reliability.deterministic_manifest(self.repo))
        self.assertNotEqual(messages[0], messages[1])

    def test_unanchored_requests_return_distinct_safe_requirement_capsules(self):
        """Break caught: inline assistance is generic or persists ordinary wording."""
        before = loom_reliability.deterministic_manifest(self.repo)
        before_actions = sorted(
            path.relative_to(self.home).as_posix()
            for path in self.home.glob(
                "instances/*/runtime/projects/*/orchestrations/*.json"))
        cases = (
            (
                "I need an accounting reconciliation workflow. "
                "Private marker copper-ibis.",
                "reconciliation",
                "copper-ibis",
            ),
            (
                "How about adding an accounting tax-period calendar and filed-period "
                "lock? Private marker indigo-tern.",
                "tax-period calendar and filed-period lock/reopen authority",
                "indigo-tern",
            ),
        )
        messages = []

        for request, expected_requirement, private_marker in cases:
            with self.subTest(expected_requirement=expected_requirement):
                result = loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)
                message = result["user_message"]
                messages.append(message)
                self.assertEqual("completed", result["status"])
                self.assertEqual("non-authoritative-plan", result["code"])
                self.assertIn("Requirement capsule:", message)
                self.assertIn(expected_requirement, message.casefold())
                self.assertNotIn(private_marker, json.dumps(result, sort_keys=True))
                self.assertNotIn("action_path", result)
                self.assertFalse((self.repo / "plans").exists())
                self.assertEqual(before, loom_reliability.deterministic_manifest(self.repo))
                self.assertEqual(
                    before_actions,
                    sorted(
                        path.relative_to(self.home).as_posix()
                        for path in self.home.glob(
                            "instances/*/runtime/projects/*/orchestrations/*.json")))
        self.assertNotEqual(messages[0], messages[1])

    def test_installed_inline_capsules_distinguish_closed_same_domain_capabilities(self):
        """Break caught: installed same-domain assistance collapses to generic output."""
        before = loom_reliability.deterministic_manifest(self.repo)
        before_actions = sorted(
            path.relative_to(self.home).as_posix()
            for path in self.home.glob(
                "instances/*/runtime/projects/*/orchestrations/*.json"))
        cases = (
            (
                "I need CSV export for inventory reports. Private marker sapphire-17.",
                "tabular data export with explicit field and failure behavior",
                "sapphire-17",
            ),
            (
                "I need password reset and account recovery. Private marker topaz-23.",
                "credential reset and account recovery behavior",
                "topaz-23",
            ),
            (
                "I need accessible search and keyboard navigation. "
                "Private marker onyx-31.",
                "accessible search and keyboard navigation behavior",
                "onyx-31",
            ),
            (
                "I need local backup and restore recovery. Private marker quartz-47.",
                "backup, restore, integrity, and recovery behavior",
                "quartz-47",
            ),
        )
        messages = []

        for request, expected_requirement, private_marker in cases:
            with self.subTest(expected_requirement=expected_requirement):
                completed = self.cli(
                    "invoke", "--request", request, "--cwd", self.repo,
                    "--home", self.home, "--install-root", self.installed)
                self.assertEqual(0, completed.returncode, completed.stderr)
                result = json.loads(completed.stdout)
                message = result["user_message"]
                messages.append(message)
                self.assertEqual("completed", result["status"])
                self.assertEqual("non-authoritative-plan", result["code"])
                self.assertIn(expected_requirement, message.casefold())
                self.assertIn("semantic-outcome-v2.unclassified.", message)
                self.assertNotIn(private_marker, json.dumps(result, sort_keys=True))
                self.assertNotIn("action_path", result)
                self.assertEqual(
                    before, loom_reliability.deterministic_manifest(self.repo))
                self.assertFalse((self.repo / "plans").exists())
                self.assertEqual(
                    before_actions,
                    sorted(
                        path.relative_to(self.home).as_posix()
                        for path in self.home.glob(
                            "instances/*/runtime/projects/*/orchestrations/*.json")))

        self.assertEqual(len(cases), len(set(messages)))

    def test_installed_product_prefix_requests_preserve_all_authority_state(self):
        """Break caught: installed prefix parsing mutates lifecycle or memory state."""
        requests = (
            "Cancel button styling.",
            "Close this modal.",
            "Keep going indicator.",
            "Repair the plan parser.",
            "Fix the stale plan template.",
            "Remember button styling.",
            "Forget password screen.",
            "Show status page design.",
        )
        repo_before = loom_reliability.deterministic_manifest(self.repo)

        for request in requests:
            with self.subTest(request=request):
                completed = self.cli(
                    "invoke", "--request", request, "--cwd", self.repo,
                    "--home", self.home, "--install-root", self.installed)
                self.assertEqual(0, completed.returncode, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertEqual("completed", result["status"])
                self.assertEqual("non-authoritative-plan", result["code"])
                self.assertNotIn("action_path", result)
                self.assertEqual(
                    repo_before,
                    loom_reliability.deterministic_manifest(self.repo))
                self.assertFalse((self.repo / "plans").exists())
                self.assertEqual(
                    [], list(self.home.glob(
                        "instances/*/runtime/projects/*/orchestrations/*.json")))
                vault = self.home / "vault" / "owner.sqlite3"
                if vault.exists():
                    with sqlite3.connect(vault) as connection:
                        self.assertEqual(
                            0,
                            connection.execute(
                                "SELECT COUNT(*) FROM memory_records"
                            ).fetchone()[0])
                        self.assertEqual(
                            0,
                            connection.execute(
                                "SELECT COUNT(*) FROM tombstones"
                            ).fetchone()[0])

    def test_no_write_inline_recovery_preserves_invalid_config_failure(self):
        """Break caught: no-write recovery erases repository config authority."""
        _write(
            self.repo / "loom.config.json",
            '{"use_profile":"yes","unknown":true}\n')

        result = loom_orchestrator.invoke(
            request=(
                "Plan an accounting reconciliation workflow with no project writes."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("blocked", result["status"])
        self.assertEqual("invalid_config", result["code"])
        self.assertIn("config", result["user_message"].casefold())
        self.assertEqual("invalid-config", result["block_reason"]["code"])
        self.assertNotIn("NON-AUTHORITATIVE PLAN", result["user_message"])
        self.assertFalse((self.repo / "plans").exists())

    def test_no_write_inline_recovery_preserves_safety_and_intent_precedence(self):
        """Break caught: safe recovery masks a higher-priority safety or intent gate."""
        cases = (
            (
                "safety",
                "Plan the release and then delete the old production data with no "
                "project writes.",
                "high_consequence_uncertain",
                "high-consequence-uncertain",
                "confirm scope, verification, and rollback",
            ),
            (
                "contradiction",
                "Plan a school attendance dashboard, then implement it immediately, "
                "with no project writes.",
                "plan_execution_contradiction",
                "plan-execution-contradiction",
                "Should any implementation begin only after you review that plan?",
            ),
        )
        for name, request, code, reason_code, expected_detail in cases:
            with self.subTest(name=name):
                before = loom_reliability.deterministic_manifest(self.repo)
                result = loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)
                if name == "safety":
                    self.assertEqual("blocked", result["status"])
                    self.assertEqual(code, result["code"])
                    self.assertEqual(
                        reason_code, result["block_reason"]["code"])
                    self.assertIn(expected_detail, result["user_message"])
                    self.assertNotIn(
                        "NON-AUTHORITATIVE PLAN", result["user_message"])
                else:
                    self.assertEqual("completed", result["status"])
                    self.assertEqual("non-authoritative-plan", result["code"])
                    self.assertIn(
                        "NON-AUTHORITATIVE PLAN", result["user_message"])
                    self.assertIn(
                        "Understood outcome:", result["user_message"])
                    self.assertNotIn("action_path", result)
                self.assertEqual(
                    before, loom_reliability.deterministic_manifest(self.repo))

    def test_planning_conflict_uses_neutral_context_without_leaking_private_evidence(self):
        """Break caught: a private preference conflict blocks planning or leaks values."""
        instance_id = "00000000-0000-4000-8000-000000005110"
        conflict_id = "00000000-0000-4000-8000-000000005111"
        owner_id = "00000000-0000-4000-8000-000000005112"
        secret_value = "private-owner-choice-never-public"

        class Vault:
            def identity(self):
                return {"owner_vault_id": owner_id}

            def relevant_preference_conflicts(self, *, domain, project_id):
                return [{
                    "conflict_id": conflict_id,
                    "preference_key": "stack_preference",
                }]

        projection_adapter = object.__new__(
            loom_orchestrator.loom_vault_adapter.VaultMemoryAdapter)
        projection_adapter.vault = Vault()

        class ConflictMemory(loom_session.NoopMemoryAdapter):
            def select_preferences(self, _context):
                return [
                    _sealed_preference(
                        "00000000-0000-4000-8000-000000005113",
                        "stack", secret_value, domain="accounting"),
                    _sealed_preference(
                        "00000000-0000-4000-8000-000000005114",
                        "report_detail", "concise"),
                ]

            def relevant_preference_conflicts(self, *, domains, project_id):
                return [{
                    "conflict_id": conflict_id,
                    "preference_key": "stack_preference",
                }]

            def project_planning_preferences(self, **arguments):
                return projection_adapter.project_planning_preferences(**arguments)

        with mock.patch.object(
                loom_orchestrator, "_memory_backend",
                return_value=(instance_id, ConflictMemory())):
            result = loom_orchestrator.invoke(
                request="Plan a small accounting change to src/app.py.",
                cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", result["status"])
        self.assertNotEqual("preference-conflict", result.get("code"))
        self.assertIn(
            {"key": "stack", "domain": "accounting", "neutral_default": True},
            result["context"]["preferences"])
        self.assertTrue(any(
            item.get("key") == "report_detail"
            for item in result["context"]["preferences"]))
        public = json.dumps(result, sort_keys=True)
        self.assertNotIn(secret_value, public)
        self.assertNotIn(conflict_id, public)
        self.assertNotIn(owner_id, public)
        _path, action, _security = loom_orchestrator._read_action(
            result["action_path"], owner_home=self.home,
            install_root=self.installed)
        private = action["host_result"]["planning_preference_conflicts"]
        self.assertEqual(["stack"], private["conflict_keys"])
        self.assertEqual(conflict_id, private["private_evidence"][0]["conflict_id"])
        self.assertNotIn(
            secret_value, json.dumps(private, sort_keys=True))

    def test_action_read_rejects_unbound_or_value_bearing_conflict_evidence(self):
        """Break caught: rehashed private conflict metadata crosses its sealed scope."""
        instance_id = "00000000-0000-4000-8000-000000005130"
        owner_id = "00000000-0000-4000-8000-000000005131"
        conflict_id = "00000000-0000-4000-8000-000000005132"

        class Vault:
            def identity(self):
                return {"owner_vault_id": owner_id}

            def relevant_preference_conflicts(self, *, domain, project_id):
                return [{
                    "conflict_id": conflict_id,
                    "preference_key": "stack_preference",
                }]

        adapter = object.__new__(
            loom_orchestrator.loom_vault_adapter.VaultMemoryAdapter)
        adapter.vault = Vault()

        class ConflictMemory(loom_session.NoopMemoryAdapter):
            def select_preferences(self, _context):
                return [_sealed_preference(
                    "00000000-0000-4000-8000-000000005133",
                    "stack", "python", domain="accounting")]

            def project_planning_preferences(self, **arguments):
                return adapter.project_planning_preferences(**arguments)

        with mock.patch.object(
                loom_orchestrator, "_memory_backend",
                return_value=(instance_id, ConflictMemory())):
            opened = loom_orchestrator.invoke(
                request="Plan a small accounting change to src/app.py.",
                cwd=self.repo, home=self.home, install_root=self.installed)
        path = Path(opened["action_path"])
        base = json.loads(path.read_text(encoding="utf-8"))
        conflict = base["host_result"]["planning_preference_conflicts"]
        evidence = conflict["private_evidence"][0]
        mutations = (
            lambda value: value.update({"project_id": "p-" + "f" * 32}),
            lambda value: value.update({"domain": "three-d"}),
            lambda value: value.update({"preference_key": "invented"}),
            lambda value: value.update({"conflict_id": "not-a-uuid"}),
            lambda value: value.update({"risk_class": "low"}),
            lambda value: value.update({"task_class": "execute"}),
            lambda value: value.update({"value": "private-python"}),
            lambda value: value.update({"unknown": True}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                action = json.loads(json.dumps(base))
                mutate(action["host_result"]["planning_preference_conflicts"]
                       ["private_evidence"][0])
                action["action_hash"] = loom_orchestrator._action_hash(action)
                path.write_text(json.dumps(action), encoding="utf-8")
                with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
                    loom_orchestrator._read_action(
                        path, owner_home=self.home, install_root=self.installed)
                self.assertEqual("ACTION_CORRUPT", raised.exception.code)

        action = json.loads(json.dumps(base))
        action["host_result"]["planning_preference_conflicts"][
            "private_evidence"].append(dict(evidence))
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as duplicate:
            loom_orchestrator._read_action(
                path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("ACTION_CORRUPT", duplicate.exception.code)

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
            "plans/manifest.md and plans/lifecycle.json",
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
        self.assertTrue((_owned_pack(action) / "lifecycle.json").is_file())

        _author_medium_action(action, request=self.request)
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
        pack = _active_pack(self.repo)
        proofline_report = json.loads(
            (pack / "proofline" / "completion-report.json").read_text(
                encoding="utf-8"))
        self.assertEqual("passed", proofline_report["gate"]["state"])
        self.assertTrue(all(
            item["semantic_claim"] == "advisory"
            for item in proofline_report["intent_coverage"]))
        self.assertEqual("legacy-ambiguous", result["usage"]["measurement_status"])
        self.assertIsNone(result["usage"]["processed_total_tokens"])
        self.assertEqual(900, result["usage"]["legacy_declared_total_tokens"])
        self.assertIsNone(result["usage"]["processed_total_tokens"])
        lifecycle = json.loads(
            (pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            ["generation-created", "plan-reviewed"],
            [event["event_type"] for event in lifecycle["events"]])
        self.assertNotIn(
            "implementation-authorized",
            [event["event_type"] for event in lifecycle["events"]])
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
        pending_pack = _owned_pack(action)
        self.assertEqual("authored", authored["status"])
        self.assertTrue(authored["ready_for_completion"])
        self.assertFalse([
            item for item in authored["diagnostics"] if item["level"] == "ERROR"])
        self.assertFalse([
            item for item in authored["diagnostics"] if item["level"] == "WARN"])
        intake = (pending_pack / "intake.md").read_text(encoding="utf-8")
        self.assertIn("| required |", intake)
        self.assertIn("| unverified |", intake)
        review = (
            pending_pack / "reviews" / "G1-plan-review.md"
        ).read_text(encoding="utf-8")
        self.assertIn("loom-deterministic-plan-validator-v2", review)
        report = loom_lint.lint(
            pending_pack, repo_path=self.repo,
            enforce_lifecycle=False, check_repo_state=False)
        self.assertEqual([], report.findings)

        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        self.assertEqual("plan-complete", completed["code"])
        pack = _active_pack(self.repo)
        plan_relative = (pack / "MANIFEST.md").relative_to(self.repo).as_posix()
        self.assertEqual(
            plan_relative,
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
        presentation = completed["plan_presentation"]
        self.assertEqual("plan-presentation-v2", presentation["format"])
        self.assertEqual("bounded", presentation["preview_mode"])
        self.assertEqual(
            action["action_id"],
            presentation["binding"]["action_id"])
        self.assertEqual(
            json.loads((pack / "reviewed-world.json").read_text(
                encoding="utf-8"))["state_sha256"],
            presentation["binding"]["world_fingerprint"])
        self.assertEqual(
            plan_relative,
            presentation["full_plan"]["relative_path"])
        self.assertIn(
            "## Preserve double-entry correctness",
            completed["plan_host_projection"]["markdown"])
        self.assertIn(
            "[Open the complete plan](",
            completed["plan_host_projection"]["markdown"])
        self.assertIn(
            (pack / "MANIFEST.md").as_posix().replace(" ", "%20"),
            completed["plan_host_projection"]["markdown"])
        self.assertNotIn(
            str(self.repo),
            json.dumps(presentation, sort_keys=True))
        ledger = json.loads((pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertNotIn(
            "implementation-authorized",
            [event["event_type"] for event in ledger["events"]])

    def test_medium_plan_requires_explicit_continue_before_authorization(self):
        _action, completed = self.complete_machine_authored_plan()
        self.assertEqual("plan-complete", completed["code"])
        pack = _active_pack(self.repo)
        manifest = loom_lint.parse_frontmatter(
            (pack / "MANIFEST.md").read_text(
                encoding="utf-8"))[0]
        self.assertEqual("gated", manifest["status"])
        ledger = json.loads((pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertNotIn(
            "implementation-authorized",
            [event["event_type"] for event in ledger["events"]])

        continued = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", continued["status"])
        self.assertEqual("execute", continued["intent"])
        self.assertEqual("WO-001", continued["work_order"])
        manifest = loom_lint.parse_frontmatter(
            (pack / "MANIFEST.md").read_text(
                encoding="utf-8"))[0]
        self.assertEqual("active", manifest["status"])
        ledger = json.loads((pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [
                "generation-created", "plan-reviewed",
                "implementation-authorized", "work-order-started",
            ],
            [event["event_type"] for event in ledger["events"]])

    def test_exact_displayed_plan_start_uses_existing_execute_authority(self):
        action, completed = self.complete_machine_authored_plan()
        reference = completed["plan_presentation"]

        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=reference["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("action-required", started["status"])
        self.assertEqual("execute", started["intent"])
        self.assertEqual("WO-001", started["work_order"])
        self.assertEqual(
            reference["presentation_sha256"],
            started["plan_decision"]["presentation_sha256"])
        self.assertEqual(
            reference["binding"]["pack_sha256"],
            started["plan_decision"]["pack_sha256"])
        resolved = loom_plan_store.resolve(self.repo)
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            [
                "generation-created", "plan-reviewed",
                "implementation-authorized", "work-order-started",
            ],
            [event["event_type"] for event in ledger["events"]])
        work_order = next(
            (resolved.generation_root / "work-orders").glob("WO-001-*.md"))
        self.assertEqual(
            "in-progress",
            loom_lint.parse_frontmatter(
                work_order.read_text(encoding="utf-8"))[0]["status"])

    def test_next_invocation_recovers_committed_start_action_and_pointer(self):
        """Break caught: a committed start can lose every owner-side projection."""
        action, completed = self.complete_machine_authored_plan()
        reference = completed["plan_presentation"]
        real_transition = loom_orchestrator.loom_lifecycle_transition.transition

        def interrupt_start(*args, **kwargs):
            command = args[1]
            if command["relation"] == "start-exact":
                kwargs["fault_at"] = "after-project-commit"
            return real_transition(*args, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition, "transition",
                side_effect=interrupt_start):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.start(
                    action["action_path"],
                    presentation_sha256=reference["presentation_sha256"],
                    owner_home=self.home, install_root=self.installed)

        transition_root = Path(action["action_path"]).parent / "lifecycle-transitions"
        envelopes = []
        for path in transition_root.glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and value.get("command", {}).get(
                    "relation") == "start-exact":
                envelopes.append(value)
        self.assertEqual(1, len(envelopes))
        envelope = envelopes[0]
        self.assertEqual("prepared", envelope["status"])
        staged = envelope["private_projection"]
        self.assertEqual("orchestration-action-transition-v1", staged["kind"])
        self.assertIn(
            staged["encoding"],
            {"owner-vault-encrypted-v1", "plaintext-v1"})
        if staged["encoding"] == "owner-vault-encrypted-v1":
            self.assertNotIn(self.request, json.dumps(staged, sort_keys=True))
        execution_action_id = staged["action_id"]
        execution_action_path = Path(action["action_path"]).parent / (
            execution_action_id + ".json")
        self.assertFalse(execution_action_path.exists())
        self.assertFalse((Path(action["action_path"]).parent /
                          loom_orchestrator.ACTIVE_POINTER_FILE).exists())

        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", status["status"])
        self.assertTrue(execution_action_path.is_file())
        _path, recovered_action, _security = loom_orchestrator._read_action(
            execution_action_path, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("pending", recovered_action["status"])
        self.assertIsNotNone(recovered_action["work_order"])
        self.assertIsNotNone(recovered_action["initial_pack_hash"])
        self.assertEqual(
            "completed", recovered_action["lifecycle_transition"]["status"])
        recovered_guard = loom_executor_guard.read(
            execution_action_path.parent, recovered_action)
        self.assertEqual("awaiting-host", recovered_guard["coverage_state"])
        pointer = loom_orchestrator._read_active_pointer(
            execution_action_path.parent)
        self.assertEqual(execution_action_id, pointer["action_id"])
        ledger = json.loads(
            (loom_plan_store.resolve(self.repo).generation_root /
             "lifecycle.json").read_text(encoding="utf-8"))
        event_types = [item["event_type"] for item in ledger["events"]]
        self.assertEqual(1, event_types.count("implementation-authorized"))
        self.assertEqual(1, event_types.count("work-order-started"))

    def test_historical_v1_plan_is_adopted_before_exact_execution(self):
        """Break caught: a valid historical pack cannot enter the sole v3 writer."""
        captured = self.root / "captured-historical-pack"
        real_prepare = \
            loom_orchestrator.loom_lifecycle_transition.prepare_generation_authority

        def capture_legacy_stage(stage, **kwargs):
            if not captured.exists():
                shutil.copytree(stage, captured)
            return real_prepare(stage, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition,
                "prepare_generation_authority", side_effect=capture_legacy_stage):
            action, completed = self.complete_machine_authored_plan()
        self.assertTrue(captured.is_dir())
        action_path, sealed_action, security = loom_orchestrator._read_action(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        legacy_binding = {
            "action_id": sealed_action["action_id"],
            "project_id": sealed_action["project_id"],
            "world_fingerprint": sealed_action["survey_hash"],
            "plan_contract_hash": sealed_action["plan_contract"]["contract_hash"],
            "pack_sha256": loom_orchestrator._pack_hash(captured),
            "revision": 1,
            "relative_path": "plans/MANIFEST.md",
            "manifest_sha256": hashlib.sha256(
                (captured / "MANIFEST.md").read_bytes()).hexdigest(),
        }
        legacy_presentation = \
            loom_orchestrator.loom_plan_presentation.compile_presentation(
                sealed_action["host_result"]["plan_review"]["semantics"],
                tier=sealed_action["tier"], binding=legacy_binding)
        sealed_action["result"] = {
            **sealed_action["result"],
            "plan_presentation": legacy_presentation,
        }
        loom_orchestrator._write_action(action_path, sealed_action, security)
        completed = {**completed, "plan_presentation": legacy_presentation}
        self.assertEqual(
            "plan-presentation-v1",
            completed["plan_presentation"]["format"])
        shutil.rmtree(self.repo / "plans")
        shutil.copytree(captured, self.repo / "plans")
        witness_path = Path(action["action_path"]).parent / \
            "lifecycle-head-witness.json"
        if witness_path.exists():
            witness_path.unlink()
        self.assertEqual(
            completed["plan_presentation"]["binding"]["pack_sha256"],
            loom_orchestrator._pack_hash(self.repo / "plans"))

        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("action-required", started["status"])
        self.assertEqual(3, started["plan_decision"]["schema_version"])
        self.assertEqual("WO-001", started["work_order"])
        resolved = loom_plan_store.resolve(self.repo)
        self.assertEqual("legacy-root", resolved.storage_kind)
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            ["generation-created", "plan-reviewed",
             "implementation-authorized", "work-order-started"],
            [event["event_type"] for event in ledger["events"]])

    def test_later_host_turn_recovers_the_exact_unchanged_plan_for_start(self):
        _action, completed = self.complete_machine_authored_plan()

        started = loom_orchestrator.start(
            cwd=self.repo, owner_home=self.home, install_root=self.installed)

        self.assertEqual("action-required", started["status"])
        self.assertEqual("execute", started["intent"])
        self.assertEqual(
            completed["plan_presentation"]["presentation_sha256"],
            started["plan_decision"]["presentation_sha256"])

    def test_exact_plan_start_rejects_tampered_reference_without_lifecycle_change(self):
        action, completed = self.complete_machine_authored_plan()
        pack = _active_pack(self.repo)
        lifecycle = pack / loom_gate.LIFECYCLE_FILE
        before = lifecycle.read_bytes()

        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.start(
                action["action_path"],
                presentation_sha256="0" * 64,
                owner_home=self.home, install_root=self.installed)

        self.assertEqual("PLAN_DECISION_MISMATCH", raised.exception.code)
        self.assertEqual(before, lifecycle.read_bytes())
        self.assertEqual(
            completed["plan_presentation"]["binding"]["pack_sha256"],
            loom_orchestrator._pack_hash(pack))

    def test_exact_plan_start_rejects_repository_drift_as_stale(self):
        action, completed = self.complete_machine_authored_plan()
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")

        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.start(
                action["action_path"],
                presentation_sha256=completed[
                    "plan_presentation"]["presentation_sha256"],
                owner_home=self.home, install_root=self.installed)

        self.assertEqual("PLAN_DECISION_STALE", raised.exception.code)

    def test_bound_revision_creates_a_new_plan_action_and_semantic_diff(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        prior_resolved = loom_plan_store.resolve(self.repo)
        prior_generation_id = prior_resolved.index.generation_id
        prior_generation_root = prior_resolved.generation_root
        prior_generation_manifest = loom_reliability.exact_tree_manifest(
            prior_generation_root)

        revision = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            request="Change the plan so the precision check also covers 1.005 rounding.",
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("action-required", revision["status"])
        self.assertEqual("plan", revision["intent"])
        self.assertEqual(2, revision["revision_context"]["revision"])
        self.assertEqual(
            prior["presentation_sha256"],
            revision["revision_context"]["parent_presentation_sha256"])
        self.assertEqual(
            "Change the plan so the precision check also covers 1.005 rounding.",
            revision["revision_context"]["request"])

        self.assertEqual(
            "Preserve double-entry correctness",
            revision["revision_context"]["prior_semantics"]["title"])
        self.assertRegex(
            revision["revision_context"]["archive_sha256"], r"^[0-9a-f]{64}$")
        revision_action_path = Path(revision["action_path"])
        self.assertTrue(revision_action_path.is_file())
        archive_paths = sorted(
            (revision_action_path.parent / "plan-revisions").glob("*.json"))
        self.assertEqual(1, len(archive_paths))
        archive = json.loads(archive_paths[0].read_text(encoding="utf-8"))
        loom_orchestrator._validate_revision_archive_payload(archive)
        self.assertEqual(
            revision["revision_context"]["archive_sha256"],
            archive["archive_sha256"])

        contract = revision["plan_contract"]
        revised_draft = {
            "schema_version": 1,
            "title": "Preserve double-entry precision and rounding",
            "summary": (
                "Keep the bounded accounting change and verify both exact decimal "
                "precision and 1.005 rounding."),
            "assumptions": [
                "The requested change remains limited to the existing src/app.py boundary."],
            "decisions": [
                "Test the 1.005 rounding rule as part of the same accounting work order."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped accounting adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Preserve decimal precision and rounding",
                "outcome": "The requested behavior preserves precision and 1.005 rounding.",
                "tasks": [
                    "Inspect the existing posting boundary.",
                    "Implement the requested bounded behavior.",
                    "Run precision and rounding checks.",
                ],
                "acceptance": [
                    "`python -m unittest` exits 0 for balanced postings.",
                    "The 1.005 rounding case returns the declared result.",
                ],
                "negative_acceptance": [
                    "an invalid rounding mode fails without a partial write"],
                "out_of_scope": ["Tax policy and data migration."],
                "escalation": ["Stop if a dated jurisdiction rule is required."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }
        loom_orchestrator.author(
            revision["action_path"], revised_draft,
            owner_home=self.home, install_root=self.installed)
        revised = loom_orchestrator.complete(
            revision["action_path"], owner_home=self.home,
            install_root=self.installed)

        self.assertEqual(2, revised["plan_presentation"]["binding"]["revision"])
        self.assertEqual(
            prior["presentation_sha256"],
            revised["plan_revision"]["parent_presentation_sha256"])
        self.assertEqual(
            ["decisions", "summary", "title", "work_orders"],
            revised["plan_revision"]["changed_sections"])
        self.assertNotEqual(
            prior["presentation_sha256"],
            revised["plan_presentation"]["presentation_sha256"])
        current_resolved = loom_plan_store.resolve(self.repo)
        self.assertEqual(prior_generation_id, current_resolved.index.generation_id)
        self.assertNotEqual(prior_generation_root, current_resolved.generation_root)
        self.assertEqual(
            prior_generation_manifest,
            loom_reliability.exact_tree_manifest(prior_generation_root))
        self.assertEqual(
            current_resolved.index.generation_path,
            current_resolved.generation_root.relative_to(self.repo).as_posix())

    def test_later_host_turn_recovers_the_exact_unchanged_plan_for_revision(self):
        _action, completed = self.complete_machine_authored_plan()
        request = "Change the plan so the precision check also covers 1.005 rounding."

        revision = loom_orchestrator.revise(
            cwd=self.repo, request=request,
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("action-required", revision["status"])
        self.assertEqual("plan", revision["intent"])
        self.assertEqual(
            completed["plan_presentation"]["presentation_sha256"],
            revision["revision_context"]["parent_presentation_sha256"])
        self.assertEqual(request, revision["revision_context"]["request"])
        _path, revised_action, _security = loom_orchestrator._read_action(
            revision["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual(["accounting"], revised_action["domains"])
        self.assertEqual(
            ["semantic-outcome-v1.accounting.4"],
            [
                item for item in revised_action["prepared"][
                    "route_contract"]["evidence"]
                if item.startswith("semantic-outcome-")
            ])

    def test_later_host_turn_recovery_rejects_project_drift(self):
        self.complete_machine_authored_plan()
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")

        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.revise(
                cwd=self.repo, request="Change one verification check.",
                owner_home=self.home, install_root=self.installed)

        self.assertEqual("PLAN_DECISION_STALE", raised.exception.code)

    def test_later_host_turn_recovery_refuses_when_no_plan_exists(self):
        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.start(
                cwd=self.repo, owner_home=self.home, install_root=self.installed)

        self.assertEqual("PLAN_DECISION_UNAVAILABLE", raised.exception.code)

    def test_bound_revision_keeps_planning_authority_when_owner_forbids_implementation(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        request = (
            "Change the plan so the greeting accepts an optional --name argument "
            "and defaults to World. Keep it small and do not implement it.")

        revision = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            request=request, owner_home=self.home, install_root=self.installed)

        self.assertEqual("action-required", revision["status"])
        self.assertEqual("plan", revision["intent"])
        self.assertEqual(request, revision["revision_context"]["request"])
        self.assertEqual(
            "bound-plan-revision",
            revision["prepared_intent_authority"])

    def test_bound_intent_cannot_be_used_without_an_exact_revision_reference(self):
        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.invoke(
                request="Do not implement anything.",
                cwd=self.repo, home=self.home, install_root=self.installed,
                bound_intent="plan")

        self.assertEqual("PLAN_DECISION_MISMATCH", raised.exception.code)

    def test_bound_revision_is_idempotent_while_pending_and_cancel_preserves_prior_plan(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        pack = _active_pack(self.repo)
        before = loom_orchestrator._pack_hash(pack)
        request = "Change the plan so one negative acceptance case names a partial write."

        first = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            request=request, owner_home=self.home, install_root=self.installed)
        repeated = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            request=request, owner_home=self.home, install_root=self.installed)

        self.assertEqual(first["action_id"], repeated["action_id"])
        self.assertEqual(
            first["revision_context"]["archive_sha256"],
            repeated["revision_context"]["archive_sha256"])
        cancelled = loom_orchestrator.cancel(
            first["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual(
            "install-stage", cancelled["recovery_receipt"]["source_path"])
        self.assertEqual(
            "quarantined",
            cancelled["recovery_receipt"]["source_disposition"])
        self.assertFalse(
            (self.repo / f".loom-plan-stage-{first['action_id']}").exists())
        self.assertEqual(before, loom_orchestrator._pack_hash(pack))
        self.assertTrue(
            (loom_plan_store.resolve(self.repo).generation_root / "MANIFEST.md")
            .is_file())
        replacement = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            request="Change the plan so the recovery check names the restored file.",
            owner_home=self.home, install_root=self.installed)
        self.assertEqual("action-required", replacement["status"])
        self.assertNotEqual(first["action_id"], replacement["action_id"])
        self.assertEqual(
            first["revision_context"]["archive_sha256"],
            replacement["revision_context"]["archive_sha256"])

    def test_bound_revision_rejects_tampered_reference_and_source_drift(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        pack = _active_pack(self.repo)
        before = loom_orchestrator._pack_hash(pack)

        with self.assertRaises(loom_orchestrator.OrchestratorError) as tampered:
            loom_orchestrator.revise(
                action["action_path"], presentation_sha256="0" * 64,
                request="Change one verification check.",
                owner_home=self.home, install_root=self.installed)
        self.assertEqual("PLAN_DECISION_MISMATCH", tampered.exception.code)
        self.assertEqual(before, loom_orchestrator._pack_hash(pack))

        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as stale:
            loom_orchestrator.revise(
                action["action_path"],
                presentation_sha256=prior["presentation_sha256"],
                request="Change one verification check.",
                owner_home=self.home, install_root=self.installed)
        self.assertEqual("PLAN_DECISION_STALE", stale.exception.code)

    def test_bound_revision_rejects_semantic_noop_and_keeps_prior_revision(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        revision = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            request="Reissue the exact same plan without changing its meaning.",
            owner_home=self.home, install_root=self.installed)
        prior_semantics = revision["revision_context"]["prior_semantics"]
        draft = {
            "schema_version": 1,
            "title": prior_semantics["title"],
            "summary": prior_semantics["summary"],
            "assumptions": prior_semantics["assumptions"],
            "decisions": prior_semantics["decisions"],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped accounting adapter",
            } for item in revision["plan_contract"]["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                **{key: value for key, value in item.items() if key != "id"},
                "routing": "strong-coding", "size": "S",
            } for item in prior_semantics["work_orders"]],
            "domain_evidence": None,
        }
        pack = _active_pack(self.repo)
        before = loom_orchestrator._pack_hash(pack)
        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.author(
                revision["action_path"], draft,
                owner_home=self.home,
                install_root=self.installed)
        self.assertEqual("PLAN_REVISION_EMPTY", raised.exception.code)
        self.assertEqual(before, loom_orchestrator._pack_hash(pack))

    def test_bound_revision_blocked_before_action_leaves_no_private_archive(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        orchestration_dir = Path(action["action_path"]).parent
        archive_dir = orchestration_dir / "plan-revisions"
        orchestration_before = loom_reliability.exact_tree_manifest(
            orchestration_dir)
        plan_before = loom_reliability.exact_tree_manifest(self.repo / "plans")
        pointer = orchestration_dir / "active.json"
        self.assertFalse(pointer.exists())
        self.assertFalse(archive_dir.exists())

        with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
            loom_orchestrator.revise(
                action["action_path"],
                presentation_sha256=prior["presentation_sha256"],
                request=(
                    "Change one verification check, but do not modify any project files."),
                owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("PLAN_DECISION_STALE", raised.exception.code)
        self.assertFalse(archive_dir.exists())
        self.assertFalse(pointer.exists())
        self.assertEqual(
            orchestration_before,
            loom_reliability.exact_tree_manifest(orchestration_dir))
        self.assertEqual(
            plan_before,
            loom_reliability.exact_tree_manifest(self.repo / "plans"))

    def test_bound_revision_archive_waits_for_action_admission(self):
        """Break caught: private revision history is written before action admission."""
        action, completed = self.complete_machine_authored_plan()
        archive_dir = Path(action["action_path"]).parent / "plan-revisions"
        self.assertFalse(archive_dir.exists())

        with mock.patch.object(
                loom_orchestrator, "_write_action",
                side_effect=loom_orchestrator.OrchestratorError(
                    "ACTION_ADMISSION_FAILED", "injected admission refusal")):
            with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
                loom_orchestrator.revise(
                    action["action_path"],
                    presentation_sha256=completed[
                        "plan_presentation"]["presentation_sha256"],
                    request="Change one verification check.",
                    owner_home=self.home,
                    install_root=self.installed)

        self.assertEqual("ACTION_ADMISSION_FAILED", raised.exception.code)
        self.assertFalse(archive_dir.exists())

    def test_exact_plan_start_returns_a_bounded_completion_contract(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]

        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)

        contract = started["execution_completion_contract"]
        expected_work_order = (
            _active_pack(self.repo)
            / "work-orders" / "WO-001-preserve-double-entry-correctness.md"
        ).relative_to(self.repo).as_posix()
        self.assertEqual({
            "schema_version": 1,
            "work_order_path": expected_work_order,
            "work_order_id": "WO-001",
            "required_status": "done",
            "acceptance_marker": "- [x]",
            "pending_evidence_text": "Pending real implementation evidence.",
            "completion_operation": "loom.complete",
        }, {
            key: contract[key]
            for key in (
                "schema_version", "work_order_path", "work_order_id",
                "required_status", "acceptance_marker", "pending_evidence_text",
                "completion_operation")
        })
        self.assertEqual(
            "loom-lifecycle-capture-v1",
            contract["evidence_capture"]["method"])
        self.assertEqual(str(self.repo), contract["evidence_capture"]["repo_path"])
        self.assertEqual(
            str(_active_pack(self.repo)),
            contract["evidence_capture"]["pack_path"])
        self.assertTrue(Path(
            contract["evidence_capture"]["tool_path"]).is_file())
        self.assertEqual(
            ["--wo", "WO-001", "--medium"],
            contract["evidence_capture"]["argv_prefix"][-3:])
        self.assertEqual(
            "--", contract["evidence_capture"]["verification_argv_separator"])

    def test_authorized_continuation_is_closed_self_bound_and_non_authorizing(self):
        """Break caught: a blocked deviation either dead-ends or grants new authority."""
        action, completed = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        self.arm_executor_guard(started)
        action_path, sealed_action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        resolved = loom_plan_store.resolve(self.repo)
        before_index = (
            self.repo / "plans" / loom_plan_store.INDEX_NAME).read_bytes()
        before_ledger = (resolved.generation_root / "lifecycle.json").read_bytes()
        before_action = action_path.read_bytes()

        continuation = loom_orchestrator.authorized_continuation(
            sealed_action, rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
            owner_home=self.home, install_root=self.installed)

        self.assertEqual({
            "schema_version", "authority_effect", "project_id", "generation_id",
            "active_action_id", "plan_semantics_sha256",
            "lifecycle_state_sha256", "observed_world_sha256",
            "work_order_id", "outcome_sha256", "allowed_touches",
            "acceptance_sha256", "negative_acceptance_sha256",
            "evidence_requirements_sha256", "rejection_code",
            "safe_next_operation", "continuation_sha256",
        }, set(continuation))
        self.assertEqual("none", continuation["authority_effect"])
        self.assertEqual("WO-001", continuation["work_order_id"])
        self.assertEqual(["src/app.py"], continuation["allowed_touches"])
        self.assertEqual(
            "continue-current-execution",
            continuation["safe_next_operation"])
        unsigned = {
            key: value for key, value in continuation.items()
            if key != "continuation_sha256"
        }
        expected_digest = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(expected_digest, continuation["continuation_sha256"])
        self.assertEqual(
            continuation,
            loom_orchestrator.verify_authorized_continuation(
                sealed_action, continuation,
                expected_rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
                owner_home=self.home, install_root=self.installed))
        self.assertEqual(
            before_index,
            (self.repo / "plans" / loom_plan_store.INDEX_NAME).read_bytes())
        self.assertEqual(
            before_ledger,
            (resolved.generation_root / "lifecycle.json").read_bytes())
        self.assertEqual(before_action, action_path.read_bytes())
        reopened = loom_orchestrator._pending_action_result(sealed_action)
        self.assertEqual(started["action_id"], reopened["action_id"])
        self.assertEqual("WO-001", reopened["work_order"])

    def test_authorized_continuation_rejects_forged_cross_project_and_stale_values(self):
        """Break caught: a stale or cross-project projection is treated as authority."""
        action, completed = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        _path, sealed_action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        continuation = loom_orchestrator.authorized_continuation(
            sealed_action, rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
            owner_home=self.home, install_root=self.installed)

        malformed = {**continuation, "unexpected": True}
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.validate_authorized_continuation(malformed)
        forged = {**continuation, "project_id": "p-" + "f" * 32}
        forged.pop("continuation_sha256")
        forged["continuation_sha256"] = hashlib.sha256(json.dumps(
            forged, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("utf-8")).hexdigest()
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.verify_authorized_continuation(
                sealed_action, forged,
                expected_rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
                owner_home=self.home, install_root=self.installed)
        cross_generation = {
            **continuation, "generation_id": "generation-" + "e" * 32}
        cross_generation.pop("continuation_sha256")
        cross_generation["continuation_sha256"] = hashlib.sha256(json.dumps(
            cross_generation, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.verify_authorized_continuation(
                sealed_action, cross_generation,
                expected_rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
                owner_home=self.home, install_root=self.installed)

        envelope_root = Path(started["action_path"]).parent / \
            "lifecycle-transitions"
        unresolved = envelope_root / "task5-unresolved.json"
        unresolved.write_text(
            json.dumps({"status": "prepared"}) + "\n", encoding="utf-8")
        self.assertIsNone(loom_orchestrator.authorized_continuation(
            sealed_action, rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
            owner_home=self.home, install_root=self.installed))
        unresolved.unlink()

        (self.repo / "src" / "app.py").write_text(
            "print('world changed')\n", encoding="utf-8")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator.verify_authorized_continuation(
                sealed_action, continuation,
                expected_rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
                owner_home=self.home, install_root=self.installed)
        self.assertEqual("AUTHORIZED_CONTINUATION_STALE", caught.exception.code)

        forged_code = {
            **continuation, "rejection_code": "FORGED_EXECUTOR_PERMISSION"}
        forged_code.pop("continuation_sha256")
        forged_code["continuation_sha256"] = hashlib.sha256(json.dumps(
            forged_code, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.verify_authorized_continuation(
                sealed_action, forged_code,
                expected_rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
                owner_home=self.home, install_root=self.installed)

        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.verify_authorized_continuation(
                sealed_action, continuation,
                expected_rejection_code="OUTSIDE_PROJECT_TARGET",
                owner_home=self.home, install_root=self.installed)

        loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertIsNone(loom_orchestrator.authorized_continuation(
            sealed_action, rejection_code="UNAUTHORIZED_PROJECT_TOUCH",
            owner_home=self.home, install_root=self.installed))

    def test_authorized_continuation_requires_canonical_resolved_envelopes(self):
        """Break caught: a corrupt completed envelope is trusted by its status."""
        action, completed = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        source_root = Path(started["action_path"]).parent / \
            "lifecycle-transitions"
        source_envelopes = []
        completed_envelope_paths = []
        for path in source_root.glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("status") == "completed":
                completed_envelope_paths.append(path)
                if "kind" not in value:
                    source_envelopes.append(value)
        self.assertTrue(source_envelopes)
        self.assertTrue(completed_envelope_paths)
        canonical = source_envelopes[-1]
        probe = self.root / "envelope-probe"
        transitions = probe / "lifecycle-transitions"
        transitions.mkdir(parents=True)
        path = transitions / "probe.json"

        for index, source_path in enumerate(completed_envelope_paths):
            with self.subTest(kind="renamed completed", source=source_path.name):
                alias = transitions / f"renamed-{index}.json"
                alias.write_bytes(source_path.read_bytes())
                self.assertTrue(
                    loom_orchestrator._unresolved_lifecycle_envelope(probe))
                alias.unlink()

        canonical_path = loom_lifecycle_transition._envelope_path(
            transitions, canonical["command_id"])
        canonical_bytes = json.dumps(canonical).encode("utf-8") + b"\n"
        canonical_path.write_bytes(canonical_bytes)
        self.assertFalse(
            loom_orchestrator._unresolved_lifecycle_envelope(probe))
        alias = transitions / "duplicate-command.json"
        alias.write_bytes(canonical_bytes)
        self.assertTrue(
            loom_orchestrator._unresolved_lifecycle_envelope(probe))
        canonical_path.unlink()
        alias.unlink()

        corrupt_completed = json.loads(json.dumps(canonical))
        corrupt_completed["command_sha256"] = "0" * 64
        corrupt_abandoned = json.loads(json.dumps(canonical))
        corrupt_abandoned["status"] = "abandoned"
        corrupt_abandoned["target_witness"]["authoritative_sha256"] = "0" * 64
        bad_receipt = json.loads(json.dumps(canonical))
        bad_receipt["receipt"]["command_id"] = "foreign-completion"
        bad_receipt["receipt"]["receipt_sha256"] = \
            loom_lifecycle_kernel.digest({
                key: value for key, value in bad_receipt["receipt"].items()
                if key != "receipt_sha256"})
        cases = {
            "corrupt completed": json.dumps(corrupt_completed),
            "corrupt abandoned": json.dumps(corrupt_abandoned),
            "foreign self-consistent receipt": json.dumps(bad_receipt),
            "duplicate keys": '{"status":"completed","status":"abandoned"}',
            "unknown kind": json.dumps({
                "schema_version": 1, "kind": "unknown-v1",
                "command_id": "unknown", "status": "completed"}),
            "truncated": '{"schema_version":1',
        }
        for label, raw in cases.items():
            with self.subTest(label=label):
                path.write_text(raw + "\n", encoding="utf-8")
                self.assertTrue(
                    loom_orchestrator._unresolved_lifecycle_envelope(probe))

        path.write_text(json.dumps({
            "schema_version": 1,
            "kind": "successor-activation-v1",
            "command_id": "candidate-switch",
            "status": "completed",
            "projection_status": "pending",
        }) + "\n", encoding="utf-8")
        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition,
                "_load_successor_envelope", return_value={
                    "status": "completed", "projection_status": "pending"}):
            self.assertTrue(
                loom_orchestrator._unresolved_lifecycle_envelope(probe))

    def test_real_hook_denial_preserves_exact_action_and_allowed_completion(self):
        """Break caught: the hook denial has no real supported continuation."""
        action, completed = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        action_path = Path(started["action_path"])
        _sealed_path, sealed_action, sealed_security = \
            loom_orchestrator._read_action(
                action_path, owner_home=self.home,
                install_root=self.installed)
        directory = action_path.parent
        loom_executor_guard.observe_post(
            directory, sealed_action, {
                "hook_event_name": "PostToolUse", "cwd": str(self.repo),
                "session_id": "real-hook-session", "turn_id": "start-turn",
                "tool_use_id": "start-hook", "tool_name": "mcp__loom__start",
                "tool_input": {},
            }, lifecycle_control=True, security=sealed_security)
        resolved = loom_plan_store.resolve(self.repo)
        control_paths = [
            self.repo / "src" / "app.py",
            self.repo / "plans" / loom_plan_store.INDEX_NAME,
            resolved.generation_root / "lifecycle.json",
            directory / "lifecycle-head-witness.json",
            action_path,
            directory / loom_orchestrator.ACTIVE_POINTER_FILE,
        ]

        def snapshot():
            return {
                str(path): path.read_bytes() if path.exists() else None
                for path in control_paths
            }

        def hook(path, tool_use_id, *, event_name="PreToolUse"):
            event = {
                "hook_event_name": event_name,
                "cwd": str(self.repo),
                "session_id": "real-hook-session",
                "turn_id": "real-hook-turn",
                "tool_use_id": tool_use_id,
                "tool_name": "Write",
                "tool_input": {"file_path": path},
            }
            with mock.patch.object(
                    loom_codex_lifecycle, "_active_action",
                    return_value=(sealed_action, sealed_security)), \
                    mock.patch.object(loom_codex_lifecycle, "_record"):
                return loom_codex_lifecycle.handle(
                    event, home=self.home, install_root=self.installed)

        baseline = snapshot()
        work_order = self.repo.joinpath(
            *PurePosixPath(started[
                "execution_completion_contract"]["work_order_path"]).parts)
        denied_attempts = {
            "outside touch": "docs/outside.py",
            "acceptance weakening or omitted work":
                work_order.relative_to(self.repo).as_posix(),
            "architecture substitution": "architecture/alternate.py",
            "invented extra work": "src/unplanned_extra.py",
            "repair or refactor loophole": "repairs/shortcut.py",
            "executor replanning": "plans/plan-semantics.json",
        }
        for ordinal, (label, path) in enumerate(denied_attempts.items()):
            with self.subTest(label=label):
                code, output = hook(path, f"denied-{ordinal}")
                self.assertEqual(0, code)
                self.assertEqual(
                    "deny", output["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    "continue current execution",
                    output["hookSpecificOutput"]["additionalContext"].lower())
                self.assertEqual(baseline, snapshot())

        premature = loom_orchestrator.complete(
            action_path, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("blocked", premature["status"])
        self.assertEqual("execute-not-ready", premature["code"])
        self.assertEqual(baseline, snapshot())

        allowed_code, allowed_output = hook("src/app.py", "allowed-write")
        self.assertEqual(0, allowed_code)
        self.assertIsNone(allowed_output)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        post_code, post_output = hook(
            "src/app.py", "allowed-write", event_name="PostToolUse")
        self.assertEqual(0, post_code)
        self.assertIsNone(post_output)
        after_allowed = snapshot()
        self.assertNotEqual(baseline[str(self.repo / "src" / "app.py")],
                            after_allowed[str(self.repo / "src" / "app.py")])
        for path in control_paths[1:]:
            self.assertEqual(baseline[str(path)], after_allowed[str(path)])

        acceptance_weakening = loom_orchestrator.complete(
            action_path, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("blocked", acceptance_weakening["status"])
        self.assertEqual("execute-not-ready", acceptance_weakening["code"])
        self.assertEqual(after_allowed, snapshot())

        contract = started["execution_completion_contract"]
        text = work_order.read_text(encoding="utf-8")
        text = text.replace("status: in-progress", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(contract["evidence_capture"]["pack_path"]), self.repo,
            contract["work_order_id"], medium="python-unittest",
            command=[sys.executable, "-c", "print('verification passed')"])
        sealed = loom_orchestrator.complete(
            action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("completed", sealed["status"])
        self.assertEqual("execute-complete", sealed["code"])

    def test_exact_plan_start_completion_contract_closes_verified_work(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=prior["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(contract["work_order_path"]).parts)

        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        text = work_order.read_text(encoding="utf-8")
        text = text.replace(
            "status: in-progress", f"status: {contract['required_status']}")
        text = text.replace("- [ ]", contract["acceptance_marker"])
        text = text.replace(
            contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(contract["evidence_capture"]["pack_path"]), self.repo,
            contract["work_order_id"],
            medium="python-unittest",
            command=[sys.executable, "-c", "print('verification passed')"])
        sealed = loom_orchestrator.complete(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", sealed["status"])
        self.assertEqual("execute-complete", sealed["code"])

    def test_next_invocation_recovers_committed_completion_and_finishes_session(self):
        """Break caught: a committed completion leaves its action permanently pending."""
        action, completed = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(contract["work_order_path"]).parts)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        text = work_order.read_text(encoding="utf-8")
        text = text.replace("status: in-progress", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(contract["evidence_capture"]["pack_path"]), self.repo,
            contract["work_order_id"], medium="python-unittest",
            command=[sys.executable, "-c", "print('verification passed')"])
        real_transition = loom_orchestrator.loom_lifecycle_transition.transition

        def interrupt_completion(*args, **kwargs):
            if args[1]["relation"] == "complete-active":
                kwargs["fault_at"] = "after-project-commit"
            return real_transition(*args, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition, "transition",
                side_effect=interrupt_completion):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.complete(
                    started["action_path"], owner_home=self.home,
                    install_root=self.installed)

        resolved = loom_plan_store.resolve(self.repo)
        evidence_path = (
            resolved.generation_root / "completion-evidence" /
            f"{contract['work_order_id']}.json")
        self.assertFalse(evidence_path.exists())
        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", status["status"])
        self.assertTrue(evidence_path.is_file())
        _path, recovered_action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("pending", recovered_action["status"])
        self.assertEqual(
            "completed", recovered_action["lifecycle_transition"]["status"])

        sealed = loom_orchestrator.complete(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", sealed["status"])
        self.assertEqual("execute-complete", sealed["code"])
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        event_types = [item["event_type"] for item in ledger["events"]]
        self.assertEqual(1, event_types.count("work-order-completed"))
        self.assertEqual(1, event_types.count("generation-completed"))

    def test_completed_v3_work_orders_advance_through_start_surface(self):
        """Every sealed frontier advances through either documented start reference."""
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        contract = opened["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Deliver three reviewed accounting steps",
            "summary": (
                "Change the implementation, document the result, then record its release."),
            "assumptions": ["The three reviewed steps remain strictly serial."],
            "decisions": [
                "Implementation must complete before documentation and release records."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped accounting adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [
                {
                    "title": "Implement the reviewed accounting change",
                    "outcome": "The bounded accounting behavior is implemented.",
                    "tasks": ["Change src/app.py.", "Run focused verification."],
                    "acceptance": ["The focused Python verification exits 0."],
                    "negative_acceptance": [
                        "A rejected posting leaves no partial result."],
                    "out_of_scope": ["Documentation and release work."],
                    "escalation": ["Stop if the product world changes unexpectedly."],
                    "touches": ["src/app.py"], "depends_on": [],
                    "routing": "strong-coding", "size": "S",
                },
                {
                    "title": "Document the verified accounting behavior",
                    "outcome": "README records the verified behavior.",
                    "tasks": ["Update README.md after implementation is complete."],
                    "acceptance": ["README names the verified behavior."],
                    "negative_acceptance": [
                        "Documentation cannot claim unverified behavior."],
                    "out_of_scope": ["Further implementation and release changes."],
                    "escalation": ["Stop if WO-001 lacks sealed completion."],
                    "touches": ["README.md"], "depends_on": ["WO-001"],
                    "routing": "strong-coding", "size": "S",
                },
                {
                    "title": "Record the verified accounting release",
                    "outcome": "CHANGELOG records only the verified behavior.",
                    "tasks": ["Update CHANGELOG.md after documentation is complete."],
                    "acceptance": ["CHANGELOG names the verified behavior."],
                    "negative_acceptance": [
                        "The release note cannot claim unverified behavior."],
                    "out_of_scope": ["Further implementation or documentation changes."],
                    "escalation": ["Stop if WO-002 lacks sealed completion."],
                    "touches": ["CHANGELOG.md"], "depends_on": ["WO-002"],
                    "routing": "strong-coding", "size": "S",
                },
            ],
            "domain_evidence": None,
        }
        loom_orchestrator.author(
            opened["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        planned = loom_orchestrator.complete(
            opened["action_path"], owner_home=self.home,
            install_root=self.installed)
        started = loom_orchestrator.start(
            opened["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        generation_id = loom_plan_store.resolve(self.repo).index.generation_id
        completion_contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(completion_contract["work_order_path"]).parts)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        text = work_order.read_text(encoding="utf-8")
        text = text.replace("status: in-progress", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            completion_contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(completion_contract["evidence_capture"]["pack_path"]), self.repo,
            "WO-001", medium="python-unittest",
            command=[sys.executable, "-c", "print('verification passed')"])
        first_completion = loom_orchestrator.complete(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("execute-complete", first_completion["code"])

        continued = loom_orchestrator.start(
            cwd=self.repo, owner_home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", continued["status"])
        self.assertEqual("execute", continued["intent"])
        self.assertEqual("WO-002", continued["work_order"])
        _path, continued_action, _security = loom_orchestrator._read_action(
            continued["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual(generation_id, continued_action["generation_id"])
        self.assertEqual(
            "continue-active", continued_action["request_control"]["relation"])
        resolved = loom_plan_store.resolve(self.repo)
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        event_types = [item["event_type"] for item in ledger["events"]]
        self.assertEqual(1, event_types.count("implementation-authorized"))
        self.assertEqual(2, event_types.count("work-order-started"))

        second_contract = continued["execution_completion_contract"]
        second_work_order = self.repo.joinpath(
            *PurePosixPath(second_contract["work_order_path"]).parts)
        readme = self.repo / "README.md"
        _write(readme, "Verified accounting behavior.\n")
        second_text = second_work_order.read_text(encoding="utf-8")
        second_text = second_text.replace("status: in-progress", "status: done")
        second_text = second_text.replace("- [ ]", "- [x]")
        second_text = second_text.replace(
            second_contract["pending_evidence_text"],
            "Evidence: documentation verification exited 0.")
        second_work_order.write_text(second_text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(second_contract["evidence_capture"]["pack_path"]), self.repo,
            "WO-002", medium="python-unittest",
            command=[sys.executable, "-c", "print('documentation verified')"])
        second_completion = loom_orchestrator.complete(
            continued["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("execute-complete", second_completion["code"])

        final = loom_orchestrator.start(
            opened["action_path"],
            presentation_sha256=planned["plan_presentation"][
                "presentation_sha256"],
            owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("WO-003", final["work_order"])
        _final_path, final_action, _final_security = loom_orchestrator._read_action(
            final["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual(generation_id, final_action["generation_id"])
        self.assertEqual(
            "continue-active", final_action["request_control"]["relation"])

        final_contract = final["execution_completion_contract"]
        final_work_order = self.repo.joinpath(
            *PurePosixPath(final_contract["work_order_path"]).parts)
        _write(self.repo / "CHANGELOG.md", "Verified accounting behavior.\n")
        final_text = final_work_order.read_text(encoding="utf-8")
        final_text = final_text.replace("status: in-progress", "status: done")
        final_text = final_text.replace("- [ ]", "- [x]")
        final_text = final_text.replace(
            final_contract["pending_evidence_text"],
            "Evidence: release-note verification exited 0.")
        final_work_order.write_text(final_text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(final_contract["evidence_capture"]["pack_path"]), self.repo,
            "WO-003", medium="python-unittest",
            command=[sys.executable, "-c", "print('release note verified')"])
        terminal = loom_orchestrator.complete(
            final["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("execute-complete", terminal["code"])
        final_ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            "generation-completed", final_ledger["events"][-1]["event_type"])

    def test_exact_start_updates_only_the_manifest_frontier_table(self):
        """Break caught: routing rows make a valid multi-WO start unrecoverable."""
        opened = loom_orchestrator.invoke(
            request=(
                "Plan an ETL and machine-learning pipeline with schema evolution, "
                "backfills, lineage, reproducibility, monitoring, recovery, release "
                "rollback, maintenance, and documentation. Plan the work only and "
                "do not implement it yet."),
            cwd=self.repo, home=self.home, install_root=self.installed)
        self.assertEqual("L", opened["tier"])
        contract = opened["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Deliver a reviewed data and model pipeline",
            "summary": "Implement ingestion, model verification, and documentation serially.",
            "assumptions": ["The three reviewed steps remain strictly serial."],
            "decisions": ["Model verification follows replay-safe ingestion."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped domain adapter",
            } for item in contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [
                {
                    "title": "Make ingestion replay safe",
                    "outcome": "Ingestion preserves schema, lineage, and idempotency.",
                    "tasks": ["Implement replay-safe ingestion.", "Run focused verification."],
                    "acceptance": ["The focused Python verification exits 0."],
                    "negative_acceptance": [
                        "A rejected record never enters the accepted dataset."],
                    "out_of_scope": ["Model training and documentation."],
                    "escalation": ["Stop if the product world changes."],
                    "touches": ["src/etl/**", "tests/etl/**"], "depends_on": [],
                    "routing": "strong-coding", "size": "S",
                },
                {
                    "title": "Prove reproducible model behavior",
                    "outcome": "Training and inference are reproducible and monitored.",
                    "tasks": ["Bind model inputs and artifacts.", "Test recovery behavior."],
                    "acceptance": ["Reproducibility and recovery verification exits 0."],
                    "negative_acceptance": [
                        "Leakage or train-serve skew blocks release."],
                    "out_of_scope": ["Documentation."],
                    "escalation": ["Stop if WO-001 lacks sealed completion."],
                    "touches": ["src/ml/**", "tests/ml/**"],
                    "depends_on": ["WO-001"],
                    "routing": "specialist", "size": "M",
                },
                {
                    "title": "Document the verified pipeline",
                    "outcome": "README documents only the verified pipeline behavior.",
                    "tasks": ["Update README.md.", "Perform a read-only audit."],
                    "acceptance": ["The documentation audit exits 0."],
                    "negative_acceptance": [
                        "Documentation cannot claim unverified behavior."],
                    "out_of_scope": ["Further implementation changes."],
                    "escalation": ["Stop if WO-002 lacks sealed completion."],
                    "touches": ["README.md"], "depends_on": ["WO-002"],
                    "routing": "strong-coding", "size": "S",
                },
            ],
            "domain_evidence": None,
        }
        loom_orchestrator.author(
            opened["action_path"], draft, owner_home=self.home,
            install_root=self.installed)
        planned = loom_orchestrator.complete(
            opened["action_path"], owner_home=self.home,
            install_root=self.installed)
        resolved = loom_plan_store.resolve(self.repo)
        manifest_path = resolved.generation_root / "MANIFEST.md"
        before = manifest_path.read_text(encoding="utf-8")
        self.assertIn("## Routing snapshot", before)
        self.assertIn("## Work order frontier", before)
        self.assertGreaterEqual(before.count("| WO-001 |"), 2)

        started = loom_orchestrator.start(
            opened["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("WO-001", started["work_order"])
        after = manifest_path.read_text(encoding="utf-8")
        routing = loom_lint.parse_markdown_table(after, "Routing snapshot")
        frontier = loom_lint.parse_markdown_table(after, "Work order frontier")
        self.assertEqual("none", routing[0]["depends on"])
        self.assertEqual("in-progress", frontier[0]["status"])
        self.assertEqual("blocked", frontier[1]["status"])
        self.assertEqual("blocked", frontier[2]["status"])

    def test_projection_rejects_duplicate_manifest_frontier_sections(self):
        """Break caught: an ambiguous second frontier escapes projection checks."""
        with tempfile.TemporaryDirectory() as temporary:
            pack = Path(temporary)
            work_orders = pack / "work-orders"
            work_orders.mkdir()
            policy = loom_plan_author._execution_policy()
            (pack / "MANIFEST.md").write_text(
                "---\n"
                "status: gated\n"
                f"execution_policy: {policy.execution_policy}\n"
                "execution_sequence: [WO-001]\n"
                f"execution_policy_sha256: {policy.policy_sha256}\n"
                "---\n"
                "## Work order frontier\n"
                "| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |\n"
                "|---|---|---|---|---|---|\n"
                "| WO-001 | ready | strong-coding | — | — | — |\n"
                "## Work order frontier\n"
                "| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |\n"
                "|---|---|---|---|---|---|\n"
                "| WO-001 | ready | strong-coding | — | — | — |\n",
                encoding="utf-8")
            (work_orders / "WO-001-example.md").write_text(
                "---\nid: WO-001\nstatus: ready\n---\n",
                encoding="utf-8")
            state = types.SimpleNamespace(
                generation_phase="reviewable",
                graph=types.SimpleNamespace(execution_sequence=("WO-001",)))
            projection = {"work_order_statuses": {"WO-001": "ready"}}

            with mock.patch.object(
                    loom_orchestrator.loom_lifecycle_kernel, "project",
                    return_value=projection):
                with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
                    loom_orchestrator._write_v3_pack_projection(pack, state)

            self.assertEqual("PLAN_PROJECTION_INVALID", raised.exception.code)

    def test_repair_supersession_waits_for_exact_open_operation_closure(self):
        """Repair cannot retire a live executor while a guarded write is open."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action = self.arm_executor_guard(started)
        write_event = {
            "hook_event_name": "PreToolUse", "cwd": str(self.repo),
            "session_id": "host-session-1", "turn_id": "host-turn-2",
            "tool_use_id": "write-before-repair", "tool_name": "Write",
            "tool_input": {"file_path": "src/app.py"},
        }
        loom_executor_guard.begin_operation(
            path.parent, action, write_event,
            operation_kind="structured-write")
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")

        with self.assertRaises(loom_orchestrator.OrchestratorError) as pending:
            loom_orchestrator.invoke(
                request="Repair the broken Loom lifecycle.", cwd=self.repo,
                home=self.home, install_root=self.installed)

        self.assertEqual("EXECUTOR_QUIESCENCE_REQUIRED", pending.exception.code)
        _path, still_active, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", still_active["status"])
        self.assertEqual(
            still_active["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])
        self.assertEqual(
            "repair-supersede",
            loom_executor_guard.read(path.parent, still_active)[
                "freeze"]["reason_code"])

        loom_executor_guard.observe_post(
            path.parent, still_active,
            {**write_event, "hook_event_name": "PostToolUse"})
        repairing = loom_orchestrator.invoke(
            request="Repair the broken Loom lifecycle.", cwd=self.repo,
            home=self.home, install_root=self.installed)
        self.assertEqual("action-required", repairing["status"])
        self.assertEqual("repair", repairing["intent"])
        _path, retired, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", retired["status"])

    def test_cancelled_attempt_can_be_repaired_and_resumed_without_replanning(self):
        """Break caught: explicit v3 repair falls into the historical pack reconciler."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        self.arm_executor_guard(started)
        loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")

        repairing = loom_orchestrator.invoke(
            request="Repair the broken Loom lifecycle.", cwd=self.repo,
            home=self.home, install_root=self.installed)

        self.assertEqual("action-required", repairing["status"])
        self.assertEqual("repair", repairing["intent"])
        self.assertEqual(
            ["active-work-order"],
            repairing["repair_plan"]["affected_plan_sections"])
        repair_result = self.root / "repair-result.json"
        _write(repair_result, json.dumps({
            "schema_version": 2,
            "repair_verification": [{
                "section": "active-work-order",
                "medium": "python-unittest",
                "command": [
                    sys.executable, "-c", "print('repair verified')"],
                "timeout_seconds": 30,
            }],
        }) + "\n")
        repaired = loom_orchestrator.complete(
            repairing["action_path"], result_path=repair_result,
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("completed", repaired["status"])
        self.assertEqual("repair-complete", repaired["code"])
        continued = loom_orchestrator.invoke(
            request="Continue the active work.", cwd=self.repo,
            home=self.home, install_root=self.installed)
        self.assertEqual("action-required", continued["status"])
        self.assertEqual("execute", continued["intent"])
        ledger = json.loads(
            (loom_plan_store.resolve(self.repo).generation_root /
             "lifecycle.json").read_text(encoding="utf-8"))
        event_types = [item["event_type"] for item in ledger["events"]]
        self.assertEqual(1, event_types.count("repair-authorized"))
        self.assertEqual(1, event_types.count("repair-completed"))
        self.assertEqual(1, event_types.count("work-order-resumed"))

    def test_next_invocation_recovers_committed_repair_action_and_pointer(self):
        """A committed repair authorization cannot lose its owner-side attempt."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        self.arm_executor_guard(started)
        loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        real_transition = loom_orchestrator.loom_lifecycle_transition.transition

        def interrupt_repair(*args, **kwargs):
            if args[1]["relation"] == "repair-active":
                kwargs["fault_at"] = "after-project-commit"
            return real_transition(*args, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition, "transition",
                side_effect=interrupt_repair):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.invoke(
                    request="Repair the broken Loom lifecycle.", cwd=self.repo,
                    home=self.home, install_root=self.installed)

        transition_root = (
            Path(plan_action["action_path"]).parent / "lifecycle-transitions")
        envelopes = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in transition_root.glob("*.json")
        ]
        repair_envelopes = [
            value for value in envelopes
            if value.get("command", {}).get("relation") == "repair-active"]
        self.assertEqual(1, len(repair_envelopes))
        repair_action_id = repair_envelopes[0]["command"]["action_id"]
        repair_action_path = transition_root.parent / (repair_action_id + ".json")
        self.assertFalse(repair_action_path.exists())

        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", status["status"])
        _path, repaired_action, _security = loom_orchestrator._read_action(
            repair_action_path, owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("repair", repaired_action["intent"])
        self.assertIsNotNone(repaired_action["repair_plan"])
        self.assertIsNotNone(repaired_action["initial_pack_hash"])
        self.assertEqual(
            "completed", repaired_action["lifecycle_transition"]["status"])
        pointer = loom_orchestrator._read_active_pointer(
            repair_action_path.parent)
        self.assertEqual(repair_action_id, pointer["action_id"])
        ledger = json.loads(
            (loom_plan_store.resolve(self.repo).generation_root /
             "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            1,
            [item["event_type"] for item in ledger["events"]].count(
                "repair-authorized"))

    def test_next_invocation_recovers_committed_repair_completion(self):
        """A committed repair completion is replayable after projection loss."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        self.arm_executor_guard(started)
        loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        repairing = loom_orchestrator.invoke(
            request="Repair the broken Loom lifecycle.", cwd=self.repo,
            home=self.home, install_root=self.installed)
        repair_result = self.root / "repair-recovery-result.json"
        _write(repair_result, json.dumps({
            "schema_version": 2,
            "repair_verification": [{
                "section": "active-work-order",
                "medium": "python-unittest",
                "command": [
                    sys.executable, "-c", "print('repair verified')"],
                "timeout_seconds": 30,
            }],
        }) + "\n")
        real_transition = loom_orchestrator.loom_lifecycle_transition.transition

        def interrupt_completion(*args, **kwargs):
            if args[1]["relation"] == "repair-complete":
                kwargs["fault_at"] = "after-project-commit"
            return real_transition(*args, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition, "transition",
                side_effect=interrupt_completion):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.complete(
                    repairing["action_path"], result_path=repair_result,
                    owner_home=self.home, install_root=self.installed)

        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", status["status"])
        _path, recovered, _security = loom_orchestrator._read_action(
            repairing["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("pending", recovered["status"])
        self.assertEqual(
            "completed", recovered["lifecycle_transition"]["status"])

        repaired = loom_orchestrator.complete(
            repairing["action_path"], result_path=repair_result,
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("repair-complete", repaired["code"])
        ledger = json.loads(
            (loom_plan_store.resolve(self.repo).generation_root /
             "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            1,
            [item["event_type"] for item in ledger["events"]].count(
                "repair-completed"))

    def test_terminal_v3_generation_rolls_over_to_new_reviewed_work(self):
        """Break caught: terminal history blocks every legitimate new plan."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(contract["work_order_path"]).parts)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        text = work_order.read_text(encoding="utf-8")
        text = text.replace("status: in-progress", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(contract["evidence_capture"]["pack_path"]), self.repo,
            "WO-001", medium="python-unittest",
            command=[sys.executable, "-c", "print('verified')"])
        loom_orchestrator.complete(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        prior = loom_plan_store.resolve(self.repo)
        prior_generation_id = prior.generation_id
        prior_manifest = loom_reliability.exact_tree_manifest(
            prior.generation_root)

        replacement = loom_orchestrator.invoke(
            request=(
                "Plan a financial accounting documentation feature for README.md. "
                "Planning only; do not implement."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", replacement["status"])
        self.assertEqual("plan", replacement["intent"])
        self.assertEqual(
            prior_generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        next_contract = replacement["plan_contract"]
        next_draft = {
            "schema_version": 1,
            "title": "Document the completed behavior",
            "summary": "Add bounded local documentation for the completed behavior.",
            "assumptions": ["README.md is the requested documentation target."],
            "decisions": ["Keep the new generation documentation-only."],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped domain evidence",
            } for item in next_contract["current_facts_to_verify"]],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Add the reviewed README section",
                "outcome": "README contains the reviewed local documentation.",
                "tasks": ["Add the bounded README section."],
                "acceptance": ["README contains the reviewed section."],
                "negative_acceptance": ["No implementation file changes."],
                "out_of_scope": ["Product implementation and release work."],
                "escalation": ["Stop if implementation files must change."],
                "touches": ["README.md"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }
        loom_orchestrator.author(
            replacement["action_path"], next_draft,
            owner_home=self.home, install_root=self.installed)
        completed_replacement = loom_orchestrator.complete(
            replacement["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("plan-complete", completed_replacement["code"])
        current = loom_plan_store.resolve(self.repo)
        self.assertNotEqual(prior_generation_id, current.generation_id)
        self.assertEqual(
            prior_manifest,
            loom_reliability.exact_tree_manifest(prior.generation_root))

    def test_reviewable_generation_can_be_cancelled_without_an_active_action(self):
        """Break caught: a valid blocking plan has no action-level cancel target."""
        plan_action, _planned = self.complete_machine_authored_plan()
        action_path = Path(plan_action["action_path"])
        stored_before = action_path.read_bytes()
        resolved_before = loom_plan_store.resolve(self.repo)
        semantics_before = (
            resolved_before.generation_root / "plan-semantics.json").read_bytes()
        self.assertIsNone(
            loom_orchestrator._read_active_pointer(action_path.parent))

        cancelled = loom_orchestrator.invoke(
            request="Cancel the current reviewed Loom plan.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("generation-cancelled", cancelled["code"])
        self.assertEqual("completed", cancelled["status"])
        self.assertTrue(cancelled["success"])
        resolved_after = loom_plan_store.resolve(self.repo)
        self.assertEqual(resolved_before.generation_id, resolved_after.generation_id)
        self.assertEqual(
            semantics_before,
            (resolved_after.generation_root / "plan-semantics.json").read_bytes())
        ledger = json.loads(
            (resolved_after.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual("generation-cancelled", ledger["events"][-1]["event_type"])
        self.assertEqual(stored_before, action_path.read_bytes())
        self.assertIsNone(
            loom_orchestrator._read_active_pointer(action_path.parent))

    def test_active_generation_cancel_freezes_without_terminal_host_proof(self):
        """Break caught: generation cancellation erases a live executor authority."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        action_path = Path(started["action_path"])
        guard_path, guarded = self.arm_executor_guard(started)
        loom_executor_guard.begin_operation(
            guard_path.parent, guarded, {
                "hook_event_name": "PreToolUse", "cwd": str(self.repo),
                "session_id": "host-session-1", "turn_id": "host-turn-cancel",
                "tool_use_id": "write-before-generation-cancel",
                "tool_name": "Write",
                "tool_input": {"file_path": "src/app.py"},
            }, operation_kind="structured-write")
        before = loom_plan_store.resolve(self.repo)
        before_ledger = json.loads(
            (before.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))

        pending = loom_orchestrator.invoke(
            request="Cancel the current Loom plan generation.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", pending["status"])
        self.assertEqual("EXECUTOR_QUIESCENCE_REQUIRED", pending["code"])
        after = loom_plan_store.resolve(self.repo)
        self.assertEqual(before.generation_id, after.generation_id)
        self.assertEqual(
            before_ledger,
            json.loads((after.generation_root / "lifecycle.json").read_text(
                encoding="utf-8")))
        path, action, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", action["status"])
        self.assertEqual(
            action["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])
        self.assertEqual(
            "generation-cancel",
            loom_executor_guard.read(
                path.parent, action)["freeze"]["reason_code"])

    def test_active_generation_cancel_uses_exact_closed_host_guard(self):
        """Break caught: no production path writes generation quiescence evidence."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        loom_executor_guard.observe_post(
            path.parent, action, {
                "hook_event_name": "PostToolUse", "cwd": str(self.repo),
                "session_id": "host-session-1", "turn_id": "host-turn-1",
                "tool_use_id": "start-1", "tool_name": "mcp__loom__start",
                "tool_input": {},
            }, lifecycle_control=True)

        cancelled = loom_orchestrator.invoke(
            request="Cancel the current Loom plan generation.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("generation-cancelled", cancelled["code"])
        resolved = loom_plan_store.resolve(self.repo)
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual("generation-cancelled", ledger["events"][-1]["event_type"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        _path, terminal, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", terminal["status"])
        evidence = terminal["host_result"]["executor_quiescence"]
        self.assertEqual("verified-host-terminal", evidence["case"])
        loom_executor_guard.validate_evidence(
            path.parent, terminal, evidence,
            project_world_sha256=evidence["project_world_sha256"])

    def test_terminal_generation_recovery_revalidates_frozen_host_evidence(self):
        """Break caught: restart clears a prepared terminal transition unchecked."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        loom_executor_guard.observe_post(
            path.parent, action, {
                "hook_event_name": "PostToolUse", "cwd": str(self.repo),
                "session_id": "host-session-1", "turn_id": "host-turn-1",
                "tool_use_id": "start-1", "tool_name": "mcp__loom__start",
                "tool_input": {},
            }, lifecycle_control=True)
        real_transition = loom_orchestrator.loom_lifecycle_transition.transition

        def interrupt_terminal(*args, **kwargs):
            if args[1]["relation"] == "cancel-generation":
                kwargs["fault_at"] = "after-project-commit"
            return real_transition(*args, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_lifecycle_transition, "transition",
                side_effect=interrupt_terminal), \
                self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.invoke(
                request="Cancel the current Loom plan generation.",
                cwd=self.repo, home=self.home, install_root=self.installed)

        _path, prepared, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", prepared["status"])
        self.assertEqual(
            prepared["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])
        self.assertEqual(
            "verified-host-terminal",
            prepared["host_result"]["executor_quiescence"]["case"])

        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", status["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        _path, recovered, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", recovered["status"])
        envelope = next(
            value for value in (
                json.loads(item.read_text(encoding="utf-8"))
                for item in (path.parent / "lifecycle-transitions").glob("*.json"))
            if value.get("command", {}).get("relation") == "cancel-generation")
        self.assertEqual("completed", envelope["status"])

    def test_terminal_generation_recovery_rejects_noncanonical_action_derivation(self):
        """Recovery accepts only the sealed pending action or its exact terminal form."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, _action = self.arm_executor_guard(started)
        real_write = loom_lifecycle_transition._write_envelope

        def interrupt_completion(envelope_path, value):
            if value.get("status") == "completed" \
                    and value.get("command", {}).get("relation") == \
                    "cancel-generation":
                raise loom_lifecycle_transition.LifecycleTransitionError(
                    "seeded envelope completion interruption")
            return real_write(envelope_path, value)

        with mock.patch.object(
                loom_lifecycle_transition, "_write_envelope",
                side_effect=interrupt_completion), \
                self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.invoke(
                request="Cancel the current Loom plan generation.",
                cwd=self.repo, home=self.home, install_root=self.installed)

        _path, terminal, security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", terminal["status"])
        terminal["attempts"] += 1
        loom_orchestrator._write_action(path, terminal, security)

        with self.assertRaises(loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request="Status", cwd=self.repo, home=self.home,
                install_root=self.installed)
        self.assertIn(
            blocked.exception.code,
            {"LIFECYCLE_PROJECTION_INVALID", "LIFECYCLE_TRANSITION_FAILED"})

    def test_generation_cancel_validates_executor_projection_before_plan_write(self):
        """Invalid private executor evidence cannot project a terminal plan first."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, _action = self.arm_executor_guard(started)
        before = loom_reliability.exact_tree_manifest(
            loom_plan_store.resolve(self.repo).generation_root)

        with mock.patch.object(
                loom_orchestrator, "_validate_executor_terminal_projection",
                side_effect=loom_orchestrator.OrchestratorError(
                    "LIFECYCLE_PROJECTION_INVALID",
                    "seeded private projection rejection")):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.invoke(
                    request="Cancel the current Loom plan generation.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(loom_reliability.exact_tree_manifests_equal(
            before, loom_reliability.exact_tree_manifest(
                loom_plan_store.resolve(self.repo).generation_root)))
        self.assertEqual(
            started["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])

    def test_exact_start_and_revision_race_has_one_live_attempt(self):
        """Start and revise serialize without splitting lifecycle authority."""
        plan_action, planned = self.complete_machine_authored_plan()
        presentation = planned["plan_presentation"]["presentation_sha256"]
        semantics_before = (
            loom_plan_store.resolve(self.repo).generation_root /
            "plan-semantics.json").read_bytes()
        real_resolve_intent = loom_orchestrator.loom_runtime.resolve_intent
        barrier = threading.Barrier(2)
        counter_lock = threading.Lock()
        calls = 0

        def gated_resolve_intent(*args, **kwargs):
            nonlocal calls
            result = real_resolve_intent(*args, **kwargs)
            with counter_lock:
                calls += 1
                wait = calls <= 2
            if wait:
                barrier.wait(timeout=20)
            return result

        def attempt_start():
            try:
                return loom_orchestrator.start(
                    plan_action["action_path"],
                    presentation_sha256=presentation,
                    owner_home=self.home, install_root=self.installed)
            except loom_orchestrator.OrchestratorError as exc:
                return {"status": "rejected", "code": exc.code}

        def attempt_revision():
            try:
                return loom_orchestrator.revise(
                    plan_action["action_path"],
                    presentation_sha256=presentation,
                    request=(
                        "Revise the exact reviewed plan to clarify verification; "
                        "do not implement."),
                    owner_home=self.home, install_root=self.installed)
            except loom_orchestrator.OrchestratorError as exc:
                return {"status": "rejected", "code": exc.code}

        with mock.patch.object(
                loom_orchestrator.loom_runtime, "resolve_intent",
                side_effect=gated_resolve_intent), \
                ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda operation: operation(),
                (attempt_start, attempt_revision)))

        accepted = [
            item for item in outcomes if item.get("status") == "action-required"]
        self.assertEqual(1, len(accepted), outcomes)
        resolved = loom_plan_store.resolve(self.repo)
        self.assertEqual(
            semantics_before,
            (resolved.generation_root / "plan-semantics.json").read_bytes())
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        events = [item["event_type"] for item in ledger["events"]]
        self.assertLessEqual(events.count("implementation-authorized"), 1)
        self.assertLessEqual(events.count("work-order-started"), 1)
        pointer = loom_orchestrator._read_active_pointer(
            Path(plan_action["action_path"]).parent)
        self.assertIsNotNone(pointer)
        _path, live_action, _security = loom_orchestrator._read_action(
            Path(plan_action["action_path"]).parent /
            (pointer["action_id"] + ".json"),
            owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", live_action["status"])
        self.assertEqual(accepted[0]["intent"], live_action["intent"])

    def test_exact_start_and_generation_cancel_race_has_one_safe_linearization(self):
        """Concurrent start/cancel either retires review or freezes live execution."""
        plan_action, planned = self.complete_machine_authored_plan()
        presentation = planned["plan_presentation"]["presentation_sha256"]
        real_resolve_intent = loom_orchestrator.loom_runtime.resolve_intent
        barrier = threading.Barrier(2)
        counter_lock = threading.Lock()
        calls = 0

        def gated_resolve_intent(*args, **kwargs):
            nonlocal calls
            result = real_resolve_intent(*args, **kwargs)
            with counter_lock:
                calls += 1
                wait = calls <= 2
            if wait:
                barrier.wait(timeout=20)
            return result

        def attempt_start():
            try:
                return loom_orchestrator.start(
                    plan_action["action_path"],
                    presentation_sha256=presentation,
                    owner_home=self.home, install_root=self.installed)
            except loom_orchestrator.OrchestratorError as exc:
                return {"status": "rejected", "code": exc.code}

        def attempt_cancel():
            try:
                return loom_orchestrator.invoke(
                    request="Cancel the current reviewed Loom plan.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)
            except loom_orchestrator.OrchestratorError as exc:
                return {"status": "rejected", "code": exc.code}

        with mock.patch.object(
                loom_orchestrator.loom_runtime, "resolve_intent",
                side_effect=gated_resolve_intent), \
                ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda operation: operation(),
                (attempt_start, attempt_cancel)))

        cancelled = [
            item for item in outcomes
            if item.get("code") == "generation-cancelled"]
        resolved = loom_plan_store.resolve(self.repo)
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        events = [item["event_type"] for item in ledger["events"]]
        self.assertLessEqual(events.count("implementation-authorized"), 1)
        self.assertLessEqual(events.count("work-order-started"), 1)
        directory = Path(plan_action["action_path"]).parent
        pointer = loom_orchestrator._read_active_pointer(directory)
        if cancelled:
            self.assertEqual(1, len(cancelled), outcomes)
            self.assertEqual(1, events.count("generation-cancelled"))
            self.assertIsNone(pointer)
        else:
            waiting = [
                item for item in outcomes
                if item.get("code") == "EXECUTOR_QUIESCENCE_REQUIRED"]
            self.assertEqual(1, len(waiting), outcomes)
            self.assertEqual(0, events.count("generation-cancelled"))
            self.assertIsNotNone(pointer)
            _path, active, _security = loom_orchestrator._read_action(
                directory / (pointer["action_id"] + ".json"),
                owner_home=self.home, install_root=self.installed)
            self.assertEqual("pending", active["status"])
            self.assertEqual(
                "generation-cancel",
                loom_executor_guard.read(directory, active)[
                    "freeze"]["reason_code"])

    def test_two_concurrent_new_plans_leave_one_live_owner_attempt(self):
        """Independent new requests serialize to one recoverable planning frontier."""
        real_resolve_intent = loom_orchestrator.loom_runtime.resolve_intent
        barrier = threading.Barrier(2)
        counter_lock = threading.Lock()
        calls = 0

        def gated_resolve_intent(*args, **kwargs):
            nonlocal calls
            result = real_resolve_intent(*args, **kwargs)
            with counter_lock:
                calls += 1
                wait = calls <= 2
            if wait:
                barrier.wait(timeout=20)
            return result

        requests = (
            "Plan a new standalone src/alpha.py feature only; do not implement.",
            "Plan a new standalone src/beta.py feature only; do not implement.",
        )

        def invoke_plan(request):
            try:
                return loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)
            except loom_orchestrator.OrchestratorError as exc:
                return {"status": "rejected", "code": exc.code}

        with mock.patch.object(
                loom_orchestrator.loom_runtime, "resolve_intent",
                side_effect=gated_resolve_intent), \
                ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(invoke_plan, requests))

        accepted = [
            item for item in outcomes if item.get("status") == "action-required"]
        self.assertGreaterEqual(len(accepted), 1, outcomes)
        final = accepted[-1]
        directory = Path(final["action_path"]).parent
        pointer = loom_orchestrator._read_active_pointer(directory)
        self.assertIsNotNone(pointer)
        live = []
        for path in directory.glob("*.json"):
            if not re.fullmatch(r"[0-9a-f-]{36}\.json", path.name):
                continue
            _path, action, _security = loom_orchestrator._read_action(
                path, owner_home=self.home, install_root=self.installed)
            if action["status"] in {"initializing", "pending"}:
                live.append(action)
        self.assertEqual(1, len(live), outcomes)
        self.assertEqual(pointer["action_id"], live[0]["action_id"])
        self.assertEqual("plan", live[0]["intent"])
        self.assertFalse(
            (self.repo / "plans" / loom_plan_store.INDEX_NAME).exists())

    def test_status_reports_canonical_generation_without_an_active_action(self):
        """Break caught: clearing an attempt pointer makes the generation invisible."""
        plan_action, _planned = self.complete_machine_authored_plan()
        action_path = Path(plan_action["action_path"])
        self.assertIsNone(
            loom_orchestrator._read_active_pointer(action_path.parent))

        status = loom_orchestrator.invoke(
            request="Show the current Loom status.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("status-complete", status["code"])
        self.assertIn("generation_phase=reviewable", status["user_message"])
        self.assertIn("transition_observation=stable", status["user_message"])
        self.assertIn("authority_validity=owned-valid", status["user_message"])
        self.assertIn("work_order_frontier=selected", status["user_message"])

    def test_explicit_invalid_store_quarantine_restores_new_plan_recovery(self):
        """Break caught: corrupt project authority permanently blocks owner control."""
        plans = self.repo / "plans"
        plans.mkdir()
        (plans / "active-generation.json").write_text(
            "{\"schema_version\":1,\"schema_version\":2}\n", encoding="utf-8")
        (plans / "preserve-me.txt").write_text(
            "bounded invalid plan bytes\n", encoding="utf-8")

        quarantined = loom_orchestrator.invoke(
            request=(
                "Quarantine this invalid blocking Loom plan store without "
                "interpreting it."),
            cwd=self.repo, home=self.home, install_root=self.installed,
            transport_invocation_id="00000000-0000-4000-8000-000000000041")

        self.assertEqual("generation-quarantined", quarantined["code"])
        self.assertEqual("completed", quarantined["status"])
        self.assertFalse(plans.exists())
        public = json.dumps(quarantined, sort_keys=True)
        self.assertNotIn(str(self.root), public)
        self.assertNotIn("bounded invalid plan bytes", public)

        replacement = loom_orchestrator.invoke(
            request="Plan a new standalone README feature only; do not implement.",
            cwd=self.repo, home=self.home, install_root=self.installed)
        self.assertEqual("action-required", replacement["status"])
        self.assertEqual("plan", replacement["intent"])

    def test_explicit_new_plan_stages_candidate_without_superseding_active_generation(self):
        """Break caught: candidate planning terminalizes its predecessor before review."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        old_action_path = Path(started["action_path"])
        old_generation = loom_plan_store.resolve(self.repo)
        world_before = loom_orchestrator.loom_survey.workspace_snapshot(
            self.repo, exclude_prefixes=("plans",)).state.state_hash

        replacement = loom_orchestrator.invoke(
            request=(
                "Plan a new standalone documentation feature for README.md, not a "
                "repair or continuation. Planning only; do not implement."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", replacement["status"])
        self.assertEqual("plan", replacement["intent"])
        self.assertNotIn("prior_generation_transition", replacement)
        self.assertEqual(
            old_generation.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        old_ledger = json.loads(
            (old_generation.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertNotIn(
            "generation-superseded",
            [item["event_type"] for item in old_ledger["events"]])
        pointer = loom_orchestrator._read_active_pointer(old_action_path.parent)
        self.assertEqual(started["action_id"], pointer["action_id"])
        _old_path, old_action, _security = loom_orchestrator._read_action(
            old_action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", old_action["status"])
        _new_path, new_action, _new_security = loom_orchestrator._read_action(
            replacement["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertIn(
            "planning-candidate-successor",
            new_action["request_control"]["evidence"])
        self.assertEqual("supersede-generation", new_action["request_control"]["relation"])
        self.assertTrue(new_action["pack_seed"]["created_pack"])
        self.assertNotEqual(
            old_generation.generation_id, new_action["generation_id"])
        candidate_pack = loom_orchestrator._action_pack_root(new_action)
        self.assertFalse(candidate_pack.is_relative_to(self.repo))
        self.assertTrue(candidate_pack.is_relative_to(self.home))
        if os.name == "nt":
            loom_windows_acl.verify_private_directory(candidate_pack)
        else:
            self.assertEqual(0, candidate_pack.stat().st_mode & 0o077)
        world_after = loom_orchestrator.loom_survey.workspace_snapshot(
            self.repo, exclude_prefixes=("plans",)).state.state_hash
        self.assertEqual(world_before, world_after)

        completion_contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(completion_contract["work_order_path"]).parts)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        work_order_text = work_order.read_text(encoding="utf-8")
        work_order_text = work_order_text.replace(
            "status: in-progress", "status: done").replace("- [ ]", "- [x]")
        work_order_text = work_order_text.replace(
            completion_contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(work_order_text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(completion_contract["evidence_capture"]["pack_path"]), self.repo,
            "WO-001", medium="python-unittest",
            command=[sys.executable, "-c", "print('verified')"])
        continued = loom_orchestrator.complete(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("execute-complete", continued["code"])

    def test_candidate_private_stage_reliability_failures_preserve_predecessor(self):
        """Break caught: candidate staging bypasses private ACL/race refusal."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        predecessor = loom_plan_store.resolve(self.repo)
        before = loom_reliability.deterministic_manifest(self.repo)
        reliability_failures = (
            "owner-private ACL cannot be proven",
            "candidate ancestor is a symlink or junction",
            "candidate ancestor identity changed",
            "private stage leaf already exists; refusing to reuse it",
        )
        for index, failure in enumerate(reliability_failures, 1):
            with self.subTest(failure=failure), mock.patch.object(
                    loom_reliability, "reserve_private_stage_leaf",
                    side_effect=loom_reliability.ReliabilityError(failure)):
                with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
                    loom_orchestrator.invoke(
                        request=(
                            "Plan a new standalone documentation feature for README.md, "
                            "not a repair or continuation. Planning only; do not implement."),
                        cwd=self.repo, home=self.home, install_root=self.installed,
                        transport_invocation_id=(
                            f"00000000-0000-4000-8000-{index:012d}"))
                self.assertEqual("BASELINE_STAGING_CONFLICT", caught.exception.code)
                self.assertEqual(
                    predecessor.generation_id,
                    loom_plan_store.resolve(self.repo).generation_id)
                self.assertEqual(before, loom_reliability.deterministic_manifest(self.repo))
        pointer = loom_orchestrator._read_active_pointer(
            Path(started["action_path"]).parent)
        self.assertEqual(started["action_id"], pointer["action_id"])

    def test_successor_copy_rejects_identical_bytes_from_replaced_owner_stage(self):
        source = self.root / "owner-stage"
        source.mkdir()
        (source / "plan.md").write_text("reviewed candidate\n", encoding="utf-8")
        identity = loom_reliability.observe_root_identity(source)
        original = self.root / "original-owner-stage"
        source.rename(original)
        shutil.copytree(original, source)

        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError,
                "SUCCESSOR_INSTALL_PREPARATION_FAILED"):
            loom_orchestrator._copy_successor_install_stage(
                source, self.root / "reserved-successor",
                expected_source_identity=identity)

        self.assertEqual(
            "reviewed candidate\n",
            source.joinpath("plan.md").read_text(encoding="utf-8"))
        self.assertFalse((self.root / "reserved-successor").exists())

    def test_partial_successor_copy_preserves_nonempty_reservation(self):
        source = self.root / "owner-stage"
        source.mkdir()
        (source / "a.md").write_text("first\n", encoding="utf-8")
        (source / "z.md").write_text("second\n", encoding="utf-8")
        identity = loom_reliability.observe_root_identity(source)
        destination = self.root / "reserved-successor"
        original_copy = loom_orchestrator._copy_successor_entry
        calls = []

        def partial_copy(copy_source, reserved):
            calls.append(Path(copy_source).name)
            if len(calls) == 1:
                return original_copy(copy_source, reserved)
            raise shutil.Error([("source", "destination", "copy failed")])

        with mock.patch.object(
                loom_orchestrator, "_copy_successor_entry",
                side_effect=partial_copy), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._copy_successor_install_stage(
                source, destination, expected_source_identity=identity)

        self.assertEqual(
            "SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
        self.assertTrue(destination.exists())
        self.assertEqual(
            "first\n", destination.joinpath("a.md").read_text(
                encoding="utf-8"))

    def test_empty_successor_reservation_is_removed_with_rmdir(self):
        source = self.root / "empty-failure-source"
        source.mkdir()
        (source / "plan.md").write_text(
            "reviewed candidate\n", encoding="utf-8")
        destination = self.root / "empty-failure-reservation"
        with mock.patch.object(
                loom_orchestrator, "_copy_successor_entry",
                side_effect=shutil.Error([
                    ("source", "destination", "copy failed")])), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._copy_successor_install_stage(
                source, destination,
                expected_source_identity=
                loom_reliability.observe_root_identity(source))
        self.assertEqual(
            "SUCCESSOR_INSTALL_PREPARATION_FAILED", caught.exception.code)
        self.assertFalse(os.path.lexists(destination))

    def test_ambiguous_successor_reservation_is_preserved_and_blocks_cleanup(self):
        source = self.root / "owner-stage"
        source.mkdir()
        (source / "plan.md").write_text("reviewed candidate\n", encoding="utf-8")
        identity = loom_reliability.observe_root_identity(source)
        destination = self.root / "reserved-successor"

        def replace_reservation(_source, _destination):
            destination.rmdir()
            destination.mkdir()
            (destination / "unrelated.txt").write_text(
                "preserve ambiguous bytes\n", encoding="utf-8")
            raise shutil.Error([("source", "destination", "copy failed")])

        with mock.patch.object(
                loom_orchestrator, "_copy_successor_entry",
                side_effect=replace_reservation), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._copy_successor_install_stage(
                source, destination, expected_source_identity=identity)

        self.assertEqual("SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
        self.assertEqual(
            "preserve ambiguous bytes\n",
            destination.joinpath("unrelated.txt").read_text(encoding="utf-8"))

    def test_successor_cleanup_preserves_injected_or_replaced_entries(self):
        mutations = ("injected-child", "replaced-file", "changed-file",
                     "directory-swap", "hardlink", "redirect")
        for ordinal, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation):
                source = self.root / f"owner-stage-{ordinal}"
                nested = source / "nested"
                nested.mkdir(parents=True)
                (nested / "plan.md").write_text(
                    "reviewed candidate\n", encoding="utf-8")
                identity = loom_reliability.observe_root_identity(source)
                destination = self.root / f"reserved-successor-{ordinal}"
                copied = loom_orchestrator._copy_successor_install_stage(
                    source, destination, expected_source_identity=identity)
                target = destination / "nested" / "plan.md"
                if mutation == "injected-child":
                    (destination / "injected.txt").write_text(
                        "untracked\n", encoding="utf-8")
                elif mutation == "replaced-file":
                    content = target.read_bytes()
                    target.unlink()
                    target.write_bytes(content)
                elif mutation == "changed-file":
                    target.write_text("changed bytes\n", encoding="utf-8")
                elif mutation == "directory-swap":
                    old = destination / "nested-old"
                    (destination / "nested").rename(old)
                    (destination / "nested").mkdir()
                    (destination / "nested" / "plan.md").write_text(
                        "reviewed candidate\n", encoding="utf-8")
                elif mutation == "hardlink":
                    os.link(target, destination / "second-name.md")
                else:
                    with mock.patch.object(
                            loom_reliability, "_is_redirect",
                            side_effect=lambda path, _target=target:
                                Path(path) == _target):
                        with self.assertRaises(
                                loom_orchestrator.OrchestratorError) as caught:
                            loom_orchestrator._remove_owned_successor_reservation(
                                destination, copied["cleanup_ownership"])
                    self.assertEqual(
                        "SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
                    self.assertTrue(destination.exists())
                    continue

                with self.assertRaises(
                        loom_orchestrator.OrchestratorError) as caught:
                    loom_orchestrator._remove_owned_successor_reservation(
                        destination, copied["cleanup_ownership"])
                self.assertEqual(
                    "SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
                self.assertTrue(destination.exists())

    def test_successor_quarantine_revalidates_manifest_after_root_identity_aba(self):
        source = self.root / "aba-owner-stage"
        source.mkdir()
        (source / "plan.md").write_text(
            "reviewed candidate\n", encoding="utf-8")
        destination = self.root / "aba-reserved-successor"
        copied = loom_orchestrator._copy_successor_install_stage(
            source, destination,
            expected_source_identity=loom_reliability.observe_root_identity(
                source))

        shutil.rmtree(destination)
        destination.mkdir()
        (destination / "owner-recovery-required.txt").write_text(
            "unowned replacement\n", encoding="utf-8")
        collision = {
            **copied["cleanup_ownership"],
            "root_identity": loom_reliability.observe_root_identity(destination),
        }
        collision["ownership_sha256"] = loom_orchestrator._hash({
            key: value for key, value in collision.items()
            if key != "ownership_sha256"
        })
        owner_root = self.root / "owner-root"
        owner_root.mkdir()
        quarantine = owner_root / "project-state" / \
            loom_orchestrator.RECOVERY_DIRECTORY / "action" / "reservation"

        def prepare_recovery_root(_owner_root, recovery_root):
            Path(recovery_root).mkdir(parents=True)
            return Path(recovery_root)

        with mock.patch.object(
                loom_orchestrator, "_prepare_recovery_root",
                side_effect=prepare_recovery_root), self.assertRaises(
                    loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._release_failed_successor_reservation(
                destination, collision, quarantine=quarantine,
                owner_root=owner_root)

        self.assertEqual("SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
        self.assertEqual(
            "unowned replacement\n",
            destination.joinpath("owner-recovery-required.txt").read_text(
                encoding="utf-8"))
        self.assertFalse(os.path.lexists(quarantine))

    def test_failed_copy_preserves_source_identical_unjournaled_entries(self):
        for ordinal, mutation in enumerate(("file", "directory")):
            with self.subTest(mutation=mutation):
                source = self.root / f"copy-source-{ordinal}"
                nested = source / "nested"
                nested.mkdir(parents=True)
                (nested / "plan.md").write_text(
                    "reviewed candidate\n", encoding="utf-8")
                identity = loom_reliability.observe_root_identity(source)
                destination = self.root / f"copy-destination-{ordinal}"

                def inject_then_fail(copy_source, copy_destination):
                    copy_destination = Path(copy_destination)
                    if mutation == "file":
                        shutil.copy2(copy_source, copy_destination)
                    else:
                        copied_parent = copy_destination.parent
                        copied_parent.rmdir()
                        copied_parent.mkdir()
                    raise shutil.Error([
                        ("source", "destination", "copy failed")])

                with mock.patch.object(
                        loom_orchestrator, "_copy_successor_entry",
                        side_effect=inject_then_fail), \
                        self.assertRaises(
                            loom_orchestrator.OrchestratorError) as caught:
                    loom_orchestrator._copy_successor_install_stage(
                        source, destination,
                        expected_source_identity=identity)
                self.assertEqual(
                    "SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
                self.assertTrue(destination.exists())

    def test_successor_cleanup_never_pathname_deletes_nonempty_reservation(self):
        source = self.root / "unlink-race-source"
        source.mkdir()
        (source / "plan.md").write_text(
            "reviewed candidate\n", encoding="utf-8")
        destination = self.root / "unlink-race-destination"
        copied = loom_orchestrator._copy_successor_install_stage(
            source, destination,
            expected_source_identity=loom_reliability.observe_root_identity(
                source))
        target = destination / "plan.md"
        with mock.patch.object(
                Path, "unlink",
                side_effect=AssertionError(
                    "nonempty successor cleanup must never pathname-delete")) \
                as unlink, self.assertRaises(
                    loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._remove_owned_successor_reservation(
                destination, copied["cleanup_ownership"])
        self.assertEqual("SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)
        self.assertEqual(0, unlink.call_count)
        self.assertTrue(destination.exists())
        self.assertEqual(
            "reviewed candidate\n", target.read_text(encoding="utf-8"))

    def test_successor_attempt_reservations_are_unique_and_bounded(self):
        action = {
            "action_id": "a" * 32,
            "attempts": 0,
            "max_attempts": 3,
            "explicit_target": str(self.root),
            "cwd": str(self.root),
        }
        observed = []
        quarantines = []
        for attempt in range(action["max_attempts"]):
            action["attempts"] = attempt
            observed.append(loom_orchestrator._successor_install_reservation(
                self.root, action))
            quarantines.append(
                loom_orchestrator._successor_reservation_quarantine(
                    self.root / "orchestrations" / "action.json", action))
        self.assertEqual(3, len(set(observed)))
        self.assertEqual(3, len(set(quarantines)))
        self.assertEqual(
            [
                self.root / "plans" / (
                    f".successor-{action['action_id']}-attempt-{attempt}")
                for attempt in range(3)
            ],
            observed)
        action["attempts"] = action["max_attempts"]
        with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
            loom_orchestrator._successor_install_reservation(self.root, action)
        self.assertEqual("SUCCESSOR_INSTALL_AMBIGUOUS", caught.exception.code)

    def test_natural_replacement_plan_supersedes_changed_reviewable_generation(self):
        """Break caught: changed-world recovery requires parser-specific wording."""
        _plan_action, _planned = self.complete_machine_authored_plan()
        old_generation = loom_plan_store.resolve(self.repo)
        (self.repo / "external-world.txt").write_text(
            "out-of-band world change\n", encoding="utf-8")

        replacement = loom_orchestrator.invoke(
            request=(
                "Plan and present a fresh replacement reviewed against the "
                "current world, explicitly superseding the stale unstarted plan "
                "generation. Do not implement."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", replacement["status"])
        self.assertEqual("plan", replacement["intent"])
        _new_path, sealed_replacement, _security = \
            loom_orchestrator._read_action(
                replacement["action_path"], owner_home=self.home,
                install_root=self.installed)
        self.assertEqual(
            "supersede-generation",
            sealed_replacement["request_control"]["relation"])
        self.assertIn(
            "planning-current-world-replan",
            sealed_replacement["request_control"]["evidence"])
        self.assertNotIn("prior_generation_transition", replacement)
        old_ledger = json.loads(
            (old_generation.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertNotIn(
            "generation-superseded",
            [item["event_type"] for item in old_ledger["events"]])
        self.assertEqual(
            old_generation.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

    def test_inert_lifecycle_language_creates_no_candidate_plan_state(self):
        """Break caught: discussion, quotation, or negation stages a successor."""
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        index_path = self.repo / "plans" / loom_plan_store.INDEX_NAME
        before_index = index_path.read_bytes()
        before_generation = loom_reliability.exact_tree_manifest(
            predecessor.generation_root)
        requests = (
            ("Explain what a replacement plan would look like without creating one. "
             "Keep the current plan unchanged.", "completed"),
            ('The reviewer wrote "Create a fresh replacement plan." Explain whether '
             "that would be safe; do not act on the quote.", "completed"),
            ("The incident report says the owner requested a fresh replacement plan. "
             "Summarize the report only; make no changes.", "action-required"),
            ("Do not revise, replace, or create a new plan. Show the current plan.",
             "completed"),
        )

        for request, expected_status in requests:
            with self.subTest(request=request):
                result = loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

                self.assertEqual(expected_status, result["status"])
                self.assertEqual(before_index, index_path.read_bytes())
                current = loom_plan_store.resolve(self.repo)
                self.assertEqual(predecessor.generation_id, current.generation_id)
                self.assertEqual(
                    before_generation,
                    loom_reliability.exact_tree_manifest(
                        current.generation_root))
                matching = []
                for path in self.home.glob(
                        "instances/*/runtime/projects/*/orchestrations/*.json"):
                    if re.fullmatch(r"[0-9a-f-]{36}\.json", path.name) is None:
                        continue
                    _path, action, _security = loom_orchestrator._read_action(
                        path, owner_home=self.home, install_root=self.installed)
                    if action["request"] == request:
                        matching.append(action)
                if expected_status == "completed":
                    self.assertEqual("non-authoritative-plan", result["code"])
                    self.assertNotIn("action_path", result)
                    self.assertEqual([], matching)
                else:
                    self.assertEqual(1, len(matching))
                    self.assertEqual(
                        "read-only", matching[0]["request_control"]["relation"])
                self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))
                if expected_status == "action-required":
                    loom_orchestrator.cancel(
                        result["action_path"], owner_home=self.home,
                        install_root=self.installed)

    def test_true_plan_authority_contradiction_returns_inline_provisional_without_mutation(self):
        """Break caught: useful clarification stages or mutates plan authority."""
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        index_path = self.repo / "plans" / loom_plan_store.INDEX_NAME
        before_index = index_path.read_bytes()
        before_generation = loom_reliability.exact_tree_manifest(
            predecessor.generation_root)
        action_directory = next(self.home.glob(
            "instances/*/runtime/projects/*/orchestrations"))
        before_actions = {
            path.name: path.read_bytes()
            for path in action_directory.glob("*.json")
        }
        request = (
            "Create a new plan now. Do not create, revise, or replace the current "
            "plan.")

        result = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertIn("NON-AUTHORITATIVE PLAN", result["user_message"])
        self.assertIn("Understood outcome:", result["user_message"])
        self.assertEqual(1, result["user_message"].count("?"))
        self.assertNotIn("action_path", result)
        self.assertEqual(before_index, index_path.read_bytes())
        self.assertEqual(
            before_generation,
            loom_reliability.exact_tree_manifest(predecessor.generation_root))
        self.assertEqual(
            before_actions,
            {path.name: path.read_bytes()
             for path in action_directory.glob("*.json")})
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))

    def test_changed_active_world_stages_non_authoritative_current_world_candidate(self):
        """Break caught: stale active authority blocks safe candidate planning."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        predecessor = loom_plan_store.resolve(self.repo)
        action_path = Path(started["action_path"])
        pointer_path = action_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        witness_path = action_path.parent / "lifecycle-head-witness.json"
        index_path = self.repo / "plans" / loom_plan_store.INDEX_NAME
        authority_before = {
            "index": index_path.read_bytes(),
            "generation": loom_reliability.exact_tree_manifest(
                predecessor.generation_root),
            "witness": witness_path.read_bytes(),
            "action": action_path.read_bytes(),
            "pointer": pointer_path.read_bytes(),
        }
        _write(self.repo / "external-world.txt", "changed outside Loom\n")
        request = (
            "Plan a current-world double-entry direction in src/app.py only; do "
            "not implement it.")

        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", candidate["status"])
        _path, candidate_action, _security = loom_orchestrator._read_action(
            candidate["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertIn(
            "planning-current-world-replan",
            candidate_action["request_control"]["evidence"])
        self.assertTrue(candidate_action["pack_seed"]["created_pack"])
        self.assertFalse(
            loom_orchestrator._action_pack_root(candidate_action).is_relative_to(
                self.repo))
        self.assertEqual(authority_before["index"], index_path.read_bytes())
        self.assertEqual(
            authority_before["generation"],
            loom_reliability.exact_tree_manifest(predecessor.generation_root))
        self.assertEqual(authority_before["witness"], witness_path.read_bytes())
        self.assertEqual(authority_before["action"], action_path.read_bytes())
        self.assertEqual(authority_before["pointer"], pointer_path.read_bytes())

        _author_medium_action(candidate, request=request)
        with self.assertRaises(loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)
        self.assertEqual(
            "SUCCESSOR_EXECUTOR_QUIESCENCE_REQUIRED", blocked.exception.code)
        self.assertEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

    def test_changed_active_world_unanchored_request_returns_inline_assistance(self):
        """Break caught: safe inline help is dead-ended by an active action."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        predecessor = loom_plan_store.resolve(self.repo)
        action_path = Path(started["action_path"])
        pointer_path = action_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        witness_path = action_path.parent / "lifecycle-head-witness.json"
        index_path = self.repo / "plans" / loom_plan_store.INDEX_NAME
        _write(self.repo / "external-world.txt", "changed outside Loom\n")
        authority_before = {
            "index": index_path.read_bytes(),
            "generation": loom_reliability.exact_tree_manifest(
                predecessor.generation_root),
            "witness": witness_path.read_bytes(),
            "action": action_path.read_bytes(),
            "pointer": pointer_path.read_bytes(),
        }

        result = loom_orchestrator.invoke(
            request=(
                "The accounting requirements changed. Prepare a current-world "
                "double-entry direction for discussion only."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertIn("NON-AUTHORITATIVE PLAN", result["user_message"])
        self.assertNotIn("action_path", result)
        self.assertEqual(authority_before["index"], index_path.read_bytes())
        self.assertEqual(
            authority_before["generation"],
            loom_reliability.exact_tree_manifest(predecessor.generation_root))
        self.assertEqual(authority_before["witness"], witness_path.read_bytes())
        self.assertEqual(authority_before["action"], action_path.read_bytes())
        self.assertEqual(authority_before["pointer"], pointer_path.read_bytes())
        self.assertEqual([], list(self.repo.glob(".loom-plan-stage-*")))

    def _make_open_pre_ux104_planning_action(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        action = json.loads(path.read_text(encoding="utf-8"))
        action["request_control"] = json.loads(json.dumps(
            PRE_UX104_PLANNING_CONTROL_V1))
        action["prepared"]["route_contract"]["evidence"] = [
            item for item in action["prepared"]["route_contract"]["evidence"]
            if not item.casefold().startswith("semantic-outcome-")]
        prepared = dict(action["prepared"])
        prepared.pop("prepared_hash")
        action["prepared"]["prepared_hash"] = loom_orchestrator._hash(prepared)
        action["action_hash"] = loom_orchestrator._action_hash(action)
        path.write_text(json.dumps(action), encoding="utf-8")
        return opened, path, action

    def _interrupt_successor_pointer_before_publication(self):
        """Build one exact receipt-bound successor with no published pointer."""
        opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def interrupt(source, destination, **kwargs):
            nonlocal injected
            if not injected \
                    and kwargs.get("source_role") == "successor_pointer_stage" \
                    and kwargs.get("destination_role") == "active_successor_pointer":
                injected = True
                raise loom_reliability.ReliabilityError(
                    "injected before successor pointer publication")
            return original_atomic(source, destination, **kwargs)

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace", side_effect=interrupt):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / loom_orchestrator.RECOVERY_CONTROL_TRANSITION)
        receipt_path = (
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_RECEIPT)
        stage_path = (
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_POINTER)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        successor_path = old_path.parent / f"{receipt['successor_action_id']}.json"
        return {
            "opened": opened,
            "old_path": old_path,
            "old_action": old_action,
            "request": request,
            "pointer_path": old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE,
            "receipt_path": receipt_path,
            "stage_path": stage_path,
            "receipt": receipt,
            "successor_path": successor_path,
        }

    def _interrupt_pending_successor_before_receipt(self):
        """Build one recovery-bound pending successor before receipt staging."""
        opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."

        with mock.patch.object(
                loom_orchestrator, "_publish_recovery_bound_active_pointer",
                side_effect=loom_orchestrator.OrchestratorError(
                    "RECOVERY_TEST_INTERRUPT",
                    "injected after pending action write")):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_TEST_INTERRUPT", interrupted.exception.code)
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / loom_orchestrator.RECOVERY_CONTROL_TRANSITION)
        bound = []
        for path in old_path.parent.glob("*.json"):
            if path.name == loom_orchestrator.ACTIVE_POINTER_FILE:
                continue
            action = json.loads(path.read_text(encoding="utf-8"))
            binding = (action.get("host_result") or {}).get(
                loom_orchestrator.SUCCESSOR_POINTER_BINDING_KEY)
            if action["status"] not in loom_orchestrator.TERMINAL_ACTION_STATUSES \
                    and binding is not None:
                bound.append((path, action))
        self.assertEqual(1, len(bound))
        return {
            "opened": opened,
            "old_path": old_path,
            "old_action": old_action,
            "request": request,
            "pointer_path": old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE,
            "receipt_path": (
                transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_RECEIPT),
            "stage_path": (
                transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_POINTER),
            "successor_path": bound[0][0],
            "successor": bound[0][1],
        }

    def test_fresh_plan_reprepares_pointer_backed_pre_ux104_action(self):
        """Break caught: ACTION_REPREPARE_REQUIRED instructs an endless retry."""
        opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        fresh_request = "Plan a separate current-world README improvement."

        fresh = loom_orchestrator.invoke(
            request=fresh_request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", fresh["status"])
        self.assertNotEqual(opened["action_id"], fresh["action_id"])
        retired = json.loads(old_path.read_text(encoding="utf-8"))
        self.assertEqual("superseded", retired["status"])
        self.assertEqual("superseded", retired["recovery_receipt"]["reason"])
        pointer = loom_orchestrator._read_active_pointer(old_path.parent)
        self.assertEqual(fresh["action_id"], pointer["action_id"])
        journal = loom_session._load_journal(
            old_action["journal_path"], old_action["instance_id"],
            old_action["project_id"])
        events = [
            item for item in journal["events"]
            if item["operation_id"] == old_action["operation_id"]]
        self.assertEqual("session-interrupted", events[-1]["kind"])

    def test_fresh_plan_reprepares_unique_pointerless_pre_ux104_action(self):
        """Break caught: restart recovery cannot discover a reprepare-only action."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        loom_orchestrator._clear_active_pointer(
            old_path.parent, opened["action_id"])

        fresh = loom_orchestrator.invoke(
            request="Plan a separate current-world README improvement.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", fresh["status"])
        retired = json.loads(old_path.read_text(encoding="utf-8"))
        self.assertEqual("superseded", retired["status"])
        pointer = loom_orchestrator._read_active_pointer(old_path.parent)
        self.assertEqual(fresh["action_id"], pointer["action_id"])

    def test_pre_ux104_reprepare_converges_after_interrupted_recovery(self):
        """Break caught: a crash can retire the action before closing its session."""
        opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."
        original_recover = loom_orchestrator._recover_plan_action

        with mock.patch.object(
                loom_orchestrator, "_recover_plan_action",
                side_effect=loom_orchestrator.OrchestratorError(
                    "RECOVERY_TEST_INTERRUPT", "injected recovery interruption")):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_TEST_INTERRUPT", interrupted.exception.code)
        self.assertEqual("pending", json.loads(
            old_path.read_text(encoding="utf-8"))["status"])
        self.assertEqual(
            opened["action_id"],
            loom_orchestrator._read_active_pointer(old_path.parent)["action_id"])
        journal = loom_session._load_journal(
            old_action["journal_path"], old_action["instance_id"],
            old_action["project_id"])
        events = [
            item for item in journal["events"]
            if item["operation_id"] == old_action["operation_id"]]
        self.assertEqual("session-interrupted", events[-1]["kind"])

        with mock.patch.object(
                loom_orchestrator, "_recover_plan_action", wraps=original_recover):
            fresh = loom_orchestrator.invoke(
                request=request, cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("action-required", fresh["status"])
        self.assertEqual("superseded", json.loads(
            old_path.read_text(encoding="utf-8"))["status"])
        self.assertNotEqual(opened["action_id"], fresh["action_id"])

    def test_pre_ux104_reprepare_preserves_changed_stage(self):
        """Break caught: compatibility recovery guesses through changed seed bytes."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        stage = loom_orchestrator._action_pack_root(old_action)
        _write(stage / "unsealed.txt", "owner bytes\n")
        before_action = old_path.read_bytes()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        before_pointer = pointer_path.read_bytes()
        journal_path = Path(old_action["journal_path"])
        before_journal = journal_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_DECISION_REQUIRED", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertEqual(before_journal, journal_path.read_bytes())
        self.assertEqual("owner bytes\n", (stage / "unsealed.txt").read_text(
            encoding="utf-8"))

    def test_pre_ux104_reprepare_preflights_quarantine_before_interrupting(self):
        """Break caught: an invalid quarantine mutates the session before refusal."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        quarantine = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY /
            old_action["action_id"] / "plans")
        _write(quarantine / "foreign.txt", "not the sealed seed\n")
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        journal_path = Path(old_action["journal_path"])
        before_action = old_path.read_bytes()
        before_pointer = pointer_path.read_bytes()
        before_journal = journal_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_DECISION_REQUIRED", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertEqual(before_journal, journal_path.read_bytes())
        self.assertEqual(
            "not the sealed seed\n",
            (quarantine / "foreign.txt").read_text(encoding="utf-8"))

    def test_pre_ux104_reprepare_revalidates_stage_identity_after_interrupt(self):
        """Break caught: byte-identical stage replacement escapes recovery preflight."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        stage = loom_orchestrator._action_pack_root(old_action)
        swapped = stage.with_name(stage.name + "-original")
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        before_action = old_path.read_bytes()
        before_pointer = pointer_path.read_bytes()
        original_interrupt = loom_session.SessionController.interrupt

        def interrupt_then_replace(controller, opened, *, code, now=None):
            result = original_interrupt(
                controller, opened, code=code, now=now)
            stage.rename(swapped)
            shutil.copytree(swapped, stage)
            return result

        with mock.patch.object(
                loom_session.SessionController, "interrupt",
                new=interrupt_then_replace):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertTrue(stage.is_dir())
        self.assertTrue(swapped.is_dir())

    def test_pre_ux104_reprepare_revalidates_action_identity_after_interrupt(self):
        """Break caught: byte-identical action replacement escapes preflight."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        swapped = old_path.with_name(old_path.stem + "-original.json")
        before_action = old_path.read_bytes()
        original_interrupt = loom_session.SessionController.interrupt

        def interrupt_then_replace(controller, opened, *, code, now=None):
            result = original_interrupt(
                controller, opened, code=code, now=now)
            old_path.rename(swapped)
            shutil.copy2(swapped, old_path)
            return result

        with mock.patch.object(
                loom_session.SessionController, "interrupt",
                new=interrupt_then_replace):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_action, swapped.read_bytes())

    def test_pre_ux104_reprepare_revalidates_pointer_identity_after_interrupt(self):
        """Break caught: byte-identical pointer replacement escapes preflight."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        swapped = pointer_path.with_name(pointer_path.name + ".original")
        before_pointer = pointer_path.read_bytes()
        original_interrupt = loom_session.SessionController.interrupt

        def interrupt_then_replace(controller, opened, *, code, now=None):
            result = original_interrupt(
                controller, opened, code=code, now=now)
            pointer_path.rename(swapped)
            shutil.copy2(swapped, pointer_path)
            return result

        with mock.patch.object(
                loom_session.SessionController, "interrupt",
                new=interrupt_then_replace):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertEqual(before_pointer, swapped.read_bytes())

    def test_pre_ux104_reprepare_cas_rejects_action_replacement_before_source_move(self):
        """Break caught: action replacement after second preflight is overwritten."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        stage = loom_orchestrator._action_pack_root(old_action)
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        swapped = old_path.with_name(old_path.stem + "-post-preflight.json")
        before_action = old_path.read_bytes()
        before_pointer = pointer_path.read_bytes()
        original_prepare = loom_orchestrator._prepare_recovery_root
        injected = False

        def prepare_then_replace(owner_root, recovery_root):
            nonlocal injected
            result = original_prepare(owner_root, recovery_root)
            if not injected:
                injected = True
                old_path.rename(swapped)
                shutil.copy2(swapped, old_path)
            return result

        with mock.patch.object(
                loom_orchestrator, "_prepare_recovery_root",
                side_effect=prepare_then_replace):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_action, swapped.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertTrue(stage.is_dir())

    def test_pre_ux104_reprepare_cas_rejects_pointer_replacement_before_source_move(self):
        """Break caught: pointer replacement after second preflight is cleared."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        stage = loom_orchestrator._action_pack_root(old_action)
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        swapped = pointer_path.with_name(pointer_path.name + ".post-preflight")
        before_action = old_path.read_bytes()
        before_pointer = pointer_path.read_bytes()
        original_prepare = loom_orchestrator._prepare_recovery_root
        injected = False

        def prepare_then_replace(owner_root, recovery_root):
            nonlocal injected
            result = original_prepare(owner_root, recovery_root)
            if not injected:
                injected = True
                pointer_path.rename(swapped)
                shutil.copy2(swapped, pointer_path)
            return result

        with mock.patch.object(
                loom_orchestrator, "_prepare_recovery_root",
                side_effect=prepare_then_replace):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertEqual(before_pointer, swapped.read_bytes())
        self.assertTrue(stage.is_dir())

    def test_pre_ux104_reprepare_cas_rejects_action_replacement_before_terminal_write(self):
        """Break caught: a late action swap is overwritten after artifact recovery."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        swapped = old_path.with_name(old_path.stem + "-before-write.json")
        before_action = old_path.read_bytes()
        before_pointer = pointer_path.read_bytes()
        original_receipt = loom_orchestrator._recovery_receipt
        injected = False

        def receipt_then_replace(*args, **kwargs):
            nonlocal injected
            result = original_receipt(*args, **kwargs)
            if not injected:
                injected = True
                old_path.rename(swapped)
                shutil.copy2(swapped, old_path)
            return result

        with mock.patch.object(
                loom_orchestrator, "_recovery_receipt",
                side_effect=receipt_then_replace):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_action, swapped.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())

    def test_pre_ux104_reprepare_cas_rejects_pointer_replacement_before_clear(self):
        """Break caught: recovery reintroduces overwrite-then-clear ordering."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        original_write = loom_orchestrator._write_action
        recovery_overwrites = []

        def reject_recovery_overwrite(path, value, security=None):
            if Path(path) == old_path and value.get("status") == "superseded":
                recovery_overwrites.append(Path(path))
                raise AssertionError("recovery must install by an exclusive move")
            return original_write(path, value, security)

        with mock.patch.object(
                loom_orchestrator, "_write_action",
                side_effect=reject_recovery_overwrite):
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual([], recovery_overwrites)
        self.assertNotEqual(
            opened["action_id"],
            json.loads(pointer_path.read_text(encoding="utf-8"))["action_id"])
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])

    def test_pre_ux104_reprepare_cas_rechecks_pointer_immediately_before_unlink(self):
        """Break caught: recovery clears its source with a destructive unlink."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        original_unlink = os.unlink
        pointer_unlinks = []

        def reject_pointer_unlink(path, *args, **kwargs):
            if Path(path) == pointer_path:
                pointer_unlinks.append(Path(path))
                raise AssertionError("recovery must retire by an exclusive move")
            return original_unlink(path, *args, **kwargs)

        with mock.patch.object(os, "unlink", side_effect=reject_pointer_unlink):
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual([], pointer_unlinks)
        self.assertNotEqual(
            opened["action_id"],
            json.loads(pointer_path.read_text(encoding="utf-8"))["action_id"])
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])

    def test_pre_ux104_reprepare_atomic_move_rejects_last_window_action_swap(self):
        """Break caught: final action replacement destroys unexpected bytes."""
        _opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        swapped = old_path.with_name(old_path.stem + "-atomic-race.json")
        before_action = old_path.read_bytes()
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def replace_inside_atomic(source, destination, **kwargs):
            nonlocal injected
            if not injected and Path(source) == old_path \
                    and Path(destination).name == "original-action.json":
                injected = True
                old_path.rename(swapped)
                shutil.copy2(swapped, old_path)
            return original_atomic(source, destination, **kwargs)

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=replace_inside_atomic):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_action, swapped.read_bytes())

    def test_pre_ux104_reprepare_atomic_move_rejects_last_window_pointer_swap(self):
        """Break caught: final pointer replacement destroys unexpected bytes."""
        _opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        swapped = pointer_path.with_name(pointer_path.name + ".atomic-race")
        before_pointer = pointer_path.read_bytes()
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def replace_inside_atomic(source, destination, **kwargs):
            nonlocal injected
            if not injected and Path(source) == pointer_path \
                    and Path(destination).name == "active-pointer.json":
                injected = True
                pointer_path.rename(swapped)
                shutil.copy2(swapped, pointer_path)
            return original_atomic(source, destination, **kwargs)

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=replace_inside_atomic):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertEqual(before_pointer, swapped.read_bytes())
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])

    def test_pre_ux104_reprepare_resumes_after_original_action_is_retired(self):
        """Break caught: a crash between no-replace action moves loses discovery."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def crash_after_retirement(source, destination, **kwargs):
            nonlocal injected
            outcome = original_atomic(source, destination, **kwargs)
            if not injected and Path(source) == old_path \
                    and Path(destination).name == "original-action.json":
                injected = True
                raise RuntimeError("crash after original action retirement")
            return outcome

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=crash_after_retirement):
            with self.assertRaisesRegex(
                    RuntimeError, "original action retirement"):
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        self.assertFalse(old_path.exists())
        fresh = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / "control-transition")
        self.assertEqual("action-required", fresh["status"])
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])
        self.assertTrue((transition / "original-action.json").is_file())
        self.assertFalse((transition / "target-action.json").exists())

    def test_pre_ux104_reprepare_resumes_after_terminal_action_install(self):
        """Break caught: a crash after terminal install leaves a stale pointer."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def crash_after_install(source, destination, **kwargs):
            nonlocal injected
            outcome = original_atomic(source, destination, **kwargs)
            if not injected and Path(source).name == "target-action.json" \
                    and Path(destination) == old_path:
                injected = True
                raise RuntimeError("crash after terminal action install")
            return outcome

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=crash_after_install):
            with self.assertRaisesRegex(RuntimeError, "terminal action install"):
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])
        fresh = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / "control-transition")
        self.assertEqual("action-required", fresh["status"])
        self.assertTrue((transition / "active-pointer.json").is_file())
        self.assertFalse((transition / "target-action.json").exists())

    def test_pre_ux104_reprepare_resumes_after_pointer_retirement(self):
        """Break caught: a crash after pointer retirement cannot finish cleanly."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def crash_after_pointer(source, destination, **kwargs):
            nonlocal injected
            outcome = original_atomic(source, destination, **kwargs)
            if not injected and Path(source) == pointer_path \
                    and Path(destination).name == "active-pointer.json":
                injected = True
                raise RuntimeError("crash after pointer retirement")
            return outcome

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=crash_after_pointer):
            with self.assertRaisesRegex(RuntimeError, "pointer retirement"):
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        self.assertFalse(pointer_path.exists())
        fresh = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / "control-transition")
        self.assertEqual("action-required", fresh["status"])
        self.assertTrue((transition / "active-pointer.json").is_file())
        self.assertEqual(
            fresh["action_id"],
            loom_orchestrator._read_active_pointer(old_path.parent)["action_id"])

    def test_pre_ux104_fresh_pointer_publication_preserves_unexpected_pointer(self):
        """Break caught: fresh publication replaces bytes created after retirement."""
        opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        foreign = {
            "schema_version": 1,
            "action_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "project_id": old_action["project_id"],
            "state": "active",
        }
        foreign["pointer_hash"] = loom_orchestrator._pointer_hash(foreign)
        foreign_bytes = loom_session._canonical_json(foreign) + b"\n"
        original_write = loom_orchestrator._write_action
        injected = False

        def write_then_compete(path, value, security=None):
            nonlocal injected
            result = original_write(path, value, security)
            if not injected and value["action_id"] != opened["action_id"] \
                    and value["status"] == "initializing" \
                    and not pointer_path.exists():
                injected = True
                loom_session._atomic_json(pointer_path, foreign)
            return result

        with mock.patch.object(
                loom_orchestrator, "_write_action", side_effect=write_then_compete):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as blocked:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertTrue(injected)
        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(foreign_bytes, pointer_path.read_bytes())
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])

    def test_pre_ux104_fresh_pointer_publication_crash_retry_converges(self):
        """Break caught: a lost response after fresh pointer commit cannot retry safely."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        request = "Plan a separate current-world README improvement."
        original_atomic = loom_reliability.atomic_rename_noreplace
        injected = False

        def crash_after_fresh_pointer(source, destination, **kwargs):
            nonlocal injected
            outcome = original_atomic(source, destination, **kwargs)
            if not injected and Path(source).name == "successor-active-pointer.json" \
                    and Path(destination) == pointer_path:
                injected = True
                raise RuntimeError("crash after fresh pointer publication")
            return outcome

        with mock.patch.object(
                loom_reliability, "atomic_rename_noreplace",
                side_effect=crash_after_fresh_pointer):
            with self.assertRaisesRegex(
                    RuntimeError, "fresh pointer publication"):
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertTrue(injected)
        committed = pointer_path.read_bytes()
        committed_action_id = json.loads(
            committed.decode("utf-8"))["action_id"]
        self.assertNotEqual(opened["action_id"], committed_action_id)

        fresh = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", fresh["status"])
        self.assertEqual(committed, pointer_path.read_bytes())
        self.assertEqual(committed_action_id, fresh["action_id"])
        self.assertEqual(
            fresh["action_id"],
            loom_orchestrator._read_active_pointer(old_path.parent)["action_id"])
        self.assertEqual(
            "superseded", json.loads(old_path.read_text(encoding="utf-8"))["status"])

    def test_pre_ux104_successor_pointer_prepublication_retry_converges(self):
        """Break caught: pre-publication failure abandons the exact successor."""
        case = self._interrupt_successor_pointer_before_publication()

        self.assertFalse(case["pointer_path"].exists())
        self.assertTrue(case["receipt_path"].is_file())
        self.assertTrue(case["stage_path"].is_file())
        self.assertEqual(
            "superseded",
            json.loads(case["old_path"].read_text(encoding="utf-8"))["status"])
        self.assertTrue(case["successor_path"].is_file())

        resumed = loom_orchestrator.invoke(
            request=case["request"], cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual(case["receipt"]["successor_action_id"], resumed["action_id"])
        self.assertEqual(
            resumed["action_id"],
            loom_orchestrator._read_active_pointer(
                case["old_path"].parent)["action_id"])
        self.assertFalse(case["stage_path"].exists())

    def test_pre_ux104_pending_successor_without_receipt_rebinds_on_retry(self):
        """Break caught: a pointerless pending successor is returned as usable."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."

        with mock.patch.object(
                loom_orchestrator, "_publish_recovery_bound_active_pointer",
                side_effect=loom_orchestrator.OrchestratorError(
                    "RECOVERY_TEST_INTERRUPT",
                    "injected after pending action write")):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_TEST_INTERRUPT", interrupted.exception.code)
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / loom_orchestrator.RECOVERY_CONTROL_TRANSITION)
        receipt_path = (
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_RECEIPT)
        stage_path = (
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_POINTER)
        self.assertFalse(pointer_path.exists())
        self.assertFalse(receipt_path.exists())
        self.assertFalse(stage_path.exists())
        pending = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in old_path.parent.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
            and json.loads(path.read_text(encoding="utf-8"))["status"]
            not in loom_orchestrator.TERMINAL_ACTION_STATUSES
        ]
        self.assertEqual(1, len(pending))
        successor_id = pending[0]["action_id"]

        resumed = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual(successor_id, resumed["action_id"])
        self.assertEqual(
            successor_id,
            loom_orchestrator._read_active_pointer(old_path.parent)["action_id"])
        self.assertTrue(receipt_path.is_file())
        self.assertFalse(stage_path.exists())

    def test_pre_ux104_bound_successor_precedes_stale_source_pointer(self):
        """Break caught: a stale source pointer is cleared before bound recovery."""
        case = self._interrupt_pending_successor_before_receipt()
        pointer_value = loom_orchestrator._active_pointer_value(
            action_id=case["opened"]["action_id"],
            project_id=case["old_action"]["project_id"])
        loom_session._atomic_json(case["pointer_path"], pointer_value)
        before_pointer = case["pointer_path"].read_bytes()
        before_successor = case["successor_path"].read_bytes()
        before_actions = {
            path.name for path in case["old_path"].parent.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
        }

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=case["request"], cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_pointer, case["pointer_path"].read_bytes())
        self.assertEqual(before_successor, case["successor_path"].read_bytes())
        self.assertEqual(
            before_actions,
            {
                path.name for path in case["old_path"].parent.glob("*.json")
                if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
            })
        self.assertFalse(case["receipt_path"].exists())
        self.assertFalse(case["stage_path"].exists())

    def test_pre_ux104_bound_successor_precedes_unrelated_pending_pointer(self):
        """Break caught: an unrelated pending pointer bypasses bound recovery."""
        case = self._interrupt_pending_successor_before_receipt()
        unrelated = json.loads(json.dumps(case["successor"]))
        unrelated["action_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        host_result = dict(unrelated["host_result"])
        host_result.pop(loom_orchestrator.SUCCESSOR_POINTER_BINDING_KEY)
        unrelated["host_result"] = host_result
        planning_mode = loom_orchestrator._extract_planning_mode(
            unrelated["request_control"])
        unrelated["owner_message"] = loom_orchestrator.loom_message.build(
            state="progress",
            consequence=loom_orchestrator._action_consequence(
                unrelated, use_domain_contract=True),
            verification="pending", freshness="current",
            changes_made=True, undo_status="unavailable",
            summary=loom_orchestrator._planning_seed_summary(
                unrelated["tier"], planning_mode),
            next_action=(
                "Have the agent finish the plan, then review it before any "
                "project work starts."),
            receipt_id="action-" + unrelated["action_id"])
        unrelated["action_hash"] = loom_orchestrator._action_hash(unrelated)
        unrelated_path = case["old_path"].parent / f"{unrelated['action_id']}.json"
        unrelated_path.write_text(json.dumps(unrelated), encoding="utf-8")
        loom_orchestrator._read_action(
            unrelated_path, owner_home=self.home,
            install_root=self.installed)
        pointer_value = loom_orchestrator._active_pointer_value(
            action_id=unrelated["action_id"], project_id=unrelated["project_id"])
        loom_session._atomic_json(case["pointer_path"], pointer_value)
        before_pointer = case["pointer_path"].read_bytes()
        before_successor = case["successor_path"].read_bytes()
        before_unrelated = unrelated_path.read_bytes()
        before_actions = {
            path.name for path in case["old_path"].parent.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
        }

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=case["request"], cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_pointer, case["pointer_path"].read_bytes())
        self.assertEqual(before_successor, case["successor_path"].read_bytes())
        self.assertEqual(before_unrelated, unrelated_path.read_bytes())
        self.assertEqual(
            before_actions,
            {
                path.name for path in case["old_path"].parent.glob("*.json")
                if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
            })
        self.assertFalse(case["receipt_path"].exists())
        self.assertFalse(case["stage_path"].exists())

    def test_pre_ux104_multiple_bound_successors_block_before_publication(self):
        """Break caught: discovery guesses between two authenticated successors."""
        case = self._interrupt_pending_successor_before_receipt()
        duplicate = json.loads(json.dumps(case["successor"]))
        duplicate["action_id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        host_result = dict(duplicate["host_result"])
        host_result.pop(loom_orchestrator.SUCCESSOR_POINTER_BINDING_KEY)
        duplicate["host_result"] = host_result
        planning_mode = loom_orchestrator._extract_planning_mode(
            duplicate["request_control"])
        duplicate["owner_message"] = loom_orchestrator.loom_message.build(
            state="progress",
            consequence=loom_orchestrator._action_consequence(
                duplicate, use_domain_contract=True),
            verification="pending", freshness="current",
            changes_made=True, undo_status="unavailable",
            summary=loom_orchestrator._planning_seed_summary(
                duplicate["tier"], planning_mode),
            next_action=(
                "Have the agent finish the plan, then review it before any "
                "project work starts."),
            receipt_id="action-" + duplicate["action_id"])
        source = json.loads(case["old_path"].read_text(encoding="utf-8"))
        duplicate["host_result"][
            loom_orchestrator.SUCCESSOR_POINTER_BINDING_KEY
        ] = loom_orchestrator._successor_pointer_binding(
            source["recovery_receipt"], duplicate)
        duplicate["action_hash"] = loom_orchestrator._action_hash(duplicate)
        duplicate_path = case["old_path"].parent / f"{duplicate['action_id']}.json"
        duplicate_path.write_text(json.dumps(duplicate), encoding="utf-8")
        loom_orchestrator._read_action(
            duplicate_path, owner_home=self.home,
            install_root=self.installed)
        before_successor = case["successor_path"].read_bytes()
        before_duplicate = duplicate_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=case["request"], cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertFalse(case["pointer_path"].exists())
        self.assertEqual(before_successor, case["successor_path"].read_bytes())
        self.assertEqual(before_duplicate, duplicate_path.read_bytes())
        self.assertFalse(case["receipt_path"].exists())
        self.assertFalse(case["stage_path"].exists())

    def test_pre_ux104_bound_successor_requires_sole_nonterminal_action(self):
        """Break caught: bound recovery hides a second unbound pending action."""
        case = self._interrupt_pending_successor_before_receipt()
        unbound = json.loads(json.dumps(case["successor"]))
        unbound["action_id"] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        host_result = dict(unbound["host_result"])
        host_result.pop(loom_orchestrator.SUCCESSOR_POINTER_BINDING_KEY)
        unbound["host_result"] = host_result
        planning_mode = loom_orchestrator._extract_planning_mode(
            unbound["request_control"])
        unbound["owner_message"] = loom_orchestrator.loom_message.build(
            state="progress",
            consequence=loom_orchestrator._action_consequence(
                unbound, use_domain_contract=True),
            verification="pending", freshness="current",
            changes_made=True, undo_status="unavailable",
            summary=loom_orchestrator._planning_seed_summary(
                unbound["tier"], planning_mode),
            next_action=(
                "Have the agent finish the plan, then review it before any "
                "project work starts."),
            receipt_id="action-" + unbound["action_id"])
        unbound["action_hash"] = loom_orchestrator._action_hash(unbound)
        unbound_path = case["old_path"].parent / f"{unbound['action_id']}.json"
        unbound_path.write_text(json.dumps(unbound), encoding="utf-8")
        loom_orchestrator._read_action(
            unbound_path, owner_home=self.home,
            install_root=self.installed)
        before_successor = case["successor_path"].read_bytes()
        before_unbound = unbound_path.read_bytes()
        before_actions = {
            path.name for path in case["old_path"].parent.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
        }

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=case["request"], cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertFalse(case["pointer_path"].exists())
        self.assertEqual(before_successor, case["successor_path"].read_bytes())
        self.assertEqual(before_unbound, unbound_path.read_bytes())
        self.assertEqual(
            before_actions,
            {
                path.name for path in case["old_path"].parent.glob("*.json")
                if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
            })
        self.assertFalse(case["receipt_path"].exists())
        self.assertFalse(case["stage_path"].exists())

    def test_pre_ux104_pending_successor_binding_tamper_blocks(self):
        """Break caught: a rehashed pending action can redirect its source binding."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."

        with mock.patch.object(
                loom_orchestrator, "_publish_recovery_bound_active_pointer",
                side_effect=loom_orchestrator.OrchestratorError(
                    "RECOVERY_TEST_INTERRUPT",
                    "injected after pending action write")):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        successor_paths = [
            path for path in old_path.parent.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
            and json.loads(path.read_text(encoding="utf-8"))["status"]
            not in loom_orchestrator.TERMINAL_ACTION_STATUSES
        ]
        self.assertEqual(1, len(successor_paths))
        successor_path = successor_paths[0]
        successor = json.loads(successor_path.read_text(encoding="utf-8"))
        binding = successor["host_result"]["successor_pointer_binding"]
        binding["source_recovery_receipt_hash"] = "0" * 64
        binding["binding_sha256"] = loom_orchestrator._hash({
            key: value for key, value in binding.items()
            if key != "binding_sha256"})
        successor["action_hash"] = loom_orchestrator._action_hash(successor)
        successor_path.write_text(json.dumps(successor), encoding="utf-8")
        before = successor_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=request, cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertIn(blocked.exception.code, {"ACTION_CORRUPT", "RECOVERY_RACE"})
        self.assertEqual(before, successor_path.read_bytes())
        self.assertFalse((
            old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE).exists())
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / loom_orchestrator.RECOVERY_CONTROL_TRANSITION)
        self.assertFalse((
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_RECEIPT
        ).exists())

    def test_pre_ux104_successor_is_not_pending_before_binding_persists(self):
        """A pre-binding interruption cannot expose a resumable successor."""
        _opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()

        with mock.patch.object(
                loom_orchestrator, "_bind_recovery_bound_successor",
                side_effect=loom_orchestrator.OrchestratorError(
                    "RECOVERY_TEST_INTERRUPT",
                    "injected before successor binding persistence")):
            with self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
                loom_orchestrator.invoke(
                    request="Plan a separate current-world README improvement.",
                    cwd=self.repo, home=self.home,
                    install_root=self.installed)

        self.assertEqual("RECOVERY_TEST_INTERRUPT", interrupted.exception.code)
        self.assertFalse((
            old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE).exists())
        successors = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in old_path.parent.glob("*.json")
            if path.name != loom_orchestrator.ACTIVE_POINTER_FILE
            and json.loads(path.read_text(encoding="utf-8"))["action_id"]
            != old_path.stem
        ]
        self.assertEqual(1, len(successors))
        self.assertEqual("initializing", successors[0]["status"])
        self.assertIsNone(successors[0]["host_result"])

    def test_pre_ux104_pending_successor_source_receipt_mismatch_blocks(self):
        """Break caught: a changed terminal receipt can authorize publication."""
        opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        request = "Plan a separate current-world README improvement."

        with mock.patch.object(
                loom_orchestrator, "_publish_recovery_bound_active_pointer",
                side_effect=loom_orchestrator.OrchestratorError(
                    "RECOVERY_TEST_INTERRUPT",
                    "injected after pending action write")):
            with self.assertRaises(loom_orchestrator.OrchestratorError):
                loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)

        source = json.loads(old_path.read_text(encoding="utf-8"))
        source["recovery_receipt"]["recovered_at"] = "2026-08-17T00:00:00Z"
        receipt_body = dict(source["recovery_receipt"])
        receipt_body.pop("receipt_hash")
        source["recovery_receipt"]["receipt_hash"] = \
            loom_orchestrator._hash(receipt_body)
        source["action_hash"] = loom_orchestrator._action_hash(source)
        old_path.write_text(json.dumps(source), encoding="utf-8")
        before_source = old_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=request, cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_source, old_path.read_bytes())
        self.assertFalse((
            old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE).exists())
        transition = (
            old_path.parent.parent / loom_orchestrator.RECOVERY_DIRECTORY
            / opened["action_id"] / loom_orchestrator.RECOVERY_CONTROL_TRANSITION)
        self.assertFalse((
            transition / loom_orchestrator.RECOVERY_CONTROL_SUCCESSOR_RECEIPT
        ).exists())

    def test_pre_ux104_successor_pointer_tampered_receipt_blocks(self):
        """Break caught: a rehashed successor receipt can redirect publication."""
        case = self._interrupt_successor_pointer_before_publication()
        receipt = dict(case["receipt"])
        receipt["pointer_sha256"] = "0" * 64
        receipt["receipt_hash"] = loom_orchestrator._hash({
            key: value for key, value in receipt.items() if key != "receipt_hash"})
        case["receipt_path"].write_text(json.dumps(receipt), encoding="utf-8")
        before_receipt = case["receipt_path"].read_bytes()
        before_stage = case["stage_path"].read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=case["request"], cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_receipt, case["receipt_path"].read_bytes())
        self.assertEqual(before_stage, case["stage_path"].read_bytes())
        self.assertFalse(case["pointer_path"].exists())

    def test_pre_ux104_successor_pointer_action_mismatch_blocks(self):
        """Break caught: a different authentic action inherits a stale receipt."""
        case = self._interrupt_successor_pointer_before_publication()
        successor = json.loads(case["successor_path"].read_text(encoding="utf-8"))
        successor["attempts"] += 1
        successor["action_hash"] = loom_orchestrator._action_hash(successor)
        case["successor_path"].write_text(json.dumps(successor), encoding="utf-8")
        before_action = case["successor_path"].read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request=case["request"], cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_RACE", blocked.exception.code)
        self.assertEqual(before_action, case["successor_path"].read_bytes())
        self.assertFalse(case["pointer_path"].exists())

    def test_pre_ux104_successor_pointer_receipt_recreates_missing_stage(self):
        """Break caught: a committed receipt cannot reconstruct its pointer stage."""
        case = self._interrupt_successor_pointer_before_publication()
        case["stage_path"].unlink()

        resumed = loom_orchestrator.invoke(
            request=case["request"], cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual(case["receipt"]["successor_action_id"], resumed["action_id"])
        self.assertEqual(
            resumed["action_id"],
            loom_orchestrator._read_active_pointer(
                case["old_path"].parent)["action_id"])
        self.assertFalse(case["stage_path"].exists())

    def test_pre_ux104_published_successor_receipt_allows_authentic_action_evolution(self):
        """Publication evidence cannot freeze later authenticated action progress."""
        case = self._interrupt_successor_pointer_before_publication()
        first_resume = loom_orchestrator.invoke(
            request=case["request"], cwd=self.repo, home=self.home,
            install_root=self.installed)
        successor_path = case["successor_path"]
        successor = json.loads(successor_path.read_text(encoding="utf-8"))
        successor["attempts"] += 1
        successor["action_hash"] = loom_orchestrator._action_hash(successor)
        successor_path.write_text(json.dumps(successor), encoding="utf-8")

        resumed = loom_orchestrator.invoke(
            request=case["request"], cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual(first_resume["action_id"], resumed["action_id"])
        self.assertEqual(
            resumed["action_id"],
            loom_orchestrator._read_active_pointer(
                case["old_path"].parent)["action_id"])

    def test_pre_ux104_reprepare_rejects_other_action_corruption(self):
        """Break caught: recovery-only compatibility bypasses normal validation."""
        _opened, old_path, _old_action = \
            self._make_open_pre_ux104_planning_action()
        action = json.loads(old_path.read_text(encoding="utf-8"))
        action["context"]["archived_count"] = -1
        action["action_hash"] = loom_orchestrator._action_hash(action)
        old_path.write_text(json.dumps(action), encoding="utf-8")
        before = old_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("ACTION_CORRUPT", blocked.exception.code)
        self.assertEqual(before, old_path.read_bytes())

    def test_pre_ux104_reprepare_rejects_cross_field_control_without_interrupting(self):
        """Break caught: a rehashed impossible legacy control reaches recovery writes."""
        _opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        action = json.loads(old_path.read_text(encoding="utf-8"))
        action["request_control"]["explicitness"] = "explicit"
        unsigned = {
            key: item for key, item in action["request_control"].items()
            if key != "control_sha256"
        }
        action["request_control"]["control_sha256"] = \
            loom_orchestrator.loom_runtime._sha(
                loom_orchestrator.loom_runtime._canonical_json(unsigned))
        action["action_hash"] = loom_orchestrator._action_hash(action)
        old_path.write_text(json.dumps(action), encoding="utf-8")
        pointer_path = old_path.parent / loom_orchestrator.ACTIVE_POINTER_FILE
        journal_path = Path(old_action["journal_path"])
        before_action = old_path.read_bytes()
        before_pointer = pointer_path.read_bytes()
        before_journal = journal_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("ACTION_CORRUPT", blocked.exception.code)
        self.assertEqual(before_action, old_path.read_bytes())
        self.assertEqual(before_pointer, pointer_path.read_bytes())
        self.assertEqual(before_journal, journal_path.read_bytes())

    def test_pre_ux104_reprepare_preserves_multiple_pointerless_actions(self):
        """Break caught: compatibility recovery guesses between two actions."""
        opened, old_path, old_action = \
            self._make_open_pre_ux104_planning_action()
        loom_orchestrator._clear_active_pointer(
            old_path.parent, opened["action_id"])
        duplicate = json.loads(json.dumps(old_action))
        duplicate_id = "11111111-1111-4111-8111-111111111111"
        duplicate["action_id"] = duplicate_id
        duplicate["owner_message"] = loom_orchestrator.loom_message.build(
            state="progress", consequence=loom_orchestrator._action_consequence(
                duplicate, use_domain_contract=True),
            verification="pending", freshness="current",
            changes_made=True, undo_status="unavailable",
            summary=loom_orchestrator._planning_seed_summary(
                duplicate["tier"]),
            next_action=(
                "Have the agent finish the plan, then review it before "
                "any project work starts."),
            receipt_id="action-" + duplicate_id)
        duplicate["action_hash"] = loom_orchestrator._action_hash(duplicate)
        duplicate_path = old_path.with_name(duplicate_id + ".json")
        duplicate_path.write_text(json.dumps(duplicate), encoding="utf-8")
        before_old = old_path.read_bytes()
        before_duplicate = duplicate_path.read_bytes()

        with self.assertRaises(
                loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.invoke(
                request="Plan a separate current-world README improvement.",
                cwd=self.repo, home=self.home,
                install_root=self.installed)

        self.assertEqual("RECOVERY_DECISION_REQUIRED", blocked.exception.code)
        self.assertEqual(before_old, old_path.read_bytes())
        self.assertEqual(before_duplicate, duplicate_path.read_bytes())
        self.assertIsNone(loom_orchestrator._read_active_pointer(old_path.parent))

    def test_semantic_owner_replanning_recovers_changed_reviewable_generation(self):
        """Break caught: recovery accepts only a parser-specific replacement phrase."""
        _plan_action, _planned = self.complete_machine_authored_plan()
        (self.repo / "external-world.txt").write_text(
            "out-of-band world change\n", encoding="utf-8")

        replacement = loom_orchestrator.invoke(
            request=(
                "Plan a fresh proposal for the changed library accessibility "
                "situation only; do not begin any work."),
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", replacement["status"])
        self.assertEqual("plan", replacement["intent"])
        self.assertNotIn("prior_generation_transition", replacement)
        self.assertIsNone(replacement["work_order"])

    def test_negated_alternative_design_keeps_the_reviewed_generation_unchanged(self):
        """Break caught: a no-change design discussion mutates the current lifecycle."""
        self.complete_machine_authored_plan()
        before = loom_plan_store.resolve(self.repo)
        before_manifest = loom_reliability.exact_tree_manifest(
            before.generation_root)
        before_lifecycle = (
            before.generation_root / "lifecycle.json").read_bytes()
        request = "Discuss another design but do not change the current plan."

        result = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertNotIn("action_path", result)
        self.assertFalse(result["owner_message"]["changes_made"])
        after = loom_plan_store.resolve(self.repo)
        self.assertEqual(before.generation_id, after.generation_id)
        self.assertEqual(before_manifest, loom_reliability.exact_tree_manifest(
            after.generation_root))
        self.assertEqual(
            before_lifecycle,
            (after.generation_root / "lifecycle.json").read_bytes())
        action_paths = sorted(self.home.glob(
            "instances/*/runtime/projects/*/orchestrations/*.json"))
        matching = []
        for path in action_paths:
            if re.fullmatch(r"[0-9a-f-]{36}\.json", path.name) is None:
                continue
            _path, action, _security = loom_orchestrator._read_action(
                path, owner_home=self.home, install_root=self.installed)
            if action["request"] == request:
                matching.append(action)
        self.assertEqual([], matching)

    def test_existing_reviewable_pack_activates_only_after_candidate_review(self):
        """A reviewed candidate supersedes only its exact still-current predecessor."""
        _action, _completed = self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        predecessor_manifest = loom_reliability.exact_tree_manifest(
            predecessor.generation_root)
        candidate_request = "Plan a small accounting accessibility enhancement."

        candidate = loom_orchestrator.invoke(
            request=candidate_request,
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", candidate["status"])
        action = json.loads(Path(candidate["action_path"]).read_text(encoding="utf-8"))
        self.assertIn("planning-candidate-successor", action["request_control"]["evidence"])
        self.assertEqual("prepared", action["pack_seed"]["state"])
        self.assertTrue(action["pack_seed"]["created_pack"])
        self.assertTrue(_owned_pack(candidate).is_dir())
        current = loom_plan_store.resolve(self.repo)
        self.assertEqual(predecessor.generation_id, current.generation_id)
        self.assertEqual(
            predecessor_manifest,
            loom_reliability.exact_tree_manifest(current.generation_root))

        candidate_stage = _owned_pack(candidate)
        _author_medium_action(candidate, request=candidate_request)
        completed = loom_orchestrator.complete(
            candidate["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("plan-complete", completed["code"])
        successor = loom_plan_store.resolve(self.repo)
        self.assertNotEqual(predecessor.generation_id, successor.generation_id)
        predecessor_ledger = json.loads(
            (predecessor.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            "generation-superseded",
            predecessor_ledger["events"][-1]["event_type"])
        self.assertEqual(
            action["generation_id"], successor.generation_id)
        self.assertFalse(candidate_stage.exists())

    def test_active_executor_without_terminal_containment_keeps_candidate_pending(self):
        """An action status cannot be mistaken for sealed executor quiescence."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a small accounting accessibility enhancement."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)

        with self.assertRaises(loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)

        self.assertEqual(
            "SUCCESSOR_EXECUTOR_QUIESCENCE_REQUIRED", blocked.exception.code)
        self.assertEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        pointer = loom_orchestrator._read_active_pointer(
            Path(started["action_path"]).parent)
        self.assertEqual(started["action_id"], pointer["action_id"])

    def test_started_execution_initializes_guard_before_exposing_pointer(self):
        """Break caught: execution begins with no durable host-operation ledger."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        guard = loom_executor_guard.read(path.parent, action)
        self.assertEqual("awaiting-host", guard["coverage_state"])
        pointer = loom_orchestrator._read_active_pointer(path.parent)
        self.assertEqual(action["action_id"], pointer["action_id"])

    def test_active_cancel_converges_when_host_never_admitted_mutation(self):
        """A fresh frozen executor has exact zero-admission terminal evidence."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)

        cancelled = loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)

        self.assertEqual("cancelled", cancelled["status"])
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("cancelled", action["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        self.assertEqual(
            "action-cancel",
            loom_executor_guard.read(path.parent, action)["freeze"]["reason_code"])
        self.assertEqual(
            "host-never-admitted",
            action["host_result"]["executor_quiescence"]["case"])

    def test_action_cancel_retry_converges_after_evidence_action_write_crash(self):
        """Break caught: guard freeze commits but a lost action write strands retirement."""
        self._enable_git_fixture()
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path = Path(started["action_path"])
        original_write = loom_orchestrator._write_action
        injected = False

        def fail_evidence_write(action_path, value, security=None):
            nonlocal injected
            evidence = (value.get("host_result") or {}).get(
                "executor_quiescence")
            if not injected and isinstance(evidence, dict):
                injected = True
                raise loom_orchestrator.OrchestratorError(
                    "INJECTED_ACTION_WRITE", "injected after guard evidence")
            return original_write(action_path, value, security)

        with mock.patch.object(
                loom_orchestrator, "_write_action",
                side_effect=fail_evidence_write), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as crashed:
            loom_orchestrator.cancel(
                path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("INJECTED_ACTION_WRITE", crashed.exception.code)
        _path, pending, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", pending["status"])
        self.assertEqual(
            pending["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])
        self.assertEqual(
            "action-cancel",
            loom_executor_guard.read(path.parent, pending)["freeze"][
                "operation_class"])

        cancelled = loom_orchestrator.cancel(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", cancelled["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))

    def test_terminal_subject_binds_exact_supersession_context(self):
        """Different successor commands cannot reuse one executor freeze."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        _path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)

        first = loom_orchestrator._executor_terminal_subject(
            action, "generation-supersede",
            operation_context_sha256="a" * 64)
        second = loom_orchestrator._executor_terminal_subject(
            action, "generation-supersede",
            operation_context_sha256="b" * 64)

        self.assertNotEqual(first, second)
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator._executor_terminal_subject(
                action, "generation-supersede")

    def test_recovered_v3_action_uses_canonical_guard_security(self):
        """Lifecycle recovery cannot silently create a legacy v2 guard projection."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        crypto = TestCrypto()

        class FakeVault:
            def __init__(self):
                self.crypto = crypto

            def identity(self):
                return {"owner_vault_id": action["instance_id"]}

        memory = object.__new__(
            loom_orchestrator.loom_vault_adapter.VaultMemoryAdapter)
        memory.vault = FakeVault()

        with mock.patch.object(
                loom_executor_guard, "initialize") as initialize:
            loom_orchestrator._ensure_recovered_action_projection(
                action, directory=path.parent, memory=memory,
                work_order=action["work_order"],
                receipt=action["lifecycle_transition"])

        security = initialize.call_args.kwargs["security"]
        self.assertIsInstance(security, loom_executor_guard.GuardSecurity)

    def test_pre_guard_executor_upgrade_preserves_authority_without_synthesizing_proof(self):
        """A pending legacy executor gets an explicit safe upgrade path, not fake proof."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        guard_path = loom_executor_guard.guard_path(path.parent, action)
        guard_path.unlink()

        with self.assertRaises(loom_orchestrator.OrchestratorError) as upgrade:
            loom_orchestrator.cancel(
                path, owner_home=self.home, install_root=self.installed)
        self.assertEqual(
            "EXECUTOR_GUARD_UPGRADE_REQUIRED", upgrade.exception.code)
        _path, pending, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", pending["status"])
        self.assertEqual(
            pending["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])
        self.assertFalse(guard_path.exists())

    def test_direct_completion_freezes_and_waits_for_exact_open_operation(self):
        """Completion cannot bypass a write admitted before authority retirement."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action = self.arm_executor_guard(started)
        write_event = {
            "hook_event_name": "PreToolUse", "cwd": str(self.repo),
            "session_id": "host-session-1", "turn_id": "host-turn-complete",
            "tool_use_id": "write-before-complete", "tool_name": "Write",
            "tool_input": {"file_path": "src/app.py"},
        }
        loom_executor_guard.begin_operation(
            path.parent, action, write_event,
            operation_kind="structured-write")
        contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(contract["work_order_path"]).parts)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        text = work_order.read_text(encoding="utf-8")
        text = text.replace("status: in-progress", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(contract["evidence_capture"]["pack_path"]), self.repo,
            contract["work_order_id"], medium="python-unittest",
            command=[sys.executable, "-c", "print('verification passed')"])

        with mock.patch.object(
                loom_orchestrator, "_reopen",
                side_effect=AssertionError("completion handler ran before quiescence")), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.complete(
                path, owner_home=self.home, install_root=self.installed)

        self.assertEqual("EXECUTOR_QUIESCENCE_REQUIRED", blocked.exception.code)
        _path, pending, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", pending["status"])
        self.assertEqual(
            pending["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])
        self.assertEqual(
            "action-completion",
            loom_executor_guard.read(path.parent, pending)["freeze"]["reason_code"])
        loom_executor_guard.observe_post(
            path.parent, pending,
            {**write_event, "hook_event_name": "PostToolUse"})

        completed = loom_orchestrator.complete(
            path, now="2035-01-01T00:00:00Z",
            owner_home=self.home, install_root=self.installed)

        self.assertEqual("execute-complete", completed["code"])
        _path, terminal, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("completed", terminal["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        self.assertEqual(
            "action-completion",
            terminal["host_result"]["executor_quiescence"][
                "freeze_operation_class"])

    def test_executor_timeout_waits_for_open_operation_then_retires(self):
        """Timeout cannot clear authority until the exact admitted write closes."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action = self.arm_executor_guard(started)
        write_event = {
            "hook_event_name": "PreToolUse", "cwd": str(self.repo),
            "session_id": "host-session-1", "turn_id": "host-turn-timeout",
            "tool_use_id": "write-before-timeout", "tool_name": "Write",
            "tool_input": {"file_path": "src/app.py"},
        }
        loom_executor_guard.begin_operation(
            path.parent, action, write_event,
            operation_kind="structured-write")
        expired = "2035-01-01T00:00:00Z"

        with self.assertRaises(loom_orchestrator.OrchestratorError) as waiting:
            loom_orchestrator.complete(
                path, now=expired, owner_home=self.home,
                install_root=self.installed)
        self.assertEqual("EXECUTOR_QUIESCENCE_REQUIRED", waiting.exception.code)
        _path, pending, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("pending", pending["status"])
        self.assertEqual(
            pending["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])

        with self.assertRaises(loom_orchestrator.OrchestratorError) as conflict:
            loom_orchestrator.cancel(
                path, now=expired, owner_home=self.home,
                install_root=self.installed)
        self.assertEqual(
            "EXECUTOR_TERMINAL_OPERATION_CONFLICT", conflict.exception.code)
        self.assertIn("action-timeout", conflict.exception.message)
        self.assertEqual(
            pending["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])

        loom_executor_guard.observe_post(
            path.parent, pending,
            {**write_event, "hook_event_name": "PostToolUse"})
        with self.assertRaises(loom_orchestrator.OrchestratorError) as timed_out:
            loom_orchestrator.complete(
                path, now=expired, owner_home=self.home,
                install_root=self.installed)
        self.assertEqual("ACTION_TIMEOUT", timed_out.exception.code)
        _path, terminal, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("expired", terminal["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        self.assertEqual(
            "timed-out",
            terminal["host_result"]["executor_quiescence"]["terminal_state"])

    def test_executor_retry_ceiling_seals_failed_quiescence_before_pointer_clear(self):
        """Terminal handler failure cannot bypass the frozen host ledger."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        action["attempts"] = action["max_attempts"] - 1
        action = loom_orchestrator._write_action(path, action, security)
        contract = started["execution_completion_contract"]
        work_order = self.repo.joinpath(
            *PurePosixPath(contract["work_order_path"]).parts)
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        text = work_order.read_text(encoding="utf-8")
        text = text.replace("status: in-progress", "status: done")
        text = text.replace("- [ ]", "- [x]")
        text = text.replace(
            contract["pending_evidence_text"],
            "Evidence: isolated real-process verification exited 0.")
        work_order.write_text(text, encoding="utf-8")
        loom_lifecycle.capture_acceptance(
            Path(contract["evidence_capture"]["pack_path"]), self.repo,
            contract["work_order_id"], medium="python-unittest",
            command=[sys.executable, "-c", "print('verification passed')"])

        with mock.patch.object(
                loom_orchestrator, "_reopen",
                side_effect=loom_session.SessionInterrupted(
                    "HANDLER_INTERRUPTED", "seeded terminal failure")), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as failed:
            loom_orchestrator.complete(
                path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("HANDLER_INTERRUPTED", failed.exception.code)
        _path, terminal, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("failed", terminal["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        self.assertEqual(
            "failed",
            terminal["host_result"]["executor_quiescence"]["terminal_state"])

    def test_frozen_executor_cannot_complete_around_pending_cancellation(self):
        """Direct completion cannot bypass the durable authority-retirement freeze."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action = self.arm_executor_guard(started)
        loom_executor_guard.begin_operation(
            path.parent, action, {
                "hook_event_name": "PreToolUse", "cwd": str(self.repo),
                "session_id": "host-session-1", "turn_id": "host-turn-frozen",
                "tool_use_id": "write-frozen", "tool_name": "Write",
                "tool_input": {"file_path": "src/app.py"},
            }, operation_kind="structured-write")
        pending = loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("EXECUTOR_QUIESCENCE_REQUIRED", pending["code"])

        with self.assertRaises(loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.complete(
                started["action_path"], owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("EXECUTION_FROZEN", blocked.exception.code)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("pending", action["status"])
        self.assertEqual(
            action["action_id"],
            loom_orchestrator._read_active_pointer(path.parent)["action_id"])

    def test_closed_host_guard_writes_quiescence_then_cancels_exact_action(self):
        """Break caught: only tests can populate host_result.executor_quiescence."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        loom_executor_guard.observe_post(
            path.parent, action, {
                "hook_event_name": "PostToolUse", "cwd": str(self.repo),
                "session_id": "host-session-1", "turn_id": "host-turn-1",
                "tool_use_id": "start-1", "tool_name": "mcp__loom__start",
                "tool_input": {},
            }, lifecycle_control=True)

        cancelled = loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)

        self.assertEqual("cancelled", cancelled["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(path.parent))
        _path, sealed, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        evidence = sealed["host_result"]["executor_quiescence"]
        self.assertEqual("verified-host-terminal", evidence["case"])
        loom_executor_guard.validate_evidence(
            path.parent, sealed, evidence,
            project_world_sha256=evidence["project_world_sha256"])

    def test_cancel_waits_for_preexisting_write_and_completes_after_exact_post(self):
        """Break caught: cancellation treats a PreToolUse without PostToolUse as closed."""
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        path, action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        control = {
            "hook_event_name": "PostToolUse", "cwd": str(self.repo),
            "session_id": "host-session-1", "turn_id": "host-turn-1",
            "tool_use_id": "start-1", "tool_name": "mcp__loom__start",
            "tool_input": {},
        }
        loom_executor_guard.observe_post(
            path.parent, action, control, lifecycle_control=True)
        pre = {
            **control, "hook_event_name": "PreToolUse",
            "tool_use_id": "write-1", "tool_name": "Write",
            "tool_input": {"file_path": "src/app.py"},
        }
        loom_executor_guard.begin_operation(
            path.parent, action, pre, operation_kind="structured-write")
        pending = loom_orchestrator.cancel(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("action-required", pending["status"])
        loom_executor_guard.observe_post(
            path.parent, action, {**pre, "hook_event_name": "PostToolUse"})
        completed = loom_orchestrator.cancel(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("cancelled", completed["status"])

    def test_successor_executor_binding_detects_action_receipt_and_pointer_change(self):
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        action_path = Path(started["action_path"])
        path, executor, security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        instance_id, memory = loom_orchestrator._memory_backend(
            self.home, self.installed, self.repo)
        self.assertEqual(executor["instance_id"], instance_id)
        witness_store = loom_orchestrator._lifecycle_witness_store(
            memory, action_path.parent, executor["project_id"])
        resolved, _semantics, ledger, _witness, state = \
            loom_lifecycle_transition.observe(
                self.repo, witness_store=witness_store)
        receipt = loom_lifecycle_transition.loom_operation_supervisor.run(
            operation_class="successor-executor-binding-test",
            command=[sys.executable, "-c", "pass"], cwd=self.repo,
            timeout=10, allowed_roots=[self.repo],
            protected_roots=[resolved.generation_root])
        raw = {
            "case": "supervisor-terminal",
            "action_id": executor["action_id"],
            "project_id": executor["project_id"],
            "generation_id": executor["generation_id"],
            "action_operation_id": executor["operation_id"],
            "supervisor_operation_id": receipt["operation_id"],
            "project_world_sha256": state.expected_world_sha256,
            "terminal_state": "completed",
            "receipt_sha256": receipt["receipt_sha256"],
            "supervisor_receipt": receipt,
        }
        raw["binding_sha256"] = loom_orchestrator.loom_lifecycle_kernel.digest(raw)
        executor["host_result"] = {
            **(executor.get("host_result") or {}),
            "executor_quiescence": raw,
        }
        executor = loom_orchestrator._write_action(path, executor, security)
        sealed = loom_orchestrator._successor_executor_quiescence(
            state, ledger, directory=action_path.parent,
            owner_home=self.home, install_root=self.installed)
        self.assertEqual(executor["action_hash"], sealed["action_sha256"])
        self.assertEqual("exact-action", sealed["pointer_expectation"])

        changed = json.loads(json.dumps(executor))
        changed["attempts"] += 1
        changed = loom_orchestrator._write_action(path, changed, security)
        rebound = loom_orchestrator._successor_executor_quiescence(
            state, ledger, directory=action_path.parent,
            owner_home=self.home, install_root=self.installed)
        self.assertNotEqual(sealed, rebound)
        self.assertEqual(changed["action_hash"], rebound["action_sha256"])

        loom_orchestrator._clear_active_pointer(
            action_path.parent, executor["action_id"])
        pointer_rebound = loom_orchestrator._successor_executor_quiescence(
            state, ledger, directory=action_path.parent,
            owner_home=self.home, install_root=self.installed)
        self.assertEqual("absent", pointer_rebound["pointer_expectation"])
        self.assertNotEqual(rebound, pointer_rebound)

        loom_orchestrator._write_active_pointer(
            action_path.parent,
            action_id="11111111-1111-4111-8111-111111111111",
            project_id=executor["project_id"])
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator._successor_executor_quiescence(
                state, ledger, directory=action_path.parent,
                owner_home=self.home, install_root=self.installed)

        loom_orchestrator._clear_active_pointer(
            action_path.parent, "11111111-1111-4111-8111-111111111111")
        stale = json.loads(json.dumps(changed))
        stale["host_result"]["executor_quiescence"][
            "action_operation_id"] = "stale-operation"
        stale_raw = stale["host_result"]["executor_quiescence"]
        stale_raw["binding_sha256"] = \
            loom_orchestrator.loom_lifecycle_kernel.digest({
            key: value for key, value in stale_raw.items()
            if key != "binding_sha256"
        })
        loom_orchestrator._write_action(path, stale, security)
        with self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator._successor_executor_quiescence(
                state, ledger, directory=action_path.parent,
                owner_home=self.home, install_root=self.installed)

    def test_cancelled_execution_and_cleared_pointer_do_not_quiesce_active_generation(self):
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned["plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        started_path, started_action, _security = loom_orchestrator._read_action(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        loom_executor_guard.observe_post(
            started_path.parent, started_action, {
                "hook_event_name": "PostToolUse", "cwd": str(self.repo),
                "session_id": "host-session-1", "turn_id": "host-turn-1",
                "tool_use_id": "start-1", "tool_name": "mcp__loom__start",
                "tool_input": {},
            }, lifecycle_control=True)
        cancelled = loom_orchestrator.cancel(
            started["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("cancelled", cancelled["status"])
        cancelled_action_bytes = started_path.read_bytes()
        _cancelled_path, cancelled_action, _cancelled_security = \
            loom_orchestrator._read_action(
                started_path, owner_home=self.home,
                install_root=self.installed)
        self.assertEqual(
            "action-cancel",
            cancelled_action["host_result"]["executor_quiescence"]
            ["freeze_operation_class"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(
            Path(started["action_path"]).parent))
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)

        with self.assertRaises(loom_orchestrator.OrchestratorError) as blocked:
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)

        self.assertEqual(
            "SUCCESSOR_EXECUTOR_QUIESCENCE_REQUIRED", blocked.exception.code)
        self.assertIn(
            "Cancel the current Loom plan generation", blocked.exception.message)
        self.assertEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

        retired = loom_orchestrator.invoke(
            request="Cancel the current Loom plan generation.",
            cwd=self.repo, home=self.home, install_root=self.installed)
        self.assertEqual("generation-cancelled", retired["code"])
        self.assertEqual(cancelled_action_bytes, started_path.read_bytes())
        completed = loom_orchestrator.complete(
            candidate["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("plan-complete", completed["code"])
        self.assertNotEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

    def test_successor_precommit_revalidates_executor_action_and_pointer(self):
        plan_action, planned = self.complete_machine_authored_plan()
        started = loom_orchestrator.start(
            plan_action["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        executor_path = Path(started["action_path"])
        path, executor, security = loom_orchestrator._read_action(
            executor_path, owner_home=self.home, install_root=self.installed)
        _instance_id, memory = loom_orchestrator._memory_backend(
            self.home, self.installed, self.repo)
        witness_store = loom_orchestrator._lifecycle_witness_store(
            memory, executor_path.parent, executor["project_id"])
        resolved, _semantics, _ledger, _witness, state = \
            loom_lifecycle_transition.observe(
                self.repo, witness_store=witness_store)
        receipt = loom_lifecycle_transition.loom_operation_supervisor.run(
            operation_class="successor-precommit-binding-test",
            command=[sys.executable, "-c", "pass"], cwd=self.repo,
            timeout=10, allowed_roots=[self.repo],
            protected_roots=[resolved.generation_root])
        raw = {
            "case": "supervisor-terminal",
            "action_id": executor["action_id"],
            "project_id": executor["project_id"],
            "generation_id": executor["generation_id"],
            "action_operation_id": executor["operation_id"],
            "supervisor_operation_id": receipt["operation_id"],
            "project_world_sha256": state.expected_world_sha256,
            "terminal_state": "completed",
            "receipt_sha256": receipt["receipt_sha256"],
            "supervisor_receipt": receipt,
        }
        raw["binding_sha256"] = loom_orchestrator.loom_lifecycle_kernel.digest(raw)
        executor["host_result"] = {
            **(executor.get("host_result") or {}),
            "executor_quiescence": raw,
        }
        executor = loom_orchestrator._write_action(path, executor, security)

        request = "Plan a new accounting accessibility change."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        original_activate = loom_lifecycle_transition.activate_successor

        def clear_exact_pointer(*args, **kwargs):
            loom_orchestrator._clear_active_pointer(
                executor_path.parent, executor["action_id"])
            return original_activate(*args, **kwargs)

        with mock.patch.object(
                loom_lifecycle_transition, "activate_successor",
                side_effect=clear_exact_pointer), \
                self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)
        self.assertEqual(
            executor["generation_id"],
            loom_plan_store.resolve(self.repo).generation_id)

        loom_orchestrator._write_active_pointer(
            executor_path.parent, action_id=executor["action_id"],
            project_id=executor["project_id"])

        def change_exact_action(*args, **kwargs):
            _path, changed, current_security = loom_orchestrator._read_action(
                executor_path, owner_home=self.home,
                install_root=self.installed)
            changed["attempts"] += 1
            loom_orchestrator._write_action(
                executor_path, changed, current_security)
            return original_activate(*args, **kwargs)

        with mock.patch.object(
                loom_lifecycle_transition, "activate_successor",
                side_effect=change_exact_action), \
                self.assertRaises(loom_orchestrator.OrchestratorError):
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)
        self.assertEqual(
            executor["generation_id"],
            loom_plan_store.resolve(self.repo).generation_id)

    def test_completed_successor_allows_an_ordinary_follow_up_invoke(self):
        """Break caught: terminal successor recovery re-enters deleted owner stage."""
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        candidate_manifest = loom_reliability.exact_tree_manifest(
            loom_orchestrator._stage_path(Path(candidate["action_path"])))
        candidate_modes = {
            entry["path"]: entry["mode"]
            for entry in candidate_manifest["entries"]
            if entry["kind"] == "file"
        }

        completed = loom_orchestrator.complete(
            candidate["action_path"], owner_home=self.home,
            install_root=self.installed)

        self.assertEqual("plan-complete", completed["code"])
        active = loom_plan_store.resolve(self.repo)
        active_manifest = loom_reliability.exact_tree_manifest(
            active.generation_root)
        active_modes = {
            entry["path"]: entry["mode"]
            for entry in active_manifest["entries"]
            if entry["kind"] == "file"
        }
        self.assertEqual(
            candidate_modes,
            {path: active_modes[path] for path in candidate_modes})
        predecessor_manifest = loom_reliability.exact_tree_manifest(
            predecessor.generation_root)
        follow_up = loom_orchestrator.invoke(
            request="Plan a separate accounting documentation improvement.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("action-required", follow_up["status"])
        self.assertEqual("plan", follow_up["intent"])
        self.assertEqual(
            active.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        self.assertEqual(
            active_manifest,
            loom_reliability.exact_tree_manifest(active.generation_root))
        self.assertEqual(
            predecessor_manifest,
            loom_reliability.exact_tree_manifest(predecessor.generation_root))

    def test_terminal_successor_allows_status_with_unrelated_pending_pointer(self):
        """Break caught: immutable history conflicts with later pending work."""
        self.complete_machine_authored_plan()
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        loom_orchestrator.complete(
            candidate["action_path"], owner_home=self.home,
            install_root=self.installed)
        action_path = Path(candidate["action_path"])
        _path, completed, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        envelope_path = loom_lifecycle_transition._successor_envelope_path(
            action_path.parent / "lifecycle-transitions",
            completed["lifecycle_transition"]["command_id"])
        completed_action_bytes = action_path.read_bytes()
        envelope_bytes = envelope_path.read_bytes()
        active = loom_plan_store.resolve(self.repo)
        active_manifest = loom_reliability.exact_tree_manifest(
            active.generation_root)

        follow_up = loom_orchestrator.invoke(
            request="Plan a separate accounting documentation improvement.",
            cwd=self.repo, home=self.home, install_root=self.installed)
        pointer = loom_orchestrator._read_active_pointer(action_path.parent)
        self.assertEqual(follow_up["action_id"], pointer["action_id"])
        self.assertNotEqual(completed["action_id"], pointer["action_id"])

        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", status["status"])
        self.assertEqual(
            follow_up["action_id"],
            loom_orchestrator._read_active_pointer(
                action_path.parent)["action_id"])
        self.assertEqual(completed_action_bytes, action_path.read_bytes())
        self.assertEqual(envelope_bytes, envelope_path.read_bytes())
        self.assertEqual(
            active.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        self.assertEqual(
            active_manifest,
            loom_reliability.exact_tree_manifest(active.generation_root))
        self.assertFalse(os.path.lexists(
            loom_orchestrator._stage_path(action_path)))

    def test_multiple_terminal_successors_remain_independently_verifiable(self):
        """Break caught: old completion is compared with the newest generation."""
        self.complete_machine_authored_plan()
        terminal_actions = []
        terminal_envelopes = []
        for request in (
                "Plan a new accounting accessibility plan.",
                "Plan a separate accounting documentation improvement."):
            candidate = loom_orchestrator.invoke(
                request=request, cwd=self.repo, home=self.home,
                install_root=self.installed)
            _author_medium_action(candidate, request=request)
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)
            action_path = Path(candidate["action_path"])
            _path, completed, _security = loom_orchestrator._read_action(
                action_path, owner_home=self.home, install_root=self.installed)
            envelope_path = loom_lifecycle_transition._successor_envelope_path(
                action_path.parent / "lifecycle-transitions",
                completed["lifecycle_transition"]["command_id"])
            terminal_actions.append((action_path, action_path.read_bytes()))
            terminal_envelopes.append((
                envelope_path, envelope_path.read_bytes()))

        active = loom_plan_store.resolve(self.repo)
        active_manifest = loom_reliability.exact_tree_manifest(
            active.generation_root)

        status = loom_orchestrator.invoke(
            request="Status", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", status["status"])
        self.assertIsNone(loom_orchestrator._read_active_pointer(
            terminal_actions[-1][0].parent))
        for action_path, expected_bytes in terminal_actions:
            self.assertEqual(expected_bytes, action_path.read_bytes())
            self.assertFalse(os.path.lexists(
                loom_orchestrator._stage_path(action_path)))
        for envelope_path, expected_bytes in terminal_envelopes:
            self.assertEqual(expected_bytes, envelope_path.read_bytes())
        self.assertEqual(
            active.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        self.assertEqual(
            active_manifest,
            loom_reliability.exact_tree_manifest(active.generation_root))

    def test_terminal_successor_scan_rejects_corrupted_completed_evidence(self):
        """Break caught: a naked terminal marker bypasses candidate verification."""
        self.complete_machine_authored_plan()
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        loom_orchestrator.complete(
            candidate["action_path"], owner_home=self.home,
            install_root=self.installed)
        action_path = Path(candidate["action_path"])
        _path, completed, security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        completed["result"] = {
            **completed["result"], "code": "forged-plan-complete",
        }
        loom_orchestrator._write_action(action_path, completed, security)
        active = loom_plan_store.resolve(self.repo)
        active_manifest = loom_reliability.exact_tree_manifest(
            active.generation_root)
        envelope_path = loom_lifecycle_transition._successor_envelope_path(
            action_path.parent / "lifecycle-transitions",
            completed["lifecycle_transition"]["command_id"])
        envelope_bytes = envelope_path.read_bytes()

        with self.assertRaises(loom_orchestrator.OrchestratorError) as rejected:
            loom_orchestrator.invoke(
                request="Plan a separate accounting documentation improvement.",
                cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("LIFECYCLE_PROJECTION_INVALID", rejected.exception.code)
        self.assertEqual(envelope_bytes, envelope_path.read_bytes())
        self.assertEqual(
            active_manifest,
            loom_reliability.exact_tree_manifest(active.generation_root))
        self.assertIsNone(
            loom_orchestrator._read_active_pointer(action_path.parent))
        self.assertFalse(os.path.lexists(
            loom_orchestrator._stage_path(action_path)))

    def test_successor_recovery_after_exact_owner_stage_cleanup_is_idempotent(self):
        """Break caught: recovery maps an absent owner stage onto active authority."""
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        action_path = Path(candidate["action_path"])
        owner_stage = loom_orchestrator._stage_path(action_path)
        self.assertTrue(owner_stage.is_dir())
        real_write_envelope = loom_lifecycle_transition._write_envelope
        observed_cleanup_boundary = []

        def interrupt_before_projection_completion(path, value):
            if value.get("kind") == "successor-activation-v1" \
                    and value.get("status") == "completed" \
                    and value.get("projection_status") == "completed":
                observed_cleanup_boundary.append(not os.path.lexists(owner_stage))
                raise loom_lifecycle_transition.LifecycleTransitionInterrupted(
                    "after-owner-stage-deletion")
            return real_write_envelope(path, value)

        with mock.patch.object(
                loom_lifecycle_transition, "_write_envelope",
                side_effect=interrupt_before_projection_completion), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as interrupted:
            loom_orchestrator.complete(
                action_path, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual(
            "LIFECYCLE_PROJECTION_INVALID", interrupted.exception.code)
        self.assertEqual([True], observed_cleanup_boundary)
        self.assertFalse(os.path.lexists(owner_stage))
        _path, completed, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        envelope_path = loom_lifecycle_transition._successor_envelope_path(
            action_path.parent / "lifecycle-transitions",
            completed["lifecycle_transition"]["command_id"])
        interrupted_envelope = json.loads(
            envelope_path.read_text(encoding="utf-8"))
        self.assertEqual("completed", interrupted_envelope["status"])
        self.assertEqual("pending", interrupted_envelope["projection_status"])
        active = loom_plan_store.resolve(self.repo)
        active_manifest = loom_reliability.exact_tree_manifest(
            active.generation_root)
        predecessor_manifest = loom_reliability.exact_tree_manifest(
            predecessor.generation_root)
        _instance_id, memory = loom_orchestrator._memory_backend(
            self.home, self.installed, self.repo)

        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(action_path.parent)):
            recovered = loom_orchestrator._recover_pending_v3_lifecycle(
                target=self.repo, directory=action_path.parent,
                memory=memory, project_id=completed["project_id"],
                owner_home=self.home, install_root=self.installed)

        self.assertEqual(1, len(recovered))
        self.assertEqual("completed", recovered[0]["status"])
        sealed_envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        self.assertEqual("completed", sealed_envelope["projection_status"])
        self.assertFalse(os.path.lexists(owner_stage))
        self.assertEqual(
            active_manifest,
            loom_reliability.exact_tree_manifest(active.generation_root))
        self.assertEqual(
            predecessor_manifest,
            loom_reliability.exact_tree_manifest(predecessor.generation_root))

    def test_successor_recovery_clears_only_its_exact_terminal_action_pointer(self):
        """Break caught: a crash before pointer clear dead-ends committed authority."""
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        action_path = Path(candidate["action_path"])
        real_clear_pointer = loom_orchestrator._clear_active_pointer
        observed_terminal_boundary = []

        def interrupt_terminal_pointer_clear(directory, action_id):
            _path, stored, _security = loom_orchestrator._read_action(
                action_path, owner_home=self.home,
                install_root=self.installed)
            if action_id == candidate["action_id"] \
                    and stored["status"] == "completed":
                observed_terminal_boundary.append(True)
                raise loom_lifecycle_transition.LifecycleTransitionInterrupted(
                    "after-terminal-action-write")
            return real_clear_pointer(directory, action_id)

        with mock.patch.object(
                loom_orchestrator, "_clear_active_pointer",
                side_effect=interrupt_terminal_pointer_clear), \
                self.assertRaises(
                    loom_lifecycle_transition.LifecycleTransitionInterrupted):
            loom_orchestrator.complete(
                action_path, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual([True], observed_terminal_boundary)
        _path, completed, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        self.assertEqual(
            candidate["action_id"],
            loom_orchestrator._read_active_pointer(action_path.parent)["action_id"])
        active = loom_plan_store.resolve(self.repo)
        active_manifest = loom_reliability.exact_tree_manifest(
            active.generation_root)
        predecessor_manifest = loom_reliability.exact_tree_manifest(
            predecessor.generation_root)
        _instance_id, memory = loom_orchestrator._memory_backend(
            self.home, self.installed, self.repo)
        unrelated_action_id = "00000000-0000-4000-8000-000000000099"
        loom_orchestrator._write_active_pointer(
            action_path.parent, action_id=unrelated_action_id,
            project_id=completed["project_id"])

        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(action_path.parent)), \
                self.assertRaises(loom_orchestrator.OrchestratorError) as conflict:
            loom_orchestrator._recover_pending_v3_lifecycle(
                target=self.repo, directory=action_path.parent,
                memory=memory, project_id=completed["project_id"],
                owner_home=self.home, install_root=self.installed)

        self.assertEqual("ACTION_POINTER_CONFLICT", conflict.exception.code)
        self.assertEqual(
            unrelated_action_id,
            loom_orchestrator._read_active_pointer(action_path.parent)["action_id"])
        loom_orchestrator._write_active_pointer(
            action_path.parent, action_id=candidate["action_id"],
            project_id=completed["project_id"])

        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(action_path.parent)):
            recovered = loom_orchestrator._recover_pending_v3_lifecycle(
                target=self.repo, directory=action_path.parent,
                memory=memory, project_id=completed["project_id"],
                owner_home=self.home, install_root=self.installed)

        self.assertEqual(1, len(recovered))
        self.assertEqual("completed", recovered[0]["status"])
        self.assertIsNone(
            loom_orchestrator._read_active_pointer(action_path.parent))
        self.assertEqual(
            active_manifest,
            loom_reliability.exact_tree_manifest(active.generation_root))
        self.assertEqual(
            predecessor_manifest,
            loom_reliability.exact_tree_manifest(predecessor.generation_root))

    def test_successor_recovery_finishes_exact_action_after_authority_commit(self):
        boundaries = (
            "after-index-commit",
            "after-predecessor-terminalization",
            "after-witness",
            "after-plan-projection",
            "after-action-projection",
            "after-envelope-completion",
        )
        original_activate = loom_lifecycle_transition.activate_successor

        for ordinal, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary):
                if ordinal:
                    self.home = self.root / f"home-{ordinal}"
                    self.home.mkdir(parents=True)
                    (self.home / loom_orchestrator.TEST_LEGACY_BACKEND_MARKER).write_bytes(
                        loom_orchestrator.TEST_LEGACY_BACKEND_MARKER_BYTES)
                    self.repo = self.root / f"target-{ordinal}"
                    self._copy_filesystem_fixture(self.repo)
                self.complete_machine_authored_plan()
                request = "Plan a new accounting accessibility plan."
                candidate = loom_orchestrator.invoke(
                    request=request, cwd=self.repo, home=self.home,
                    install_root=self.installed)
                _author_medium_action(candidate, request=request)

                if boundary.startswith("after-") and boundary in {
                        "after-index-commit",
                        "after-predecessor-terminalization",
                        "after-witness"}:
                    def activate_with_fault(*args, **kwargs):
                        kwargs["fault_at"] = boundary
                        return original_activate(*args, **kwargs)
                    patcher = mock.patch.object(
                        loom_lifecycle_transition, "activate_successor",
                        side_effect=activate_with_fault)
                else:
                    def inject_projection_fault(observed):
                        if observed == boundary:
                            raise loom_lifecycle_transition.LifecycleTransitionInterrupted(
                                boundary)
                    patcher = mock.patch.object(
                        loom_orchestrator, "_successor_fault",
                        side_effect=inject_projection_fault)
                with patcher, self.assertRaises(
                        loom_orchestrator.OrchestratorError) as interrupted:
                    loom_orchestrator.complete(
                        candidate["action_path"], owner_home=self.home,
                        install_root=self.installed)
                self.assertEqual("HANDLER_INTERRUPTED", interrupted.exception.code)

                action_path = Path(candidate["action_path"])
                _path, pending, _security = loom_orchestrator._read_action(
                    action_path, owner_home=self.home,
                    install_root=self.installed)
                self.assertEqual("pending", pending["status"])
                instance_id, memory = loom_orchestrator._memory_backend(
                    self.home, self.installed, self.repo)
                self.assertEqual(pending["instance_id"], instance_id)
                with loom_reliability.exclusive_file_lock(
                        loom_orchestrator._orchestration_lock(action_path.parent)):
                    loom_orchestrator._recover_pending_v3_lifecycle(
                        target=self.repo, directory=action_path.parent,
                        memory=memory, project_id=pending["project_id"],
                        owner_home=self.home, install_root=self.installed)

                _path, completed, _security = loom_orchestrator._read_action(
                    action_path, owner_home=self.home,
                    install_root=self.installed)
                self.assertEqual("completed", completed["status"])
                self.assertEqual("installed", completed["pack_seed"]["state"])
                self.assertEqual(
                    "plan-complete", completed["result"]["code"])
                self.assertIsNone(loom_orchestrator._read_active_pointer(
                    action_path.parent))
                self.assertEqual(
                    completed["generation_id"],
                    loom_plan_store.resolve(self.repo).generation_id)

    def test_precommit_failure_preserves_reservation_and_same_action_retries(self):
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        action_path = Path(candidate["action_path"])
        _path, candidate_action, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        source_index = (self.repo / "plans" / "active-generation.json").read_bytes()
        source_ledger = (predecessor.generation_root / "lifecycle.json").read_bytes()
        _instance_id, memory = loom_orchestrator._memory_backend(
            self.home, self.installed, self.repo)
        witness_store = loom_orchestrator._lifecycle_witness_store(
            memory, action_path.parent, candidate_action["project_id"])
        source_witness = witness_store.read()
        source_pointer = loom_orchestrator._read_active_pointer(action_path.parent)
        first_reservation = self.repo / "plans" / (
            ".successor-" + candidate["action_id"] + "-attempt-0")
        retry_reservation = self.repo / "plans" / (
            ".successor-" + candidate["action_id"] + "-attempt-1")
        first_quarantine = action_path.parent.parent / \
            loom_orchestrator.RECOVERY_DIRECTORY / candidate["action_id"] / \
            "successor-reservation-attempt-0"

        with mock.patch.object(
                loom_lifecycle_transition, "activate_successor",
                side_effect=loom_lifecycle_transition.LifecycleTransitionError(
                    "precommit identity failed")), self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
            loom_orchestrator.complete(
                action_path, owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("HANDLER_INTERRUPTED", interrupted.exception.code)
        self.assertFalse(os.path.lexists(first_reservation))
        self.assertTrue(os.path.lexists(first_quarantine))
        self.assertEqual(
            source_index,
            (self.repo / "plans" / "active-generation.json").read_bytes())
        self.assertEqual(
            source_ledger,
            (predecessor.generation_root / "lifecycle.json").read_bytes())
        self.assertEqual(source_witness, witness_store.read())
        self.assertEqual(
            source_pointer,
            loom_orchestrator._read_active_pointer(action_path.parent))
        self.assertEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)
        completed = loom_orchestrator.complete(
            action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("plan-complete", completed["code"])
        self.assertFalse(os.path.lexists(first_reservation))
        self.assertTrue(os.path.lexists(first_quarantine))
        self.assertFalse(os.path.lexists(retry_reservation))
        self.assertNotEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

    def test_precommit_ambiguous_reservation_is_preserved_for_owner_recovery(self):
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        reservation = self.repo / "plans" / (
            ".successor-" + candidate["action_id"] + "-attempt-0")

        def replace_reservation(_root, stage, _prepared, **_kwargs):
            shutil.rmtree(stage)
            stage.mkdir()
            (stage / "owner-recovery-required.txt").write_text(
                "ambiguous replacement\n", encoding="utf-8")
            raise loom_lifecycle_transition.LifecycleTransitionError(
                "precommit identity failed")

        with mock.patch.object(
                loom_lifecycle_transition, "activate_successor",
                side_effect=replace_reservation), self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
            loom_orchestrator.complete(
                candidate["action_path"], owner_home=self.home,
                install_root=self.installed)

        self.assertEqual("HANDLER_INTERRUPTED", interrupted.exception.code)
        self.assertEqual(
            "ambiguous replacement\n",
            (reservation / "owner-recovery-required.txt").read_text(
                encoding="utf-8"))
        self.assertEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

    def test_preindex_abandonment_preserves_candidate_for_exact_retry(self):
        self.complete_machine_authored_plan()
        predecessor = loom_plan_store.resolve(self.repo)
        request = "Plan a new accounting accessibility plan."
        candidate = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(candidate, request=request)
        action_path = Path(candidate["action_path"])
        original_activate = loom_lifecycle_transition.activate_successor

        def activate_with_fault(*args, **kwargs):
            kwargs["fault_at"] = "after-generation-install"
            return original_activate(*args, **kwargs)

        with mock.patch.object(
                loom_lifecycle_transition, "activate_successor",
                side_effect=activate_with_fault), self.assertRaises(
                    loom_orchestrator.OrchestratorError) as interrupted:
            loom_orchestrator.complete(
                action_path, owner_home=self.home,
                install_root=self.installed)
        self.assertEqual("HANDLER_INTERRUPTED", interrupted.exception.code)

        _path, pending, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        _instance_id, memory = loom_orchestrator._memory_backend(
            self.home, self.installed, self.repo)
        with loom_reliability.exclusive_file_lock(
                loom_orchestrator._orchestration_lock(action_path.parent)):
            recovered = loom_orchestrator._recover_pending_v3_lifecycle(
                target=self.repo, directory=action_path.parent,
                memory=memory, project_id=pending["project_id"],
                owner_home=self.home, install_root=self.installed)
        self.assertEqual("abandoned", recovered[0]["status"])
        self.assertEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

        completed = loom_orchestrator.complete(
            action_path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("plan-complete", completed["code"])
        self.assertNotEqual(
            predecessor.generation_id,
            loom_plan_store.resolve(self.repo).generation_id)

    def test_corrupt_lifecycle_returns_sealed_inline_plan_without_exposing_bytes(self):
        """Break caught: untrusted lifecycle storage prevents any useful planning output."""
        plans = self.repo / "plans"
        plans.mkdir()
        (plans / "active-generation.json").write_text(
            '{"schema_version":1,"schema_version":2}\n', encoding="utf-8")
        secret = "private-conflict-value-never-expose"
        (plans / "preserve-me.txt").write_text(secret + "\n", encoding="utf-8")
        before = loom_reliability.exact_tree_manifest(plans)

        result = loom_orchestrator.invoke(
            request="Plan a safe accounting documentation update for README.md.",
            cwd=self.repo, home=self.home, install_root=self.installed)

        self.assertEqual("completed", result["status"])
        self.assertEqual("non-authoritative-plan", result["code"])
        self.assertIn("NON-AUTHORITATIVE PLAN", result["user_message"])
        self.assertIn(
            "Reason code: LIFECYCLE_AUTHORITY_UNTRUSTED",
            result["user_message"])
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))
        self.assertNotIn("action_path", result)
        self.assertEqual(before, loom_reliability.exact_tree_manifest(plans))
        self.assertFalse(any(self.repo.glob(".loom-plan-stage-*")))

    def test_stale_plan_decision_reports_a_real_bounded_recovery_path(self):
        """Break caught: a stale displayed plan hides its recovery requirement."""
        action, completed = self.complete_machine_authored_plan()
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as stale:
            loom_orchestrator.start(
                action["action_path"],
                presentation_sha256=completed[
                    "plan_presentation"]["presentation_sha256"],
                owner_home=self.home, install_root=self.installed)
        self.assertEqual("PLAN_DECISION_STALE", stale.exception.code)
        self.assertIn("changed", str(stale.exception))

    def test_indeterminate_repair_scope_reports_a_real_bounded_recovery_path(self):
        """Break caught: an empty active repair scope mutates the reviewed plan."""
        repair_action, repair_completed = self.complete_machine_authored_plan()
        loom_orchestrator.start(
            repair_action["action_path"],
            presentation_sha256=repair_completed[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        active = loom_plan_store.resolve(self.repo)
        before_repair = loom_reliability.exact_tree_manifest(
            active.generation_root)
        with self.assertRaises(loom_orchestrator.OrchestratorError) as indeterminate:
            loom_orchestrator.invoke(
                request="Repair the failed active action.", cwd=self.repo,
                home=self.home, install_root=self.installed)
        self.assertEqual("REPAIR_SCOPE_INDETERMINATE", indeterminate.exception.code)
        self.assertIn(
            "no exact product-world difference", str(indeterminate.exception))
        self.assertEqual(before_repair, loom_reliability.exact_tree_manifest(
            loom_plan_store.resolve(self.repo).generation_root))

    def test_revision_archive_and_encrypted_envelope_are_schema_valid(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        action_path = Path(action["action_path"])
        _path, stored_action, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        pack = _active_pack(self.repo)
        payload = loom_orchestrator._revision_archive_payload(
            stored_action, prior, pack)
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "plan-revision-archive.schema.json", payload,
            "plan-revision-archive.schema.json")
        self.assertEqual([], report.errors)

        loom_orchestrator._write_revision_archive(
            action_path, stored_action,
            (TestCrypto(), stored_action["instance_id"]),
            prior, pack, payload=payload)
        archive_path = next(
            (action_path.parent / "plan-revisions").glob("*.json"))
        envelope = json.loads(archive_path.read_text(encoding="utf-8"))
        report = loom_lint.Report()
        loom_lint.validate_schema(
            report, "plan-revision-archive.schema.json", envelope,
            "plan-revision-archive.schema.json")
        self.assertEqual([], report.errors)

    def test_revision_archive_rejects_changed_payload_and_redirected_entry(self):
        action, completed = self.complete_machine_authored_plan()
        prior = completed["plan_presentation"]
        action_path = Path(action["action_path"])
        _path, stored_action, _security = loom_orchestrator._read_action(
            action_path, owner_home=self.home, install_root=self.installed)
        pack = _active_pack(self.repo)
        payload = loom_orchestrator._revision_archive_payload(
            stored_action, prior, pack)
        payload["archive_sha256"] = "0" * 64

        with self.assertRaises(loom_orchestrator.OrchestratorError) as changed:
            loom_orchestrator._write_revision_archive(
                action_path, stored_action, None, prior, pack,
                payload=payload)
        self.assertEqual("PLAN_REVISION_ARCHIVE_FAILED", changed.exception.code)

        redirected = pack / "redirected-secret.txt"
        redirected.write_text("private\n", encoding="utf-8")
        original_redirect = loom_orchestrator.loom_privacy._is_redirect
        with mock.patch.object(
                loom_orchestrator.loom_privacy, "_is_redirect",
                side_effect=lambda path: (
                    Path(path).name == redirected.name
                    or original_redirect(path))):
            with self.assertRaises(loom_orchestrator.OrchestratorError) as unsafe:
                loom_orchestrator._revision_archive_payload(
                    stored_action, prior, pack)
        self.assertEqual("PLAN_REVISION_ARCHIVE_FAILED", unsafe.exception.code)

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
        pending_pack = _owned_pack(action)
        manifest = (pending_pack / "MANIFEST.md").read_text(
            encoding="utf-8")
        self.assertIn("## Routing snapshot", manifest)
        report = loom_lint.lint(
            pending_pack, repo_path=self.repo,
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
            "canonical lifecycle transition",
            undone["owner_message"]["human"])
        self.assertNotIn(
            "completed the requested safe frontier",
            undone["owner_message"]["human"])
        self.assertTrue((self.repo / "plans").is_dir())
        resolved = loom_plan_store.resolve(self.repo)
        ledger = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            "generation-cancelled", ledger["events"][-1]["event_type"])
        self.assertFalse((self.repo / ".loom-history").exists())
        _path, restored, _security = loom_orchestrator._read_action(
            action["action_path"])
        self.assertEqual(sealed, restored)

    def test_completed_plan_replays_only_in_the_exact_unchanged_world(self):
        action, completed = self.complete_machine_authored_plan()
        pack = _active_pack(self.repo)
        before = loom_reliability.exact_tree_manifest(pack)
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
        self.assertEqual("blocked", changed["status"])
        self.assertEqual("plan_decision_stale", changed["code"])
        self.assertNotIn("action_id", changed)
        self.assertTrue(loom_reliability.exact_tree_manifests_equal(
            before, loom_reliability.exact_tree_manifest(pack)))
        self.assertIsNone(loom_orchestrator._read_active_pointer(action_directory))
        self.assertEqual(
            2, len(list(action_directory.glob(
                "????????-????-????-????-????????????.json"))))

    def test_completed_plan_manifest_only_drift_returns_sealed_stale_block(self):
        action, _completed = self.complete_machine_authored_plan()
        manifest = _active_pack(self.repo) / "MANIFEST.md"
        mutated = manifest.read_bytes() + b"\n<!-- out-of-band manifest drift -->\n"
        manifest.write_bytes(mutated)
        action_directory = Path(action["action_path"]).parent

        changed = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("blocked", changed["status"])
        self.assertEqual("plan_decision_stale", changed["code"])
        self.assertNotIn("action_id", changed)
        self.assertNotIn("action_path", changed)
        self.assertIsNone(loom_orchestrator._read_active_pointer(action_directory))
        self.assertEqual(mutated, manifest.read_bytes())

    def test_cancelled_completed_plan_same_request_starts_legitimate_new_plan(self):
        action, _completed = self.complete_machine_authored_plan()
        action_path = Path(action["action_path"])
        sealed = action_path.read_bytes()
        cancelled = loom_orchestrator.invoke(
            request="Cancel the current reviewed Loom plan.",
            cwd=self.repo, home=self.home, install_root=self.installed)
        self.assertEqual("generation-cancelled", cancelled["code"])

        replacement = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("action-required", replacement["status"])
        self.assertEqual("plan", replacement["intent"])
        _path, replacement_action, _security = loom_orchestrator._read_action(
            replacement["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("new", replacement_action["request_control"]["relation"])
        self.assertEqual(sealed, action_path.read_bytes())

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
        pack = _owned_pack(action)
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
        decisions = _active_pack(self.repo) / "decisions.md"
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

    def test_plan_undo_v3_ignores_legacy_destination_collision_without_overwriting(self):
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

        self.assertEqual("completed", refused["status"])
        self.assertEqual("undo-complete", refused["code"])
        self.assertTrue((self.repo / "plans").is_dir())
        self.assertEqual("preserve\n", marker.read_text(encoding="utf-8"))
        lifecycle = json.loads(
            (_active_pack(self.repo) / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            "generation-cancelled", lifecycle["events"][-1]["event_type"])

    def test_plan_undo_cancels_reviewable_v3_generation_without_moving_store(self):
        action, _completed = self.complete_machine_authored_plan()

        cancelled = loom_orchestrator.invoke(
            request="Undo the last Loom plan", cwd=self.repo, home=self.home,
            install_root=self.installed)

        self.assertEqual("completed", cancelled["status"])
        self.assertEqual("undo-complete", cancelled["code"])
        self.assertTrue((self.repo / "plans").is_dir())
        resolved = loom_plan_store.resolve(self.repo)
        lifecycle = json.loads(
            (resolved.generation_root / "lifecycle.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            "generation-cancelled", lifecycle["events"][-1]["event_type"])
        self.assertFalse((self.repo / ".loom-history").exists())

    def test_machine_authoring_seals_semantic_unknown_domain_evidence(self):
        self._enable_git_fixture()
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
        pending_pack = _owned_pack(action)
        bundle = json.loads(
            (pending_pack / "domain-discovery.json").read_text(
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
            pending_pack, repo_path=self.repo,
            enforce_lifecycle=False, check_repo_state=False)
        self.assertEqual([], report.findings)
        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        pack = _active_pack(self.repo)
        ledger = json.loads((pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertNotIn(
            "implementation-authorized",
            [event["event_type"] for event in ledger["events"]])

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
        pending_pack = _owned_pack(action)
        self.assertEqual([
            ".loom-small-lifecycle.json",
            "WO-001.md",
            "proofline/material-intent-ledger.json",
            "proofline/proof-graph.json",
        ], authored["files"])
        self.assertEqual(
            [], loom_lint.lint(
                pending_pack, repo_path=self.repo).errors)
        pending_wo = pending_pack / "WO-001.md"
        original_wo = pending_wo.read_text(encoding="utf-8")
        pending_wo.write_text(
            original_wo.replace(
                "id: WO-001", "id: WO-999", 1),
            encoding="utf-8")
        self.assertTrue(
            loom_lint.lint(pending_pack, repo_path=self.repo).errors)
        pending_wo.write_text(original_wo, encoding="utf-8")
        completed = loom_orchestrator.complete(
            action["action_path"], owner_home=self.home,
            install_root=self.installed)
        self.assertEqual("completed", completed["status"])
        pack = _active_pack(self.repo)
        self.assertTrue((pack / ".loom-small-lifecycle.json").is_file())
        self.assertEqual([], loom_gate.verify_small(
            pack / ".loom-small-lifecycle.json"))
        ledger = json.loads((pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            ["generation-created", "plan-reviewed"],
            [event["event_type"] for event in ledger["events"]])
        compact_wo = pack / "WO-001.md"
        self.assertTrue(compact_wo.is_file())
        self.assertFalse((pack / "work-orders").exists())

    def test_bound_revision_replaces_a_compact_plan_with_a_fresh_lifecycle(self):
        request = (
            "Plan a small Python command-line project that reads a text file, "
            "reports the number of lines and words, and includes tests. "
            "Do not implement it.")
        action = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("S", action["tier"])
        contract = action["plan_contract"]
        draft = {
            "schema_version": 1,
            "title": "Plan a small Python text statistics CLI",
            "summary": "Read one text file and report line and word counts.",
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
                "title": "Implement text statistics",
                "outcome": "The CLI reports deterministic line and word counts.",
                "tasks": ["Implement line and word counting."],
                "acceptance": ["`python -m unittest` exits 0."],
                "negative_acceptance": ["a missing path exits nonzero"],
                "out_of_scope": ["Directory traversal."],
                "escalation": ["Stop if another component must change."],
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

        prior_generation = loom_plan_store.resolve(self.repo).generation_root
        prior_manifest = loom_reliability.exact_tree_manifest(prior_generation)

        revision = loom_orchestrator.revise(
            action["action_path"],
            presentation_sha256=completed[
                "plan_presentation"]["presentation_sha256"],
            request=(
                "Revise the plan so the command also reports character count "
                "and handles missing files with a clear error. Do not implement it."),
            owner_home=self.home, install_root=self.installed)
        revised_contract = revision["plan_contract"]
        self.assertEqual("M", revised_contract["tier"])
        revised_facts = revised_contract.get(
            "current_facts_to_verify", revised_contract.get("current_facts", []))
        revised_draft = {
            "schema_version": 1,
            "title": "Plan a small Python text statistics CLI",
            "summary": (
                "Read one text file and report line, word, and character counts "
                "with a clear missing-file error."),
            "assumptions": [], "decisions": [],
            "current_facts": [{
                "domain": item["domain"], "fact": item["fact"],
                "source": "sealed project inspection and shipped CLI adapter",
            } for item in revised_facts],
            "release_exposure": {
                "external_users": 0, "irreversible": False,
                "data_migration": False, "regulated": False,
            },
            "work_orders": [{
                "title": "Implement revised text statistics",
                "outcome": (
                    "The CLI reports deterministic line, word, and character counts."),
                "tasks": [
                    "Implement line, word, and character counting.",
                    "Add a clear missing-file error.",
                ],
                "acceptance": [
                    "`python -m unittest` exits 0 with exact counts."],
                "negative_acceptance": [
                    "a missing path exits nonzero without a traceback"],
                "out_of_scope": ["Directory traversal."],
                "escalation": ["Stop if another component must change."],
                "touches": ["src/app.py"], "depends_on": [],
                "routing": "strong-coding", "size": "S",
            }],
            "domain_evidence": None,
        }

        authored = loom_orchestrator.author(
            revision["action_path"], revised_draft,
            owner_home=self.home, install_root=self.installed)

        lifecycle = (
            ".loom-small-lifecycle.json"
            if revised_contract["tier"] == "S" else loom_gate.LIFECYCLE_FILE)
        self.assertIn(lifecycle, authored["files"])
        self.assertTrue(
            (loom_orchestrator._project_stage_path(
                {"explicit_target": str(self.repo), "cwd": str(self.repo),
                 "action_id": revision["action_id"]}) / lifecycle).is_file())
        self.assertEqual(
            prior_manifest,
            loom_reliability.exact_tree_manifest(prior_generation))
        revised = loom_orchestrator.complete(
            revision["action_path"], owner_home=self.home,
            install_root=self.installed)
        current_generation = loom_plan_store.resolve(self.repo).generation_root
        self.assertEqual(2, revised["plan_presentation"]["binding"]["revision"])
        self.assertNotEqual(prior_generation, current_generation)
        self.assertEqual(
            prior_manifest,
            loom_reliability.exact_tree_manifest(prior_generation))

    def test_machine_authoring_rejects_malformed_draft_without_replacing_seed(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = _owned_pack(action)
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
        self.assertEqual([pack], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertEqual([], list(self.repo.glob(".loom-plan-backup-*")))

    def test_machine_authoring_runs_final_contract_validation_before_activation(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = _owned_pack(action)
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
        self.assertEqual([pack], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertEqual([], list(self.repo.glob(".loom-plan-backup-*")))

    def test_machine_authoring_refuses_a_warning_before_activation(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = _owned_pack(action)
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
        self.assertEqual([pack], list(self.repo.glob(".loom-plan-stage-*")))
        self.assertEqual([], list(self.repo.glob(".loom-plan-backup-*")))

    def test_machine_authoring_rejects_world_drift_before_any_plan_write(self):
        action = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        pack = _owned_pack(action)
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

    def test_verified_resolve_supplies_the_private_lifecycle_witness_reader(self):
        target = self.root / "verified-resolve-witness-target"
        target.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        capabilities = {
            key: key in {"invoke", "complete", "cancel", "status", "markdown"}
            for key in loom_adapter_protocol.CAPABILITY_KEYS
        }
        envelope = loom_adapter_protocol.request_envelope(
            {
                "schema_version": 2, "message_type": "invoke",
                "request_id": "verified-resolve-witness-source",
                "request": request, "cwd": str(target),
            },
            {"id": "codex", "version": "test"},
            adapter={"id": "codex-prompt-hook", "version": "1.0.0"},
            capabilities=capabilities)
        opened = loom_orchestrator.invoke(
            request=request, cwd=target, home=self.home,
            install_root=self.installed,
            transport_invocation_id=loom_orchestrator._transport_invocation_id(
                envelope),
            assurance=envelope["assurance"])
        action_path = Path(opened["action_path"])
        action_sha256 = hashlib.sha256(action_path.read_bytes()).hexdigest()
        original = loom_orchestrator.loom_runtime.prepare_invocation
        witnessed = []

        def require_witness_reader(*args, **kwargs):
            witnessed.append(callable(kwargs.get("lifecycle_witness_reader")))
            return original(*args, **kwargs)

        with mock.patch.object(
                loom_orchestrator.loom_runtime, "prepare_invocation",
                side_effect=require_witness_reader):
            loom_orchestrator.resolve(
                request=request, cwd=target, action_path=action_path,
                action_sha256=action_sha256, home=self.home,
                install_root=self.installed)

        self.assertEqual([True], witnessed)

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

    def test_standard_resolve_rejects_host_before_plan_author_reconciliation(self):
        target = self.root / "standard-resolve-reconciliation-target"
        target.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        opened = loom_orchestrator.invoke(
            request=request, cwd=target, home=self.home,
            install_root=self.installed)
        action_path = Path(opened["action_path"])
        action = json.loads(action_path.read_text(encoding="utf-8"))
        transaction_path = loom_orchestrator._plan_author_transaction_path(action)
        _write(transaction_path, "{}\n")
        injected = loom_plan_author.PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "deterministic reconciliation fault")

        with mock.patch.object(
                loom_orchestrator.loom_plan_author, "reconcile",
                side_effect=injected) as reconcile:
            with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
                loom_orchestrator.resolve(
                    request=request, cwd=target, action_path=action_path,
                    action_sha256=hashlib.sha256(action_path.read_bytes()).hexdigest(),
                    home=self.home, install_root=self.installed)

        self.assertEqual("HOST_UNVERIFIED", caught.exception.code)
        reconcile.assert_not_called()

    def test_verified_resolve_reconciles_plan_author_before_continuing(self):
        target = self.root / "verified-resolve-reconciliation-target"
        target.mkdir()
        request = "Plan a tiny Python command-line greeting tool."
        capabilities = {
            key: key in {"invoke", "complete", "cancel", "status", "markdown"}
            for key in loom_adapter_protocol.CAPABILITY_KEYS
        }
        source = {
            "schema_version": 2, "message_type": "invoke",
            "request_id": "verified-resolve-reconciliation-source",
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
        action = json.loads(action_path.read_text(encoding="utf-8"))
        transaction_path = loom_orchestrator._plan_author_transaction_path(action)
        _write(transaction_path, "{}\n")
        injected = loom_plan_author.PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "deterministic reconciliation fault")

        with mock.patch.object(
                loom_orchestrator.loom_plan_author, "reconcile",
                side_effect=injected) as reconcile:
            with self.assertRaises(loom_orchestrator.OrchestratorError) as caught:
                loom_orchestrator.resolve(
                    request=request, cwd=target, action_path=action_path,
                    action_sha256=hashlib.sha256(action_path.read_bytes()).hexdigest(),
                    home=self.home, install_root=self.installed)

        self.assertEqual("PLAN_AUTHOR_RECOVERY_REQUIRED", caught.exception.code)
        reconcile.assert_called_once()

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
        with mock.patch.object(
                loom_orchestrator.loom_runtime.loom_survey,
                "STATE_HASH_DEADLINE_SECONDS", -1):
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
                "(workspace-content)",
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

        _author_medium_action(result, request=self.request)
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
            def __init__(self):
                self.crypto = crypto

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
            "Plan a museum conservation protocol for water-damaged manuscripts",
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
        pending_pack = _owned_pack(action)
        self.assertTrue((pending_pack / "MANIFEST.md").is_file())
        self.assertFalse((pending_pack / ".loom-small-lifecycle.json").exists())

    def test_named_opaque_domain_survives_known_cli_routing(self):
        self._enable_git_fixture()
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
        pending_pack = _owned_pack(opened)
        self.assertTrue((pending_pack / "MANIFEST.md").is_file())
        self.assertFalse((pending_pack / ".loom-small-lifecycle.json").exists())
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
            pending_pack, repo_path=self.repo,
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
        pack = _owned_pack(opened)
        self.assertTrue((pack / "MANIFEST.md").is_file())
        self.assertFalse((pack / ".loom-small-lifecycle.json").exists())

    def test_research_plan_owner_message_uses_domain_consequence_and_plain_action(self):
        action = loom_orchestrator.invoke(
            request=(
                "Plan a cited research comparison of embedded databases, including "
                "source checks and validation checkpoints. "
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
            ("Plan a cross-platform command-line developer tool with config discovery, "
             "plugin loading, shell completion, package installers, and compatibility tests.",
             "cli", "L"),
            ("Plan an offline-first Android and iOS field inspection app with camera, GPS, "
             "sync conflict resolution, accessibility, and signed store releases.",
             "android", "L"),
            ("Plan a streaming ETL and machine-learning pipeline with schema evolution, "
             "backfills, data quality, drift monitoring, reproducible training, and rollback.",
             "data-etl", "L"),
            ("Plan desktop bookkeeping software with double-entry correctness, currency "
             "precision, tax rules, reconciliation, immutable audit trails, period close, "
             "migrations, and signed releases.", "accounting", "L"),
            ("Plan firmware design and validation for a battery-powered sensor node with bootloader "
             "rollback, secure updates, power-loss recovery, hardware-in-loop tests, and "
             "manufacturing calibration.", "firmware-hardware", "L"),
            ("Plan a publishable research study with three methods, statistical analysis, "
             "source provenance, reproducible notebooks, limitations, and publication package.",
             "research", "L"),
            ("Plan a real-time 3D room configurator with renderer, spatial UX, asset pipeline, "
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
                self.assertTrue((_owned_pack(action) / "MANIFEST.md").is_file())

    def test_plan_completion_rejects_artifact_rows_outside_the_sealed_contract(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(opened, request=self.request)
        manifest = _owned_pack(opened) / "MANIFEST.md"
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
        _author_medium_action(opened, request=self.request)
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        loom_orchestrator._validate_authored_plan(action)
        pending_pack = _owned_pack(opened)
        cases = (
            (pending_pack / "intake.md", "| accounting | balanced postings |",
             "required domain invariants"),
            (pending_pack / "intake.md",
             "| accounting | current platform/tool versions and limits |",
             "required current facts"),
            (pending_pack / "testing.md",
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
        _author_medium_action(opened, request=self.request)
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        path = _owned_pack(opened) / "planning-obligations.json"
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
            "Plan three implementation phases from the completed Phase 8, Phase 9, "
            "and Phase 10 research. Cover outcomes and requirements, architecture "
            "boundaries, and verification evidence. Do not implement.")
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
        _author_medium_action(opened, request=self.request)
        action = json.loads(Path(opened["action_path"]).read_text(encoding="utf-8"))
        pending_pack = _owned_pack(opened)
        decisions = pending_pack / "decisions.md"
        original = decisions.read_text(encoding="utf-8")
        decisions.write_text(original + ("x" * 30000), encoding="utf-8")
        with self.assertRaisesRegex(
                loom_orchestrator.OrchestratorError, "sealed planning budget"):
            loom_orchestrator._validate_authored_plan(action)
        decisions.write_text(original, encoding="utf-8")

        template = next((pending_pack / "work-orders").glob("WO-001-*.md"))
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
        action.pop("generation_id")
        action.pop("request_control")
        action.pop("lifecycle_transition")
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

    def test_pre_ux104_current_schema_plan_action_is_terminal_only_compatible(self):
        """Break caught: a valid pre-mode current-schema action becomes corrupt."""
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        original = json.loads(path.read_text(encoding="utf-8"))
        historical_open = json.loads(json.dumps(original))
        historical_open["request_control"] = json.loads(json.dumps(
            PRE_UX104_PLANNING_CONTROL_V1))
        historical_open["prepared"]["route_contract"]["evidence"] = [
            item for item in historical_open["prepared"]["route_contract"]["evidence"]
            if not item.casefold().startswith("semantic-outcome-")]
        historical_prepared = dict(historical_open["prepared"])
        historical_prepared.pop("prepared_hash")
        historical_open["prepared"]["prepared_hash"] = loom_orchestrator._hash(
            historical_prepared)
        historical_open["action_hash"] = loom_orchestrator._action_hash(
            historical_open)
        path.write_text(json.dumps(historical_open), encoding="utf-8")

        with self.assertRaises(loom_orchestrator.OrchestratorError) as open_error:
            loom_orchestrator._read_action(
                path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("ACTION_REPREPARE_REQUIRED", open_error.exception.code)

        malformed_open = json.loads(json.dumps(historical_open))
        malformed_open["context"]["archived_count"] = -1
        malformed_open["action_hash"] = loom_orchestrator._action_hash(
            malformed_open)
        path.write_text(json.dumps(malformed_open), encoding="utf-8")
        with self.assertRaises(loom_orchestrator.OrchestratorError) as corrupt:
            loom_orchestrator._read_action(
                path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("ACTION_CORRUPT", corrupt.exception.code)

        path.write_text(json.dumps(original), encoding="utf-8")
        _author_medium_action(opened, request=self.request)
        loom_orchestrator.complete(
            opened["action_path"], owner_home=self.home,
            install_root=self.installed)
        terminal = json.loads(path.read_text(encoding="utf-8"))
        terminal["request_control"] = json.loads(json.dumps(
            PRE_UX104_PLANNING_CONTROL_V1))
        terminal["prepared"] = json.loads(json.dumps(historical_open["prepared"]))
        terminal["action_hash"] = loom_orchestrator._action_hash(terminal)
        path.write_text(json.dumps(terminal), encoding="utf-8")

        _path, restored, _security = loom_orchestrator._read_action(
            path, owner_home=self.home, install_root=self.installed)
        self.assertEqual("completed", restored["status"])

    def test_action_read_rejects_noncanonical_or_duplicate_semantic_outcome_tokens(self):
        """Break caught: rehashed forged outcome evidence survives action validation."""
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        path = Path(opened["action_path"])
        base = json.loads(path.read_text(encoding="utf-8"))
        evidence = base["prepared"]["route_contract"]["evidence"]
        ordinary = [
            item for item in evidence
            if not item.casefold().startswith("semantic-outcome-")]
        for tokens in (
                ["semantic-outcome-v1.accounting.-1"],
                ["semantic-outcome-v1.accounting.+1"],
                ["semantic-outcome-v1.accounting.01"],
                ["semantic-outcome-v1.accounting.1 "],
                ["semantic-outcome-v1.accounting.999999"],
                ["semantic-outcome-v1.cli.0"],
                ["semantic-outcome-v1.unknown.0"],
                ["semantic-outcome-v2.accounting.owner-private-export"],
                ["semantic-outcome-v2.cli.tabular-data-export"],
                [
                    "semantic-outcome-v1.accounting.0",
                    "semantic-outcome-v1.accounting.generic",
                ],
                [
                    "semantic-outcome-v1.accounting.0",
                    "semantic-outcome-v2.accounting.tabular-data-export",
                ]):
            with self.subTest(tokens=tokens):
                action = json.loads(json.dumps(base))
                action["prepared"]["route_contract"]["evidence"] = [
                    *ordinary[:14], *tokens]
                prepared_body = dict(action["prepared"])
                prepared_body.pop("prepared_hash")
                action["prepared"]["prepared_hash"] = loom_orchestrator._hash(
                    prepared_body)
                action["action_hash"] = loom_orchestrator._action_hash(action)
                path.write_text(json.dumps(action), encoding="utf-8")

                with self.assertRaises(loom_orchestrator.OrchestratorError) as raised:
                    loom_orchestrator._read_action(
                        path, owner_home=self.home, install_root=self.installed)
                self.assertEqual("ACTION_CORRUPT", raised.exception.code)

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
        _author_medium_action(opened, request=self.request)
        pending_pack = _owned_pack(opened)
        usage = self.root / "replay-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        enabled_evidence = pending_pack / "evidence" / "enabled-replay.json"
        disabled_evidence = pending_pack / "evidence" / "disabled-replay.json"
        _write(enabled_evidence, '{"verification_passed":true,"rework":0}\n')
        _write(disabled_evidence, '{"verification_passed":true,"rework":1}\n')

        def cohort(value, response_id, evidence, memory_ids):
            return {
                "value": value, "memory_ids": memory_ids,
                "outcome_evidence_path":
                    evidence.relative_to(pending_pack).as_posix(),
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
            request="Plan an ETL and machine-learning pipeline",
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
        _author_small_action(action, request=request)
        completed = self.cli(
            "complete", "--action", action["action_path"])
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual("completed", result["status"])
        self.assertEqual("plan-complete", result["code"])
        pack = _active_pack(self.repo)
        result_path = (pack / "WO-001.md").relative_to(self.repo).as_posix()
        self.assertEqual(result_path, result["owner_message"]["result_path"])
        self.assertIn(f"Open: {result_path}.", result["owner_message"]["human"])
        self.assertNotIn("MANIFEST.md", result["owner_message"]["human"])
        self.assertEqual("unavailable", result["usage"]["measurement_status"])
        self.assertEqual([], loom_gate.verify_small(
            pack / ".loom-small-lifecycle.json"))
        self.assertFalse((pack / "MANIFEST.md").exists())
        replayed = self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed)
        self.assertEqual(0, replayed.returncode, replayed.stderr + replayed.stdout)
        replay = json.loads(replayed.stdout)
        self.assertEqual(result["receipt_hash"], replay["receipt_hash"])
        self.assertEqual(result["invocation_id"], replay["invocation_id"])
        self.assertEqual(result_path, replay["owner_message"]["result_path"])
        action_directory = Path(action["action_path"]).parent
        self.assertEqual(
            1, len(list(action_directory.glob(
                "????????-????-????-????-????????????.json"))))

    def test_tier_s_continue_preserves_cli_route_and_seals_real_change(self):
        request = "Plan a single-file CLI flag in src/app.py"
        opened = json.loads(self.cli(
            "invoke", "--request", request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_small_action(opened, request=request)
        usage = self.root / "small-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 300, "cache_read_tokens": 50,
            "output_tokens": 150, "tool_tokens": 50, "retry_tokens": 0,
        }), encoding="utf-8")
        self.assertEqual(0, self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage).returncode)
        pack = _active_pack(self.repo)
        record = pack / ".loom-small-lifecycle.json"
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
        lifecycle = json.loads(
            (pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual([
            "generation-created", "plan-reviewed",
            "implementation-authorized", "work-order-started",
        ], [event["event_type"] for event in lifecycle["events"]])
        self.assertIn(
            "small lifecycle is not authorized",
            loom_gate.verify_small(record, require_authorized=True))
        (self.repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        _mark_small_wo_done(pack)
        loom_lifecycle.capture_acceptance(
            pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('small verification passed')"])
        completed = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        self.assertEqual(
            "completed", json.loads(completed.stdout)["status"],
            completed.stderr + completed.stdout)
        self.assertEqual([], loom_gate.verify_small(
            pack / ".loom-small-lifecycle.json"))

    def test_tier_s_elapsed_freshness_blocks_start_and_keeps_revision_available(self):
        request = "Plan a single-file CLI flag in src/app.py"
        started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        opened = loom_orchestrator.invoke(
            request=request, cwd=self.repo, home=self.home,
            install_root=self.installed, now=started)
        _author_small_action(opened, request=request)
        usage = self.root / "small-stale-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 300, "cache_read_tokens": 50,
            "output_tokens": 150, "tool_tokens": 50, "retry_tokens": 0,
        }), encoding="utf-8")
        planned = loom_orchestrator.complete(
            opened["action_path"], usage, now=started)
        self.assertEqual("plan-complete", planned["code"])
        pack = _active_pack(self.repo)
        before = loom_reliability.exact_tree_manifest(pack)

        future = started + dt.timedelta(days=16)
        blocked = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("blocked", blocked["status"])
        self.assertEqual("plan_decision_stale", blocked["code"])
        self.assertNotIn("action_path", blocked)
        self.assertTrue(loom_reliability.exact_tree_manifests_equal(
            before, loom_reliability.exact_tree_manifest(pack)))

        repair = loom_orchestrator.invoke(
            request="Repair the stale Loom plan", cwd=self.repo,
            home=self.home, install_root=self.installed, now=future)
        self.assertEqual("blocked", repair["status"])
        self.assertEqual("generation_not_active", repair["code"])
        self.assertNotIn("action_path", repair)
        self.assertTrue(loom_reliability.exact_tree_manifests_equal(
            before, loom_reliability.exact_tree_manifest(pack)))

        revision = loom_orchestrator.revise(
            opened["action_path"],
            presentation_sha256=planned["plan_presentation"][
                "presentation_sha256"],
            request="Refresh the compact reviewed plan before implementation.",
            owner_home=self.home, install_root=self.installed, now=future)
        self.assertEqual("action-required", revision["status"])
        self.assertEqual("plan", revision["intent"])
        self.assertEqual(2, revision["revision_context"]["revision"])

    def test_continue_executes_one_declared_work_order_and_seals_completion(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_action(opened, request=self.request)
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
        pack = _active_pack(self.repo)
        work_order = _mark_medium_wo_done(pack)
        loom_lifecycle.capture_acceptance(
            pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('accounting verification passed')"])

        completed = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, completed.returncode, completed.stderr + completed.stdout)
        receipt = json.loads(completed.stdout)
        self.assertEqual("completed", receipt["status"], receipt)
        self.assertEqual("execute-complete", receipt["code"])
        pack = _active_pack(self.repo)
        completion_evidence = json.loads(
            (pack / "completion-evidence" / "WO-001.json").read_text(
                encoding="utf-8"))
        self.assertEqual(
            ["src/app.py"],
            completion_evidence["changed_paths"])
        self.assertEqual("implementation", completion_evidence["causal_scope"])
        self.assertEqual("evidence/WO-001.json",
                         completion_evidence["acceptance_evidence"])
        self.assertEqual(
            f"{pack.relative_to(self.repo).as_posix()}/"
            "completion-evidence/WO-001.json",
            receipt["owner_message"]["result_path"])
        lifecycle = json.loads(
            (pack / "lifecycle.json").read_text(encoding="utf-8"))
        completion_events = [
            event for event in lifecycle["events"]
            if event["event_type"] == "work-order-completed"]
        self.assertEqual(1, len(completion_events))
        self.assertEqual("WO-001", completion_events[0]["payload"]["work_order_id"])
        self.assertEqual(
            completion_evidence["completion_sha256"],
            completion_events[0]["payload"]["completion_sha256"])
        self.assertEqual("done", loom_lint.parse_frontmatter(
            work_order.read_text(encoding="utf-8"))[0]["status"])

        advanced = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)
        self.assertEqual("blocked", advanced["status"])
        self.assertEqual("generation_terminal", advanced["code"])
        self.assertNotIn("action_path", advanced)
        self.assertFalse(advanced.get("repeated", False))

    def test_v3_completion_does_not_depend_on_legacy_proofline_refresh(self):
        opened = loom_orchestrator.invoke(
            request=self.request, cwd=self.repo, home=self.home,
            install_root=self.installed)
        _author_medium_action(opened, request=self.request)
        planned = loom_orchestrator.complete(opened["action_path"])
        self.assertEqual("plan-complete", planned["code"])
        execute = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed)
        (self.repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        pack = _active_pack(self.repo)
        _mark_medium_wo_done(pack)
        loom_lifecycle.capture_acceptance(
            pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('verified')"])
        with mock.patch.object(
                loom_orchestrator, "_refresh_proofline_completion",
                side_effect=loom_orchestrator.OrchestratorError(
                    "PROOFLINE_COMPLETION_INVALID", "fixture failure")):
            completed = loom_orchestrator.complete(execute["action_path"])
        self.assertEqual("completed", completed["status"])
        self.assertEqual("execute-complete", completed["code"])
        lifecycle = json.loads(
            (pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertIn(
            "work-order-completed",
            [event["event_type"] for event in lifecycle["events"]])

    def test_execute_refuses_noop_completion(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_action(opened, request=self.request)
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
        pack = _active_pack(self.repo)
        _mark_medium_wo_done(pack)
        loom_lifecycle.capture_acceptance(
            pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('no-op probe')"])

        result = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        receipt = json.loads(result.stdout)
        self.assertEqual("blocked", receipt["status"])
        self.assertIn("no declared target changed", receipt["user_message"])
        lifecycle = json.loads(
            (pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [], [event for event in lifecycle["events"]
                 if event["event_type"] == "work-order-completed"])

    def test_execute_refuses_changes_outside_declared_touches(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_action(opened, request=self.request)
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
        pack = _active_pack(self.repo)
        _mark_medium_wo_done(pack)
        loom_lifecycle.capture_acceptance(
            pack, self.repo, "WO-001", medium="cli-process",
            command=[sys.executable, "-c", "print('scope probe')"])

        result = self.cli(
            "complete", "--action", execute["action_path"], "--usage", usage)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        receipt = json.loads(result.stdout)
        self.assertEqual("blocked", receipt["status"])
        self.assertIn("outside declared touches", receipt["user_message"])
        lifecycle = json.loads(
            (pack / "lifecycle.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [], [event for event in lifecycle["events"]
                 if event["event_type"] == "work-order-completed"])

    def test_elapsed_freshness_blocks_start_and_keeps_revision_available(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_action(opened, request=self.request)
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        planned_process = self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage)
        self.assertEqual(
            0, planned_process.returncode,
            planned_process.stderr + planned_process.stdout)
        planned = json.loads(planned_process.stdout)

        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=62)
        blocked = loom_orchestrator.invoke(
            request="Continue", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("blocked", blocked["status"])
        self.assertEqual("plan_decision_stale", blocked["code"])
        self.assertNotIn("action_path", blocked)

        repair = loom_orchestrator.invoke(
            request="Repair the stale Loom plan", cwd=self.repo, home=self.home,
            install_root=self.installed, now=future)
        self.assertEqual("blocked", repair["status"])
        self.assertEqual("generation_not_active", repair["code"])
        self.assertNotIn("action_path", repair)

        revision = loom_orchestrator.revise(
            opened["action_path"],
            presentation_sha256=planned["plan_presentation"][
                "presentation_sha256"],
            request="Refresh the reviewed plan before any implementation starts.",
            owner_home=self.home, install_root=self.installed, now=future)
        self.assertEqual("action-required", revision["status"])
        self.assertEqual("plan", revision["intent"])
        self.assertEqual(2, revision["revision_context"]["revision"])

    def test_repair_requires_exact_content_bound_evidence(self):
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_action(opened, request=self.request)
        usage = self.root / "usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        planned_process = self.cli(
            "complete", "--action", opened["action_path"], "--usage", usage)
        self.assertEqual(
            0, planned_process.returncode,
            planned_process.stderr + planned_process.stdout)
        planned = json.loads(planned_process.stdout)
        started = loom_orchestrator.start(
            opened["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        self.assertEqual("execute", started["intent"])
        _write(self.repo / "src" / "app.py", "VALUE = 2\n")
        repair = loom_orchestrator.invoke(
            request="Repair the failed active action.", cwd=self.repo, home=self.home,
            install_root=self.installed)
        prior_attempt = json.loads(
            Path(started["action_path"]).read_text(encoding="utf-8"))
        self.assertEqual("cancelled", prior_attempt["status"])
        pointer = loom_orchestrator._read_active_pointer(
            Path(repair["action_path"]).parent)
        self.assertEqual(repair["action_id"], pointer["action_id"])
        self.assertEqual("selective", repair["repair_plan"]["regate_scope"])
        sections = repair["repair_plan"]["affected_plan_sections"]
        self.assertEqual(["active-work-order"], sections)
        self.assertEqual(
            ["src/app.py"], repair["repair_plan"]["changed_paths"])
        self.assertIsNone(repair["contract_rebase"])
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
                for section in sections
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
                for section in sections
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
                for section in sections
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
        self.assertEqual(len(sections), len(entries))
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

    def test_repair_compiles_and_executes_closed_recipe_once(self):
        _write(
            self.repo / "test_repair_probe.py",
            "import unittest\n\n"
            "class RepairProbeTests(unittest.TestCase):\n"
            "    def test_current_target(self):\n"
            "        self.assertTrue(True)\n")
        opened = json.loads(self.cli(
            "invoke", "--request", self.request, "--cwd", self.repo,
            "--home", self.home, "--install-root", self.installed).stdout)
        _author_medium_action(opened, request=self.request)
        usage = self.root / "compiled-usage.json"
        usage.write_text(json.dumps({
            "input_tokens": 500, "cache_read_tokens": 100,
            "output_tokens": 200, "tool_tokens": 100, "retry_tokens": 0,
        }), encoding="utf-8")
        planned_process = self.cli(
            "complete", "--action", opened["action_path"],
            "--usage", usage)
        self.assertEqual(
            0, planned_process.returncode,
            planned_process.stderr + planned_process.stdout)
        planned = json.loads(planned_process.stdout)
        started = loom_orchestrator.start(
            opened["action_path"],
            presentation_sha256=planned[
                "plan_presentation"]["presentation_sha256"],
            owner_home=self.home, install_root=self.installed)
        self.assertEqual("execute", started["intent"])
        _write(self.repo / "src" / "app.py", "VALUE = 3\n")
        repair = loom_orchestrator.invoke(
            request="Repair the failed active action.", cwd=self.repo, home=self.home,
            install_root=self.installed)
        sections = repair["repair_plan"]["affected_plan_sections"]
        result = self.root / "compiled-repair.json"
        result.write_text(json.dumps({
            "schema_version": 3,
            "risk": "medium",
            "verification_requests": [{
                "section": section,
                "template_id": "python-unittest-v1",
                "target": "test_repair_probe",
                "timeout_seconds": 30,
            } for section in sections],
        }), encoding="utf-8")
        completed = loom_orchestrator.complete(
            repair["action_path"], usage, result_path=result)
        self.assertEqual("repair-complete", completed["code"])
        action = json.loads(
            Path(repair["action_path"]).read_text(encoding="utf-8"))
        entries = action["host_result"]["repair_verification"]
        self.assertEqual(sorted(sections), sorted(
            item["section"] for item in entries))
        self.assertTrue(all(
            item["attestation_status"] == "loom-compiled-executed-local"
            for item in entries))
        self.assertEqual(1, len({
            item["evidence_id"] for item in entries}))
        recipe = (
            Path(repair["action_path"]).parent
            / f"{action['action_id']}.evidence" / "compiled-recipe.json")
        self.assertTrue(recipe.is_file())
        self.assertFalse(json.loads(
            recipe.read_text(encoding="utf-8"))["implementation_authorized"])

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
        _author_medium_action(second, request=self.request)
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
