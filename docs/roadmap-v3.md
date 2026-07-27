# Loom Roadmap v3

Status cut: 2026-07-27

This is the public operational roadmap. It replaces the obsolete 1.8.4 baseline in the original
master-roadmap analysis with the current repository, release, merged-remediation, and assurance
state. It does not copy private planning packs, owner state, local paths, or unrelated portfolio
material.

## Status language

Roadmap status describes the strongest evidence available:

- **Released**: present in an immutable published release with bound release evidence.
- **Merged**: present on `main`, but not necessarily part of the published release or a green
  release candidate.
- **Candidate**: implemented on an unmerged branch with repository tests or receipts.
- **Planned**: specified, but the roadmap exit criteria have not been demonstrated.
- **Blocked**: promotion is stopped by a known missing or failing gate.

Code presence, test presence, test count, a simulated adapter, or a passing helper build does not
upgrade an item to released or supported.

## Current baseline

| Subject | Exact state | Interpretation |
|---|---|---|
| Published release | `v1.8.15` at `ac3906a1450c6a625ee77f945eaa90169ee037ef` | Published 2026-07-25 with a signed tag and release assets |
| Plugin ZIP | `loom-plugin-v1.8.15.zip` | SHA-256 `1a252a9ce02a6a86235bb1831617af7f1a83680852326b1399d1b9455132b49a` |
| Release candidate | `1.8.16` | Prepared from the current protected `main`; it remains unreleased until exact-cut, signing, and draft-release verification pass |
| Current `main` | `7b10cf18a8e539cd32097d256c9d9dd130082555` | Merge commit for [PR #33](https://github.com/saroo98/loom/pull/33), following the Phase 1–2 remediation in PR #32 |
| Remediation checks | 9 required quality checks and 21 native-compatibility checks passed | Merge evidence for PR #32; not release, installation, deployment, support, or independent-assurance evidence |
| Known blockers at merge | No known Critical or High blocker | Absence of a known blocker is not a guarantee of security, reliability, or recovery |
| Website/documentation | Merged through PR #33 | Public-facing changes are on `main`; Pages deployment and software release promotion remain separate |
| Pages source | `main:/docs` | GitHub Pages source; the public site changes only after this branch is reviewed, merged, and the Pages workflow succeeds |
| Current generated inventory | 1,218 test methods in 109 modules | Repository inventory only; it does not say the full suite passed in this website task |
| Generated readiness | `not-ready` | 0 supported claims, 9 experimental, 1 stale, 2 unsupported, 14 unverified |

## Immediate release truth

The published 1.8.15 release remains the current immutable public artifact. The Phase 1–2
remediation merged into `main` through PR #32 after 9 required quality checks and 21
native-compatibility checks passed. No known Critical or High blocker was reported at merge.

Those results supersede the earlier pre-remediation workflow failures recorded by the previous
roadmap cut. They do not publish a new artifact, modify an installation, deploy the website,
establish supported hosts or platforms, or replace exact release and independent evidence. This
documentation task does not change the runtime, schemas, behavioral tests, CI, release code,
exact-cut artifact, or remediation logic.

## Phase status

| Phase | Roadmap outcome | Current status | Evidence and remaining gate |
|---|---|---|---|
| PH-0 | Exact public baseline | Released | 1.8.15 tag and assets exist; later commits remain separate |
| PH-1 | Safety and self-hosting foundation | Merged, not released | PR #32 merged the remediation after required quality and native-compatibility checks passed; release promotion, generated support claims, live-host acceptance, and independent assurance remain separate |
| PH-2 | Truth authority, neutral identity, common measurement | Planned | Individual truth and measurement mechanisms exist, but the phase exit criteria have not been demonstrated as one promoted system |
| PH-3 | Proofline semantic core and owner trust state | Planned | No public evidence that all material intent atoms and promotion paths meet the roadmap thresholds |
| PH-4 | Scope-creep detection and reviewer proof bundle | Planned | Existing receipts and support bundles do not establish the full product outcome |
| PH-5 | Bounded speed and outcome-specific verification | Planned | Performance contracts and verification recipes exist in part; no promoted parity and latency result closes the phase |
| PH-6 | Living proof and measured memory | Planned | Scoped memory and forgetting exist; controlled benefit, harm, rebase, and replay outcomes remain incomplete |
| PH-7 | Exact host and native platform evidence | Blocked | Generated readiness has no supported host or platform claims |
| PH-8 | Release passport and promotion contract | Planned | Release-subject machinery exists; no current passport promotes the remediation subject |
| PH-9 | Neutral rebrand and compatibility migration | Planned | No rename or migration is authorized by this roadmap update |
| PH-10 | Independent validation and launch gate | Blocked | No qualifying independent hostile, privacy, usability, and fresh-machine evidence |
| PH-11 | Bounded research | Planned | Research outputs must not become production authority without a separate promotion decision |

## PH-1 work-item status

The original roadmap treats PH-1 as one exit gate. The repository contains merged implementation
for each family, but merge status alone does not complete the release, host, platform, or
independent-assurance gates.

| Work item | Merged implementation | Promotion status |
|---|---|---|
| `FND-004` Mandatory Hermetic Execution Supervisor | Process supervision, environment policy, containment tests, and remediation are present on `main` | Merged; release and independent hostile evidence remain separate |
| `FND-005` Central Filesystem Path Authority | Central path receipts, protected-root checks, ownership, and hostile path tests are present on `main` | Merged; not released or generally supported |
| `FND-006` Canonical Semantic Models and Projection Parity | Schema and semantic-parity generation exist; remediation binds version and compatibility semantics | Merged; promotion evidence remains separate |
| `FND-007` Universal Write-Ahead Operation Journal | Operation envelopes and supervised execution receipts are present | Merged; promotion evidence remains separate |
| `FND-008` End-to-End Execution-Chain Identity | Session, action, operation, and evidence identity fields are implemented | Merged; promotion evidence remains separate |
| `GOV-001` Stable Controller, Candidate Runtime, and Owner-Authorized Repair | Self-hosting authority and continuation controls exist; remediation separates planning from execution authority | Merged; live-host acceptance remains unverified |
| `FND-009` Atomic Runtime-State Activation Pair | Activation sets, runtime pointers, bootstrap checks, and rollback boundaries exist | Merged; installed-host recovery evidence remains incomplete |
| `MEM-002` Durable Forgetting and Anti-Resurrection | Tombstones, deletion epochs, scope tests, and conflict behavior exist | Merged; longitudinal and multi-device assurance remains incomplete |

## Defect families addressed by the merged remediation

The following families are addressed at the merged implementation and repository-test level. They
are not called released fixes or independent assurance.

### 1. Containment, path, and operation authority

- reject user-profile and filesystem roots before bootstrap writes;
- prevent a pre-existing path from being claimed or removed;
- write an operation envelope before a supervised sensitive process starts;
- bind process completion to the operation receipt; and
- prevent sensitive production modules from bypassing the write-ahead envelope.

Relevant merged changes include `tools/loom_path_authority.py`,
`tools/loom_operation_envelope.py`, `tools/loom_operation_supervisor.py`,
`tools/test_path_authority.py`, and `tools/test_operation_envelope.py`.

### 2. Bootstrap, installation, and activation recovery

- converge concurrent identical cold bootstraps on one verified runtime;
- reject a mismatched concurrent activation destination;
- wait for operating-system lock release after process termination;
- preserve the primary failure while cleanup and recovery run; and
- keep helper build paths bounded instead of nesting them under a deep runtime path.

Relevant merged changes include `scripts/loom_bootstrap.py`, `tools/loom_install.py`,
`tools/test_loom_bootstrap_v11.py`, and `tools/test_release_standard.py`.

### 3. Planning versus execution authority

- prevent plan-deliverable language from creating implementation permission;
- keep planning release checks distinct from release authority;
- require explicit continuation for medium-consequence plans;
- finalize only after machine authoring proves the plan ready; and
- block destructive effects even when they are embedded in a planning request.

Relevant merged changes include `tools/loom_gate.py`, `tools/loom_plan_author.py`,
`tools/loom_orchestrator.py`, `tools/test_continuation_authority.py`,
`tools/test_consumer_planning.py`, and `tools/test_production_orchestrator.py`.

### 4. Request routing and scoped memory

- distinguish product nouns from real operational effects;
- stop negative website language from activating website work;
- route research, writing, mobile, accounting, firmware, and explanation requests by the active
  subject rather than incidental words;
- isolate project preferences across project switches while retaining them across domain switches;
- allow exact-ID forgetting of an active but unselected record; and
- prevent forgotten content from being reported as active under a new identifier.

Relevant merged changes include `tools/loom_domain.py`, `tools/loom_tier.py`,
`tools/loom_vault.py`, `tools/test_phase1_routing.py`, `tools/test_domain_universality.py`,
and `tools/test_loom_vault_v11.py`.

### 5. Performance, parity, and evidence binding

- make compatibility-test semantics part of generated parity;
- detect reader-version branch drift;
- avoid staling semantic projections on documentation-only whitespace;
- bind final inventory before the suite and certify it only after the suite; and
- fail before running tests when an output parent is missing.

Relevant merged changes include `tools/loom_semantic_parity.py`,
`tools/loom_performance_baseline.py`, `tools/loom_test.py`,
`tools/test_semantic_parity.py`, `tools/test_performance_foundation_baseline.py`, and
`tools/test_test_runner.py`.

## Architectural and behavioral decisions retained

1. **Implementation code cannot be its own sole certifier.** Repository tests are necessary but do not
   replace exact-main, released-host, provider, or independent evidence.
2. **A plan is not execution authority.** Authorization is content-bound and baseline-bound.
3. **Unsafe effects use one path and operation authority.** A direct or duplicated effect path is a
   defect, even if a nearby test passes.
4. **Failure preserves the primary cause.** Cleanup, quarantine, and recovery cannot overwrite the
   error that caused the action to stop.
5. **Memory is selected by exact scope.** Incidental domain words and ambient repository content do
   not activate unrelated owner state.
6. **Forgetting is an anti-resurrection contract.** Tombstones and deletion epochs matter more than
   deleting one visible record.
7. **Evidence classes do not upgrade each other.** Test inventory, local tests, simulated hosts,
   native builds, exact release receipts, and independent review remain distinct.
8. **Public claims follow released evidence.** Merged code is not described as released, installed,
   deployed, generally available, supported, or reliable without the corresponding evidence.

## Testing and verification changes

PR #32 merged the Phase 1–2 remediation at
`17be7f58ff43c56339a39f90f03e2bacf2c00896`. The merge records 9 required quality checks and 21
native-compatibility checks passing. The generated repository inventory at the merge discovers
1,218 methods across 109 modules.

That evidence supports only these statements:

- `main` contains targeted regression coverage for the defect families above;
- the generated inventory and semantic-parity artifacts were refreshed; and
- the remediation passed its recorded merge checks but has not thereby earned release promotion.

This website/documentation task intentionally does not run the full 1,200-plus suite. Its scoped
validation is limited to website build-equivalent serving, JavaScript syntax, HTML, links, assets,
accessibility, responsive rendering, reduced motion, runtime errors, and documentation checks.

## Remaining risks and assurance gaps

- The PR #32 merge checks do not replace exact release-subject, installed-host, provider, or
  independent evidence.
- No release containing the merged remediation has been published, installed, or deployed.
- Generated readiness records no supported host or native platform claim.
- Several host claims are experimental, one is stale, and two are unsupported.
- Release, privacy, reproducibility, SBOM, provenance, rollback, threshold-authority, and external
  hostile-audit claims lack a current qualifying subject in generated readiness.
- A test count does not establish correctness, performance, reliability, security, or recovery.
- Scoped learning records do not establish persistent improvement.
- Real-host behavior may differ from simulated protocol conformance.
- The public website will continue to show the old content until a later approved merge and Pages
  deployment.

## Next work

### Required before release promotion

1. Bind exact-cut, capability, readiness, performance, parity, provenance, privacy, rollback, and
   release-passport evidence to one immutable release subject.
2. Complete fresh installed-host and real-host acceptance for every host or platform claim.
3. Resolve every missing or failing required release cell, or explicitly narrow the claim.
4. Obtain qualifying independent hostile and usability evidence where the claim requires it.
5. Obtain owner approval before release, installation, deployment, or publication.

### Required before PH-1 can be marked complete

1. Demonstrate the PH-1 exit gate against one exact promoted subject.
2. Prove rollback and recovery preserve the primary failure and owner state.
3. Prove candidate repair cannot directly certify or promote itself.
4. Bind platform and host observations to exact subject and environment identities.
5. Update this roadmap from the resulting receipts, not from implementation intent.

### Later roadmap work

After PH-1 promotion, proceed in dependency order:

1. PH-2 truth authority, neutral identity, and common measurement;
2. PH-3 Proofline semantics and the owner trust state;
3. PH-4 orphan-change detection and proof bundles;
4. PH-5 bounded speed and verification recipes;
5. PH-6 living proof and measured memory;
6. PH-7 exact host and platform evidence;
7. PH-8 release passport;
8. PH-9 rebrand only after compatibility and rollback design;
9. PH-10 independent launch validation; and
10. PH-11 research without production promotion by implication.

## Non-directions

Roadmap v3 does not authorize:

- a full autonomous coding-agent runtime;
- default cloud owner memory or centralized Loom telemetry;
- unbounded cross-project memory;
- implicit deployment, spending, publication, or destructive action;
- a host or platform support badge without current exact evidence;
- a rebrand before identity, migration, compatibility, and rollback boundaries exist; or
- treating GitHub Issues, a website, or generated prose as Loom’s execution authority.
