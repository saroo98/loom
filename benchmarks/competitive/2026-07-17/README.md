# Competitive evidence snapshot — 2026-07-17

## Verdict

Loom's exact public-cut score is **71.60/100**. That score is mechanically bound to the cut that
passed Loom's suite, privacy firewall, publication audit, and explicit private-token scans.

There is **no defensible absolute winner** in this snapshot. GSD Core is the strongest current peer
on inspected source, with a known-evidence score of **66.67** and a possible range of **54.00–73.00**
because its tool correctness, runtime speed, and hostile robustness were not rerun here. Loom's
71.60 therefore leads the evidence actually reproduced in this audit, but incomplete peer execution
coverage means this snapshot does not establish absolute leadership.

This is the useful conclusion: Loom is strongest in scoped owner learning, memory isolation,
privacy, unknown-domain refusal, and evidence-bound claims. GSD Core is stronger in ecosystem
breadth, release maturity, and the depth of its existing command/workflow machinery. Superpowers
has the simplest normal interaction. BMAD has the broadest authored product-method guidance.
OpenSpec and Spec Kit have more mature public adoption and integration surfaces.

## Method

- The same 17-category, 100-point rubric in
  [score-rubric-v1.json](../../../contracts/score-rubric-v1.json) was used for all six projects.
- Each peer was cloned at an exact commit and inspected from primary repository sources.
- Categories outside a project's stated scope are **N/A**, not scored as failures. Spec Kit,
  OpenSpec, and Superpowers do not claim evolving per-owner memory, so owner-learning and
  memory-vault categories are removed from their denominator.
- Loom was exercised as an exact public cut. Peer suites were not installed and rerun in this
  pass. Their tool correctness, speed, and hostile robustness cells are therefore **[UNVERIFIED]**,
  not inferred from workflow files.
- A peer's `known score` is normalized over verified applicable categories. Its lower bound treats
  every unverified category as zero; its upper bound treats every unverified category as 100.
- “Verified” in a peer snapshot means the cited source at the exact revision was inspected. It is
  not a clean-room execution certificate.
- Snapshots expire after 30 days. A current comparison must refresh commits, sources, public facts,
  and unknowns.

## Revisions

| Project | Exact revision | Repository inventory observed |
|---|---|---|
| Loom | `a0628bae76abc3e33ae22824ef40b2e77b595cfc` | Exact public cut: 283 files, 2,611,202 bytes; 589 tests, 0 failures/errors, 7 Windows capability skips reproduced on WSL |
| Spec Kit | `7bdf6c50416c2e7ea96d8398b569a78808adc6e9` | 428 tracked files; about 131 test-related paths; 20 workflow files/items |
| OpenSpec | `0a99f410457271aa773d8b106f03f637f7c6b3c0` | 903 tracked files; about 298 test-related paths; 3 workflow files |
| Superpowers | `d884ae04edebef577e82ff7c4e143debd0bbec99` | 153 tracked files; about 66 test-related paths; no GitHub Actions workflow at this revision |
| BMAD Method | `717479bc3f50f38119fd958b9e577a8bde2e0184` | 565 tracked files; about 29 test-related paths; 5 workflow files |
| GSD Core | `a30fb75b51544359a546b8a833d52e31a702bbd8` | 1,919 tracked files; about 722 test-related paths; 26 workflow files |

The test-related counts are path inventories, not pass counts. The original
`gsd-build/get-shit-done` repository is archived and redirects to the active GSD Core successor;
the active successor is the comparison target.

## Overall comparison

| Project | Known score | Lower bound | Upper bound | Evidence coverage | Important normalization |
|---|---:|---:|---:|---:|---|
| Loom | **71.60** | 71.60 | 71.60 | 100% | All categories applicable; exact cut executed |
| GSD Core | **66.67** | 54.00 | 73.00 | 81.00% | Runtime correctness/speed/robustness unverified |
| Superpowers | **59.34** | 46.38 | 68.22 | 78.16% | Owner learning and owner-vault memory N/A |
| BMAD Method | **58.77** | 47.60 | 66.60 | 81.00% | Runtime correctness/speed/robustness unverified |
| Spec Kit | **56.47** | 44.14 | 65.98 | 78.16% | Owner learning and owner-vault memory N/A |
| OpenSpec | **56.18** | 43.91 | 65.75 | 78.16% | Owner learning and owner-vault memory N/A |

Do not rank by `known score` alone when coverage differs. The lower/upper interval is part of the
result, not a footnote.

## Category matrix

`U` means **[UNVERIFIED]** in this audit. `N/A` is excluded from that project's denominator.

| Category | Loom | Spec Kit | OpenSpec | Superpowers | BMAD | GSD Core |
|---|---:|---:|---:|---:|---:|---:|
| Architecture and structure | 80 | 80 | 80 | 70 | 75 | 85 |
| Tool correctness | 75 | U | U | U | U | U |
| Planning and guidance quality | 70 | 65 | 60 | 90 | 95 | 90 |
| Lifecycle enforcement | 80 | 45 | 50 | 80 | 90 | 90 |
| Adaptability and universality | 75 | 60 | 70 | 60 | 90 | 75 |
| Token efficiency | 65 | 20 | 15 | 25 | 25 | 50 |
| Speed and friction | 65 | U | U | U | U | U |
| Surface simplicity | 75 | 40 | 55 | 95 | 35 | 40 |
| Owner-specific learning | 65 | N/A | N/A | N/A | 35 | 50 |
| Memory isolation and bounds | 100 | N/A | N/A | N/A | 25 | 40 |
| Integration ecosystem | 65 | 65 | 65 | 65 | 65 | 65 |
| Robustness and safety | 70 | U | U | U | U | U |
| Privacy and sovereignty | 100 | 55 | 20 | 30 | 60 | 60 |
| Testing and release engineering | 60 | 75 | 75 | 30 | 50 | 75 |
| Documentation and onboarding | 80 | 90 | 85 | 85 | 90 | 90 |
| Observability and claim honesty | 70 | 35 | 50 | 20 | 25 | 60 |
| Adoption and external validation | 20 | 50 | 50 | 50 | 50 | 50 |

## Project findings

### Loom

**What is proven:** exact-cut privacy, complete local token categories, bounded small-task context,
causal lifecycle gates, unknown-domain refusal, scoped learning, deterministic forgetting/merge,
and one intent-routed surface.

**What holds the score down:** no provider-attested production p95 corpus, no full real-host adapter
matrix, no hosted cross-platform release matrix for the exact cut, no independent user study or
hostile audit, and minimal public adoption.

### GSD Core

**Strongest evidence:** very broad runtime integrations; explicit architecture; large test,
security, coverage, and mutation surfaces; multi-OS CI; npm OIDC provenance; deep lifecycle and
context-engineering documentation.

**Material gaps against Loom's scope:** user profiling and learning extraction require explicit
workflows; promotion is HITL; no automatic effect attribution/forgetting; no encrypted owner vault;
no all-file public firewall; context headroom is documented as heuristic; the command surface is
large. Its three runtime-heavy categories remain **[UNVERIFIED]** here.

### Superpowers

**Strongest evidence:** automatic skill activation, exceptionally simple normal use, strong
brainstorming/TDD/review/verification method, and broad host ports.

**Material gaps:** no evolving owner memory, no scoped forgetting, no complete token accounting,
no current repository CI workflow, and the optional visual companion introduces remote behavior.
Runtime-heavy categories remain **[UNVERIFIED]**.

### BMAD Method

**Strongest evidence:** the broadest authored planning method, scale-adaptive quick-to-enterprise
flows, specialist roles, strong retrospectives, documentation, and release provenance.

**Material gaps:** command/chat friction, no complete token accounting, static rather than measured
owner adaptation, append-only workspace memory without bounded forgetting, and an Ubuntu-only
primary quality workflow. Runtime-heavy categories remain **[UNVERIFIED]**.

### OpenSpec

**Strongest evidence:** clear change/spec/archive model, large TypeScript test surface, multi-OS CI,
npm OIDC release flow, broad assistant integrations, and practical status/validation tooling.

**Material gaps:** no owner learning, no owner vault, no complete token accounting, no causal
plan-before-build gate, and PostHog telemetry enabled by default. Runtime-heavy categories remain
**[UNVERIFIED]**.

### Spec Kit

**Strongest evidence:** coherent constitution/spec/plan/tasks method, broad integrations,
extensions/presets, multi-OS CI, pinned workflow actions, and excellent public documentation.

**Material gaps:** no owner learning, no owner vault, no complete token accounting, a multi-command
surface, and a documented force-upgrade path that can overwrite customized files. Runtime-heavy
categories remain **[UNVERIFIED]**.

## Loom-owned improvement priorities

The benchmark identifies capability gaps. Loom should close them through its own architecture and
product principles:

1. Generate a signed capability registry from executable conformance evidence.
2. Expand adapter documentation and disposable real-host verification while retaining one command.
3. Deepen cross-platform CI, immutable release provenance, rollback proof, and exact-cut testing.
4. Make the Tier-S path measurably faster without weakening causal planning or verification.
5. Broaden domain invariant discovery and retrospective evidence without adding visible workflow
   complexity or unbounded memory.
6. Provide concise status and validation receipts through `/loom`, with no telemetry and no
   destructive upgrade behavior.

## Exact next score work

1. Reproduce every supported host with a disposable invocation and signed conformance receipt.
2. Run the required OS/architecture matrix against the exact public artifact.
3. Capture provider-attested token and p95 latency receipts for a fixed small-task corpus.
4. Commission an independent hostile audit and unfamiliar-user completion study.
5. Publish immutable signed releases from the default branch and track real adoption separately
   from engineering quality.

Those steps can raise Loom's score. Changing promotional language cannot.
