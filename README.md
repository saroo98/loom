<p align="center">
  <a href="https://saroo98.github.io/loom/">
    <img src="./docs/readme-hero.svg" alt="Loom turns one request into a current, domain-aware execution contract" width="100%">
  </a>
</p>

<p align="center">
  <strong>Loom 1.6.0 · Planning intelligence for AI coding agents.</strong><br>
  Plan from the current world. Verify in the real one.
</p>

<p align="center">
  <a href="https://saroo98.github.io/loom/">Website</a> ·
  <a href="#install">Install</a> ·
  <a href="#what-happens-after-one-request">How it works</a> ·
  <a href="#how-learning-works">Learning</a> ·
  <a href="#evidence-and-current-limits">Evidence</a>
</p>

---

## What Loom is

Loom is a planning runtime for AI coding agents.

You describe the work once:

```text
/loom <request>
```

Loom resolves the real project, fingerprints its current state, chooses the planning depth, applies
the domain's rules, selects only relevant owner memory, seals the plan before implementation, and
defines how the result must be verified.

The output is not a longer prompt. It is an execution contract that can be reviewed, become stale,
or be refused.

Loom is not another coding agent, a project board, or a template collection. It sits between what a
person asks for and what an agent is allowed to build.

## Install

Requirements: Python 3.10 or newer and a clean checkout.

```powershell
git clone https://github.com/saroo98/loom.git
cd loom
python tools/loom_install.py install . "$HOME/.codex/skills/loom"
```

Then open a project and ask for the work you want:

```text
/loom Migrate local authentication to passkeys without locking out existing users.
```

Check the installed copy at any time:

```powershell
python tools/loom_install.py check "$HOME/.codex/skills/loom"
```

The installer writes only to a new target, hashes every owned file, records an installation
identity, and verifies the copy. Removal is all-or-nothing: if an owned file changed, Loom refuses
to delete it.

This repository is directly installable. A public Codex marketplace listing is not claimed until
submission and approval actually happen.

## What happens after one request

| Stage | Loom decides | What this prevents |
|---|---|---|
| Resolve | Which project, installation, lifecycle, and authority are real | Planning the wrong folder or Loom instance |
| Survey | What is committed, staged, unstaged, untracked, runtime-only, or time-drifted | A plan based on an incomplete world |
| Route | Whether the work is S, M, L, or XL from consequence and uncertainty | Spending a migration-sized process on a typo, or a typo-sized process on a migration |
| Discover | Which domain invariants, current facts, and proof medium apply | Web-shaped planning in accounting, 3D, firmware, research, or an unknown field |
| Seal | Which artifacts, work orders, touched paths, gate records, and evidence are authorized | Implementation changing the plan after approval |
| Verify | Which real-medium checks must pass before completion | “Looks good” or a host-authored status replacing evidence |

The owner sees one command. The machinery stays behind it.

## Small work stays small

A small, low-consequence change receives one compact contract and one bounded work order. Loom has
hard Tier-S budgets and automatically promotes the task when uncertainty, scope, domain coverage,
or consequence makes the small path unsafe.

Examples:

| Request | Route | Planning result |
|---|---|---|
| Fix a CSV header typo | S | Current file state, one compact work order, one targeted real check |
| Replace local auth with passkeys | L | Architecture, security, migration, rollback, testing, rollout, and recovery plans |
| Plan a laboratory calibration procedure | Promoted | Domain discovery first; authorization stays blocked until authority and proof apply |

No extra document is produced merely because a template exists. Loom accounts for all 15 candidate
artifacts. Each one is either produced for a named consumer making a named decision, or skipped with
a reason.

## The useful part is what Loom refuses

Loom fails closed when trust-critical state is unknown.

| If this happens | Loom does this | Reason |
|---|---|---|
| The repository changes during planning | Blocks G1 | The plan no longer describes the same world |
| Domain authority or a current governing fact is missing | Discovers and re-gates | Generic defaults cannot stand in for domain truth |
| The work-order plan changes after approval | Refuses execution | Approval belongs to exact content, not a filename |
| A deliverable already existed before planning | Refuses causal plan credit | Planning cannot take credit for build-first work |
| No declared target changed | Refuses completion | A no-op is not an implemented work order |
| Real-medium evidence is absent | Refuses completion | A written “passed” flag is not proof |
| A repo-local adapter conflicts with the shared runtime | Refuses split-brain operation | One request must reach one runtime and one state authority |

## Domain-aware does not mean “knows everything”

Loom ships adapters for known domains and a separate discovery gate for unknown ones.

An accounting plan can require balanced postings, currency precision, reconciliation, audit trails,
and period-close behavior. A real-time 3D plan can require coordinate-system discipline, asset
provenance, spatial interaction states, frame-time budgets, and target-device profiling. Firmware
can require timing, power, interrupt, recovery, and hardware-in-loop evidence. Research can require
source quality, method, uncertainty, and reproducibility.

When Loom does not know a domain, it says so. It identifies the affected subsystem, finds governing
invariants and current facts, records contradictions, defines a real verification medium, and keeps
the execution gate closed until the evidence is applicable and fresh.

The deterministic domain benchmark is regression evidence. It is not proof that Loom knows every
field.

## How learning works

Loom's memory is not one growing prompt.

| Scope | What belongs there | When it loads |
|---|---|---|
| General | Calibration, decision batching, review preferences, and judgment that has earned transfer | Across projects when evidence supports transfer |
| Domain | Accounting, 3D, firmware, mobile, data, or other domain rules | Only for matching domain work |
| Project | Repository facts, decisions, outcomes, and local preferences | Only for the exact project lineage |
| Installation | Device/runtime state and adapter ownership | Only inside that installation boundary |

Learning admission is evidence-based. Loom records where a candidate came from, whether it helped or
hurt, confidence, utility, scope, and future use. Active context remains capped at 16 records and
8 KB.

When a domain stops being useful, its active records become dormant. They can return for the exact
domain or expire when utility and evidence no longer justify keeping them. Project facts archive
with the project. A durable forget operation erases content and keeps only the bounded deletion
commitment needed to stop an old device or backup from resurrecting it.

Counts do not become “improvement.” Loom reports measured benefit only when a valid comparison
design and evidence support it.

## Privacy is a build property

Loom is local-first and has no Loom telemetry.

The public builder:

- starts from a positive allowlist;
- scans every filename and every file byte;
- checks text and binary content for owner tokens and secret signatures;
- rejects redirected files, unsupported opaque containers, and dangerous paths;
- emits a content-bound build manifest;
- refuses publication when a claimed protection would protect nothing.

Owner memory, project content, credentials, transcripts, local paths, and executable private
adaptations are not public-release material.

Read the exact boundary in [PRIVACY.md](./PRIVACY.md).

## Evidence and current limits

Loom separates source inventory, local behavior, real-host evidence, provider receipts,
longitudinal outcomes, independent review, and public adoption. One class cannot silently stand in
for another.

Current records:

- [Capability registry](./docs/capabilities.json): each mechanical claim names enforcement code and tests.
- [Generated repository inventory](./docs/generated-evidence.json): live counts, explicitly not a test-pass claim.
- [Competitive evidence snapshot](./benchmarks/competitive/2026-07-17/README.md): one rubric, exact peer revisions, N/A normalization, and visible **[UNVERIFIED]** cells.
- [Current limitations](./docs/limitations.md): proof Loom does not yet have.
- [Unknown-domain contract](./docs/unknown-domain-intelligence.md): what the discovery gate proves and does not prove.

Loom does not claim a perfect score or production certification. Those require a complete hosted
platform matrix, real disposable host runs, provider-native token and latency measurements,
independent unfamiliar-user and hostile audits, and measured longitudinal owner benefit against
the exact release.

## Architecture in one view

```text
/loom <request>
       |
       v
project identity + complete world fingerprint
       |
       +---- relevant owner memory (bounded by scope)
       |
       +---- domain route
                |
                +---- known: apply exact invariants
                |
                +---- unknown: discover authority, facts, conflicts, proof
       |
       v
content-bound plan contract
       |
       v
independent G1 gate -> atomic work orders -> real-medium verification
       |
       v
compact receipt + scoped outcome evidence
```

Start with:

| File | Purpose |
|---|---|
| [START-HERE.md](./START-HERE.md) | Compact agent kernel |
| [skill/loom/SKILL.md](./skill/loom/SKILL.md) | One-command bridge |
| [docs/architecture.md](./docs/architecture.md) | Runtime, state, memory, adapter, and release architecture |
| [loom/intake/artifact-matrix.md](./loom/intake/artifact-matrix.md) | Consumer-driven artifact selection |
| [loom/core/epistemics.md](./loom/core/epistemics.md) | Fact, assumption, speculation, unknown, and decision rules |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Public contribution and verification procedure |

## Verify this source

```powershell
python -B tools/loom_release.py verify . --source-classification public-release
```

This runs the release suite, adaptation scenarios, all-file privacy firewall, offline audit,
reproducibility checks, installer cycle, performance contracts, documentation audit, and bounded
longitudinal checks.

Local verification is necessary. It is not independent certification.

The installable artifact is `loom-plugin-vX.Y.Z.zip`, not GitHub's generated source archive.
Verify its receipt-bound bytes before installation:

```powershell
python -B tools/loom_release_verify.py loom-plugin-vX.Y.Z.zip
```

---

<p align="center">
  <strong>Plan from the current world. Verify in the real one.</strong><br>
  Local-first · no telemetry · standard-library Python · Apache-2.0
</p>
