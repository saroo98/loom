<p align="center">
  <a href="https://saroo98.github.io/loom/">
    <img src="./docs/readme-hero.svg" alt="Loom — one request, a plan that has earned the right to execute" width="100%">
  </a>
</p>

<p align="center">
  <strong>Loom 1.3.0 · Planning intelligence for AI coding agents.</strong><br>
  One request in. A release-ready, evidence-backed execution plan out.
</p>

<p align="center">
  <a href="https://saroo98.github.io/loom/">Website</a> ·
  <a href="#install-once">Install</a> ·
  <a href="#what-makes-loom-different">Why Loom</a> ·
  <a href="./docs/architecture.md">Architecture</a> ·
  <a href="./docs/limitations.md">Limitations</a>
</p>

---

## Loom does one thing

Loom turns a plain-language request into a plan an AI coding agent can execute safely.

```text
/loom <request>
```

That one interaction hides a complete planning runtime. Loom resolves the real project, reads its
current state, chooses planning depth from consequence and uncertainty, discovers domain
invariants, selects only useful owner memory, seals the plan before implementation, verifies work
in the medium where it actually runs, and returns a compact receipt.

It is not a chatbot, a project-management board, a template dump, or a second agent harness. Loom
is the layer between **what someone asks for** and **what an agent is allowed to build**.

```text
request
   │
   ▼
real project state ── domain invariants ── bounded owner memory
   │                         │                       │
   └─────────────────────────┼───────────────────────┘
                             ▼
                   sealed execution plan
                             │
                      independent G1 gate
                             │
                  atomic, evidence-bound work
                             │
                             ▼
                       compact receipt
```

## What makes Loom different

Most agents can write a plausible plan. Loom asks whether that plan has earned the right to guide
execution.

| | A prompt or checklist | A task runner | Loom |
|---|---|---|---|
| Understands committed, staged, unstaged, and untracked state | Sometimes | Partly | Mechanically fingerprinted |
| Changes planning depth with real consequence | Rarely | No | S / M / L / XL routing |
| Knows accounting is not a website | Prompt-dependent | No | Domain adapters plus discovery gate |
| Prevents build-first work receiving planning credit | No | No | Content-bound lifecycle chain |
| Produces only artifacts with a consumer and decision | No | No | Sealed 15-row artifact contract |
| Refuses stale or mutated plans | Rarely | Partly | Freshness, drift, and selective re-gating |
| Learns without mixing projects and domains | No | No | Scoped, bounded, local memory |
| Can reject forgotten state from active use | No | No | Derived-state deletion, checkpointed deletion floor, and replay rejection |
| Distinguishes evidence from “better over time” | No | No | Explicit uncertainty states; counts never become improvement claims |
| Ships owner data anywhere | Depends | Depends | No telemetry; local-first by construction |

## The extraordinary machinery behind one command

### Plans scale to the work

Loom classifies every request as **S, M, L, or XL**. A tiny change gets one bounded work order.
A cross-system release gets a dependency-aware plan. Unknown domain coverage automatically leaves
the small path instead of pretending confidence.

### Every artifact must earn its place

The plan contract accounts for all 15 candidate artifacts. Each one is either produced for a named
consumer making a named decision, or explicitly skipped with a reason. More documents are not
mistaken for more rigor.

### Unknown domains cannot borrow confidence

Accounting receives balanced-posting, precision, reconciliation, audit-trail, and period-close
concerns. Real-time 3D receives spatial interaction, asset-pipeline, frame-time, and device-medium
concerns. Firmware, research, data, ML, mobile, desktop, web, and security-sensitive work receive
their own invariants and verification media. If Loom lacks coverage, it preserves the named domain,
classifies the consequence separately, and discovers only the affected subsystem rules. G1 remains
blocked until a content-bound machine bundle proves authority, exact-target applicability,
freshness, absence of unresolved contradiction, and a real verification medium. A Markdown status
word cannot satisfy that gate.

The release benchmark expands 12 sanitized families into 240 deterministic cases, including 120
outside shipped adapters. It is regression evidence, not proof that Loom knows every domain.

### Planning must precede implementation

The lifecycle binds the planning baseline, exact G1 review, authorization, work-order plan, target
changes, and acceptance evidence into one tamper-evident chain. Pre-existing deliverables and
build-first history cannot receive causal plan credit.

### Verification happens in reality

Work orders declare exact `touches`, checkable acceptance criteria, and a real verification medium.
Loom refuses no-op completion, changes outside declared scope, missing evidence, mutated plans,
stale authorization, and host-authored “passed” claims that it did not execute.

### Memory transfers only when it should

Loom separates:

- **general judgment** that may transfer across projects, such as calibration and decision batching;
- **domain knowledge** that loads only for the matching domain;
- **project state** that belongs only to one project;
- **installation state** that never crosses Loom instances.

Inactive domain memory becomes dormant automatically. Useful knowledge can return when that exact
domain returns. Harmful or unused rules retire faster. Stated preferences supersede older ones.
`why`, `undo`, and durable `forget` remain available through the same plain-language surface.

### Privacy is a build property

The public builder starts from a positive allowlist, scans every filename and every file byte,
detects owner tokens and secret signatures across text and binary content, rejects unsupported
opaque containers, and emits a reproducible manifest. Owner memory and project content never
become contributions automatically.

### Numbers cannot outrun evidence

Token accounting requires input, cache-read, output, tool, and retry categories. A subset is never
reported as a total. Loom does not call itself improved because a log grew, and it does not call
itself production-certified because local tests passed. Missing independent evidence stays visible.

## Install once

Requirements: a clean checkout and Python 3.10 or newer.

```powershell
git clone https://github.com/saroo98/loom.git
cd loom
python tools/loom_install.py install . "$HOME/.codex/skills/loom"
```

Then use Loom from a project:

```text
/loom Design and implement the safest migration from SQLite to Postgres.
```

The installer accepts only a new target, hashes every owned file, creates a unique installation
identity, and verifies the installed copy immediately.

```powershell
python tools/loom_install.py check "$HOME/.codex/skills/loom"
```

Uninstall is all-or-nothing: it requires the exact installation ID and refuses to remove anything
if an owned file changed.

## The trust contract

Loom fails closed when project state, lifecycle state, freshness, identity, memory integrity, or
required evidence cannot be proven.

The repository distinguishes mechanical capabilities from advisory judgment in
[`docs/capabilities.json`](./docs/capabilities.json). Generated repository inventory lives in
[`docs/generated-evidence.json`](./docs/generated-evidence.json); it does not claim tests passed.
Current external evidence gaps remain explicit in [`docs/limitations.md`](./docs/limitations.md).
The unknown-domain state machine and non-claims are specified in
[`docs/unknown-domain-intelligence.md`](./docs/unknown-domain-intelligence.md).

Production certification requires all of the following against the exact release:

1. the complete cross-platform CI matrix;
2. a clean install and real request by someone unfamiliar with Loom;
3. an independent hostile review with no Critical or High findings;
4. provider-attested token and latency measurements;
5. independently reproduced production memory-on/off improvement evidence.

Until all five exist, Loom refuses the 100 label.

## Explore the system

| Start here | Purpose |
|---|---|
| [`START-HERE.md`](./START-HERE.md) | The compact agent kernel |
| [`skill/loom/SKILL.md`](./skill/loom/SKILL.md) | The installed one-command bridge |
| [`docs/architecture.md`](./docs/architecture.md) | Runtime, trust, memory, and release architecture |
| [`loom/intake/artifact-matrix.md`](./loom/intake/artifact-matrix.md) | Consumer-driven planning depth |
| [`loom/core/epistemics.md`](./loom/core/epistemics.md) | Fact, assumption, speculation, unknown, and decision discipline |
| [`PRIVACY.md`](./PRIVACY.md) | Local-state and publication boundaries |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Public contribution and verification procedure |

## Verify the public source

```powershell
python -B tools/loom_release.py verify . --source-classification public-release
```

This runs the release suite, adaptation scenarios, all-file privacy firewall, offline audit,
reproducibility check, installer cycle, performance contracts, documentation audit, and bounded
longitudinal checks. Local verification is necessary, but it does not replace the external
certification evidence above.

The installable release asset is `loom-plugin-vX.Y.Z.zip`, not GitHub's generated source archive.
Verify its exact receipt-bound bytes before installation:

```powershell
python -B tools/loom_release_verify.py loom-plugin-vX.Y.Z.zip
```

---

<p align="center">
  <strong>One request. The right plan. Evidence before execution.</strong><br>
  Local-first · No telemetry · Standard-library tooling · Apache-2.0
</p>
