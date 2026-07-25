<p align="center">
  <a href="https://saroo98.github.io/loom/">
    <img src="./docs/readme-hero.svg" alt="Loom maps one request through the current world, domain rules, an exact plan, real verification, and scoped learning." width="100%">
  </a>
</p>

<p align="center">
  <strong>Planning intelligence for AI coding agents.</strong><br>
  One request becomes a current, domain-aware plan that must earn execution.
</p>

<p align="center">
  <a href="https://saroo98.github.io/loom/">Explore Loom</a> ·
  <a href="https://github.com/saroo98/loom/releases/tag/v1.8.15">Signed 1.8.15 release</a> ·
  <a href="#install">Install</a> ·
  <a href="#proof-not-promises">Evidence</a> ·
  <a href="./PRIVACY.md">Privacy</a>
</p>

---

## One surface

```text
/loom <request>
```

That is the interface. Loom keeps project inspection, tiering, domain discovery, artifact
selection, work orders, gates, verification, learning, and cleanup behind it.

Loom is not another coding agent and it is not a template library. It is the control plane between
what a person asks for and what an agent may safely build.

## One request, six decisions

| Route | Loom has to establish | Why it matters |
|---|---|---|
| **Current world** | The real project, committed state, staged and unstaged changes, untracked files, lifecycle, and time drift | A plan for yesterday's repository is not a safe plan |
| **Domain** | The governing invariants, current facts, uncertainty, and real proof medium | Generic software advice cannot replace accounting, 3D, firmware, research, or an unfamiliar field |
| **Plan** | Only the artifacts a named consumer needs for a named decision | Small work stays small; ceremony has to justify its cost |
| **Authorize** | Exact work orders, touched paths, acceptance evidence, and a sealed pre-build baseline | Approval belongs to exact content, not a filename |
| **Verify** | Evidence from the real medium before completion | A written “passed” flag is not proof |
| **Learn** | What helped, what hurt, where it belongs, and when it should expire | Useful judgment transfers; project and domain residue does not become a permanent prompt tax |

```text
request
   │
   ├── current world ── uncertain? ── block or resolve
   ├── domain rules  ── unknown?   ── discover and re-gate
   ├── exact plan    ── changed?   ── invalidate authorization
   ├── real proof    ── missing?   ── refuse completion
   └── scoped outcome evidence    ── admit, demote, archive, or forget
```

## Small work stays small

A low-consequence fix receives one compact contract, one bounded work order, and one targeted real
check. Loom promotes it only when consequence, uncertainty, scope, or missing domain coverage makes
the small path unsafe.

| Request shape | Result |
|---|---|
| Fix a CSV header typo | Current file state, one work order, one targeted check |
| Replace local authentication with passkeys | Architecture, security, migration, rollback, testing, rollout, and recovery decisions |
| Plan a laboratory calibration procedure | Domain discovery first; execution remains blocked until authority and proof are applicable |

Every candidate artifact is accounted for. It is produced for a named consumer making a named
decision, or skipped with a reason.

## The useful part is what Loom refuses

Loom fails closed when trust-critical state is unknown.

- The repository changes during planning: the gate no longer describes the same world.
- A domain authority or current fact is missing: discovery must resolve it before execution.
- A work-order plan changes after approval: authorization no longer matches.
- A deliverable existed before planning: the plan cannot take causal credit for it.
- No declared target changed: a no-op cannot be called implementation.
- Real-medium evidence is absent: completion remains unearned.
- A local adapter conflicts with the shared runtime: Loom refuses split-brain execution.

These refusals are the product, not edge-case decoration.

## Learning without one growing prompt

Loom keeps learning local, scoped, evidence-bound, and bounded.

| Scope | What belongs there | When it can load |
|---|---|---|
| General | Earned calibration, review preferences, and transferable judgment | Across projects when evidence supports transfer |
| Domain | Rules specific to accounting, 3D, firmware, mobile, data, or another field | Only for matching domain work |
| Project | Repository facts, local decisions, outcomes, and project preferences | Only for the exact project lineage |
| Installation | Runtime, device, and adapter ownership state | Only inside that installation boundary |

Loom records provenance, confidence, utility, help, and harm. Active context is capped at 16 records
and 8 KB. Unused domain learning becomes dormant. Project facts archive with the project. Forgetting
removes content and retains only the bounded deletion commitment required to stop an old device or
backup from resurrecting it.

Counts are not called improvement. Loom reports benefit only when the evidence supports it.

## Codex assurance modes

The Codex plugin exposes one visible command with two mechanically labeled assurance levels:

- **Standard** uses the local stdio integration and the same sealed Loom runtime without requiring
  hook trust.
- **Verified** is an explicit opt-in lifecycle-hook layer. It adds request sealing and lifecycle
  observations, preserves unrelated hooks, records ownership receipts, and remains honest about
  host paths that ordinary hooks cannot govern.

Both modes use the same owner vault, memory selection, planning method, and sealed action format.
Standard work is never relabeled as Verified work.

## Install

The verified installable artifact is
[`loom-plugin-v1.8.15.zip`](https://github.com/saroo98/loom/releases/download/v1.8.15/loom-plugin-v1.8.15.zip).
Its SHA-256 is:

```text
1a252a9ce02a6a86235bb1831617af7f1a83680852326b1399d1b9455132b49a
```

Verify the downloaded artifact:

```powershell
python -B tools/loom_release_verify.py loom-plugin-v1.8.15.zip
```

For a direct public-source install:

```powershell
git clone https://github.com/saroo98/loom.git
cd loom
python tools/loom_install.py install . "$HOME/.codex/skills/loom"
python "$HOME/.codex/skills/loom/scripts/loom_bootstrap.py" --ensure --plugin-root "$HOME/.codex/skills/loom" --home "$HOME/.loom"
```

Requirements are Python 3.10 or newer and a clean checkout. Direct source installation proves byte
ownership, not publisher identity, and is labeled accordingly. A public Codex marketplace listing
is not claimed until submission and approval actually happen.

Open a project and ask for the work:

```text
/loom Migrate local authentication to passkeys without locking out existing users.
```

The installer creates a new target, hashes every owned file, records an installation identity, and
verifies the copy. Removal is all-or-nothing: if an owned file changed, Loom refuses to delete it.

## Privacy is a build property

Loom is local-first and has no Loom telemetry.

The public builder starts from a positive allowlist, scans every filename and file byte, rejects
redirected or dangerous paths, checks text and binary content for owner tokens and secret
signatures, and emits a content-bound manifest. A claimed protection that would protect nothing
fails loudly.

Owner memory, private project content, credentials, transcripts, local paths, and executable private
adaptations are not public-release material. The exact boundary is documented in
[PRIVACY.md](./PRIVACY.md).

## Proof, not promises

Loom separates source inventory, local tests, real-host evidence, provider receipts, longitudinal
outcomes, independent review, and public adoption. One class cannot silently stand in for another.

- [Capability registry](./docs/capabilities.json): mechanical claims mapped to enforcement and tests.
- [Release readiness](./docs/release-readiness.md): generated status with missing proof left visible.
- [Current limitations](./docs/limitations.md): proof Loom does not yet have.
- [Unknown-domain contract](./docs/unknown-domain-intelligence.md): what discovery can and cannot establish.
- [Architecture](./docs/architecture.md): runtime, vault, learning, adapters, updates, and recovery.
- [Operations](./docs/operations.md): update, rollback, uninstall, and conflict behavior.
- [Generated inventory](./docs/generated-evidence.json): live repository counts, explicitly not a test-pass claim.

Loom does not claim perfection or independent production certification. Those require continuing
real-host, provider, longitudinal, unfamiliar-user, and hostile-review evidence against exact
release artifacts.

## Verify this source

```powershell
python -B tools/loom_release.py verify . --source-classification public-release
```

That runs the release suite, adaptability scenarios, all-file privacy firewall, offline audit,
reproducibility checks, installer cycle, performance contracts, documentation audit, and bounded
longitudinal checks.

Local verification is necessary. It is not independent certification.

---

<p align="center">
  <strong>Plan from the current world. Verify in the real one.</strong><br>
  Local-first · no telemetry · Python 3.10+ · Apache-2.0
</p>
