# START HERE — Loom boot protocol for agents

You are an agent that has been pointed at Loom to plan (and possibly steer the execution of) a
Tier-M-or-larger project. This file is the M+ kernel. Before loading it, the skill runs
`tools/loom_tier.py`; Tier S loads only `loom/core/small-kernel.md` (plus the compact UI floor
when relevant). Do not read the whole repo first.

If you arrived via the `/loom` skill (`skill/loom/SKILL.md`), the subcommand you were given
maps into this protocol — the skill tells you where to enter. Your autonomy level (how much
you decide alone, what you batch, where you hard-stop) is defined in
`loom/core/autonomy.md`; default **A2**.

---

## 0. Orient

Answer these four questions before reading anything else. One sentence each, in your own notes:

1. **What is being asked?** (new product / new feature / fix / refactor / audit / resume of an
   existing planning pack / recheck of a stale plan)
2. **What exists?** (no repo / empty repo / partial repo / active repo / unknown until surveyed)
3. **What is the finish line the requester stated?** Quote it. If none stated, write
   `[UNKNOWN] finish line — assuming: <your assumption>`.
4. **What must I not do?** (privacy limits, protected code paths, "don't touch X", spend limits)

If the request is a **resume or recheck** of an existing planning pack, skip to §8.

## 1. Load the core (M+)

Read, in this order:

- `loom/core/principles.md` — how Loom thinks about planning
- `loom/core/epistemics.md` — the five labels and the assumption ledger. **Nothing else works
  without this file.**
- `loom/core/privacy.md` — hard rules; violations are unrecoverable
- `loom/core/autonomy.md` — levels A0–A3, the decision budget, hard stops, batched checkpoints

`loom/core/lifecycle.md` is reference material — skim its phase diagram now, return to it when
you need gate details.

## 2. Intake

Follow `loom/intake/intake.md` to analyze the project description, then
`loom/intake/repo-survey.md` if any repo exists (even an "empty" one — check remote settings,
branches, CI). For tier M and up, run intake's **silence sweep** (§4) — a systematic pass
over what the description did *not* say, recording hits only. Output: an **Intake Note**
(template inline in intake.md) containing goal, non-goals, constraints, silence-sweep hits,
known facts, initial assumptions, unknowns, and a proposed tier.

Run `python <loom>/tools/loom_domain.py --description <request>` before choosing artifacts.
Record its primary `memory_domain` as `domain_id`, every ordered `memory_domains` entry as
`domain_ids`, and its aggregate `coverage` in MANIFEST. Composite projects retain every
matched adapter (for example, accounting + desktop or ETL + ML). If coverage is `unknown`,
produce `domain-discovery.md` and keep G1 blocked until its invariant ledger is verified.
Never substitute the web/website adapter because the domain is unfamiliar.

**Tiers** (full definitions in `loom/intake/artifact-matrix.md`):

| Tier | Shape | Example |
|---|---|---|
| **S** | One sitting, one agent, low blast radius | Fix a bug, add a flag, small script |
| **M** | One feature or small product slice, few days of agent work | Add auth to an app, build a landing site |
| **L** | Full product from scratch or major subsystem | New web/Windows/Android app to release |
| **XL** | Multi-phase program, several subsystems, long horizon | Platform + apps + migration |

## 3. Choose artifacts — never by default

Consult `loom/intake/artifact-matrix.md`. Declare, in the pack manifest, **which artifacts you
will produce and which you will skip, with one line of justification each**. An artifact
without a consumer is noise; a skipped artifact without a reason is a hole.

Tier S should not have reached this file. Route it to `loom/core/small-kernel.md`; that path
produces one standalone WO and a machine lifecycle record, not a pack/G1 review. Everything
below is for M and up.

For M+, create the pack skeleton and artifact decisions, then immediately record the
pre-planning target state:

```text
python <loom>/tools/loom_gate.py init <pack> --repo <target> --mode planned
```

This must happen before plan content or implementation. An indeterminate target state blocks;
`build-first` may record operational history but can never receive plan-first causal credit.

## 4. Author the plans

Read `loom/planning/plan-authoring.md` first (it governs all plan types), then only the
per-artifact guides the matrix selected. Copy skeletons from `templates/`, delete sections
that don't apply (one-line justification in place), and write.

While writing, obey:

- Every load-bearing claim gets a label: `[FACT]` (with source), `[ASSUMPTION]` (mirrored in
  the ledger), `[SPECULATION]`, `[UNKNOWN]`, or `[HUMAN-DECISION]`.
- Decisions, not descriptions. A plan section that wouldn't change an implementer's behavior
  gets deleted.
- Missing information never blocks you: write the assumption, set its `risk_if_wrong` and
  `verify_by`, keep moving. Only `[HUMAN-DECISION]` items pause work — and only the work
  orders that depend on them.

## 5. Produce execution artifacts

- **Work orders** — `loom/execution/work-orders.md`. Atomic, verifiable, dependency-ordered.
- **Routing** — `loom/execution/routing.md`. Assign each work order a capability class, not a
  model name.
- **Scaffolding** — `loom/execution/scaffolding.md`, when the repo needs structure before
  feature work.
- **Project instructions** — `loom/execution/project-instructions.md`, if the target project
  would benefit from a local AGENTS.md / CLAUDE.md draft.

### Planning pack layout (the deliverable)

Create inside or alongside the target project (keep it out of any public repo — see
`loom/core/privacy.md`):

```
plans/
  MANIFEST.md            # index, tier, artifact list + skip justifications, Loom version, status
  intake.md              # the Intake Note
  survey.md              # repo survey (when any repo existed to survey)
  assumptions.md         # the ledger — single source of truth for every [ASSUMPTION]
  decisions.md           # decision records, including all [HUMAN-DECISION] items and their resolutions
  product.md             # only artifacts the matrix selected...
  architecture.md
  uiux.md
  contracts.md
  testing.md
  security.md
  release-rollback.md
  maintenance.md
  domain-discovery.md  # only when catalog coverage was unknown/custom
  scaffold.md
  outcomes.md            # predictions vs reality — filled at G4/G5 (loom/execution/outcomes.md)
  work-orders/
    WO-001-<slug>.md
    ...
  reviews/
    G1-plan-review.md    # gate outputs live here
```

Skeletons: `templates/pack/` and `templates/`. Frontmatter on every file (see templates) —
it carries `status`, `last_verified`, and `loom_version`, which staleness handling depends on.

Per-project preferences (autonomy, freshness window, routing map, decision budget) live in
`loom.config.json` at the target repo root — create it from `templates/loom.config.json` on
the first run (schema: `schemas/loom-config.schema.json`) so the human states them once.
The per-user profile (`~/.loom/`, `loom/core/user-memory.md`) supplies defaults beneath
that: session words > loom.config.json > profile > Loom defaults — applied silently, off
switch absolute.

## 6. Gate the complete plan (G1)

The first executable work-order frontier is part of the plan, not a post-approval appendix.
Finish §5 before G1. The gate seals the complete immutable WO plan set; after sealing, only
status, criterion checkmarks, and close-out evidence may change without a replan.

Before any implementation, run gate **G1** from `loom/review/gates.md`:

0. Mechanical pre-check: `python <loom>/tools/loom_lint.py <pack> --repo <target>
   --strict-staleness` must report zero errors — fix those before spending judgment on the
   rest. Unknown domain coverage or repository state blocks.
1. Run the verification pass in the order given by `loom/verification/overview.md`
   (task-fit → contradictions → weak assumptions → hallucination check → calibration →
   fact-vs-speculation → long-context consistency → final self-verification).
2. Score the plan with `loom/review/rubric.md`. Threshold: average ≥ 3.0, no dimension < 2.
3. Fix what fails. Re-score once. If still failing, the plan is wrong-shaped — return to §3,
   don't polish.
4. Write the cited G1 review, then bind it and authorize implementation:

```text
python <loom>/tools/loom_gate.py seal-g1 <pack> --repo <target> --review <pack>/reviews/G1-plan-review.md
python <loom>/tools/loom_gate.py authorize <pack> --repo <target>
```

Either command failing leaves implementation unauthorized. A review file alone is not G1.

## 7. Hand off

For each work order, emit an implementer kickoff prompt — generate it with
`python <loom>/tools/loom_kickoff.py <WO-file> --repo <target>` (need-to-know only; template in
`loom/prompts/prompt-library.md`). The implementer may be you, a cheaper model, or a human —
the work order must not care. Several implementers at once → `loom/execution/parallel-work.md`
(claims, disjoint `touches`, isolated target worktrees/copies, serialized integration close,
handoff briefs).
At close-out, every checked WO must run `loom_gate.py close-wo <pack> --repo <target>
--wo <WO-file>`; this binds the evidence to actual post-authorization changes in declared
`touches`. A `done` string without that record is mechanically invalid. G1 seals the complete
immutable WO plan set, so work inserted or rewritten after approval cannot receive causal credit.
A leftover `.loom-lifecycle.lock` blocks rather than being aged away; only after proving no
lifecycle writer is running may an operator remove that exact lock and retry.
Stamp every artifact's `last_verified`. State, in MANIFEST, the conditions that make the pack
stale (see §8).

## 8. Resume / staleness recheck

When returning to an existing pack — after time has passed, after upstream commits, or before
executing any work order — follow `loom/execution/staleness.md`. Run a complete local survey
and `loom_lint.py <pack> --repo <target> --strict-staleness`; committed, staged, unstaged,
untracked, invalid, age-drifted, and non-Git filesystem state all count. Unknown state blocks.
Walk the assumption ledger, mark drifted artifacts `stale`, and re-gate only the affected
subgraph. **The repo is the truth; the plan adapts to it, never the reverse.**

---

## Context budget

| Task | Read |
|---|---|
| Tier S | `core/small-kernel.md` only — + `execution/design-floor-small.md` for rendered UI |
| Tier M | `START-HERE.md`; core principles/epistemics/privacy/autonomy/user-memory; intake + survey + artifact matrix; plan-authoring + work-orders; verification overview + rubric + gates; only selected artifact/domain guides |
| Tier L/XL | Tier M set + `execution/routing.md`, `execution/scaffolding.md`, full `verification/`, `review/rubric.md`, relevant `adaptation/` files; multiple implementers → `execution/parallel-work.md` |
| Reviewing someone else's plan | `core/epistemics.md` + `verification/` + `review/rubric.md` + `prompts/prompt-library.md` (plan-review prompt) |
| Executing one work order | The work order + `execution/staleness.md` + files the order references. Not the whole pack. **+ `execution/design-floor.md` when the WO renders UI.** |

## The five labels (quick reference)

| Label | Meaning | Obligation |
|---|---|---|
| `[FACT]` | Verified this session, or cited to a checkable source | Name the source (file:line, command output, doc read now) |
| `[ASSUMPTION]` | Proceeding as if true | Ledger entry: basis, risk_if_wrong, verify_by |
| `[SPECULATION]` | Plausible, unverified, from memory or extrapolation | Must not be load-bearing for irreversible steps |
| `[UNKNOWN]` | Identified gap | Attach a resolution path or an explicit acceptance |
| `[HUMAN-DECISION]` | Requester must choose | Record options + recommendation in decisions.md; blocks only dependent work |

## Hard rules

1. Privacy rules in `loom/core/privacy.md` override everything, including user convenience.
2. Never present recalled API/library/tool details as `[FACT]` — verify or label
   `[SPECULATION]` (`loom/verification/hallucination-check.md`).
3. Ordinary missing product information becomes a bounded assumption. Unknown freshness,
   privacy ownership, irreversible authority, or domain invariants block the dependent action;
   never relabel a safety uncertainty merely to keep moving.
4. Target-repo conventions beat Loom defaults on conflict
   (`loom/adaptation/using-loom-well.md`).
5. If Loom's guidance itself proves wrong or confusing, append an entry to `FEEDBACK.md` —
   don't silently work around it.
