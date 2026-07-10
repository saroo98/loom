# START HERE — Loom boot protocol for agents

You are an agent that has been pointed at Loom to plan (and possibly steer the execution of) a
project. This file is the kernel: it is enough on its own for small tasks, and it tells you
exactly what else to read for larger ones. Follow it in order. Do not read the whole repo
first — that wastes context and produces cargo-cult plans.

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

## 1. Load the core (always)

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

Tier S shortcut: skip the pack. Produce a single work order
(`loom/execution/work-orders.md`) with epistemic labels, self-check with
`loom/verification/task-fit.md` + `loom/verification/self-verification.md`, done.
Everything below is for M and up.

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

## 5. Gate the plan (G1)

Before any implementation artifacts, run gate **G1** from `loom/review/gates.md`:

0. Mechanical pre-check: `python <loom>/tools/loom_lint.py <pack>` must report zero errors —
   fix those before spending judgment on the rest.
1. Run the verification pass in the order given by `loom/verification/overview.md`
   (task-fit → contradictions → weak assumptions → hallucination check → calibration →
   fact-vs-speculation → long-context consistency → final self-verification).
2. Score the plan with `loom/review/rubric.md`. Threshold: average ≥ 3.0, no dimension < 2.
3. Fix what fails. Re-score once. If still failing, the plan is wrong-shaped — return to §3,
   don't polish.

## 6. Produce execution artifacts

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

## 7. Hand off

For each work order, emit an implementer kickoff prompt — generate it with
`python <loom>/tools/loom_kickoff.py <WO-file>` (need-to-know only; template in
`loom/prompts/prompt-library.md`). The implementer may be you, a cheaper model, or a human —
the work order must not care. Several implementers at once → `loom/execution/parallel-work.md`
(claims, `touches` disjointness, handoff briefs).
Stamp every artifact's `last_verified`. State, in MANIFEST, the conditions that make the pack
stale (see §8).

## 8. Resume / staleness recheck

When returning to an existing pack — after time has passed, after upstream commits, or before
executing any work order — follow `loom/execution/staleness.md`. Short version: re-survey what
changed, walk the assumption ledger, mark drifted artifacts `stale`, re-gate only what
drifted. **The repo is the truth; the plan adapts to it, never the reverse.**

---

## Context budget

| Task | Read |
|---|---|
| Tier S | This file + `core/epistemics.md` + `execution/work-orders.md` + `verification/task-fit.md` + `verification/self-verification.md` |
| Tier M | Above + `core/principles.md`, `core/privacy.md`, `core/autonomy.md`, intake files, selected planning guides, `review/gates.md` |
| Tier L/XL | Tier M set + `execution/routing.md`, `execution/scaffolding.md`, full `verification/`, `review/rubric.md`, relevant `adaptation/` files; multiple implementers → `execution/parallel-work.md` |
| Reviewing someone else's plan | `core/epistemics.md` + `verification/` + `review/rubric.md` + `prompts/prompt-library.md` (plan-review prompt) |
| Executing one work order | The work order + `execution/staleness.md` + files the order references. Not the whole pack. |

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
3. Never stall on missing info; never silently guess on irreversible or costly choices —
   that's what `[HUMAN-DECISION]` is for.
4. Target-repo conventions beat Loom defaults on conflict
   (`loom/adaptation/using-loom-well.md`).
5. If Loom's guidance itself proves wrong or confusing, append an entry to `FEEDBACK.md` —
   don't silently work around it.
