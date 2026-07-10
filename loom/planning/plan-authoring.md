# Plan authoring — rules that govern every plan type

Read this before any per-artifact guide. The per-artifact guides say *what* goes in each plan;
this file says *how to write anything called a plan*.

## The reader is an agent

Assume the reader is a model with a limited context window, no memory of your session, and the
job of acting on your words. Consequences:

- **Front-load decisions.** The first screen of every plan carries the decisions; rationale
  and alternatives come after. An implementer skimming under context pressure must still get
  the decisions.
- **Link, don't repeat.** Repeated content diverges silently. State each thing once, in the
  artifact that owns it, and reference it (`see contracts.md §3`). Exception: a work order may
  inline the two or three sentences an implementer absolutely needs, because work orders are
  read alone (`loom/execution/work-orders.md`).
- **Names are contracts.** Choose names for components/concepts once, record them in a
  glossary section in MANIFEST if there are more than a handful, and never drift. Two names
  for one thing is how long-context inconsistency starts
  (`loom/verification/long-context-consistency.md`).

## Decisions, not descriptions

The test for every section: **what would an implementer do differently after reading it?**
Nothing → delete it. Plans fail by being travel brochures — describing a system pleasantly
without ever committing to anything.

Weak: "The backend will be robust and scalable, using modern best practices."
Strong: "Single FastAPI service. No queue in v1 — expected load is ~10 req/min
`[ASSUMPTION A-004]`; the decision record D-002 states what load level triggers adding one."

Ban as load-bearing vocabulary: *robust, scalable, modern, clean, properly, efficient,
seamless, best-practice* — each is either a measurable statement or padding.

## Structure of any plan

1. **Header (frontmatter)** — artifact, project, tier, status, `last_verified`,
   `loom_version`, `depends_on`. Canonical artifact statuses: `draft` (being written) →
   `gated` (passed its gate) → `stale` (staleness trigger fired; re-gate to return to
   `gated`) → `superseded` (replaced, kept for history). Contracts additionally use
   `frozen` (`loom/planning/contracts.md`).
2. **Decisions** — the choices this plan commits to, each one sentence up front.
3. **Body** — per-artifact content (see its guide).
4. **Risks & assumptions touching this plan** — references into the ledger, not copies.
5. **Verification hooks** — how a reader checks this plan still matches reality
   (feeds `loom/execution/staleness.md`).

## Length budgets

Right-sizing is part of quality (rubric dimension 10):

| Tier | Any single plan | Whole pack |
|---|---|---|
| M | ≤ ~2 pages | ≤ ~6 pages + work orders |
| L | ≤ ~5 pages | ≤ ~20 pages + work orders |
| XL | ≤ ~5 pages per plan | sliced per milestone; no single slice above L budget |

Over budget → you are describing, not deciding, or the tier is wrong. These are honesty
budgets, not formatting rules: cutting content by cramming does not count.

## Labels in plans

Per `loom/core/epistemics.md`. In practice, the densest label sites are: capacity/load claims,
"the library supports X" claims, timeline claims, and anything about the target users. When in
doubt whether a claim is load-bearing, ask: if wrong, does anyone waste an hour? Label it.

## Writing under uncertainty

An honest plan under uncertainty states a **default + trigger**, not a hedge:

Weak: "We might need caching depending on performance."
Strong: "No caching in v1. Trigger to revisit: p95 > 500ms on the list endpoint
(measured in WO-011's perf check)."

Defaults keep work moving; triggers make revisiting mechanical instead of anxious.

## Good/bad examples

`loom/examples/good-vs-bad.md` has side-by-side excerpts for each artifact type. When unsure
what "decisions, not descriptions" looks like for a specific plan, read those before writing.
