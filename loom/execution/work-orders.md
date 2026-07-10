# Work orders

The unit of implementation. A work order (WO) is a self-contained instruction package that
one implementer (agent or human) can execute in one sitting and verify objectively. Work
orders are the only Loom artifact that **must** exist at every tier.

Template: `templates/work-order.md` · machine shape: `schemas/work-order.schema.json`.

## Atomicity — the definition

A WO is atomic when all four hold:

1. **One implementer, one sitting.** If it plausibly needs two sessions, split it.
2. **One verifiable outcome.** A named acceptance check passes that didn't before.
3. **Self-contained context.** The implementer needs the WO + the files it names — not the
   whole pack, not your session memory. Inline the 2–3 sentences of plan context that are
   truly load-bearing; reference the rest by file§section.
4. **No "and also".** Conjunctions in the title are a splitting instruction.

## Required fields

```markdown
---
id: WO-007
title: Add session refresh to auth middleware
status: ready          # draft | ready | blocked | in-progress | done | cancelled
depends_on: [WO-004]
blocks: []
routing: strong-coding # capability class, see routing.md
size: S                # S: <1h · M: one sitting · L: split it
last_verified: 2026-07-08
---

## Intent
One paragraph: what outcome exists after this WO, and why the project needs it.
(The "why" is what lets a good implementer make correct micro-decisions.)

## Context
- Load-bearing facts, inlined: "Sessions live in `auth/session.py:SessionStore` [FACT —
  survey §3]. Expiry check currently `<`; contract requires `<=` [FACT — contracts.md §2]."
  State-claims about test/build status paste the actual output line ("8 tests, 8 errors:
  NotImplementedError"), not just the claim — the pre-WO check needs something concrete
  to compare against.
- References: architecture.md §D-002, contracts.md §2.
- Conventions to follow: <target-repo conventions from survey, not Loom defaults>.

## Preconditions
- What must be true before starting (WO-004 merged; contract C-2 frozen).
- Staleness check: if `last_verified` predates repo HEAD, run loom/execution/staleness.md §pre-WO.

## Task
Outcome-focused statements of what to build/change. Constraints that are real decisions
("use the existing SessionStore; do not add a cache") — not keystroke choreography.

## Acceptance criteria
Each one objectively checkable, using the testing plan's verification commands:
- [ ] `pytest tests/auth -q` green, including new test covering refresh-at-expiry boundary
- [ ] `curl` against dev server: expired session + valid refresh → 200 with new token
- [ ] No changes outside `auth/` (`git diff --stat` shows only auth/ paths)

## Out of scope
Explicitly named temptations: "Do NOT refactor SessionStore's storage backend (that's WO-012)."

## Escalation triggers
Conditions under which the implementer stops and reports instead of improvising — see below.

## Epistemic notes
Assumptions this WO rests on (ledger IDs), unknowns it may surface.
```

## Acceptance criteria discipline

The single highest-leverage field. Rules:
- Every criterion is a command with expected output, or an observation a reviewer can
  reproduce. "Works correctly" is not a criterion; "the three commands in testing-plan §2
  exit 0" is.
- **Human-routed WOs use the attestation pattern:** a dated attestation *artifact* with a
  count or named observable — "`i18n review: pass`, dated, in close-out", "2 promote
  actions with timestamps" — never a bare "owner confirms". (Pattern earned by a real run:
  lint W10 flagged nine bare attestations in one pack.)
- **Criteria that depend on external trigger topology name the triggering mechanism**,
  not just the action: CI path/branch filters, webhooks, cron. "Push a broken build →
  CI fails" is wrong when the workflow only fires on `main` or on PRs — write "open a PR
  with a broken build → the `build` check fails". (Earned: one wasted push + a mid-WO
  re-route through a PR, 2026-07-10.)
- **Cross-calendar/i18n fixtures derive from the target library's documented semantics,
  never from mental arithmetic** — a date the author computes in one calendar system
  while the library documents another is a wrong-fact acceptance vector; prefer
  "calendar-clean" fixtures (same-calendar anniversaries) where the expectation is
  arithmetic-free. (Earned: one Jalali/Gregorian fixture defect, 2026-07-10.)
- **No interaction may fake success.** A form that confirms "you're subscribed" while
  storing nothing, a button that pretends to order — these are lies wearing polish. If
  the backend isn't in scope: cut the interaction, visibly stub it ("coming soon",
  disabled state), or wire the honest minimum. A criterion covering any user-visible
  action asserts what ACTUALLY happens, not what the confirmation text claims.
- **The deliverable's feature list answers to the scope ladder, not to momentum.**
  Before building, every feature beyond the MUST rung names its consumer or gets cut —
  the same law packs obey (`artifact-matrix.md`), applied to the product. The stronger
  the builder, the more this line matters: capability is a gold-plating temptation, and
  unrequested features ship unreviewed risk.
- Include at least one **negative check** (what must NOT have changed) on any WO touching
  shared code — that's the blast-radius guard.
- Criteria written after implementation are confessions, not criteria. They ship with the WO.

## Escalation triggers (default set — extend per WO)

The implementer stops and reports (rather than improvising) when:
- An acceptance criterion is ambiguous or two criteria conflict.
- Reality contradicts the WO's stated facts (file moved, API differs) — the staleness chain
  failed; the WO needs re-verification, not creative reinterpretation.
- The change can't be done without touching out-of-scope areas.
- A frozen contract would need to change.
- Anything on the danger-zones list must be modified and the WO didn't say so.

Escalation is cheap; a wrong improvisation inside a stale WO is expensive. Say so in the
implementer kickoff prompt (`loom/prompts/prompt-library.md`).

## Ordering and the DAG

`depends_on`/`blocks` must form a DAG (no cycles — a cycle means the split is wrong).
Maximize width: independent WOs are parallel-executable by different agents, which is the
payoff of contract-first planning. MANIFEST lists the current frontier (ready + unblocked).

Every WO declares `touches:` — the path globs it may modify. Concurrently-ready WOs need
disjoint `touches`; multi-agent runtime rules (claiming, heartbeats, handoff briefs) are in
`loom/execution/parallel-work.md`. Exceeding declared `touches` mid-work is an escalation
trigger, not a judgment call.

## Sizing failures

- WO too big → implementer meanders, partial work, unverifiable state. Split by outcome, not
  by file. Lint's heft check (W13) makes this observable: criteria count, `touches` breadth,
  body length, and 'and'-joined titles against the declared size — advisory, judgment stays
  with the planner.
- WO too small → coordination cost exceeds work ("rename a variable" is not a WO unless it
  crosses contracts).
- Hidden coupling → two "independent" WOs edit the same function. The negative checks and
  `git diff --stat` criteria catch it at G3; the fix is re-slicing, not merge heroics.
