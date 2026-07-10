# Task-fit — "does this actually solve the task?"

## What it's for

Catching the most expensive failure in agent work: a competent, polished output that answers
a *different* question than the one asked. Everything else in verification assumes the target
is right; this skill checks the target.

## When to use

- Gate G0 (Intake Note vs the request), G1 (plan vs intake), G3 (each WO's output vs the WO),
  G4 (the built thing vs the **original request** — not vs the plan; the plan may have
  drifted with you).
- Any time you notice you're very fluent — fluency is what wrong-target work feels like from
  the inside.
- Last thing before any handoff.

## Evidence to require

- The requester's **original wording**, re-read in full, *after* finishing the work. Not your
  summary of it — your summary was written by the same process that may have drifted.
- A trace: each stated goal / constraint / non-goal → where the output satisfies it.
- For WOs: each acceptance criterion → the command output or observation that proves it.

## Questions to ask

1. Re-read the request cold. Does the output answer *all of it*? (Dropped sub-requests are
   the #1 finding — especially "and also…" clauses mid-paragraph.)
2. Does it answer *only* it? Extra scope is not generosity; it's unreviewed risk and spent
   budget. (Exception: labeled LATER/NEVER rungs — recording extras is fine, building them isn't.)
3. Is the *form* right? A brilliant plan when they asked for a fix; an essay when they asked
   for a number; English when they asked in Persian.
4. Would the requester, reading this cold, recognize it as "what I asked for"?
5. The finish-line check: does the output reach the intake's finish line, or does it stop at
   "hard part done, glue remaining"?

## Common failures (what wrong-target looks like)

- **Solved the interesting version** — the agent upgraded a boring request into a fun one.
- **Solved the example** — requester gave one example of a general need; output handles
  exactly the example.
- **Solved the assumed context** — output fits the project the agent imagined (see ghost
  requirements, `loom/intake/intake.md` §1).
- **Answered the summary** — drift between original words and the working summary, then
  faithfulness to the summary.
- **Local fit, global miss** — every WO passed G3, and the assembled thing still isn't what
  was asked (why G4 re-checks against the original request).

## When confidence is low

If you genuinely can't tell whether the output fits the request — the request is ambiguous
between two readings with different outputs — that's not a verification finding, it's an
intake defect that survived. Do not pick silently: surface both readings, state which one the
output serves and why you chose it, and mark the other `[HUMAN-DECISION]` or handle per the
intake question policy.

## How to report

Standard format (overview.md). Task-fit findings cite the requester's words:

```markdown
### F-01 [task-fit] [HIGH]
- claim: pack delivers web dashboard + API
- problem: request says "and my brother should be able to use it on his phone offline"
  — quote, intake §goal. No offline capability anywhere in pack; not on any scope rung.
- action: return to intake; offline is either MUST (replan) or explicitly NEVER with
  requester sign-off [HUMAN-DECISION]
```

## Application by phase

| Phase | What task-fit means there |
|---|---|
| Planning | Plan ↔ Intake Note ↔ original request: three-way trace of goals and constraints |
| Scaffolding | Skeleton serves the planned architecture — not a generic best-practice repo |
| Implementation | WO output ↔ WO criteria; also "did I do the WO or the WO I'd have preferred" |
| Review | Assembled slice ↔ original request, full re-read, dropped-clause hunt |
| Release | Shipped artifact ↔ finish line + success metrics from the product plan |
| Maintenance | Recurring duties still serve the *current* project reality, not the delivery-day one |
