# Review gates

Gates are the checkpoints where work must prove itself before proceeding. Each defines entry
criteria, required checks, exit criteria, and who decides. Gates produce a written record in
`plans/reviews/` — an unrecorded gate didn't happen.

**Human-review triggers apply at every gate:** any unresolved `[HUMAN-DECISION]` touching the
gated work; any privacy-boundary question; any irreversible step whose confidence basis is an
assumption; anything the requester flagged "ask me first". Everything else the agent decides
and records.

## Tier collapse

| Tier | Gates in force |
|---|---|
| S | Single self-check: task-fit + self-verification on the one WO. Recorded in the WO itself. |
| M | G0 folded into G1 · G1 · G2 only if scaffold exists · G3 per WO · G4+G5 may merge for trivial releases |
| L/XL | All gates; XL runs G1/G4 per milestone slice |

## G0 — Intake accepted

- **Entry:** Intake Note drafted; survey done if a repo exists.
- **Checks:** task-fit (Note vs original request, quotes verified), fact-vs-speculation
  (every inference labeled), tier justification sane (smallest that fits, promotion trigger
  named), silence sweep performed for M+ (`loom/intake/intake.md` §4 — hits only).
- **Exit:** the Note would be recognized by the requester as their project; proposed
  artifact list has one-line justifications.
- **Decider:** agent, unless a fork-the-plan ambiguity exists (then the batched-questions
  rule, `loom/intake/intake.md` §5).

## G1 — Plan approved

- **Entry:** all matrix-selected artifacts drafted; ledger and decisions.md populated;
  MANIFEST current; **`tools/loom_lint.py` reports zero errors** (the mechanical fraction is
  a precondition, not a check to spend judgment on).
- **Checks:** full verification battery in composition order (`loom/verification/overview.md`);
  rubric score (`rubric.md`).
- **Exit:** rubric ≥ 3.0 average, no dimension < 2; zero HIGH findings open; every
  `[HUMAN-DECISION]` either resolved or explicitly parked with its dependent WOs marked
  `blocked`; work orders exist for the first executable frontier.
- **Decider:** agent on the rubric; requester on parked decisions.
- **Reviewer independence:** when the harness can spawn agent sessions, route this review
  to a fresh session by default (it gets the reviewer context budget + the plan-review
  prompt). Author-review is the fallback, and must be declared in the review file's
  `reviewer:` field — an undeclared author-review is a defect.
- **Failure handling:** fix findings → re-score **once**. A second failure means the plan is
  wrong-shaped — return to artifact selection or intake; do not polish a third draft of the
  wrong plan.

## G2 — Scaffold verified

- **Entry:** scaffold plan executed on the real repo.
- **Checks:** the command-output checklist in `loom/execution/scaffolding.md` (build, lint,
  test, CI, `.gitignore` secret-proof — all as actual output, not assertion).
- **Exit:** a clean checkout reaches green by following the scaffold instructions alone.
- **Decider:** agent. This gate is fully mechanical by design.

## G3 — Work order done (per WO)

- **Entry:** WO status `in-progress` complete; implementer claims done.
- **Checks:** every acceptance criterion demonstrated (command output / reproducible
  observation); negative checks pass (no out-of-scope diff); escalation triggers respected
  (an improvised-through trigger = automatic fail); task-fit against the WO text.
- **Exit:** criteria evidenced in the WO's close-out block; WO `done`; MANIFEST frontier
  updated.
- **Decider:** agent — but danger-zone WOs (survey list) additionally require a review by a
  session that didn't implement them (`loom/execution/routing.md` rule 5).
- **Failure handling:** criteria unmet → WO stays open. Criteria unmeetable as written →
  back to the planner (that's a plan defect, not an implementation defect — record which).

## G4 — Slice review / release readiness

- **Entry:** a coherent slice (milestone, or the whole tier-M/L build) has all WOs `done`;
  `tools/loom_lint.py` zero errors (run with `--repo` for the drift check).
- **Checks:** full battery with weight on long-context consistency (spine walk) and task-fit
  **against the original request**; ledger reconciliation (which assumptions did reality
  confirm/break — update, don't just read); release readiness checklist from
  `release-rollback.md` §1; instructions-draft consistency.
- **Exit:** zero HIGH findings; readiness boxes all evidenced; rollback plan names its
  previous-good-state and triggers.
- **Decider:** agent for internal slices; **requester for anything user-visible shipping** —
  present the readiness record, get explicit go.

## G5 — Post-release

- **Entry:** release executed (or rollback executed — both paths land here).
- **Checks:** post-release verification from the release plan (smoke checks, staged-rollout
  metrics); calibration retro — which readiness claims proved wrong, written to FEEDBACK.md
  or the pack's retro section.
- **Exit:** rollback window closed (triggers unfired for the defined period) or rollback
  completed and verified; maintenance plan activated (ownership handed off, runbook
  confirmed once against production reality).
- **Decider:** agent, with requester informed per the comms section.

## Gate hygiene

- Gates are checkpoints, not ceremonies: the checks listed are the *minimum*, and adding
  checks a specific project needs is normal. Removing listed checks requires a decision
  record.
- A gate passed under time pressure with checks skipped is recorded as such ("passed;
  hallucination sweep sampled 30% only") — an honest partial record keeps the staleness and
  trust chain alive; a false complete record poisons it.
- Consecutive gate failures for the same root cause escalate per the lifecycle replan
  triggers — gates detect planning defects; they don't fix them.
