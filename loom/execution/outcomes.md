# Outcomes — measuring the plan against what happened

The outcome ledger closes Loom's biggest epistemic loop: plans are full of predictions
(confidences, risk ratings, size estimates, routing choices), and without recording how
they landed, every future pack starts from the same untrained priors. Calibration comes
from data, not from resolving to be more careful.

Template: `templates/pack/outcomes.md` — lives at `plans/outcomes.md`, written at G5/retro
(and incrementally at G4 if the project runs long).

## What gets recorded

One row per **prediction that had consequences**, four columns: what was predicted (with
its stated confidence/label), what actually happened, the delta class, and the lesson-shape.
Sources to sweep when filling it:

1. **Confidence claims** — every "~90%", "likely", "certain" that gated an action
   (`loom/verification/uncertainty-calibration.md` vocabulary). Held or broke?
2. **Assumption ledger** — final status of every entry: verified/broken/still-open-at-
   delivery. Broken HIGH-risk assumptions that the staleness chain *caught in time* are
   successes; record them as such — the system working is data too.
3. **Risk ratings** — risks that fired vs risks that were furniture; the risk that fired
   *unlisted* is the most valuable row in the table.
4. **Routing choices** — per WO: routed class vs how it actually went (clean / escalated /
   redone). Feeds the routing review below.
5. **Size estimates** — WOs marked S that took three sittings; tiers that got promoted.
6. **Gate findings** — did G-findings predict real problems, or generate busywork? (Rubric
   dimensions that scored 4 while the delivered thing struggled = rubric feedback.)

## Delta classes

| Class | Meaning |
|---|---|
| `held` | Prediction right, roughly at stated confidence |
| `broke-caught` | Wrong, but a Loom mechanism caught it before it cost anything — name the mechanism |
| `broke-cost` | Wrong and it cost rework/incident — the rows that teach the most |
| `unpredicted` | Something consequential no plan artifact anticipated |
| `unresolvable` | Can't tell (metric never existed, scope changed under it) — a verifiability lesson |

## The routing review (part of retro)

For each capability class used: count clean / escalated / redone. Patterns to act on:
- Escalations clustering on one class → those WOs were under-specified for it; the fix is
  planning depth, not bigger models (routing rule 2).
- A class that never once escalated across many WOs → probably over-routed; try the next
  class down on the same WO shapes next time.
Record the adjusted instinct as a sentence in outcomes.md; update `loom.config.json`
`routing_map` if the roster itself changed.

## Aggregation across packs (Loom-release time)

The release ritual (`loom/meta/evolving-loom.md`) sweeps outcome ledgers of packs completed
since the last version — patterns, not project details, cross the privacy boundary:

- Confidence words vs reality: if "~90%" claims held ~60% of the time, the calibration
  guidance gets a correction, quoted from data.
- Recurring `unpredicted` rows → missing-coverage candidates for the artifact matrix.
- Recurring `broke-caught` mechanisms → the mechanisms that earn their cost (keep, teach);
  mechanisms that never catch anything → over-prescription candidates (relax).

This is what ROADMAP's category 3 and 11 "100" definitions mean by *measured*: the loop
exists the moment two packs have outcome ledgers.

## Failure modes

- **Victory-lap ledger** — only `held` rows. The sweep sources above force the misses in;
  an outcomes table with zero `broke-*` rows on a nontrivial project is itself miscalibrated.
- **Blame framing** — rows about *who* erred instead of *which prediction* failed. The
  ledger tunes the system, not the agents; write predictions, not conduct.
- **Retro theater** — written, never swept. Aggregation is a named release-ritual step so
  the ledgers have a consumer (artifact-must-have-a-consumer applies to Loom too).
