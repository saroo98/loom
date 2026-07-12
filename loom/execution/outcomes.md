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

## Bounded aggregation at retro

Packs remain the project-local source evidence. Nothing scans arbitrary project paths at
Loom-release time. At G4/G5, the retro explicitly converts consequential numeric predictions
to `[0,1]` pairs and calls `tools/loom_memory.py record-outcome` with the exact domain and,
when appropriate, generated project ID. General judgment uses `domain=general`; domain
behavior never does.

`loom_memory.py report` compares early and recent mean absolute error and reports the sample
counts. Active raw evidence is capped; bounded aggregate windows preserve longitudinal
measurement. A lower recent error is evidence of improvement. Merely having two ledgers or
more rows is not.

Recurring qualitative failures may enter the structured outbox only as controlled generic
pattern/action values. Free-form project details stay in the pack. Contribution into the
same Loom installation is explicit and UUID-bound.

## Failure modes

- **Victory-lap ledger** — only `held` rows. The sweep sources above force the misses in;
  an outcomes table with zero `broke-*` rows on a nontrivial project is itself miscalibrated.
- **Blame framing** — rows about *who* erred instead of *which prediction* failed. The
  ledger tunes the system, not the agents; write predictions, not conduct.
- **Retro theater** — written, never measured. G4/G5 is incomplete until consequential
  numeric predictions have either been recorded or explicitly marked unmeasurable.
- **Cross-domain averaging** — a web outcome recorded as `general`. Treat that as a scope
  defect; correct the record before using its report.
