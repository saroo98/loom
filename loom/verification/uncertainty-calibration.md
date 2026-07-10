# Uncertainty calibration

## What it's for

Making stated confidence match actual evidence — in both directions. Overconfidence ships
wrongness with a straight face; *underconfidence* buries real signal in hedges until the
reader can't find the one warning that mattered. A calibrated plan lets a reader allocate
their scarce attention to the genuinely shaky parts.

## When to use

- Gate G1 (plan-wide) and G5 (release readiness claims specifically — "should be fine" in a
  rollback plan is a G5 blocker).
- Whenever a finding from the other skills gets a severity — severities are confidence
  claims too.
- When writing any sentence containing a confidence word (likely, probably, certainly,
  should, might). Cheapest at the source.

## The vocabulary contract

Within a pack, confidence words are bound to rough numbers — so they mean something:

| Word | Commitment |
|---|---|
| "certain / will" | ~99%+ — evidence in hand; treat failure as a shock worth investigating |
| "very likely" | ~90% — would mildly surprise me to be wrong |
| "likely / expect" | ~70–80% |
| "plausible / may" | ~50% — genuinely open |
| "unlikely" | ~20% |
| (banned as load-bearing) | "should work", "probably fine", "in principle" — replace with a row above + basis |

The numbers aren't ceremony; they force the question *"would I actually take that bet?"* —
which is the calibration act itself.

## Evidence to require

For any confidence statement that gates an action: the **basis, stated next to it.**
"~90% — pattern verified in three similar modules this session" is calibrated; "~90%" alone
is a decorated guess. Bases worth accepting: in-session verification, repo evidence,
requester statements, genuinely comparable prior cases. Bases to reject: fluency, effort
spent, wanting it to be true.

## Questions to ask

1. **The bet test:** would I stake the rollback window / the release / an hour of the
   requester's time on this? If not, the stated confidence is too high.
2. **The portfolio test:** the pack asserts ~ten "90%" claims. Statistically one is wrong —
   *which failure would hurt most?* That one gets verification now, regardless of its 90%.
3. **The asymmetry test:** are consequences symmetric? 80% confidence is plenty for a
   reversible choice and reckless for an irreversible one — calibration sets thresholds
   jointly with reversibility, never alone.
4. **The surprise audit:** what has already surprised me in this project? Each surprise is
   evidence my priors here run hot; correct downward in that region.
5. **The hedge-density check (underconfidence):** if every paragraph hedges, none of the
   hedges inform. Which three uncertainties actually matter? Promote those; commit on the rest.

## Common failures

- **Fluency-confidence coupling** — confidence tracking how smoothly the text came out.
  (Correlates ~zero with correctness; see hallucination-check.)
- **Uniform confidence** — everything "likely": the tell of no calibration at all. Real
  evidence produces *spread*.
- **Hedge inflation** — defensive uniform hedging; the reader can no longer triage.
- **Severity mis-tagging** — verification findings marked MED because HIGH feels
  confrontational. Severity is a prediction, not a mood.
- **Confidence laundering by aggregation** — five 80% steps presented as an 80% plan
  (serially dependent steps compound: ≈33%). State chain confidence for chains.

## When confidence is low

Say so, with structure: what you believe, rough odds, what evidence would move it, and the
default+trigger you've set so work continues (`loom/planning/plan-authoring.md`). Low
confidence with a plan is fine; low confidence hidden inside "likely" is the failure. If
*calibrating itself* is impossible (no evidence either way, no cheap test), that's an
`[UNKNOWN]` with a resolution path, not a number pulled from air.

## How to report

```markdown
### F-14 [calibration] [MED]
- claim: "migration is low-risk, should complete in minutes" — release-rollback.md §2
- problem: two unverified links (row count [ASSUMPTION A-011, unchecked], index rebuild
  behavior [SPECULATION]) under a "certain"-register sentence; irreversible step
- action: either verify A-011 + the rebuild behavior on a copy (preferred — spend the
  frontier budget here), or restate at true confidence and add a mid-migration abort point
```

## Application by phase

| Phase | Calibration focus |
|---|---|
| Planning | Decision records' "why" sections; capacity claims; timeline implications |
| Scaffolding | "This toolchain will support X later" claims — usually 60% dressed as 95% |
| Implementation | Pre-WO: does the WO's stated risk match its epistemic notes? |
| Review | Post-hoc scoring: which planning-time confidences proved wrong? Write the misses into FEEDBACK.md — that's how the *next* pack gets calibrated |
| Release | Readiness checklist: every checked box has evidence, not optimism; rollback triggers set at honest thresholds |
| Maintenance | Aging confidence decays: restate or re-verify on each recheck |
