# Self-verification and critique

## What it's for

The final pass: reviewing your own output as a hostile, competent stranger would — after the
other skills have run, because it reviews their fixes too. Self-review has a known structural
weakness (you built the blind spots you're now searching), so this skill is mostly technique
for *defeating your own authorship*.

## When to use

- Last step of every gate's verification battery.
- Before any handoff, however small — tier S's entire battery is task-fit + this.
- After applying fixes from the other passes (fixes introduce fresh defects at a remarkable
  rate — the re-check is not optional).

## Evidence to require

Self-verification produces claims like "I checked X" — hold them to the FACT standard:
- Checks are **mechanical wherever possible**: re-run the command, re-grep the term,
  re-follow the link. Re-reading your prose and nodding is not a check.
- The pass produces a written record (the gate review file), even when everything passes —
  "clean pass, checks run: …" is auditable; a silent pass is indistinguishable from a
  skipped one.

## Method — defeating authorship

1. **Cold re-entry.** Break before the pass (or at minimum, switch documents and return).
   You review what's *on the page* only when your working memory of what you *meant* has
   faded — the gap between the two is where the defects are.
2. **Role flip.** Re-read as: the implementer who must execute this with no session context
   ("can I actually start WO-004 from its text alone?"); the requester ("is this what I
   asked for?"); the maintenance agent six months out ("what will confuse them first?").
3. **Adversarial pass.** Actively try to break it: "if I wanted to prove this plan fails,
   where would I attack?" The three weakest points get strengthened or explicitly
   acknowledged as accepted risk. (A plan with no admitted weak points wasn't reviewed;
   it was admired.)
4. **Mechanical sweep.** Every command in the doc: run it. Every path: check it exists.
   Every cross-reference (`see contracts.md §3`): follow it — section exists and says what
   you claimed. Every checklist in the pack: actually tick it.
5. **Diff-the-intent.** Compare what you *set out* to produce (the gate's entry criteria,
   the WO's intent, the artifact matrix's selection) against what exists. Missing pieces
   hide behind completed impressive ones.
6. **Observe the running artifact, not its source.** A claim about behavior or output is
   verified only by exercising the deliverable *in its real medium* and observing the actual
   result — never by reading the code and confirming it "says" the right thing. Render a page
   in a real browser and look; run a CLI and read its output; call the endpoint and inspect the
   response; execute the job and check the rows; launch the app and drive the flow. "The source
   specifies X" is `[SPECULATION]` about behavior until X is *observed*. The medium is
   project-specific — the pack's testing plan and the work order's acceptance commands name the
   concrete way THIS project is rendered and observed, and the instance's calibration accrues the
   defect shapes only the running artifact reveals. The defects this step exists to catch — a
   shattered layout, an overlapping control, an empty response, an off-by-one row — live *only*
   in the running state and are invisible to source review.

## Questions to ask

1. What am I most proud of here? (Pride marks the spot you'll under-review — check it first,
   deliberately.)
2. What did I fix *last*? (Last fixes get the least re-verification; re-run their checks.)
3. Where was I under time/context pressure? (Pressure sites carry defects; find what you
   wrote in a hurry and re-read it cold.)
4. If another agent handed me this exact output, what would I flag? (The empathy inversion —
   surprisingly effective at unlocking the critic.)
5. What question am I avoiding asking because the answer might mean rework?  Ask it now;
   it's cheaper now than at the next gate.

## Common failures

- **Approval reading** — re-reading to confirm rather than to break. The adversarial pass
  exists because intention isn't enough; you need a hostile *procedure*.
- **Checklist theater** — ticking "verified" from memory. Mechanical sweep or it didn't
  happen.
- **Fix-blindness** — reviewing the original thoroughly and the fixes not at all.
- **Global pass, local skip** — verifying the pack "as a whole" while no individual
  artifact got its own pass. Verification happens at the artifact level; the pack-level
  feeling is a summary, not a check.
- **Critique without consequence** — finding real issues, filing them as "notes", shipping
  anyway. A finding either changes the artifact, becomes an accepted-risk line with an
  owner, or was noise — pick one, in writing.
- **Source-certification** — ticking a behavioral criterion by reading the code ("the CSS sets
  44px", "the handler returns 200") instead of running the artifact and observing it. The most
  dangerous passes are the confident ones written from source over a deliverable that is visibly
  broken the instant it renders. Method step 6 is the antidote.

## When confidence is low

Low confidence *after* self-verification is information: the artifact is probably not ready,
or the checks available to you are too weak to tell. Escalate the verification, not the
confidence: route the review to a different session/model (`loom/execution/routing.md` rule
4), or add the missing mechanical check (a test, a spike WO) that would settle it. Never
resolve post-review doubt by re-reading one more time until it feels better — that converges
on comfort, not correctness.

## How to report

Self-verification's report is the **gate review file itself** — findings in standard format,
plus the closing block every gate requires:

```markdown
## Self-verification close-out (G1, 2026-07-08)
- Passes run: task-fit ✓, contradiction ✓, weak-assumptions ✓, hallucination ✓,
  calibration ✓, fact-vs-speculation ✓, long-context n/a (single-sitting pack)
- Mechanical sweep: 14 cross-refs followed (2 fixed), 6 commands run (all exit 0),
  3 paths checked
- Fixes applied and re-checked: F-03, F-08, F-11
- Accepted risks: A-009 rides to WO-011 (verify_by set), see ledger
- Weakest three points, named: rollback §data (untested), A-002 basis, uiux §RTL depth
- Verdict: pass-with-fixes
```

## Application by phase

| Phase | Self-verification emphasis |
|---|---|
| Intake | Role-flip as requester; quote-check the goal against the original message |
| Planning | Full method; adversarial pass on the architecture's weakest boundary |
| Scaffolding | Mechanical sweep IS the gate (G2 = command output) |
| Implementation | Per-WO: acceptance criteria **observed on the running artifact** (rendered/executed in its real medium, not read from source); diff-the-intent vs the WO text |
| Review | Empathy inversion over the whole slice; fix-blindness check on everything patched since G1 |
| Release | Checklist anti-theater: every box's evidence physically present in the review file |
| Maintenance | Cold re-entry is free here (time passed) — spend it on the runbook's commands |
