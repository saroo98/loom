# Verification — overview

Eight skills that separate a plan that *sounds* right from one that *is* right. They run
formally at gates and informally the whole time. This file defines the shared report format,
the composition order, and where each skill applies in the lifecycle.

## The skills

| # | Skill | One-line job |
|---|---|---|
| 1 | `task-fit.md` | Does the output actually solve the stated task? |
| 2 | `contradiction-detection.md` | Do the artifacts disagree with each other or the repo? |
| 3 | `weak-assumptions.md` | Which assumptions are load-bearing and poorly supported? |
| 4 | `hallucination-check.md` | Which "facts" were never verified? |
| 5 | `uncertainty-calibration.md` | Do the confidence levels match the evidence? |
| 6 | `fact-vs-speculation.md` | Is the labeling discipline actually applied? |
| 7 | `long-context-consistency.md` | Has drift crept in across a long session or doc set? |
| 8 | `self-verification.md` | Final adversarial pass on your own output |

## Composition order (full pass, at G1/G4)

```
task-fit → contradiction → weak-assumptions → hallucination → calibration
        → fact-vs-speculation → long-context consistency → self-verification
```

Why this order: task-fit first because verifying a wrong-target plan wastes everything after;
mechanical checks (contradiction/hallucination) before judgment checks (calibration) because
their findings feed it; self-verification last because it reviews the fixes the earlier
passes produced.

Not every pass runs everywhere: **verification effort scales with blast radius.** Tier S =
task-fit + self-verification. Gate definitions (`loom/review/gates.md`) name the required
set per gate. Spending the full battery on a typo-fix WO is its own calibration failure.

The mechanical fraction of these skills runs as a command: `tools/loom_lint.py` covers
reference integrity, ledger completeness, DAG validity, enum/date shape, staleness windows,
hedge-verb and secret scans. Run it **before** the judgment passes — machines first, then
minds on what machines can't see.

## Shared report format

Every skill reports findings the same way, into the gate's review file
(`plans/reviews/<gate>-<date>.md`):

```markdown
### F-03 [hallucination-check] [HIGH]
- claim: "framework X supports built-in session rotation" — architecture.md §4
- problem: stated as [FACT], no source; not verified this session
- evidence: no doc read, no code checked; recalled from training
- action: verify against X's docs before WO-007 starts, or relabel [SPECULATION] and
  add fallback to D-004
- confidence: high (the *absence of a source* is itself verifiable)
```

Severity scale: **HIGH** = acting on this unfixed risks wrong irreversible action or major
rework · **MED** = will cause rework or confusion, recoverable · **LOW** = hygiene.
Findings are actionable or they're noise: every finding names the artifact, the location, and
a concrete action.

## Verdicts

A verification pass ends in one of:
- **pass** — proceed.
- **pass-with-fixes** — findings applied inline, nothing structural. Most common healthy outcome.
- **fail** — structural problem; the artifact returns to its author phase. Two consecutive
  fails on the same artifact = the approach is wrong, not the polish (`loom/review/gates.md`).

## Lifecycle application map

| Phase | Mandatory skills | Typical trigger findings |
|---|---|---|
| Intake (G0) | task-fit, fact-vs-speculation | invented requirements, unlabeled inferences |
| Planning (G1) | full battery | everything below |
| Scaffolding (G2) | hallucination (versions/commands), self-verification | remembered versions, fictional flags |
| Per-WO (G3) | task-fit (against the WO), self-verification; contradiction on shared-code WOs | criterion drift, scope creep |
| Review (G4) | full battery, weight on long-context consistency + task-fit against the *original* request | plan/repo divergence, dropped requirements |
| Release (G5) | calibration (are the readiness claims evidenced?), hallucination on procedural steps | "should work" in a rollback plan |
| Maintenance | weak-assumptions + hallucination on the aging pack (staleness rechecks) | expired assumptions, decayed facts |

## Self-review honesty

These skills are strongest when someone else runs them. When you verify your own work
(usually unavoidable): fresh pass, re-read the *source* documents rather than your memory of
them, and prefer mechanical checks (grep, diff, re-run commands) over re-reading your own
prose approvingly. Where practical, route G1/G4 verification to a different session/model
than the author (`loom/execution/routing.md` rule 4).
