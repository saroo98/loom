---
artifact: gate-review
project: "<name>"
gate: <G0|G1|G2|G3|G4|G5>
date: <YYYY-MM-DD>
reviewer: "<model/session — note if same as author>"
verdict: <pass | pass-with-fixes | fail>
loom_version: "0.7.0"
---

# <Gate> review — <project> — <date>

<!-- Lives at plans/reviews/<gate>-<date>.md. Formats: loom/verification/overview.md;
     gate definitions: loom/review/gates.md. -->

## Findings

### F-01 [<skill>] [<HIGH|MED|LOW>]
- claim: <what+where, quoted>
- problem: <the defect>
- evidence: <why this is a finding>
- action: <concrete, names the artifact(s) to change>
- confidence: <basis>
- resolution: <fixed <how> / accepted-risk <owner+record> / …>

## Rubric scorecard (G1/G4)

| Dimension | Score | Evidence (pack location) |
|---|---|---|
| 1 Goal fidelity | | |
| 2 Epistemic hygiene | | |
| 3 Right-sizing | | |
| 4 Decision quality | | |
| 5 Boundary clarity | | |
| 6 WO executability | | |
| 7 Verifiability | | |
| 8 Failure preparedness | | |
| 9 Adaptation fit | | |
| 10 Clarity | | |

Average: <x.x> · Min: <n> · Threshold: avg ≥ 3.0, no dim < 2 (n/a dims excluded, listed: <…>)

## Self-verification close-out
- Passes run: <list with ✓ / n/a+reason>
- Mechanical sweep: <cross-refs followed, commands run, paths checked — counts + fixes>
- Fixes applied and re-checked: <F-ids>
- Accepted risks: <ledger/decision refs>
- Weakest three points, named: <even when passing>
- Verdict: <pass | pass-with-fixes | fail>  <!-- fail: next step per gate's failure handling -->
