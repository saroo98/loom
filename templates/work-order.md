---
id: WO-000
title: "<verb + outcome — no 'and'>"
status: draft            # draft | ready | blocked | in-progress | done | cancelled
depends_on: []
blocks: []
routing: strong-coding   # frontier-reasoning | strong-coding | fast-cheap | specialist | human
size: S                  # S <1h · M one sitting · L → split it
touches: []              # path globs this WO may modify — parallel WOs must not overlap (loom/execution/parallel-work.md)
last_verified: <YYYY-MM-DD>
---

# WO-000: <title>

## Intent
<!-- One paragraph: what exists after this WO and why the project needs it. The "why" is
     what lets a good implementer make correct micro-decisions. -->

## Context
<!-- Inline the 2–3 load-bearing facts WITH labels+sources — the pre-WO staleness check
     verifies exactly these. Reference the rest: "see contracts.md §2". Name the target
     repo conventions that apply. -->

## Preconditions
- <WO-ids merged / contracts frozen / assumptions verified>
- Pre-WO staleness check per loom/execution/staleness.md.

## Task
<!-- Outcome-focused. Constraints that are real decisions ("use existing SessionStore; no
     new cache") — not keystroke choreography. -->

## Acceptance criteria
<!-- Each = a command with expected result, or a reproducible observation. At least one
     negative check if this touches shared code. Written BEFORE implementation. -->
- [ ] <command> → <expected>
- [ ] Negative: <what must NOT have changed> (`git diff --stat` scope check)

## Out of scope
<!-- Name the adjacent temptations explicitly, with where they live instead. -->

## Escalation triggers
<!-- Default set from loom/execution/work-orders.md applies; add WO-specific ones. -->

## Epistemic notes
<!-- Ledger IDs this WO rests on; unknowns it may surface. -->

## Close-out (filled by implementer)
<!-- Evidence per criterion (output/transcript), deviations + why, surprises worth the
     ledger or FEEDBACK.md. -->
