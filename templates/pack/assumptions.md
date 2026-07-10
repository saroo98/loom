---
artifact: assumption-ledger
project: "<name>"
status: active
last_verified: <YYYY-MM-DD>
loom_version: "0.7.0"
---

# Assumption ledger — <project>

Single source of truth for every inline `[ASSUMPTION]` in this pack. Machine shape:
`schemas/assumption.schema.json`. Rules in `loom/core/epistemics.md`; audit procedure in
`loom/verification/weak-assumptions.md`.

<!-- Keep sorted by ID. When one breaks: status=broken, then walk used_in and mark every
     listed artifact stale. Never delete entries — retired history is calibration data. -->

## A-001: <statement — one sentence, falsifiable>
- status: open              # open | verified | broken | retired
- basis: <evidence or origin — "requester said X" / "estimated from Y". "It's usually so" = prior, say so>
- risk_if_wrong: <LOW|MED|HIGH> — <one concrete sentence: what breaks>
- verify_by: <event, not intention — "G1 exit" / "before WO-004 starts" / date>
- used_in: <artifact §, WO-ids — complete list; the staleness chain depends on it>

## A-002: ...
