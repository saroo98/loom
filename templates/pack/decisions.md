---
artifact: decision-log
project: "<name>"
status: active
last_verified: <YYYY-MM-DD>
loom_version: "0.7.0"
---

# Decision log — <project>

Every decision record in the pack, including all `[HUMAN-DECISION]` items and their
resolutions. Records are append-mostly: a changed decision gets a new entry superseding the
old (supersession chain visible), because the *history* of a decision is what stops it from
being re-litigated.

<!-- After changing any record: run the decision echo check
     (loom/verification/contradiction-detection.md method §3) on its subject. -->

## D-001: <title — the choice, not the topic: "SQLite, not Postgres" not "Database">
- type: agent-decided | HUMAN-DECISION (resolved <date> / OPEN)
- options: <a / b / c>
- chosen: <x>   (for OPEN human decisions: "recommendation: <x>")
- why: <evidence-based; claims labeled — [FACT source] / [ASSUMPTION A-id]>
- reversibility: <LOW|MED|HIGH> — <what reversal costs>
- revisit trigger: <condition that reopens this — or "none foreseen">
- blocks (if OPEN): <WO-ids marked blocked pending this>

## D-002: ...
