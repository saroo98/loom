# Loom feedback log

Append-only. When Loom's guidance was wrong, contradictory, missing, or misleading for a
real task, record it here instead of silently working around it. This file is the input
queue for your Loom's next version — triaged by the playbook in
`loom/meta/evolving-loom.md` before any new feature work (release ritual step 1).

This queue is **yours**: entries come from your runs and your `~/.loom/` outbox, and they
improve your instance only. Loom has no automatic export channel; owner-run Git or other
explicit export remains outside that tool-level guarantee.

**Rules:** newest active entry last; no target-project secrets or private content—describe
the failure, not the project internals. Do not silently rewrite history. The bounded compactor
moves old bodies unchanged to the ignored local `.loom-private/` archive.

## Entry format (compact — clutter compounds)

```
### YYYY-MM-DD — <source> — <loom file involved>
- saw: <what happened, one line>
- fix: <suggested change, one line — or "worked-as-designed, calibration datum">
```

Triage appends one line: `- ✔ <date> <class>: <what changed>` (classes per
`loom/meta/evolving-loom.md`; "noise" is a legitimate class and carries no blame — the
value filter lives here, at triage; entry creation may be local, but contribution to this file
always requires the owner's explicit command).

---
