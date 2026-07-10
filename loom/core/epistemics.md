# Epistemics — the five labels and the assumption ledger

This file defines how Loom separates what is known from what is guessed. Every planning
artifact depends on it. The discipline here is what makes plans written by one agent safely
executable by another.

## The five labels

Label any claim that a reader might act on and might reasonably doubt. Don't label the
obvious ("Python files end in .py") — labeling everything is as useless as labeling nothing.
The test: **if this claim were wrong, would someone waste an hour or break something?** Then
it gets a label.

### `[FACT]`
Verified in this session, or cited to a source the reader can check.
- Obligation: name the source inline — `file:line`, a command and its output, a document read
  during this session, or a requester statement (quote it).
- A fact from a previous session is not a fact anymore; it's an `[ASSUMPTION]` with basis
  "verified on <date>".

### `[ASSUMPTION]`
Something you proceed on as if true, chosen because verifying now is impossible or not worth
the cost.
- Obligation: a mirrored entry in the pack's `assumptions.md` ledger (format below). An
  inline `[ASSUMPTION]` with no ledger entry is a defect.

### `[SPECULATION]`
Plausible but unverified — recalled from training, extrapolated, or pattern-matched.
- Obligation: must never be load-bearing for an irreversible or expensive step. Fine for
  brainstorming sections and options lists; not fine as the basis of a data-model choice.
- Typical honest phrasing: "`[SPECULATION]` v5 of this library likely kept the same config
  format — verify before relying on it."

### `[UNKNOWN]`
An identified gap you are not papering over.
- Obligation: attach either a resolution path ("resolved by WO-003's spike") or an explicit
  acceptance ("acceptable to discover during implementation; blast radius is one module").

### `[HUMAN-DECISION]`
A choice the requester must make: taste, money, risk appetite, scope, anything irreversible
whose options are genuinely open.
- Obligation: a record in `decisions.md` with the options, tradeoffs, and **your
  recommendation** (never present a menu without one). Blocks only the work orders that
  depend on it — everything else proceeds.

*How and when the human is actually consulted — batching, defaults, autonomy levels — is
defined in `loom/core/autonomy.md`. This file defines what qualifies; that one defines the
interaction.*

### Standard triggers for `[HUMAN-DECISION]`

Security boundaries and auth models · anything that spends money or commits to a paid service ·
deleting or migrating user data · licensing · public API commitments · user-visible scope
changes · brand/visual identity direction · platform choice when the description doesn't imply
one · anything the requester marked "ask me first".

## The assumption ledger (`plans/assumptions.md`)

Single source of truth for every `[ASSUMPTION]` in the pack. Machine shape in
`schemas/assumption.schema.json`; human shape:

```markdown
## A-007: The target audience reads Iranian Persian (fa-IR), not Dari (fa-AF)
- status: open            # open | verified | broken | retired
- basis: requester said "Persian app" and lives in Shiraz; not explicitly confirmed
- risk_if_wrong: HIGH — vocabulary, formality norms, and date conventions diverge; UI copy reworked
- verify_by: ask requester before G1 exit; if unreachable, before any UI work order starts
- used_in: uiux.md §2, work-orders/WO-004
```

Rules:
- `risk_if_wrong` is LOW / MED / HIGH plus one concrete sentence of what breaks.
- `verify_by` is an event, not a vague intention: a gate, a work order start, a date.
- When an assumption breaks, mark it `broken`, then walk `used_in` and mark every touched
  artifact `status: stale` in its frontmatter. That's the staleness chain working as designed.

## Calibration language

Vague confidence words hide miscalibration. In plans:

- Prefer a rough number over an adjective: "~90% — standard pattern, verified similar code in
  repo" beats "very likely".
- Banned as load-bearing phrasing: "should work", "probably fine", "as everyone knows",
  "obviously", "simply". Each is either a `[FACT]` with a source, or gets a real label.
- It is always acceptable to write "I don't know" — paired with what it would take to find out.

## Where labels appear

- Inline in any plan, survey, or work order, on load-bearing claims.
- Aggregated: assumptions → `assumptions.md`; human decisions → `decisions.md`; unknowns —
  inline, plus in MANIFEST if they threaten the tier or the schedule.
- In verification reports (`loom/verification/overview.md`) findings reference labels:
  "claim stated as fact, no source → relabel or verify".

## Staleness interaction

`last_verified` in artifact frontmatter refers to the **facts and assumptions inside it**.
Re-verification (see `loom/execution/staleness.md`) walks the ledger first — it's the cheapest
complete list of everything the pack believes without proof.
