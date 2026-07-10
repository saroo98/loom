# Long-context consistency checking

## What it's for

Catching **drift** — the slow divergence that happens when work spans a long session, many
documents, or several sessions: names mutate, decided things get re-decided differently,
requirements silently vanish, dead ideas resurrect. No single edit is wrong; the *trajectory*
is. Distinct from contradiction detection: contradictions are a state (two statements
conflict *now*); drift is a process, and you hunt it along the time axis.

## When to use

- Gate G1 for packs written across multiple sittings; **mandatory at G4** (implementation
  time is drift time).
- Every session resume on an existing pack — drift concentrates at session boundaries,
  where the new session starts from a *summary* of the old one, and summaries shed detail.
- Whenever you notice *yourself* using a term the pack doesn't define — you may be mid-drift.
- Long single sessions: a sweep every major phase transition.

## Evidence to require

Drift findings compare **early vs late**, both quoted with locations: the term at first
definition vs current usage; the decision record vs the newest artifact touching it; the
intake requirement list vs the current WO set. One-sided "this seems off" isn't a finding.

## Method — the spine walk

Drift hides in prose but can't hide from the pack's own registries. Walk them:

1. **Glossary sweep.** For each MANIFEST glossary term: grep the pack; list variant names.
   Two names for one thing → merge to canonical everywhere (pick the glossary's). One name
   for two things → worse; split and rename now, before another session compounds it.
2. **Decision echo check.** For each decision record: grep for its subject; every mention
   either agrees or is a drift site. (Overlaps contradiction detection — report there if two
   *current* statements conflict; here if the story mutated over time.)
3. **Requirement roll-call.** Every intake goal / MUST rung → point to its current carrier
   (plan section, WO). Unaccounted = **silently dropped requirement** — the most expensive
   drift, because everything remaining still looks coherent.
4. **Necromancy scan.** For each NEVER rung and rejected option: any recent artifact
   re-proposing it, without new facts? (With new facts it's a legitimate revisit → decision
   record update; without, it's the ghost walking back in through a summarization gap.)
5. **Session-boundary diff** (on resume): the previous session's handoff stamp vs your
   inherited beliefs — before doing anything else.

## Questions to ask

1. Would the agent who wrote intake recognize the current WO set as the same project?
2. Which requirement has no WO carrying it? (Run the roll-call, don't trust the feeling
   that "everything's covered".)
3. What has each summarization boundary (session resume, context compaction) *shed*?
   Details lost at boundaries are the drift seeds — check the pack's edges written just
   after them.
4. Are late documents subtly *easier* than early ones? Scope softening is drift with a
   motive: the work gets lighter one restatement at a time ("must sync in real time" →
   "syncs periodically" → "manual refresh button").
5. Same number, everywhere? (Port, limit, version, count — numbers drift silently through
   restatements; grep the load-bearing ones.)

## Common failures

- **Name mutation** — `SessionStore` → "the session manager" → a *different* thing also
  called `SessionManager` in a WO. Merge-or-split, immediately.
- **Silent requirement drop** — see method §3.
- **Idea necromancy** — see method §4.
- **Scope softening** — see question 4; softening across *time* reports here, softening
  between two *current* docs reports as contradiction.
- **Summary anchoring** — a resumed session faithful to its inherited summary and
  unfaithful to the pack. The summary is not a source; the pack is.
- **Fresh-eyes overcorrection** — the opposite failure: a resuming agent "fixing"
  consistent, decided things it merely hadn't read yet. The decision log is the antidote —
  read it *before* judging anything as drift.

## When confidence is low

Can't tell drift from legitimate evolution? Check the decision log: evolution leaves a
record (or should have — a large undocumented change is itself a finding: "evolved without
a decision record"). Genuinely ambiguous cases go to the pack's author-agent if reachable,
else: current-state-wins *if gated*, and the ambiguity gets written into decisions.md so it
stops being re-litigated.

## How to report

```markdown
### F-20 [long-context] [HIGH]
- early: intake MUST — "brother can use it on his phone offline" (intake §goal, quoted)
- late: no WO implements offline; uiux.md §3 assumes online; last mention: product.md
  draft 1 (since edited out)
- drift type: silent requirement drop, likely at the session-2 resume boundary
- action: restore to scope ladder or get explicit de-scope [HUMAN-DECISION]; then
  roll-call the other intake goals — drops cluster at the same boundary
```

## Application by phase

| Phase | Consistency focus |
|---|---|
| Planning | Glossary + decision echoes as the pack grows; roll-call before G1 |
| Scaffolding | Names in the scaffold match the glossary — directories teach names to every future session |
| Implementation | WO stream vs plan: is each WO still the plan's WO, or the drift's? Session resumes: boundary diff first |
| Review | Full spine walk (all five sweeps) — G4's core |
| Release | Version/artifact names consistent across release plan, changelog, tags |
| Maintenance | Long-horizon drift: does the running system still match the pack's story? Each recheck runs a mini roll-call |
