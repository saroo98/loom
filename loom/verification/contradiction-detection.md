# Hidden contradiction detection

## What it's for

Finding places where the plan disagrees with itself, with the repo, or with the request —
*before* two implementers each build their half of an impossibility. Contradictions hide
because each statement is locally reasonable; only the pair is wrong. Nobody writes them on
purpose, which is exactly why a dedicated pass is needed.

## When to use

- Gate G1 (whole pack) and G4 (pack vs built reality).
- After **any edit to a decision record or frozen contract** — changed decisions are the #1
  contradiction source, because their echoes elsewhere don't update themselves.
- On any WO touching shared code (G3), against its neighbor WOs.
- During staleness rechecks (plan vs moved repo).

## Evidence to require

A contradiction finding needs **both statements, quoted, with locations.** "These feel
inconsistent" is a hunch, not a finding — chase it until you hold the pair (or release it).

## Method — how to actually hunt

Reading the pack top-to-bottom rarely works; each document re-anchors you to its own local
story. Instead:

1. **Extract the invariants.** Pull every cross-cutting commitment into one flat list:
   names, versions, ports, limits, formats, IDs, "always/never" statements, ownership claims.
   (The MANIFEST glossary is the seed; the extraction finds what escaped it.)
2. **Scan the list, not the prose.** Two entries about the same thing → compare hard.
   `uiux.md: "works down to 320px"` vs `testing.md: "viewport matrix starts at 375px"` is
   invisible in prose, obvious in a list.
3. **Check the high-risk pairs** (where contradictions cluster):
   - product scope ladder ↔ work-order set (MUST with no WO; WO building a NEVER)
   - contracts ↔ every WO that touches the boundary
   - architecture decision records ↔ scaffold plan toolchain
   - release plan's migration steps ↔ rollback plan's reversibility claims
   - project-instructions draft ↔ the decisions it summarizes
   - plan ↔ survey (the plan assuming what the survey disproved)
4. **Directional reads.** For each pair of artifacts that share a noun, read only the shared-
   noun sentences side by side.

## Questions to ask

1. If two implementers executed these two documents independently, could their outputs merge?
2. Does anything promise both halves of a tradeoff (fast *and* exhaustive; zero-config *and*
   customizable) without a decision resolving when each applies?
3. Do numbers that must relate, relate? (limits ≤ capacities; timeout hierarchy sane; the
   sum of parts ≤ the stated whole)
4. Did any decision record change after other documents referenced it?
5. Is the same concept named twice under different words — and did the two names silently
   acquire different properties? (hand off to `long-context-consistency.md` if it's drift,
   report here if it's now contradictory)

## Common failures

- **Echo staleness** — decision changed, three echoes didn't (the modal case).
- **Tradeoff double-promising** — see question 2.
- **Boundary both-sides ownership** — two components each "own" the same data per their own
  sections.
- **Requirement vs constraint collision** — "offline-capable" (product) + "server-validated
  on every action" (architecture), unreconciled.
- **The polite non-contradiction** — later document *softens* an earlier commitment
  ("must" → "where practical"). Softening is contradiction wearing manners.

## When confidence is low

A *suspected* contradiction you can't confirm (imprecise wording on both sides) is still
reportable — as MED with the honest note "may be reconcilable; wording too loose to tell".
Vagueness that can hide a contradiction is itself a defect; the action is "sharpen the
wording", which either dissolves or exposes the conflict.

## How to report

```markdown
### F-05 [contradiction] [HIGH]
- A: "all timestamps stored UTC" — contracts.md §1
- B: "daily report cut at local midnight, computed in the DB" — architecture.md §5
- problem: B is unimplementable as stated under A without a timezone the contract doesn't carry
- action: add user_timezone to the profile entity (contract change → D-009) or move the
  cut to app code; decide, then fix BOTH documents + WO-014
```

Always name **both** artifacts in the action. Fixing one side of a contradiction is how the
next contradiction is born.

## Application by phase

| Phase | Focus pairs |
|---|---|
| Planning | The full high-risk pair list (method §3) |
| Scaffolding | Scaffold vs architecture decisions; generated config vs toolchain records |
| Implementation | WO vs frozen contracts; WO vs neighbor WOs on shared files |
| Review | Built reality vs every plan statement about it; instructions draft vs decisions |
| Release | Release steps vs rollback claims; version numbers everywhere they appear |
| Maintenance | Runbook vs current deploy reality; policy vs what's actually pinned |
