# Weak assumption identification

## What it's for

Two jobs: (1) find the assumptions that are **load-bearing but poorly supported** — the ones
whose failure collapses real work; (2) find the assumptions that **aren't labeled at all**,
hiding as facts or defaults. The ledger makes labeled assumptions manageable; this skill
audits the ledger and hunts the escapees.

## When to use

- Gate G1 (full ledger audit + escapee hunt) and G4.
- Before any irreversible step (release, migration, deletion, spend) — audit the assumptions
  that step rests on, specifically.
- During staleness rechecks (assumptions age worse than facts).
- When something feels "obviously fine" — that feeling is where unlabeled assumptions live.

## Evidence to require

For each assumption under audit, the ledger entry's own fields, actually stress-tested:
- **basis** — is it evidence, or is it habit? "Requester said X" is a basis. "This is how
  projects usually work" is a prior, and gets the assumption downgraded, not removed.
- **risk_if_wrong** — re-derive it independently; ledger authors systematically underrate
  the blast radius of their own assumptions.
- **used_in** — is it complete? Grep the pack for the assumption's subject; an incomplete
  used_in list breaks the staleness chain exactly when it's needed.

## The audit: score and sort

For every `open` ledger entry: `exposure = evidence-weakness × impact`. No arithmetic
ceremony — a three-bucket sort suffices:

- **Red: weak basis × HIGH impact.** Act now: verify it, redesign so it stops mattering
  ("hedge the design"), or gate it (`[HUMAN-DECISION]` / a spike WO). Reds don't ride along.
- **Yellow: weak × MED, or strong × HIGH.** Must have a real `verify_by` event that fires
  *before* the assumption's first irreversible use. Check that ordering explicitly.
- **Green: everything else.** Leave them alone. An audit that "strengthens" green
  assumptions is procrastination with rigor cosplay.

## The escapee hunt — unlabeled assumptions

Where they hide, and the tells that expose them:

1. **Hedge-verbs stating facts:** "should", "presumably", "typically", "we can assume",
   "of course". Grep the pack for them; each is either promotable to `[FACT]` with a source
   or gets a label and a ledger entry.
2. **Silent defaults:** every choice made without a decision record is an assumption that
   the default is right. (Postgres-because-obviously; UTF-8-everywhere; latest-LTS.)
   Most are green — but *scan* them; audience and platform defaults are notorious reds
   (the requester's users are on old Android phones; the "obvious" desktop-first default
   just failed).
3. **Numbers without sources:** capacities, rates, sizes, timeouts stated bare. A number
   with no label is claiming to be a fact.
4. **The requester model:** everything you believe about users, their devices, their
   language, their tolerance — intake §1's fourth list. Highest escapee density in the pack.
5. **Tool/API behavior from memory** — overlaps `hallucination-check.md`; report there,
   ledger here if kept.

## Questions to ask

1. If this assumption is wrong, what is the *first* observable symptom — and would we see it
   before or after the irreversible step it feeds?
2. What would a cheap disconfirmation test look like? (Five minutes of checking beats three
   paragraphs of risk prose.)
3. Are any two ledger entries secretly the *same* assumption (fix: merge) or secretly
   *exclusive* (that's a contradiction — hand off)?
4. What is the pack's single most load-bearing assumption? (If you can't answer instantly,
   the audit isn't done. Every pack has one.)

## Common failures

- **Ledger theater** — entries filed, never revisited; `verify_by` events that already
  passed unverified. The audit checks dates first for exactly this.
- **Prior dressed as basis** — see evidence section.
- **Impact myopia** — risk assessed on the artifact it lives in, ignoring `used_in` fan-out.
- **Strengthening the wrong ones** — polishing greens (comfortable) instead of confronting
  reds (uncomfortable).

## When confidence is low

Low confidence *about an assumption's risk* means treat it as the higher bucket — asymmetric
by design: the cost of over-verifying is minutes; the cost of a red riding to release is the
project. If you can't even tell whether something *is* assumed (the docs are too vague to
say), report the vagueness itself (MED, "cannot determine what this section assumes").

## How to report

```markdown
### F-08 [weak-assumptions] [HIGH]
- claim: A-003 "users' phones run Android 10+" — basis: "modern phones do" (prior, not evidence)
- problem: RED — weak basis × HIGH impact (minSdk decision D-006, three UI WOs)
- action: verify with requester before D-006 freezes (verify_by: G1 exit, currently
  unordered vs D-006 — also fix that ordering)
```

## Application by phase

| Phase | Focus |
|---|---|
| Planning | Full audit + escapee hunt; the "single most load-bearing" question |
| Scaffolding | Toolchain/version/platform defaults (escapee type 2) |
| Implementation | Pre-WO: the WO's epistemic notes — fresh, not expired |
| Review | Which assumptions did implementation *actually* confirm or break? Update ledger — reviews that don't touch the ledger wasted half their value |
| Release | Audit of everything the release + rollback rest on ("backups restorable" is an assumption until §2 of maintenance says tested) |
| Maintenance | Aging audit each recheck: bases decay (the requester quote from 6 months ago may no longer hold) |
