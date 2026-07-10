# Using Loom well — adaptation over imitation

Loom is a system of judgments, not a form to fill. This file is the guard against the
failure mode of template systems: producing Loom-*shaped* output that carries none of Loom's
value.

## The prime rule

**Templates are menus; the matrix is the waiter; judgment pays the bill.** Every template
section is an offer. You take what the project needs, decline the rest with a one-line
reason, and add what the template never imagined. A pack where every template section is
dutifully filled is *prima facie* evidence of blind copying — real projects never need
exactly the template.

## Precedence when guidance collides

1. Requester's explicit instructions (including their CLAUDE.md/AGENTS.md conventions)
2. Privacy rules (`loom/core/privacy.md`) — the one Loom layer that outranks even
   convenience-flavored requester requests; surface the conflict rather than complying
   silently
3. Target repo's established conventions and reality (survey findings)
4. Loom principles (`loom/core/principles.md`)
5. Loom's specific guides and templates ← lowest, deliberately

A specific guide losing to repo reality is normal and expected. Note the deviation in
MANIFEST when it's structural; don't note every trivial one — deviation-noting is for future
agents' orientation, not ritual compliance.

## Legitimate deviations (do these freely)

- **Merging artifacts** — website: uiux absorbs architecture; small API: contracts absorb
  architecture. Declare in MANIFEST.
- **Skipping verification passes below their value** — the battery scales with blast radius
  (`loom/verification/overview.md`); running all eight on a README fix is calibration
  failure, not diligence.
- **Local vocabularies** — if the requester's world says "ticket" not "work order", rename
  it in the pack; keep the *fields*, which is what actually matters.
- **New artifact types** — a migration-heavy project may need a data-migration plan Loom has
  no guide for. Write it under plan-authoring rules; consider a FEEDBACK.md entry proposing
  it join Loom.
- **Structural extensions** — an XL program may need a milestone index above MANIFEST.
  Loom's layout is a floor, not a ceiling.

## Illegitimate deviations (these need a decision record, or are forbidden)

- Dropping epistemic labels because "this project is simple" — labeling costs nothing on a
  genuinely simple project *because* few claims are load-bearing; skipping it is only
  attractive exactly when it's needed.
- Skipping gates under schedule pressure silently — a recorded partial gate is legitimate
  (`loom/review/gates.md` hygiene); a skipped-and-unrecorded one poisons every downstream
  trust decision.
- Privacy-rule exceptions — never; not deviation territory at all.
- "The plan is fine, the repo is wrong" — divergence rulings exist
  (`loom/execution/staleness.md`); plan-worship is the named anti-pattern.

## Reading Loom itself

- Follow the context budgets in START-HERE — reading all of Loom for a tier-S task is a
  worse failure than not reading it at all, because it *feels* diligent.
- When two Loom files seem to disagree, the precedence within Loom is: principles >
  lifecycle/epistemics/privacy (core) > specific guides. Report the collision in
  FEEDBACK.md either way — core-vs-guide friction is a bug in Loom, not in your reading.
- Loom describes agents' obligations with "must/never" language where discipline pays for
  itself. That register is earned by the failure modes it prevents — but it's aimed at the
  *defaults*, not at your judgment: the escape hatch is always the same, **decide, record,
  proceed**, never silent exception.

## The self-check

Before delivering a pack, ask once: *if Loom didn't exist, and I were simply an excellent
planner, would this pack look materially the same?* It should. Loom is scaffolding for
judgment, and scaffolding is supposed to disappear into the building. If the pack contains
anything that exists only because Loom mentioned it — no consumer, no project reason — remove
it, and consider whether Loom's mention misled you (FEEDBACK.md).
