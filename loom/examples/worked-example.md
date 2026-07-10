# Worked example — "Sofreh", a tier-M project, end to end (compressed)

A compressed walkthrough of Loom applied to one fictional request. Elisions marked `⟨…⟩`;
what remains is the *shape* of a correct pack. Don't copy the content — copy the moves.

## The request (verbatim)

> "I want a simple website for my family's restaurant in Shiraz. Menu, photos, opening
> hours, and people should be able to see it on their phones. My cousin will update the
> menu prices — he is not technical. Persian and English."

## Intake Note (excerpts)

```markdown
tier: M — one small product, but two languages incl. RTL + a non-technical editor make it
more than S. Promotion trigger: online ordering enters scope → L.

## Finish line
Site live on a public URL; cousin successfully changes a price without developer help. [FACT — derived from quotes]

## Known facts
- Audience: Shiraz → Persian means Iranian Persian (fa-IR), RTL [ASSUMPTION A-001 — city
  implies it, but Dari (fa-AF) exists; verify variety with requester by G1]
  ← note: labeled despite being probable
- Editor is non-technical [FACT — quote: "he is not technical"]

## Unknowns
- Photo sourcing: who provides? [UNKNOWN — blocks uiux §photos only; ask in G1 batch]

## Human decisions needed
- D-001 hosting (costs money). Recommendation: static hosting free tier ⟨…⟩

## Proposed artifacts
Produce: uiux.md (absorbs architecture — static site, no boundaries worth a separate doc),
contracts.md (menu data shape — the cousin-edit path depends on it), work orders.
Skip: product.md (scope fully stated in request + ladder below fits in intake ⟨…⟩),
testing plan as separate doc (folded into WO criteria — tier M, low risk), maintenance.md
(one runbook page inside release-rollback.md instead — cousin's update procedure IS the
maintenance story).
```

*The moves:* tier justified with a promotion trigger; "Shiraz → fa-IR" is treated as an
assumption, not a fact, because the wrong variety flips typography and idiom; artifact skips
have reasons; the unusual merge (maintenance → runbook page) is declared, not hidden.

## The load-bearing decision (decisions.md excerpt)

```markdown
## D-002: Menu content lives in one structured file (menu.json), site rebuilds on change
- Options: (a) CMS, (b) menu.json + form-based editor, (c) hardcoded HTML
- Chosen: (b)
- Why: the finish line includes a non-technical editor [FACT]; a full CMS is maximalism
  for 30 menu items; hardcoded HTML fails the finish line outright.
- Reversibility: HIGH — menu.json migrates into any future CMS trivially.
- Consequence: menu.json's shape is a frozen contract (contracts.md §1) — the editor form
  and the site renderer are built against it in parallel (WO-004 ∥ WO-005).
```

*The move:* the "simple website" hides one real architectural fact — the cousin. The
decision is derived from the finish line, and it immediately produces a frozen contract
that unlocks parallel WOs.

## Contract excerpt (contracts.md, status: frozen)

```markdown
menu.json — owner: editor form (WO-005). Renderer (WO-004) reads only.
{ "categories": [ { "name_fa": str, "name_en": str,
    "items": [ { "name_fa": str, "name_en": str, "price_toman": int,  // whole tomans,
                 "photo": str|null, "available": bool } ] } ] }      // NOT rials (10×)
Normalization: all _fa strings pass faNormalize() on save (ی/ک canonicalization —
loom/adaptation/localization-playbook.md §normalization traps) [decision D-004].
```

*The moves:* units in the field name (`price_toman`, and the rial/toman 10× ambiguity —
the classic silent bug — pre-killed in the name); both languages first-class in the shape,
not bolted on; the normalization lesson from the playbook lands as a contract line, not a
vague intention.

## Two of the six work orders (compressed)

```markdown
WO-004 [strong-coding] Build menu renderer against frozen menu.json contract
  depends_on: [WO-002 scaffold] · parallel with WO-005
  Context: RTL-first layout, logical CSS properties only [uiux §2]; test content:
  plans/fixtures/menu-real.json (real Persian strings incl. mixed Latin) [FACT — exists]
  AC: renders fixture at 360px/768px/1280px without overflow (screenshots in close-out);
  fa page dir=rtl with prices readable; `npm test` green; diff touches only src/site/
  Escalate if: contract needs a field the fixture lacks (contract change = D-record, not improv)

WO-005 [strong-coding] Build cousin's editor form (writes menu.json via commit API)
  ⟨…⟩ AC includes: a non-developer walkthrough script — every step doable without terminal ⟨…⟩
```

*The moves:* routing recorded; a real-Persian fixture exists *before* layout work (the
real-content rule); the acceptance criteria carry the testing plan; escalation trigger names
the exact temptation this WO will face.

## G1 findings that changed things (reviews/G1 excerpt)

```
F-02 [weak-assumptions][HIGH] A-001 (fa-IR) unverified but sizing all UI work → moved to
  G1-exit question batch; UI WOs marked blocked until answered.        → requester: "yes, Iran" ✓
F-05 [contradiction][MED] intake says "photos" plural prominent; uiux §photos deferred
  pending UNKNOWN — but WO-004's AC requires photo layout. Resolved: placeholder-art
  policy decided (D-006), AC updated.
Rubric: 3.3 avg, min 2 (failure-preparedness — no rollback rehearsal planned for the
  hosting cutover) → fix: added dry-run deploy to WO-006. Verdict: pass-with-fixes.
```

*The move:* the gate caught the plan building on an unverified audience assumption and an
intake/uiux/WO three-way inconsistency — exactly the two failure classes gates exist for.
Verification wasn't ceremony; it changed the WO set.

## What tier M did NOT get

No product plan, no separate architecture doc, no maintenance plan, no routing table beyond
per-WO tags, no staged rollout (hosting cutover + 48h old-hosting-live window instead).
Right-sizing is the deliverable too.
