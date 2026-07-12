# Localization playbook — any language, one method

Language and script work follows one method regardless of the language's size or support
level. This file is the method; a full worked instance (Persian/Farsi) at the end shows it
applied. Your Loom grows per-language deep-dive files in `loom/adaptation/` as its owner's
projects earn them — those deep-dives are owner-layer instances of exactly this method.

The core lesson never changes: **language and script decisions are architecture.**
Discovered late, they invalidate layouts, components, fonts, and content plans.

## The seven questions (answer at intake, all of them labeled)

1. **Which language variety, exactly?** Not "Persian", not "Chinese", not "Spanish" —
   varieties differ in script, direction, vocabulary, and formality norms. Wrong variety =
   wrong everything downstream. `[FACT]` from the requester or a HIGH-risk assumption.
2. **Which script and direction?** RTL/LTR/bidirectional is structural (layout, CSS
   strategy, mirroring policy). Some languages have *script choices* (Serbian, Kazakh,
   several minority languages of the Middle East and Central Asia) — that's a
   `[HUMAN-DECISION]` if the audience doesn't settle it.
3. **How well does the platform stack support it?** Check in-session, per stack: CLDR
   presence and quality, ICU behavior, framework locale files, font coverage. Support
   tiers change everything:
   - **Tier 1 (e.g. Arabic, French, Chinese):** the stack does the heavy lifting; your
     job is choosing and testing, not building.
   - **Tier 2 (partial data, quirks):** budget verification of every stack claim.
   - **Tier 3 (missing/ambiguous locale data):** budget manual catalogs, human
     review, and custom handling; machine translation is draft-only.
4. **What are the codepoint traps?** Visually-identical characters from neighboring
   languages' keyboards (Arabic ي vs Farsi ی), multiple encodings of one letter,
   normalization forms. Answer becomes a **normalization function at every input
   boundary**, specified in `contracts.md`.
5. **Which fonts actually cover it?** Verify glyph coverage with a real test string
   exercising the language's distinctive letters — font names from memory are
   `[SPECULATION]` (hallucination rule).
6. **Numbers, dates, calendars, collation?** Numeral style (and accept *both* styles in
   input parsing), calendar systems in cultural contexts, sort order for user-visible
   lists. Each a recorded decision, applied consistently.
7. **Who translates and who reviews?** Workflow decision at product/maintenance level:
   source-of-truth language, catalog format, reviewer (native speaker for tier 2–3 —
   named, or the SHOULD rung says "ship the source language first").

## Standing rules (every localized project)

- **Real-content rule, doubled:** layouts tested with real target-language paragraphs —
  including mixed-direction strings (embedded Latin/URLs/numbers) for RTL, long compound
  words for German-likes, tall glyph stacks for Thai/Vietnamese. Lorem ipsum hides every
  bug that matters.
- **Logical CSS properties from the first component** when any RTL audience is possible;
  retrofitting direction is the most expensive UI rework there is.
- **Mirroring policy written down** (what flips, what doesn't) — per-component
  improvisation produces a haunted UI.
- **Bidi isolation** for user-generated mixed-direction content; unisolated bidi is also
  a spoofing surface (security plan §5).
- **Locale codes precise** (the specific variety's code, never the macrolanguage code;
  `zh-Hant` not `zh`) — ambiguous codes are future contradictions.
- **Rendering coverage is `[UNKNOWN]` until a spike proves it.** Before estimating any
  text-rendering work for a minority-script language, run a one-hour spike that renders the
  FULL alphabet through the actual stack (fonts, shaping, the specific library — not a
  "representative sample"). A single unsupported codepoint (real case: one vowel letter
  outside the base Arabic block) can turn an "effort 1" work order into a 4× overrun. The
  spike is cheaper than the estimate error, every time. Diagnostic corollary: when digits
  or letters misalign *inconsistently*, dump the font's cmap for the exact codepoints in
  question (e.g. fontTools) before debugging the environment — partial coverage in a
  legacy font is the usual culprit (per-glyph fallback splits one word or number across
  two fonts), and a unicode-range-restricted `@font-face` is the surgical fix. (Earned: a
  "digits misaligned only outside incognito" environment chase resolved by one cmap dump.)
- **Fixture before layout WOs:** the target-language test content exists as a pack
  fixture *before* the first UI work order starts (it's a WO precondition).
- **E2E locators default to exact matching in bilingual/RTL apps.** Chrome labels and
  content text collide across languages (a script name in the dataset matches a UI
  label; "Month" matches month-nav buttons) — strict-mode locator collisions are the
  symptom. Exact-match posture (`exact: true` or equivalent) from the first test, not
  after the third collision. (Earned: 3 collisions in one e2e slice, 2026-07-10.)
- **Clip masks clip the FINAL state too, not just the reveal.** A `clip-path: inset()`
  or masked reveal animation leaves the mask in place at rest — and tall ascenders in
  Arabic-script languages (گ, ك, ل) or accented Latin get shaved off in the settled
  layout, not only mid-animation. `inset()` cannot go negative to escape its own box;
  the fix is vertical `padding-block` headroom on the clipped element, budgeted for the
  tallest glyph in the target script. (Earned: clipped ascenders on a reveal, 2026-07-10.)

## Worked instance: Persian (Farsi, `fa`)

- **Q1/Q2:** Iranian Persian (`fa-IR`), Arabic-based script, RTL. Dari (`fa-AF`/`prs`) is
  a distinct variety decision if the audience includes Afghanistan.
- **Q3:** Tier 1–2. CLDR/ICU data is solid (dates, plurals, numerals); fonts abundant
  (Vazirmatn et al.); machine translation usable as a first draft with native review.
  A tier-3 language with the same script would share the pipeline but need a very
  different budget — the tier drives the budget, not the script. Verify current stack
  behavior in-session anyway.
- **Q4:** ی (U+06CC) vs Arabic ي (U+064A), ک (U+06A9) vs ك (U+0643) — keyboard-neighbor
  twins that corrupt search/compare/dedup — plus **ZWNJ (U+200C)**, which Persian uses
  *semantically* (می‌روم): strip it in a careless "whitespace cleanup" and you corrupt
  words. Normalization spec must preserve ZWNJ; search should treat ZWNJ-variants as
  equivalent.
- **Q6:** Persian (Eastern-Arabic-Indic) digits ۰–۹ are the common UI convention (decide,
  accept both in input); **the Solar Hijri calendar is the default civil calendar in
  Iran** — a date-display decision Gregorian-only planning gets wrong on day one;
  collation follows Persian alphabet order (ICU handles it — but verify گچپژ placement in
  any custom sort).
- **Q7:** translation reviewable by any of the large Persian-speaking community; formality
  register (شما vs تو) is a product-tone decision — record it in uiux §6.

One method, any language: the seven questions produce different budgets, different risks,
and different decisions per language — from the same checklist. That's what "adaptation,
not templates" means (`using-loom-well.md`).
