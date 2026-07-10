# v1.0 scorecard — how Loom gets to call itself 1.0

ROADMAP states the v1.0 bar falsifiably; this file fixes the **procedure** so the
assessment can't drift into self-congratulation. Binding per decision D-003 in Loom's own
pack: **the author of a release cannot score it for 1.0.**

## Preconditions (all must exist before scoring starts)

1. ≥3 real projects (not fixtures) planned and steered through `/loom` end-to-end, packs
   retained, outcome ledgers filled. At least one on an existing living codebase; at least
   two different implementing models across their WOs.
2. At least one multi-agent run (≥2 concurrent implementers) on a *real* pack.
3. FEEDBACK.md shows ≥1 completed burn-down cycle with resolutions.
4. Outcomes aggregation performed at least twice (two Loom releases), with ≥1 guidance
   change quoting outcome data as its basis.

Missing preconditions = not scoreable. There is no partial credit at this layer — that's
what the 0.x series is for.

## The independent scorer

- A capable agent session that did **not** author the release under assessment and does
  not load this repo's authorship context (fresh session; the bootstrap is
  `loom/prompts/bootstrap.md` variant 5, pointed at Loom itself plus the evidence packs).
- The scorer receives: the repo, the real packs (or their outcome ledgers + gate reviews
  if the packs are too private to share whole), and this scorecard.
- The scorer's product: a category-by-category verdict with **evidence citations for every
  score** — the rubric's own rule, applied to Loom.

## Category evidence requirements

Score each ROADMAP category against its "100/100 looks like" definition. A category scores
≥90 only when its definition is demonstrated **in the evidence packs**, not in Loom's
prose. Anchors:

| Category | ≥90 requires evidence like |
|---|---|
| Entry & UX | transcripts: /loom runs starting correctly in ≥2 harnesses, mode auto-detected |
| Autonomy | touchpoint counts from real packs: tier-M median ≤1 batched checkpoint + release go |
| Epistemics & calibration | outcome ledgers show stated confidences tracking reality within a stated tolerance |
| Intake & survey | two scorer-run intakes of the same description agreeing on tier + artifact set |
| Planning coverage | no real project in evidence hit a missing-artifact wall (or the wall got a guide within one release) |
| Execution | WO close-outs complete; lint histories clean; kickoffs generated not hand-written |
| Verification & gates | gate reviews exist, findings actually changed artifacts (not filed-and-ignored) |
| Staleness | ≥1 real drift event caught by the pre-WO check or recheck before it cost anything |
| Adaptation | evidence packs span ≥3 project types; type guidance visibly shaped the plans |
| Multi-agent | the real parallel run: zero collisions, claims/briefs present, merge clean |
| Self-improvement | FEEDBACK cycles + data-quoting guidance changes, dated |
| Privacy | zero violations across all evidence packs; scrub/secret-scan records present |

## Verdict rules

- **1.0 declared:** every category ≥90 with citations, all preconditions met.
- **Not yet:** anything else. The scorer lists the shortest path per failing category.
- The scorer's report lands in `loom/meta/evidence/` and the verdict (either way) goes in
  CHANGELOG. A failed scoring is a normal, useful event — it is the roadmap for the next
  0.x release, not an embarrassment.

## Anti-gaming clause

Evidence packs assembled *for the scoring* (fixtures dressed as projects, packs written
retroactively) void the assessment — the scorer is instructed to check pack timestamps,
handoff stamps, and outcome-ledger dates against the claimed project timelines. The
fixture stress tests in `loom/meta/evidence/` are labeled as fixtures for exactly this
reason: they support 0.x scores, never the 1.0 verdict.
