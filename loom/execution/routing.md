# Routing — matching work to models and agents

Routing assigns each work order a **capability class**. Classes are stable; model names churn
every few months. A plan that says "give this to <model X>" is stale on arrival; a plan that
says "frontier-reasoning" is executable for years.

## Capability classes

| Class | What it's for | Signals in the WO |
|---|---|---|
| **frontier-reasoning** | Ambiguity, architecture, cross-cutting refactors, debugging without a known cause, planning itself, verification passes at G1/G4 | high blast radius · unknowns in epistemic notes · "decide" verbs |
| **strong-coding** | Well-specified implementation: clear contract, clear acceptance criteria, bounded scope | `size: M` · frozen contracts · low ambiguity |
| **fast-cheap** | Mechanical work: renames, boilerplate, doc formatting, test scaffolds from a pattern, bulk edits with a checkable invariant | fully specified · verifiable by command · zero decisions |
| **specialist** | Domain tools/skills: image generation, UI design skills, SEO, PDF manipulation, platform-specific toolchains | the WO names the domain |
| **human** | Taste calls, credentials/spend, physical-world steps, final judgment on `[HUMAN-DECISION]` items | epistemics triggers |

## Routing rules

1. Route by the WO's **hardest** required capability, not its average. One genuinely open
   design question inside an otherwise mechanical WO makes it frontier-reasoning — or better,
   split the question out.
2. **Downgrade by specification.** The way to use cheap capacity is to make WOs so well
   specified they stop requiring judgment. Planning effort converts directly into routing
   savings.
3. **Never route ambiguity downward.** A fast-cheap model executing an ambiguous WO doesn't
   fail loudly; it fails plausibly. That's the worst failure mode available.
4. Verification of a WO's output should when practical use a **different** session (and
   ideally different model) than the one that produced it — self-review has known blind spots
   (`loom/verification/self-verification.md`).
5. Danger-zone WOs (survey list): minimum strong-coding, plus a mandatory review step at G3
   regardless of size.

## Current examples (snapshot — 2026-07-08, goes stale; classes above do not)

frontier-reasoning: Claude Fable/Mythos 5, Claude Opus 4.8, GPT-5.5-class ·
strong-coding: Claude Sonnet 5-class, Codex-class coding models ·
fast-cheap: Claude Haiku 4.5-class ·
specialist: skill-augmented sessions (design, imagegen, PDF, platform toolchains).

When applying this file, re-derive the mapping from whatever models are actually available;
record the mapping you used in MANIFEST so the pack is auditable. Projects with a stable
model roster pin it in `loom.config.json` (`routing_map`) so every session inherits it.

## Assignment record

Routing lives in each WO's frontmatter (`routing:`). MANIFEST aggregates a one-line view:
`WO-007 strong-coding · WO-008 fast-cheap · WO-009 frontier (open data-model question)`.

## Escalation & de-escalation

- Implementer escalates per WO triggers → the WO returns to the planner (frontier class),
  not to a bigger implementer by default: ambiguity is a planning defect, not a horsepower
  problem.
- A WO that a strong-coding session completes trivially and flawlessly is a signal the
  neighboring WOs of the same shape can go fast-cheap. Adjust the remaining assignments —
  routing is allowed to learn.

## Cost stance

Loom's default: **spend on planning and verification, save on execution.** A well-planned
pack routes most WOs below frontier class; the frontier budget goes to intake, architecture,
gates, and the WOs that genuinely decide things. If everything is routed frontier, the plan
is under-specified; if everything is fast-cheap, someone is about to ship plausible-looking
wrongness.

## Cost model (rough, relative — absolute prices go stale in weeks)

Think in ratios and in *total cost of being wrong*, not sticker price per token:

| Class | Relative $/token | Latency | Real cost driver |
|---|---|---|---|
| frontier-reasoning | ~10–30× | slow | cheap relative to the rework it prevents on decisions |
| strong-coding | ~2–5× | medium | the workhorse; most WO-hours land here |
| fast-cheap | 1× | fast | only cheap if the WO needed zero judgment — a redone WO costs 3–5× a right-classed one |
| specialist | varies | varies | priced by the skill, not the tokens |
| human | highest | days | spend only where reversibility can't buy it back (autonomy hard stops) |

Two rules of thumb the ratios imply: an escalated-then-redone fast-cheap WO usually costs
more than routing strong-coding from the start (so under-routing needs a *verified* pattern,
not hope); and one frontier verification pass over a batch of cheap WOs is the cheapest
insurance in the table.

**The model is a prior; the routing review corrects it.** Per-pack clean/escalated/redone
counts land in `plans/outcomes.md` (`loom/execution/outcomes.md`), and the adjusted
instinct — "this WO shape goes one class down" — is the output that matters. Absolute
prices, when needed for a spend decision, get looked up in-session (hallucination rule),
never recalled.
