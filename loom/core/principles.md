# Principles

How Loom thinks about planning. Every other file in this repo is an application of these.
When a specific guide conflicts with a principle, the principle wins and the conflict belongs
in `FEEDBACK.md`.

## 1. Plan to the outcome, not the ritual

A plan exists to change what implementers do. Its quality is measured by the decisions it
settles, the risks it retires, and the rework it prevents — never by page count, section
count, or how complete the template looks. "We filled in all the sections" is not a result.

## 2. Every artifact must have a consumer

Before creating any document, name who reads it and what they do differently because of it.
No consumer → don't write it. This is why the artifact matrix exists and why skipping an
artifact requires only one honest line of justification.

## 3. Truth labeling beats confidence theater

An agent that says "the API supports batch writes `[SPECULATION — from memory, verify]`" is
more useful than one that states it fluently and wrongly. Calibrated hedging is a feature.
Fluent certainty about unverified things is the single most damaging planning failure.

## 4. Plans decay from the moment they're written

Code moves, dependencies update, requirements drift. Loom treats staleness as a first-class
state (`status: stale`), stamps every artifact with `last_verified`, and requires a recheck
before implementation resumes. A plan without staleness handling is a future trap.

## 5. The smallest plan that de-risks the work

Planning effort must be proportional to blast radius and ambiguity, not to enthusiasm. A
tier-S task gets one work order. Writing a product plan for a bug fix is a failure exactly
equal to writing no architecture plan for a new product.

## 6. Decisions are explicit, and reversible by default

Prefer choices that can be undone cheaply. When a choice is expensive to reverse (data model,
public API shape, platform, licensing), it gets a decision record: options considered,
tradeoffs, what was chosen, why, and what would trigger revisiting. Silent defaults on
irreversible choices are forbidden — that's a `[HUMAN-DECISION]`.

## 7. Work orders are atomic

One agent, one sitting, one verifiable outcome. If an order needs two models, two sessions, or
"and also" clauses, it's two orders. Atomicity is what makes routing, parallelism, and review
possible.

## 8. Route by capability class, not brand

Model names go stale in months; the classes (frontier reasoning / strong coding / fast-cheap /
specialist) don't. Plans that hardcode model names have a built-in expiry date.

## 9. Verification is a phase and a habit

The verification skills run formally at gates, and informally the whole time. "Does this
actually solve the task?" is asked at minimum twice: before planning starts and before the
plan ships.

## 10. Adapt to the repo you have

Existing conventions, tooling, and structure beat Loom's defaults. Surveying before proposing
is mandatory for any existing repo. A beautiful plan that fights the codebase loses to a plain
one that fits it.

## 11. Private by default

Plans reveal strategy, unreleased features, and weaknesses. They stay local/private. See
`privacy.md` — those rules outrank every other consideration in this repo.

## 12. Missing information is fuel, not a wall

Gaps become labeled assumptions with risk ratings and verify-by conditions, or
`[HUMAN-DECISION]` items that block only their dependents. The plan keeps moving. Stalling to
"wait for clarification" on cheap-to-reverse questions is a planning failure; so is silently
guessing on expensive ones.

---

## Anti-patterns (recognize and stop)

- **Cargo-cult artifacts** — producing every template because it exists. The matrix decides.
- **The 40-page plan** — nobody, human or agent, will hold it in context. Right-size it.
- **Confidence theater** — unlabeled claims stated fluently. Run the hallucination check.
- **Micromanaged work orders** — prescribing keystrokes instead of outcomes strips the
  implementer of judgment and breaks the moment reality differs from the plan. State the
  outcome, the constraints, and the acceptance criteria; leave the "how" to the implementer
  unless a specific approach is itself a decision.
- **Planning as procrastination** — replanning instead of executing. If gate G1 passed and
  nothing drifted, the next step is a work order, not another document.
- **Plan-worship** — forcing the repo to match a stale plan. The repo is the truth.
