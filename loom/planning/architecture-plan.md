# Architecture plan

**Consumer:** implementers (boundaries they must not cross), the scaffold plan, and every
future agent wondering "why is it built this way".
**Produce when:** a new component, integration, or data-model change exists. For an existing
repo, the survey's architecture-as-found is the starting point — this plan describes the
*delta*, not a fantasy rewrite.

Template: `templates/architecture-plan.md`.

## What architecture means here

Architecture = **boundaries + decisions**, not box-drawing. A diagram with six labeled boxes
and no statement about what may call what, who owns which data, or why this shape was chosen
is decoration.

## Contents

### 1. Context sketch
One diagram (ASCII is fine — it survives every toolchain) showing the system, its users, and
external systems. Ten boxes maximum; if you need more, you're diagramming components, which is
§2's job — or the tier is XL and you should slice.

### 2. Components & boundaries
Per component: name (glossary-stable), single-sentence responsibility, what it may call, what
may call it, what data it owns. **Data ownership is the boundary that hurts most when fuzzy** —
one owner per datum; everyone else asks.

### 3. Decision records
The heart of the plan. Every choice that is expensive to reverse — language, framework,
data store, API style, auth model, hosting, build system — gets:

```markdown
## D-003: SQLite, not Postgres
- Options: SQLite / Postgres / flat files
- Chosen: SQLite
- Why: single-user desktop app [FACT — intake]; zero-ops requirement [FACT — requester quote];
  write volume trivial [ASSUMPTION A-009]
- Reversibility: MED — schema portable, migration script ~1 WO
- Revisit trigger: multi-user sync lands on the roadmap (currently NEVER-rung)
```

Options you rejected without stating why will be re-proposed by the next agent. That's the
whole reason decision records exist.

### 4. Cross-cutting concerns
One short subsection each, only where a real decision exists: error handling strategy, config
& secrets handling (where they live, **never values** — `loom/core/privacy.md`), logging,
auth, i18n/RTL (mandatory section if the audience includes RTL-script users — see
`loom/adaptation/localization-playbook.md`), persistence/migrations.

### 5. Failure modes
What breaks first under load/network loss/bad input, and what the design does about it —
or explicitly doesn't ("offline mode: NEVER rung, see product plan"). Capacity claims are the
classic unlabeled-assumption site: "~10 req/min `[ASSUMPTION A-004]`", never bare numbers.

### 6. Delta plan (existing repos only)
Current state → target state as a sequence of safe intermediate states, each shippable.
Big-bang rewrites need a `[HUMAN-DECISION]` — they're a risk appetite question, not a
technical one.

## Smallest viable architecture (tier M)

At tier M this plan is often one page: context sketch, the one or two new boundaries, one or
two decision records, and the cross-cutting subsections that changed. That page still beats
zero pages — the discipline is the decision records, not the length.

## Failure modes

- **Resume-driven design** — tech chosen for interestingness. The decision record format
  makes this visible: "why" has no fact or assumption in it.
- **Boundary fiction** — boundaries drawn but nothing about enforcement (imports, reviews,
  contracts). State the enforcement or expect erosion.
- **Invisible defaults** — no decision record because "obviously Postgres". If it's obvious,
  the record is three lines; write it.
- **Architecture for the fantasy repo** — ignoring the survey. The delta plan section is
  mandatory for existing repos precisely to force contact with reality.
