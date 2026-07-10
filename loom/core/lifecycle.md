# Lifecycle — phases, loops, and where the gates sit

Loom's lifecycle is a loop with checkpoints, not a waterfall. Phases can overlap; gates cannot
be skipped, though at tier S most collapse into a single self-check (see
`loom/review/gates.md`).

```
        ┌──────────────────────────── replan triggers ───────────────────────────┐
        │                                                                        │
        ▼                                                                        │
  P0 Intake ──G0──► P1 Planning ──G1──► P2 Scaffolding ──G2──► P3 Implementation │
                                                                  │  (per WO: G3)│
                                                                  ▼              │
                                        P6 Maintenance ◄──G5── P5 Release ◄──G4── P4 Review
```

## Phases

### P0 — Intake
- **In:** project description, repo (or absence of one), constraints.
- **Do:** `loom/intake/intake.md` + `loom/intake/repo-survey.md`.
- **Out:** Intake Note (goal, non-goals, facts, assumptions, unknowns, tier, proposed pack).
- **Gate G0:** the Intake Note faithfully represents the request; tier justified; task-fit
  check run against the original wording.

### P1 — Planning
- **In:** Intake Note, artifact matrix selection.
- **Do:** author selected plans per `loom/planning/`.
- **Out:** planning pack (plans + ledger + decisions + manifest).
- **Gate G1:** full verification pass + rubric score ≥ threshold. `[HUMAN-DECISION]` items
  surfaced with recommendations.

### P2 — Scaffolding (only when the matrix selected it)
- **In:** architecture plan, scaffold plan.
- **Do:** `loom/execution/scaffolding.md`.
- **Out:** repo skeleton that builds, lints, and tests green while still empty; scaffold
  instructions for implementers.
- **Gate G2:** skeleton verified by command output, not by inspection.

### P3 — Implementation
- **In:** work orders, routing assignments.
- **Do:** implementers execute work orders; each starts with the staleness pre-check
  (`loom/execution/staleness.md`).
- **Out:** changes satisfying each order's acceptance criteria.
- **Gate G3 (per work order):** acceptance criteria demonstrated (command output or observed
  behavior), scope respected, escalations resolved.

### P4 — Review
- **In:** completed work orders for a slice or milestone.
- **Do:** integration-level review — the slice as a whole against the plan, cross-order
  consistency, plan drift assessment.
- **Gate G4:** release readiness checklist from `loom/planning/release-rollback.md` passes.

### P5 — Release
- **Do:** release plan execution, staged if planned; rollback readiness confirmed **before**,
  not during, the incident.
- **Gate G5:** post-release verification passed; rollback window closed or rollback executed.

### P6 — Maintenance
- **Do:** maintenance plan duties; the pack shifts to maintenance mode — MANIFEST records what
  is authoritative and what is now historical.

## Replan triggers (return to P1, scoped)

- A HIGH-risk assumption breaks.
- Requirements change in a way that invalidates a decision record.
- Repo survey during staleness recheck shows drift the plan can't absorb.
- Two or more work orders in a row escalate for the same root cause — the plan, not the
  implementers, is wrong.

Replanning is **scoped**: rework the invalidated artifacts and their dependents (follow
`used_in` chains and MANIFEST's dependency list), not the whole pack.

## Tier collapse

- **S:** P0+P1 collapse into one work order; G0–G3 collapse into task-fit + self-verification.
- **M:** all phases exist but G2 may be trivial (no scaffold) and P4 may be one review session.
- **L/XL:** full lifecycle; XL additionally slices into milestones, each cycling P1→P5.
