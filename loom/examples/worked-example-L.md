# Worked example — "Bazar", tier L on an existing repo (compressed)

Companion to `worked-example.md` (tier M, greenfield). This one shows what changes at
tier L with a **living codebase**: survey-driven planning, delta architecture, contract
freezes enabling parallel agents, expand-contract migration, staged release. Elisions
`⟨…⟩`; copy the moves, not the content.

## The request (verbatim)

> "Our shop platform (Django, running 3 years, ~40k monthly users) needs vendor accounts —
> other shops selling through us, with their own dashboards and payouts. Don't break
> checkout, it's our income. Team: me reviewing, you and whatever agents you route to."

## What tier L changed at intake

```markdown
tier: L — new subsystem (vendors) with own data model, auth surface, and money path,
inside a revenue-critical live system. Not XL: one subsystem, one milestone arc.

Danger zones (requester + survey): checkout/*, payments/*, order fulfillment signals.
"Don't break checkout" [FACT — quote] → characterization tests BEFORE any shared-file WO.

Human decisions parked at intake: D-002 payout provider (money → hard stop),
D-003 vendor approval flow (policy, not tech).
```

## Survey moves that mattered (survey.md excerpts)

```markdown
- Django 3.2 [FACT — requirements.txt:4] — TWO majors behind; upgrade is OUT of scope
  (decision D-001: scope ladder NEVER for this milestone; recorded, not silently absorbed)
- payments/stripe_client.py has a hand-rolled retry wrapper with a comment "DO NOT TOUCH,
  see incident 2024-11" [FACT — file:12] → danger zone confirmed + characterization test WO
- Orders write path: signals fan out to 7 receivers [FACT — grep] — architecture-as-found
  diagram drawn from code, NOT from the stale docs/architecture.png (docs claim 4)
```

*The move:* the survey contradicted the repo's own docs and produced two scope decisions
before any planning prose existed. Facts carry file:line; the stale diagram was reported,
not trusted.

## Delta architecture (architecture.md §6 excerpt)

```markdown
Target: vendors as a bounded app (vendors/) owning vendor, vendor_user, payout_ledger.
Orders stay owned by orders/ — vendors READ order lines via a new query interface, never
write [boundary rule, enforced: no imports of orders.models into vendors/ (lint grep in CI)].

Safe intermediate states (each shippable):
  S1 vendors app + models, feature-flagged off        (expand)
  S2 vendor dashboard read-only over existing orders  (still zero checkout risk)
  S3 checkout tags order lines with vendor_id — THE shared-file change, one WO, its own
     characterization suite first (WO-009 → WO-010)
  S4 payouts ledger + admin approval                  (money path; D-002 resolved by then)
  S5 flag on for pilot vendors                        (staged release)
```

*The move:* the delta plan is a ladder of shippable states, and the single dangerous
shared-file change (S3) is isolated into one WO with a characterization gate in front.

## Contract freeze → parallel agents

```markdown
Frozen at G1: C-4 vendor query interface (vendors ⇄ orders read boundary),
C-5 dashboard JSON shapes.  [contracts.md freeze log]

Frontier after freeze (disjoint touches):
| WO | touches | routing | claimed by |
| WO-005 dashboard UI      | vendors/templates/**, vendors/static/** | strong-coding | codex-a |
| WO-006 query interface   | orders/queries.py (new file only)       | strong-coding | claude-b |
| WO-007 vendor models     | vendors/models.py, vendors/migrations/* | strong-coding | claude-c |
| WO-009 checkout charact. | tests/characterization/**               | fast-cheap    | haiku-d |
```

*The moves:* freeze first, then width — four agents, zero shared paths, `touches` declared
per WO so lint's overlap check guards the frontier; the mechanical characterization suite
routed cheap; the one future shared-file WO (WO-010) not even ready until WO-009 is done.

## The G4 finding that earned its gate

```
F-03 [contradiction][HIGH] release plan §2 migration 0007 adds NOT NULL vendor_id to
order lines (contract phase) — but rollback §4 claims "expand-only, old code safe".
Both true only if 0007 waits for the post-pilot window. Fix: 0007 moved behind G5
(rollback window close), release re-staged. The classic expand-contract lie, caught
because both documents state the same fact and one of them had drifted.
```

## Staged release (release-rollback.md excerpt)

```markdown
Stage 1: flag on for 3 pilot vendors (internal) — 48h; widen-criteria: zero checkout
  error-rate delta [metric exists: FACT — dashboards/checkout.json], payout ledger balances
  to the cent against Stripe test events.
Stage 2: 20 vendors — 7 days. Stage 3: open signup [D-003 resolved: manual approval].
Rollback: flag off (seconds, rehearsed); data written by vendors survives (expand-only
until G5) — the S3 tagging column stays, unread. Time-to-rollback: <5 min, tested.
```

## What tier L added over tier M (the actual delta)

Characterization-before-touch on danger zones · delta plan as shippable states · contract
freezes bought real parallelism (4 agents) · migration split expand/contract across the
rollback window · G4 ran the full battery and caught a HIGH · maintenance plan produced
(vendor support runbook, payout reconciliation check) — because someone operates this after
delivery. Same kernel, same labels, same gates; only the weight moved.
