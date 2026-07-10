# Prompt library — lifecycle prompts

Smaller prompts for moments inside a running project. Same conventions as bootstrap.md.

---

## Implementer kickoff (per work order)

The prompt a planner emits when routing a WO to an implementing agent. Self-contained on
purpose — the implementer does not get the whole pack (context cost + privacy rule 5).
Prefer generating it: `python <loom>/tools/loom_kickoff.py <WO-file>` emits this template
filled, including the `touches` scope rule — identical every time instead of hand-assembled.

```
Execute work order {WO-id} for project {name}. The work order text follows at the end of
this prompt; it is your contract.

Rules:
1. Run the pre-WO staleness check first ({loom_path}/loom/execution/staleness.md §pre-WO).
   If the WO's stated facts no longer hold, STOP and report the drift — do not improvise
   around a stale work order.
2. Respect the escalation triggers listed in the WO. Escalating is success, not failure.
3. Follow the target repo's conventions named in the WO's Context section.
4. Done = every acceptance criterion demonstrated with command output or a reproducible
   observation, recorded in a close-out block, including the negative checks.
5. Out-of-scope items are out of scope even when tempting and adjacent.

--- WORK ORDER ---
{full WO text}
```

## Gate runner (G1 or G4)

```
Run gate {G1|G4} on the pack at {pack_path} per {loom_path}/loom/review/gates.md.

Run the verification battery in composition order; scale per the gate's check list. Score
the rubric with cited evidence. Write plans/reviews/{gate}-{date}.md: findings (standard
format), scorecard, self-verification close-out block, verdict.
Original request for task-fit, verbatim: --- {request} ---
Remember the G1 rule: fix-and-rescore happens once; a second failure is a shape problem —
say so instead of polishing.
```

## Plan-drift triage (when an implementer escalated)

```
Work order {WO-id} escalated: {escalation report}.

Per {loom_path}/loom/execution/staleness.md divergence rulings and
loom/core/lifecycle.md replan triggers: determine whether this is (a) a stale WO to
re-verify and reissue, (b) a plan defect to fix at its artifact (which one), or (c) the
second same-root-cause escalation → scoped replan. Update the ledger and decisions.md
accordingly. Report the ruling, the artifacts touched, and the reissued frontier.
```

## Release runner (G4 exit → G5)

```
Execute the release for {project} per {pack_path}/release-rollback.md.

Preconditions: G4 review file shows pass; requester go recorded for user-visible ship.
Walk the release procedure exactly; at each staged-exposure checkpoint, evaluate the named
widen-criteria before proceeding. If any rollback trigger fires, execute the rollback
procedure without debate — triggers were pre-agreed precisely so this moment involves no
judgment call. Close with the G5 checks and the calibration retro (which readiness claims
proved wrong → FEEDBACK.md or pack retro).
```

## Post-delivery retro (feeds Loom's evolution)

```
The project at {pack_path} reached {G5/handoff}. Run the retro:

1. Fill {pack_path}/outcomes.md per {loom_path}/loom/execution/outcomes.md — sweep
   confidence claims, assumption finals, risk ratings, routing per WO, size estimates,
   gate findings into the predictions-vs-reality table. Include the routing review.
   A nontrivial project with zero broke-* rows means you swept too gently.
2. Which Loom guidance helped most / misled / was missing? → append entries to
   {loom_path}/FEEDBACK.md per its format.
3. Which artifacts were never read by anyone? (Candidates for the matrix to demote.)
4. Unless the profile is off (loom/core/user-memory.md rule 7): write Tier-1 updates to
   ~/.loom/ — profile preferences confirmed or contradicted (with provenance), calibration
   rows (counts, dated) — and queue Tier-2 candidates in the outbox (anonymized at capture).
   Then run: python {loom_path}/tools/loom_lint.py --home
No project secrets in FEEDBACK.md, outcome patterns, or the outbox — failure shapes, not internals.
```
