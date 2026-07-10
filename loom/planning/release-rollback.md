# Release & rollback plan

**Consumer:** whoever executes the release (agent or human) — under time pressure, possibly
mid-incident. Write it to be executed by someone stressed: imperative steps, no narrative.
**Produce when:** anything user-visible ships. The rollback half is not optional garnish —
**a release plan without a tested rollback path fails gate G4.**

Template: `templates/release-rollback.md`.

## Contents

### 1. Release readiness checklist
The concrete preconditions of shipping, each checkable: verification commands green (from
`testing-plan.md` §2), MUST flows manually confirmed, version bumped, changelog written,
`[HUMAN-DECISION]` items affecting release all resolved, privacy scrub done on anything
public-facing (`loom/core/privacy.md`).

### 2. Release procedure
Numbered, imperative, environment-explicit. Per project type the shape differs
(`loom/adaptation/project-types.md`): web → deploy pipeline steps + smoke URL checks;
Windows → build, sign, installer, clean-machine test; Android → signed bundle, store listing,
staged rollout percentage; library → tag, publish, verify install from registry. The plan
names the *actual* steps for *this* project, not the genre.

### 3. Staged exposure (when the platform allows)
Default to gradual: internal → small % → full, with a named check between stages ("crash-free
sessions ≥ 99.5% over 24h before widening"). If the platform is all-or-nothing (an .exe on a
website), compensate with a longer pre-release manual pass.

### 4. Rollback plan
The part everyone regrets skipping:

- **Triggers** — the observable conditions that mean roll back, decided *now*, not during the
  incident ("payment errors > 1%", "crash on launch on any supported OS"). An incident with
  no pre-agreed trigger becomes a debate.
- **Procedure** — imperative steps to restore the previous good state. Name the previous good
  state explicitly (tag/version/artifact).
- **Data reversibility** — the hard part. For every migration in the release: is it
  expand-contract (safe: old code runs against new schema)? If any step is destructive
  (column drop, format change), the rollback plan must state how data written *during* the
  bad window survives — or escalate the release design to `[HUMAN-DECISION]`, because
  "we lose up to N hours of writes" is a risk-appetite call.
- **Time-to-rollback** — rough honest estimate. If it's "hours", say so; that fact alone may
  change the staging decision.
- **Verification** — how you know the rollback worked (same smoke checks as release).

### 5. Comms (when users exist)
Who is told what, on failure and success. One line each is enough at most tiers.

## Failure modes

- **Rollback as theory** — a plan never rehearsed. At tier L+, one work order rehearses the
  rollback path (on staging / a VM / a copy) before first release.
- **Destructive migrations hiding in "misc changes"** — every migration is named in the
  release plan; the expand-contract question is asked for each.
- **Trigger-free rollbacks** — see §4.
- **Version ambiguity** — "roll back to the previous version" without naming it. Name it.
