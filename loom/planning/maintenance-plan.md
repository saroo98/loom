# Maintenance plan

**Consumer:** the agent or human who operates and evolves the system after delivery — often a
different agent, months later, with zero session context. This plan is a letter to them.
**Produce when:** the delivered thing keeps running or keeps being developed after handoff.
Skip for one-shot scripts and deliverables the requester owns entirely from day one — but say
which handoff facts moved into the release plan instead.

Template: `templates/maintenance-plan.md`.

## Contents

### 1. Ownership & escalation
Who (person/agent/role) owns runtime health, dependency updates, and user reports. If the
answer is "the requester, alone", the whole plan compresses toward a runbook — optimize for
their 2am self.

### 2. Runbook
The 5–10 operations that will actually be needed, imperative and copy-pasteable: start/stop/
restart, check health, read logs (where are they), back up, restore (**with the restore
actually tested once before handoff** — an untested backup is a hope, not a backup), rotate
a credential (procedure only, no values), deploy a small fix.

### 3. Monitoring & signals
What indicates trouble and where to look — as concrete signals, even if primitive ("if the
site is down, UptimeRobot emails X" is a real monitoring plan for a small site; a Grafana
wishlist is not). Alert thresholds echo the rollback triggers where applicable.

### 4. Dependency & platform policy
Cadence and rules for updates: what auto-updates, what waits for review, what is pinned and
why. Note the platform decay clocks explicitly — OS updates, store policy changes, API
deprecations, cert expiries (calendar-date items get actual dates).

### 5. Evolution guardrails
For the future agent changing the code:
- Pointers into the pack: which decision records still bind, which contracts are frozen.
- Danger zones carried forward from the survey + new ones this project created.
- The staleness rule restated: **re-survey before trusting this pack; the repo is the truth**
  (`loom/execution/staleness.md`).
- Where the project instructions file lives (AGENTS.md/CLAUDE.md) and that it must be kept
  consistent with this plan (`loom/execution/project-instructions.md`).

### 6. Deprecation & end-of-life
Under what conditions the thing gets retired or replaced, and what must be preserved when it
is (data export path, final backup). One paragraph; its existence is what matters — systems
without an EOL thought become immortal zombies.

## Failure modes

- **The aspirational runbook** — commands nobody ran. Every runbook line is executed once
  before handoff; the plan records that it was.
- **Untested restore** — see §2. This is the most common and most expensive maintenance lie.
- **Update policy by vibes** — "keep dependencies fresh" is not a policy; a cadence and a
  pinning rule are.
- **Context-free handoff** — a maintenance plan that doesn't point back into the pack's
  decisions, forcing the future agent to re-derive (or contradict) them.
