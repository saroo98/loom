# Staleness — plans decay; here is the protocol

Every artifact carries `last_verified` and `status` in frontmatter. This file defines when
those stamps demand action and what the action is. The prime directive throughout:
**the repo is the truth; the plan adapts to it, never the reverse.**

## Staleness triggers

An artifact (or the whole pack) must be rechecked when any of these fire:

1. **Time** — `last_verified` older than the pack's freshness window (default: 14 days for
   active projects, set in MANIFEST; anything predating it is suspect, not condemned).
2. **Upstream movement** — repo HEAD ≠ the commit hash stamped in the survey; dependency
   versions changed; platform/tooling updated.
3. **Broken assumption** — a ledger entry flips to `broken`; everything in its `used_in` list
   is stale by definition (`loom/core/epistemics.md`).
4. **Requirement change** — the requester said anything that touches the Intake Note.
5. **Repeated escalation** — two+ WOs escalate for the same root cause: treat the plan itself
   as stale (`loom/core/lifecycle.md` replan triggers).
6. **Agent capability change** — the executing agent's own tooling moved since planning
   (new MCP servers authenticated, new skills installed, model roster changed). Decision
   options can go stale inside the agent, not the repo — a plan that chose "manual process"
   because no tool existed is wrong the day the tool appears. Rechecks include a one-minute
   capability re-survey: *what can I do now that the planner couldn't?* (Earned by a real
   run, 2026-07-10: MCPs authenticated mid-project staled a pack's decision options within
   a day.)

**Tool support:** `python <loom>/tools/loom_lint.py <pack> --repo <repo>` mechanically fires
trigger 1 (freshness windows, W03) and trigger 2 (repo_head drift, W04), and flags broken-
assumption fan-out that wasn't marked (W05). For the full recheck's step 1,
`python <loom>/tools/loom_survey.py <repo> --since <surveyed-hash>` emits the delta report
(commits, diffstat, manifest/CI/danger-zone changes) ready to walk the ledger against.
Run the tools first; they're cheaper than remembering.

## The pre-WO check (cheap, every time)

Before executing **any** work order, the implementer spends two minutes:

```
1. git log --oneline <survey-hash>..HEAD -- <paths the WO touches>   # what moved?
2. Do the WO's stated facts still hold? (files exist, functions named, contract unchanged)
3. Ledger scan: any assumption in this WO's epistemic notes broken/expired (verify_by passed)?
4. All clear  → execute.
   Drift found → stop; mark WO status: blocked; report what drifted (escalation, not improvisation).
```

This check is why WOs inline their load-bearing facts — it makes drift detectable in
seconds by exactly the agent about to rely on them.

## The full recheck (when a trigger fires pack-wide)

1. **Diff the world:** re-run the survey *delta* — `git diff --stat <survey-hash>..HEAD`,
   dependency manifest diff, CI status. You are diffing, not re-surveying from scratch.
2. **Walk the ledger:** every `open` assumption — still plausible? `verify_by` event passed?
   Verify the cheap ones now; re-ledger the rest with updated risk.
3. **Mark honestly:** plans contradicted by the diff get `status: stale`; affected work
   orders get `status: blocked` (their status set has no stale — and a stale WO left
   `ready` is a trap armed for the next implementer; `blocked` beats wrong).
4. **Re-gate scoped:** stale artifacts get reworked and pass through their gate again
   (G1 for plans, G2 for scaffold). Untouched artifacts keep their stamps — a full re-gate
   of a pack because one corner drifted is planning-as-procrastination.
5. **Restamp:** `last_verified` moves only on artifacts actually rechecked. Never bulk-bump
   stamps — an unearned fresh stamp is worse than an honest stale one.

## Divergence rulings

When plan and repo disagree:

| Case | Ruling |
|---|---|
| Repo changed for reasons outside the pack (other contributors, hotfixes) | Repo wins. Update plan; note the absorbed change in decisions.md if it altered a decision. |
| An implementer deviated from a WO and it's shipped and working | Repo wins, but log it: was the WO wrong, or the deviation sloppy? Feeds the G4 review. |
| The repo state is plainly broken and the plan is right | The *fix* is a new WO; the plan doesn't pretend the breakage isn't there. |
| Plan and repo both defensible, genuinely different directions | That's a decision, not a sync problem → decisions.md, possibly `[HUMAN-DECISION]`. |

## Handoff stamping

At every handoff (end of session, pack delivery, milestone close), MANIFEST records: date,
repo HEAD hash, ledger open-count, and the explicit sentence "stale after: <window> or any
trigger in loom/execution/staleness.md". Future agents start there.
