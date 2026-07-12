# Staleness — plans decay; here is the protocol

Every artifact carries `last_verified` and `status` in frontmatter. This file defines when
those stamps demand action and what the action is. The prime directive throughout:
**the repo is the truth; the plan adapts to it, never the reverse.**

## Staleness triggers

An artifact (or the whole pack) must be rechecked when any of these fire:

1. **Time** — `last_verified` older than the pack's freshness window (default: 14 days for
   active projects, set in MANIFEST). Expiry blocks execution until the affected material is
   rechecked; it is not evidence that the material is wrong, and it is not permission to use it.
2. **World movement** — the current repository-state hash differs from the stamped hash;
   repo HEAD differs from the surveyed commit; dependencies, platform APIs, firmware/toolchains,
   qualified sources, or other domain authorities may have changed.
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

**Tool support:** before a gate, resume, or work order, run:

```text
python <loom>/tools/loom_lint.py <pack> --repo <repo> --strict-staleness
```

Strict mode blocks on an expired authoritative artifact (W03), invalid or moved commit stamp
(W04), missing or changed repository-state stamp (W15), and any failure to establish state
(E16). The state fingerprint covers current HEAD plus staged, unstaged, and untracked Git-visible
content; for a non-Git workspace it covers every non-pack file. Ignored build/cache files and the
private pack are intentionally outside that product-state fingerprint. A read error, Git error,
timeout, or complete-snapshot safety-limit breach produces **unknown**, never a partial "clean"
answer. `python <loom>/tools/loom_survey.py <repo> --since <surveyed-hash>` adds the committed
delta report; it does not replace the state fingerprint.

Loom is local-first, so it cannot silently infer that remote dependency registries, platform
APIs, tax rules, research evidence, device datasheets, or other authorities remained unchanged.
After the freshness window or a known platform event, record an actual authoritative check (or
an explicit unavailable/unknown result) in the relevant artifact. Unknown blocks the affected
gate.

## The pre-WO check (cheap, every time)

Before executing **any** work order, the implementer performs this bounded check:

```
1. Run loom_lint.py <pack> --repo <repo> --strict-staleness.
2. If the state hash moved, inspect committed, staged, unstaged, and untracked changes touching
   this WO or its dependencies; never use committed history as the whole world state.
3. Do the WO's stated facts still hold? (files exist, symbols/contracts/invariants unchanged.)
4. Ledger scan: is any used assumption broken, expired, or past verify_by?
5. Confirm time-sensitive external facts in their real authority/medium when their check expired.
6. All clear → execute. Unknown or drift → stop; mark the WO blocked and record the evidence.
```

This check is why WOs inline their load-bearing facts — it makes drift detectable in
seconds by exactly the agent about to rely on them.

## The full recheck (when a trigger fires pack-wide)

1. **Establish the world:** re-run the complete state snapshot and the committed survey delta.
   Inventory staged, unstaged, and untracked changes, dependency/lockfile movement, CI/toolchain
   changes, and any time-sensitive external authority. If any required source cannot be checked,
   record unknown and block what depends on it.
2. **Walk the ledger:** every `open` assumption — still plausible? `verify_by` event passed?
   Verify the cheap ones now; re-ledger the rest with updated risk.
3. **Mark honestly:** plans contradicted by the diff get `status: stale`; affected work
   orders get `status: blocked` (their status set has no stale — and a stale WO left
   `ready` is a trap armed for the next implementer; `blocked` beats wrong).
4. **Re-gate the affected subgraph:** follow references, `depends_on`, `blocks`, and assumption
   `used_in` edges from each changed fact. Rework and re-gate only that closure (G1 for affected
   plans, G2 for an affected scaffold, later gates as applicable). Unaffected artifacts keep
   their stamps; "unaffected" must be demonstrated by the graph, not guessed.
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

At every handoff (end of session, pack delivery, milestone close), MANIFEST records the date,
full repo HEAD (when Git exists), full `repo_state_hash`, ledger open-count, and the explicit
sentence "stale after: <window> or any trigger in loom/execution/staleness.md". Generate the hash
from `loom_survey.py`; never hand-invent it. Future agents start by re-running strict staleness,
not by trusting the sentence.
