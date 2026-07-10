# Parallel work — several agents, one pack, no collisions

Protocol for running multiple implementers (different models, different sessions, or
Claude + Codex sharing one folder) against the same planning pack without coordination by
luck. Everything here assumes the WO DAG already exists; this file governs the *runtime*.

## The three instruments

1. **`touches` declarations** — every WO frontmatter lists the path globs it may modify.
   Planner's slicing duty: WOs meant to run in parallel have **disjoint `touches`**.
   `loom_lint` warns (W07) when ready/in-progress WOs overlap — by literal path-prefix
   heuristic, so non-prefix collisions (two globs like `**/config.json`) are NOT
   caught mechanically; the planner still owns true disjointness. An implementer whose real
   work exceeds its declared `touches` has hit an escalation trigger — the WO was sliced
   wrong; stop, don't sprawl.
2. **Claims** — before starting a WO, an implementer claims it in MANIFEST (format below).
   The claim is what turns "two agents grabbed WO-007" from a merge disaster into a
   ten-second race with a loser who picks the next frontier item.
3. **Frozen contracts** — parallel WOs on two sides of a boundary require the contract
   `frozen` *before* either starts (`loom/planning/contracts.md`). A frozen contract plus
   disjoint `touches` is what makes parallel work merge cleanly: agreement at the boundary,
   separation everywhere else.

## Claiming protocol

Claims live in MANIFEST's frontier table:

```markdown
## Work order frontier
| WO | Status | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|
| WO-007 | in-progress | codex-session-a | 2026-07-09T14:02Z | 2026-07-09T15:40Z |
| WO-008 | ready | — | | |
```

Rules (the first two are load-bearing — they came out of the 2026-07-09 stress test,
see `loom/meta/evidence/`):
- **Claims are row-level compare-and-swap.** Claim by replacing the exact current text of
  your WO's row with the claimed version, using an edit mechanism that *fails if the row
  changed underneath you* (exact-match string replacement has this property; a plain
  overwrite does not and doesn't count as a claim). Re-read the row immediately before the
  swap; if it already carries a name, you lost the race — take the next frontier item.
  In a shared git remote, the push is the additional arbiter: rejected push = pull,
  re-check your row, re-claim if still yours.
- **Never rewrite MANIFEST whole while a frontier is open.** All shared-file pack edits by
  implementers are minimal single-row replacements (your frontier row; your appended
  stamp). A whole-file Write silently clobbers rows other agents changed concurrently.
  Handoff stamps append at the **end of the table only** — never anchored to another
  agent's row.
- **Both status fields flip at close-out.** The WO file's frontmatter `status` is
  authoritative; the implementer updates it (`done` / `blocked`) *and* mirrors it in the
  frontier row. A pack with disagreeing statuses fails its next lint honesty check.
- **Heartbeat only for WOs spanning more than one session.** Refresh it when a session
  ends with the WO unfinished; single-sitting WOs legitimately leave it empty. A claim
  whose heartbeat (or claimed_at, if no heartbeat) is older than the pack's `claim_ttl`
  (default: 24h, in MANIFEST or loom.config.json) is **stale and reclaimable** — note the
  takeover in the row and read the previous handoff brief first.
- **Release on exit.** Done → `done`, claim cleared. Blocked → `blocked` + one-line
  reason, claim cleared. Abandoning silently is the one forbidden move: it costs another
  agent a TTL of waiting.
- **Non-git targets get a baseline hash manifest.** Where the negative scope check can't
  use `git diff --stat`, the planner records file hashes at frontier-open (one command:
  `find … | xargs sha256sum > baseline-hashes.txt`); implementers and reviewers diff
  against it. Without git or a baseline, scope compliance is unattestable — don't open a
  parallel frontier that way.

## Slicing rules (for the planner)

- Disjoint `touches` between any two WOs intended to be concurrently `ready`. Where two
  features genuinely need the same file, either sequence them (`depends_on`) or split the
  shared file's change into its own tiny WO both depend on.
- Shared surfaces (routing tables, DI registries, migration indexes — files everything
  edits) are the classic collision point: give each parallel WO its own file and one
  serializing WO that wires them, or freeze an append-only convention in the contract.
- Width without depth: prefer many parallel small WOs over deep chains — chains serialize
  agents; width uses them. But never buy width by fuzzing boundaries.

## Handoff briefs

Whenever a session stops (WO finished or not), it leaves a brief — MANIFEST handoff table
row plus, for in-flight work, a short block in the WO's close-out section:

```markdown
## Handoff (2026-07-09, codex-session-a, WO-007 in-progress)
- Done: refresh path implemented; unit tests green locally.
- In flight: boundary test for expiry edge not written (that's next).
- Surprises: SessionStore caches aggressively — see note added to A-014.
- Repo state: committed on branch wo-007, not merged. Lint: clean.
```

Four lines, always the same four: done / in flight / surprises / repo state. The next agent
(or the same agent next week) starts from the brief, not from re-derivation. The brief is
also what makes stale-claim takeover safe.

## Verification in parallel mode

- G3 review of a danger-zone WO must come from a session that didn't implement it
  (`loom/execution/routing.md` rule 5) — parallel mode makes this cheap: reviewers are
  already running.
- After any batch of parallel WOs merges, run `loom_lint` (touches overlap, DAG, staleness)
  plus a contradiction spot-check on the shared contracts — the merge is where plans meet.

## Failure modes

- **Optimistic sprawl** — implementer "quickly also fixes" a file outside its `touches`.
  The negative acceptance check (`git diff --stat` scope) catches it at G3; the fix is a
  new WO, not a bigger diff.
- **Claim squatting** — claimed, then idle. TTL + heartbeat exist for this; takeover is
  legitimate and logged.
- **Contract drift under parallel load** — someone "small-fixes" a frozen contract.
  Freeze log + lint W-checks + the escalation trigger on every WO touching it.
- **Serialization theater** — everything chained `depends_on` out of caution, agents idle.
  That's a slicing defect: revisit with the slicing rules, not more caution.
