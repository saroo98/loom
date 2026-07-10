---
artifact: manifest
project: "<name>"
tier: <S|M|L|XL>
status: draft            # draft | gated | active | stale | maintenance | archived
last_verified: <YYYY-MM-DD>
loom_version: "0.7.0"
repo_head: "<commit hash at last survey — staleness diffs against this>"
freshness_window_days: 14
---

# Planning pack — <project>

Original request (verbatim, do not paraphrase):
> "<quote>"

## Artifacts

| Artifact | Decision | Why (one line) | Status | last_verified |
|---|---|---|---|---|
| intake.md | produce | — (always at M+) | | |
| <plan>.md | produce/skip | <reason> | | |

<!-- Every matrix row accounted for. Merges declared here ("uiux absorbs architecture"). -->

## Glossary (canonical names)

| Term | Means | Not to be confused with |
|---|---|---|

<!-- Seed for the long-context consistency spine walk. Add every name two docs share. -->

## Work order frontier

<!-- Claiming protocol + TTL rules: loom/execution/parallel-work.md. claim_ttl default 24h. -->

| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|---|

Blocked: <WO-id — blocked on what (D-id / WO-id / assumption)>

## Routing snapshot

<class → model mapping used for this pack, with date — see loom/execution/routing.md>

## Handoff stamps

<!-- One row per session exit; in-flight WOs also get a 4-line brief (done / in flight /
     surprises / repo state) in their close-out section — loom/execution/parallel-work.md. -->

| Date | Agent/session | Repo HEAD | Ledger open | Note |
|---|---|---|---|---|

Stale after: <freshness window> or any trigger in loom/execution/staleness.md.
