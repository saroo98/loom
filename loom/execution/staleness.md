# Freshness and resume

Loom checks freshness before every execution or resume. Uncertain state blocks execution.

## Pre-work check

1. Recompute the complete repository state, including committed, staged, unstaged, untracked, and
   unsupported/special entries.
2. Verify the lifecycle and work-order hash chains and status parity.
3. Compare the current state with the latest authorization/completion checkpoint.
4. Enforce `freshness_window_days` from the active route contract.
5. Revalidate time-sensitive external facts, dependencies, APIs, regulations, credentials, and
   platform assumptions named by affected artifacts.

Target drift routes to selective repair using `plan-dependencies.json`; elapsed-time expiry routes
to repair even when the repository bytes are unchanged. Repair verifies only affected sections
when dependency evidence proves that scope. Unknown scope requires a full recheck.

Tier S has no dependency map, so repair uses one `compact-plan` scope. The orchestrator archives
the previously authorized lifecycle by SHA-256, records a fresh repository baseline, invalidates
the old authorization, and requires content-bound real-medium review evidence before it reauthorizes
the standalone work order. Target or lifecycle drift during that review blocks completion.

Execution remains blocked until repair produces current real-medium evidence and a new checkpoint.
Changing a date without rerunning the verification is not a refresh.
The production orchestrator seals the affected-section list before delegated work, accepts exactly
one content-hashed evidence record per affected section, rejects scope or digest drift, writes the
regate receipt, and rolls the receipt and stamps back on a failed postcheck. Elapsed-time expiry
forces a full-pack revalidation even when target bytes did not move.
