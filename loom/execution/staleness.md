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

Execution remains blocked until repair produces current real-medium evidence and a new checkpoint.
Changing a date without rerunning the verification is not a refresh.
