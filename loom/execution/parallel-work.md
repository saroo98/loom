# Parallel work protocol

Parallel execution is allowed only when ready work orders have disjoint declared `touches` and no
unmet dependency edge.

## Claim protocol

1. An agent atomically claims one ready work order in the MANIFEST frontier.
2. Record claimant, UTC claim time, and heartbeat. Default claim TTL is 24 hours unless the pack
   states a shorter value.
3. A live claim cannot be stolen. An expired claim requires a fresh target/staleness check before
   reassignment.
4. The agent may modify only declared touches. Newly discovered overlap blocks both orders until
   the frontier is replanned.
5. Close-out records changed paths, acceptance evidence, unexpected findings, and escalation.

Status parity is mandatory: work-order frontmatter, the MANIFEST frontier, and lifecycle records
must agree. `ready -> in-progress -> done` is the normal path. A failed or abandoned claim returns
to `ready` only with an interruption/reconciliation record; never edit history to make a collision
disappear.
