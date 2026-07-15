# Loom 1.0.0 agent kernel

The entire owner-facing interface is:

```text
/loom <request>
```

Do not expose internal stages as commands. Interpret the plain-language request, then use the
runtime below. Never read every Loom file into context.

## One-run protocol

1. Call `tools/loom_orchestrator.py invoke` exactly as specified by the installed skill. It checks
   the installation receipt, opens an authenticated session, calls `loom_runtime` through
   `loom_session`, and records the pre-plan baseline before returning host-agent work. The runtime
   resolves the exact project, surveys committed, staged, unstaged, untracked, ignored-runtime,
   lifecycle, and owner state, and produces a sealed route contract. Unknown or invalid state
   blocks.
2. Accept the inferred tier unless consequence or uncertainty requires promotion. Tier S uses one
   work order. Larger work uses only artifact rows selected by the consumer-driven matrix in
   `loom/intake/artifact-matrix.md`.
3. Use `tools/loom_domain.py` to select every applicable domain adapter. Unknown coverage requires
   invariant discovery and evidence before authorization. Never substitute web rules for an
   unfamiliar domain.
4. For planned implementation, record the target baseline with `tools/loom_gate.py` before plan
   credit can be earned. Use `tools/loom_lint.py` to validate required artifacts, references,
   ledgers, work-order invariants, and status parity.
5. Finish through `tools/loom_orchestrator.py complete`. Its registered production handlers drive
   plan, resume, execute, review, repair, close, and remember; the session controller owns status,
   why, undo, and forget. The bridge validates the unchanged target, gates the authored pack,
   enforces deadline/retry/cancellation state, captures real-medium evidence, seals the receipt,
   records outcomes, and runs bounded compaction. Do not estimate missing usage or claim a subset
   as total.
6. Return the compact owner receipt: what Loom understood, did, changed, learned, archived, remains
   uncertain, needs owner input, and what happens next. Explain a prior decision with its receipt,
   evidence, and memory identifiers. Forget only after a durable content-erased tombstone exists.

## Non-negotiable boundaries

- Epistemic status is explicit: fact with evidence, assumption with a verification route,
  speculation, unknown, or human decision.
- No implementation authorization from stale, unknown, corrupt, or time-drifted state.
- No artifact without a named consumer and decision. No work order without acceptance evidence.
- General memory contains no domain or project identity. Domain and project memory load only for
  an exact relevant scope. Installation identity never crosses instances.
- No telemetry, implicit contribution, publication, commit, push, deployment, destructive action,
  or access outside the request's authority.

The implementation modules and claim-to-proof links are listed in
`docs/capabilities.json`. Maintainer detail belongs in `docs/architecture.md`, not in the public
command surface.
