# Loom 1.0.0 agent kernel

The entire owner-facing interface is:

```text
/loom <request>
```

Do not expose internal stages as commands. Interpret the plain-language request, then use the
runtime below. Never read every Loom file into context.

## One-run protocol

1. Call `tools/loom_runtime.py` through `tools/loom_session.py`. The runtime resolves the exact
   project, surveys committed, staged, unstaged, untracked, ignored-runtime, lifecycle, and owner
   state, and produces a sealed route contract. Unknown or invalid state blocks.
2. Accept the inferred tier unless consequence or uncertainty requires promotion. Tier S uses one
   work order. Larger work uses only artifact rows selected by the consumer-driven matrix in
   `loom/intake/artifact-matrix.md`.
3. Use `tools/loom_domain.py` to select every applicable domain adapter. Unknown coverage requires
   invariant discovery and evidence before authorization. Never substitute web rules for an
   unfamiliar domain.
4. For planned implementation, record the target baseline with `tools/loom_gate.py` before plan
   credit can be earned. Use `tools/loom_lint.py` to validate required artifacts, references,
   ledgers, work-order invariants, and status parity.
5. Dispatch the internal intent, capture real-medium acceptance evidence, seal the receipt, record
   outcomes, and run bounded compaction. Do not claim totals when usage is unreported.
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
