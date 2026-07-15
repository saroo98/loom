# Epistemic contract

Loom separates what is observed from what is merely plausible. Every load-bearing claim in a
plan must use one of these labels:

- `[FACT — source]`: directly observed in the target, a named authoritative source, or recorded
  tool output. Include the path, command, receipt, or source date.
- `[INFERENCE — basis]`: a conclusion drawn from named facts. State what would falsify it.
- `[ASSUMPTION A-NNN]`: an unresolved proposition recorded in `assumptions.md`, with risk,
  verification owner, deadline, and every artifact that consumes it.
- `[UNKNOWN]`: information Loom could not establish. Unknown high-consequence facts block the
  affected gate; they are never silently converted to assumptions.

Confidence words are not evidence. A repeated assertion is still one source. Generated prose,
self-review, and a model's own confidence are not independent verification.

## Gate rules

1. A fact is current only within its named freshness window.
2. An inference cannot be stronger than its inputs.
3. A high-risk assumption must be verified or explicitly accepted by the owner before G1.
4. Acceptance evidence must come from the real execution medium and bind to the current target
   state. A transcript describing an unrun check does not count.
5. Contradictory evidence remains visible until resolved. Do not average it away.
6. If evidence is unavailable, say `[UNVERIFIED]`, lower confidence, and block any unsafe action.

## Minimal citation shape

Use `path:line`, an exact command plus exit status, a content-bound receipt ID, or a dated primary
source. Never copy secrets, owner paths, or private project names into a shippable artifact.
