---
name: loom
description: Loom 1.1.0 turns a plain-language request into a safe, evidence-backed execution plan.
---

# Loom

Use one surface only:

```text
/loom <request>
```

`LOOM_ROOT` is the installed directory containing this file. Keep the following internal protocol
invisible to the owner:

1. Read `START-HERE.md`, not the entire installation.
2. Run `python -B LOOM_ROOT/scripts/loom_bootstrap.py --ensure --plugin-root LOOM_ROOT
   --home <absolute user home>/.loom`, then run `<absolute user home>/.loom/bin/loom
   --home <absolute user home>/.loom invoke --request <verbatim request>
   --cwd <absolute project root> --agent codex --agent-version <actual host version>`.
3. If the JSON is a terminal receipt, return its compact owner message. If it says
   `action-required`, honor its exact tier, domains, deadline, and session identity. The
   orchestrator has already recorded the planning baseline. Treat the returned `context_manifest`
   hash as the stable static-context cache key. The sealed capsule and plan contract are complete;
   do not reload Loom guidance after invocation. For `plan`, use the returned content-hashed
   `plan_contract` directly; do not reload the artifact matrix or guess a plan.
   Match all 15 produce/skip rows exactly, verify every required domain invariant/current fact,
   plan the named real media, stay within its lexical-token/character budget and work-order
   topology, use a genuinely independent reviewer for G1, and do not mutate implementation
   targets. Completion rejects any omitted, extra, or changed contract row.
   For `repair`, write the private schema-v2 verification plan defined by
   `schemas/repair-result.schema.json`, covering exactly
   `repair_plan.affected_plan_sections`. Supply one bounded real-medium command and timeout per
   section. Loom, not the host, runs each command in a disposable target snapshot, captures the
   transcript and world hashes, and derives the immutable evidence ID. A host-authored `passed`
   flag, evidence file, or digest is invalid.
4. Write the harness's complete five-category token measurement to a private temporary JSON file:
   `input_tokens`, `cache_read_tokens`, `output_tokens`, `tool_tokens`, and `retry_tokens`. Never
   estimate a missing category or label a subset as total. When the harness exposes the real
   provider response receipt, wrap the five counts with its provider, model, response ID, capture
   time, and raw-response SHA-256. Loom retains only that bounded provenance and labels it as still
   requiring independent attestation; never fabricate a provider receipt.
   When selected memory, observed preferences, measured outcome metrics, or artifact-use facts
   affected the work, also write the private `schemas/host-outcome.schema.json` receipt. Report
   only selected memory IDs and observed facts. This receipt is local agent-reported evidence, not
   independent proof. When the harness has actually run a controlled memory-enabled and memory-
   disabled production pair against the same sealed request/world, attach the optional
   `replay_pair` contract with both distinct provider-response receipts and real-medium evidence.
   Never synthesize the disabled result, reuse a provider response, or label a test/simulation as
   production. Omit the pair when the harness did not perform it; never fabricate an empty receipt.
5. Run `<absolute user home>/.loom/bin/loom --home <absolute user home>/.loom complete
   --action <action_path> --usage <private usage JSON> [--result <private result JSON>]`.
   `--result` is required for
   repair and optional for an evidence-bearing host outcome. Return the sealed receipt. On owner
   cancellation, run the same
   launcher's `cancel --action <action_path>` operation. Retry only a structured transient interruption;
   the orchestrator caps retries at three and enforces the deadline.

Keep tiering, domain discovery, freshness checks, planning artifacts, gates, learning, compaction,
and receipts behind the one plain-language interaction. Ask only one decision checkpoint when a
consequential unknown cannot be resolved safely. Never load unrelated domain or project memory.
