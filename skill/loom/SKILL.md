---
name: loom
description: Loom 1.0.0 turns a plain-language request into a safe, evidence-backed execution plan.
---

# Loom

Use one surface only:

```text
/loom <request>
```

`LOOM_ROOT` is the installed directory containing this file. Keep the following internal protocol
invisible to the owner:

1. Read `START-HERE.md`, not the entire installation.
2. Run `python -B LOOM_ROOT/tools/loom_orchestrator.py invoke --request <verbatim request>
   --cwd <absolute project root> --home <absolute user home>/.loom --install-root LOOM_ROOT`.
3. If the JSON is a terminal receipt, return its compact owner message. If it says
   `action-required`, honor its exact tier, domains, deadline, and session identity. The
   orchestrator has already recorded the planning baseline. Author only the consumer-selected
   plan, use a genuinely independent reviewer for G1, and do not mutate implementation targets.
   For `repair`, revalidate exactly `repair_plan.affected_plan_sections` using a real medium and
   write the private repair-result JSON defined by `schemas/repair-result.schema.json`. Every
   evidence path is relative to the private pack and its SHA-256 must match the observed file.
4. Write the harness's complete five-category token measurement to a private temporary JSON file:
   `input_tokens`, `cache_read_tokens`, `output_tokens`, `tool_tokens`, and `retry_tokens`. Never
   estimate a missing category or label a subset as total.
   When selected memory, observed preferences, measured outcome metrics, or artifact-use facts
   affected the work, also write the private `schemas/host-outcome.schema.json` receipt. Report
   only selected memory IDs and observed facts. This receipt is local agent-reported evidence, not
   independent proof. When the harness has actually run a controlled memory-enabled and memory-
   disabled production pair against the same sealed request/world, attach the optional
   `replay_pair` contract with both distinct provider-response receipts and real-medium evidence.
   Never synthesize the disabled result, reuse a provider response, or label a test/simulation as
   production. Omit the pair when the harness did not perform it; never fabricate an empty receipt.
5. Run `python -B LOOM_ROOT/tools/loom_orchestrator.py complete --action <action_path>
   --usage <private usage JSON> [--result <private result JSON>]`. `--result` is required for
   repair and optional for an evidence-bearing host outcome. Return the sealed receipt. On owner
   cancellation, run the same
   tool's `cancel --action <action_path>` operation. Retry only a structured transient interruption;
   the orchestrator caps retries at three and enforces the deadline.

Keep tiering, domain discovery, freshness checks, planning artifacts, gates, learning, compaction,
and receipts behind the one plain-language interaction. Ask only one decision checkpoint when a
consequential unknown cannot be resolved safely. Never load unrelated domain or project memory.
