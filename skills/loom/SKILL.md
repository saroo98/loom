---
name: loom
description: Invoke Loom immediately with no preamble or request classification; Loom 1.8.24 turns the exact request into a safe, evidence-backed execution plan.
---

# Loom

Use only `/loom <request>`. This is the complete Codex run contract. Do not read `START-HERE.md`, the full installation,
or another Loom copy during a Codex invocation.

Invoke Loom immediately. Do not narrate or analyze the request first; do not characterize the request as broad, intentional, complex,
simple, underspecified, or belonging to a domain.
Classification belongs to Loom.

On Codex:

1. If trusted developer context contains `LOOM_CODEX_HOOK_RECEIPT_V2`, call `loom.resolve` exactly
   once with its exact request, absolute working directory, action path, and digest. Otherwise call
   `loom.invoke` exactly once with the exact request and absolute working directory. Missing hook
   context is not an error. Never call both routes for one turn.
2. A blocked receipt is terminal: return `owner_message.human` and stop.
3. For a plan action, submit one strict-JSON semantic draft through `loom.author` with
   `finalize: true`. Never hand-author plan files. Copy sealed current facts exactly.
   Honor `semantic_draft_limits`. Encode `release_exposure` exactly as
   `{"external_users": <integer>, "irreversible": <boolean>, "data_migration": <boolean>,
   "regulated": <boolean>}`. For unknown domains, submit only requested readable
   `domain_evidence`. Never invent IDs, hashes, discovery receipts, or sealed bundles. Follow
   `semantic_draft_shape.domain_invariant_type_guidance`; never relabel a safety claim.
4. Successful finalization returns the sealed result and review projection.
   Return `plan_host_projection.markdown` verbatim without receipt narration. Do not replace the review surface with `owner_message.human`.
   The complete inline fallback is mandatory. Preserve `plan_decision_reference`; do not call
   `loom.complete` again.
5. When the owner requests a change, call `loom.revise` with that exact reference and exact request.
   Author and finalize the returned fresh action from its sealed contract and `revision_context`.
   Never edit a displayed plan in place.
6. When the owner chooses to start, call `loom.start` with that exact reference and honor only its
   sealed execution frontier. Never replace either bound decision with plain `loom.invoke`, an
   unbound `Continue`, or a guessed path.

Never read encrypted actions as plan content or invent a fallback when integration is unavailable.
Keep internal tiers, discovery, gates, receipts, and learning hidden unless the owner asks.
