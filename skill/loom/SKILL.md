---
name: loom
description: Invoke Loom immediately with no preamble or request classification; Loom 1.8.19 turns the exact request into a safe, evidence-backed execution plan.
---

# Loom

Use one owner-facing surface:

```text
/loom <request>
```

This skill is the complete Codex run contract. Do not read `START-HERE.md`, the full installation,
or another Loom copy during a Codex invocation. `START-HERE.md` remains the non-Codex kernel and
maintainer reference.

Invoke Loom immediately. Do not narrate or analyze the request before invocation. In particular,
do not characterize the request as broad, intentional, complex, simple, underspecified, or
belonging to any domain. Classification belongs to Loom's sealed runtime.

On Codex:

1. If trusted developer context contains `LOOM_CODEX_HOOK_RECEIPT_V2`, call `loom.resolve` exactly
   once with the exact request, absolute working directory, sealed action path, and action digest.
   Do not call `loom.invoke` for that turn.
2. Otherwise call `loom.invoke` exactly once with the exact request and absolute working
   directory. Missing optional hook context is not an error.
3. A blocked receipt is terminal. Return its `owner_message.human` and stop.
4. For a plan action, serialize one semantic draft as strict JSON and submit it through
   `loom.author` with `finalize: true`. Do not hand-author or patch plan files. Copy sealed
   current facts exactly. Honor `semantic_draft_limits`. Encode `release_exposure` as exactly
   `{"external_users": <integer>, "irreversible": <boolean>, "data_migration": <boolean>,
   "regulated": <boolean>}`. Do not substitute strings, arrays, or booleans for
   `external_users`. For an unknown
   domain, submit only the readable `domain_evidence` requested by the draft schema. Never create
   source IDs, applicability IDs, invariant IDs, hashes, digests, discovery receipts, or sealed
   bundles; Loom derives and validates all of them. Follow
   `semantic_draft_shape.domain_invariant_type_guidance` exactly. Never relabel a genuine safety
   claim to pass validation.
5. `finalize: true` completes the ordinary plan only after successful authoring and returns the
   final sealed receipt in the same tool call. Return its `owner_message.human` verbatim, with no
   paraphrase, omission, added claim, or reformatted receipt. Do not call `loom.complete` again.

Never read the encrypted action file as planning content. Never invent a fallback when the local
integration is unavailable. Keep tiering, discovery, gates, receipts, and learning invisible unless
the owner asks to inspect them.
