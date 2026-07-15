# Loom 1.1 compatibility and migration contract

Loom software and owner intelligence have independent lifecycles. A runtime may be replaced in
full; a verified owner vault is not replaced, implicitly merged, or reset.

## Semantic reconciliation invariants

- **No semantic disappearance.** Every recognized legacy record becomes preserved, rekeyed,
  dormant, quarantined, or forgotten, with a receipt row.
- **No scope widening.** Project data remains on its exact project lineage; domain data remains in
  its exact domain; installation-specific material never becomes global by inference.
- **No implicit activation.** Ambiguous 0.8 Markdown, executable-looking content, unknown schemas,
  and contradictory rules enter inactive quarantine.
- **No provenance loss.** Source IDs, hashes, evidence counts, status, utility, and migration action
  remain attributable after compaction.
- **Executable payloads never transfer.** Scripts, commands, plugins, credentials, raw transcripts,
  caches, absolute paths, and repository artifacts are excluded or converted to inactive text that
  must be regenerated locally.
- Tombstones import before active records and dominate every earlier copy.
- Running the same migration twice against the same sources produces the same semantic inventory.
- The exact active verified legacy installation migrates into the owner vault. Additional
  independent legacy installations remain untouched and are never merged implicitly. Automatic
  discovery and separate inactive candidate-vault creation remains a declared release gap in
  `docs/limitations.md`.

## Identity compatibility

`owner_vault_id` is the stable owner namespace. `device_id` identifies one OS installation.
`runtime_install_id` identifies one immutable runtime. `project_id` is keyed by the owner vault and
project lineage. Legacy installation UUIDs survive only as lookup aliases.

Git identity uses root commits plus hashed origin metadata. Non-Git path mappings transfer only as
encrypted hints. If two folders are indistinguishable, Loom asks one association question and does
not guess.

## Version policy

Every release declares its state-schema range, complete migration chain, adapter range, platform
targets, monotonically increasing release sequence, hashes, and sizes. Major releases may stage
automatically but activate only after semantic preservation and health checks succeed. Unknown or
incompatible versions leave the last working runtime active.

## Rollback policy

The previous runtime and pre-upgrade snapshot remain available until at least ten successful
sessions and 30 days have passed. A rollback never feeds post-upgrade events to old code. Those
events remain encrypted in versioned quarantine for a later compatible runtime.
