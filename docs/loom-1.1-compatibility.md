# Loom 1.3 compatibility and migration contract

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

Vault schema 2 and event payload schema 2 are the current authority. Opening a vault-schema-1
database stages a same-directory SQLite backup, adds exact source-event and source-device
provenance to every materialized collection, validates integrity and foreign keys, and only then
atomically replaces the active database. The untouched schema-1 database remains as the rollback
snapshot. Local writes, legacy imports, lifecycle expiry, and authenticated remote events all use
the same deterministic materializer. Release manifests therefore advertise schema range 1 through
2 and the complete `vault-1`, `vault-2` chain.

Pairing uses transcript v2. A pairing request is receiver-bound, challenge-bound, expires after
five minutes, and must be explicitly owner-authorized on the sending device. Acceptance pins the
sender fingerprint, verifies an owner-comparable short authentication string, validates the
restored vault's active sender membership, and records the bundle in a bounded durable replay
store. A replay, expired request, wrong sender, wrong SAS, mixed signing key, or changed transcript
fails before activation.

Release-root replacement advances one root version at a time and is accepted only when both the
previous and replacement 2-of-3 authorities sign the same replacement root. This prevents an
expired, compromised, or substituted single authority set from silently redefining trust.

## Rollback policy

The previous runtime and pre-upgrade snapshot remain available until at least ten successful
sessions and 30 days have passed. A rollback never feeds post-upgrade events to old code. Those
events remain encrypted in versioned quarantine for a later compatible runtime.

Recovery backups are `loom-recovery-v2` and carry the vault deletion epoch. A separately signed
current recovery anchor is required before restore. A backup older than that anchor cannot expose
memory to agent context, even if its recovery phrase is valid.
