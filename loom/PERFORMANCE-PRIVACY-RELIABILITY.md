# Performance, privacy, and reliability contract

This contract is mechanical. Claims below are backed by the named production module and its
failure-injection suite.

## Context and token accounting

- The production orchestrator uses `tools/loom_performance.py` to read and content-hash the exact
  `SKILL.md` and `START-HERE.md` guidance set into every sealed action. The returned manifest is a
  stable provider-cache key; changed guidance invalidates the action. The sealed plan contract and
  bounded capsule are complete, so the host is instructed not to reload other Loom guidance.
- Execution capsules exclude project history. Dormant domains are not selected. Tier S receives a
  sub-512-character memory budget unless a smaller caller ceiling applies.
- Usage is either all five categories (`input`, `cache-read`, `output`, `tool`, `retry`) plus their
  exact sum, or explicitly `unreported` with no claimed total. A provider receipt retains bounded
  provider/model/response/hash provenance; it remains `requires-independent-attestation`. Plain
  caller totals are descriptive only and can never produce a certified budget claim.
- The deterministic benchmark covers cold start, warm session, project switch, resume, year-long
  state, and a tiny-task overhead ceiling.

## Sovereign privacy

- `tools/loom_privacy.py scan` inspects every regular file's bytes and relative filename, including
  UTF-8 and UTF-16 token/secret views. Owner/private publication mode refuses to run without
  explicit real owner tokens. Unsupported opaque binary/container files fail closed rather than
  receiving a clean result.
- Production `loom_*.py` modules are statically checked for direct and literal dynamic network
  imports and literal network subprocess commands by `offline-audit`. Current source has no
  built-in telemetry transport. Dynamically constructed or owner-selected verification commands
  remain outside that static proof and require an OS sandbox for containment.
- Global memory cannot contain domain/project identity or raw local paths. Private export is an
  explicit receiver-bound local operation. Erasure requires the exact installation UUID and only
  removes that marker-proven instance.
- Forgetting scrubs active and archived copies. A content-free semantic tombstone prevents the
  same learning from being silently re-admitted.
- Persisted acceptance transcripts and commands are bounded and redact recognized secrets, the
  project root, and the owner home. Raw transcripts are represented only by hashes.

## Durable and reversible state

- `tools/loom_reliability.py` writes through a same-directory temporary file, flushes it, atomically
  replaces the target, and synchronizes the parent directory where the OS supports that primitive.
- Migration planning is write-free. Apply creates an external durable journal before mutation,
  resumes idempotently after interruption, and rollback restores exact prior bytes.
- Corrupt bytes are copied to an external quarantine and remain blocking at the original path.
- Uninstall removes only unchanged files named and hashed in a validated ownership receipt. It
  never recursively deletes an arbitrary root.
- Reproducible manifests contain sorted relative paths, sizes, hashes, and a deterministic root
  hash. They contain no timestamps or machine-local absolute paths.
- `.github/workflows/quality.yml` runs a 10-test trust-critical PR gate on Windows, macOS, and Linux
  with Python 3.10 and 3.13 under a 30-second budget. Pushes run the complete suite on all three OSes
  with Python 3.10 through 3.13. `tools/loom_test.py` emits per-test timings for both lanes, and the
  workflow uploads them. Local results prove the current host only; remote matrix status must never
  be claimed before CI actually runs.
