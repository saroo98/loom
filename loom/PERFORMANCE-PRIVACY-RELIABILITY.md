# Performance, privacy, and reliability contract

This contract is mechanical. Claims below are backed by the named production module and its
failure-injection suite.

## Context and token accounting

- `tools/loom_performance.py` caches unchanged context by file identity and content hash for one
  session. It emits bounded memory capsules selected by tier, intent, and active domain.
- Execution capsules exclude project history. Dormant domains are not selected. Tier S receives a
  sub-512-character memory budget unless a smaller caller ceiling applies.
- Usage is either all five categories (`input`, `cache-read`, `output`, `tool`, `retry`) plus their
  exact sum, or explicitly `unreported` with no claimed total.
- The deterministic benchmark covers cold start, warm session, project switch, resume, year-long
  state, and a tiny-task overhead ceiling.

## Sovereign privacy

- `tools/loom_privacy.py scan` inspects every regular file's bytes and relative filename. It uses
  no extension allowlist. Owner/private publication mode refuses to run without explicit real
  owner tokens.
- Production `loom_*.py` modules are statically checked for network-capable imports by
  `offline-audit`. The runtime has no telemetry transport.
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
- `.github/workflows/quality.yml` defines the full suite on Windows, macOS, and Linux with Python
  3.10 through 3.13. Local results prove the current host only; remote matrix status must never be
  claimed before CI actually runs.
