# Changelog

## Unreleased

## 1.8.7

- Add automatic Codex Standard mode through a bounded local stdio MCP server with no network
  listener and no lifecycle-hook trust requirement.
- Add an explicit Verified mode whose receipt-owned user hooks provide request sealing, bounded
  session and compaction continuity, structured-write scope checks, and lifecycle observations.
- Bind every action and receipt to its actual assurance mode so Standard work cannot be reported
  as Verified work, while preserving one `/loom <request>` surface and the same private vault.
- Make Codex integration transactional and ownership-safe across install, upgrade, interruption,
  rollback, and uninstall without overwriting unrelated user configuration.
- Align exhaustive exact-cut and CI time budgets with the measured public-cut suite while retaining
  fail-closed correctness, firewall, offline, and capability requirements.

## 1.8.6

- Give the Codex hook a complete, bounded semantic frontier so the agent can author the required
  plan artifacts without reading private encrypted action state or guessing missing context.
- Make transport retries idempotent only for the same operation in the same world, while an
  identical natural-language request after repository or lifecycle drift creates a new operation
  or fails closed instead of replaying stale authorization.
- Preserve non-Git project completion identity, improve actionable hook diagnostics, and add
  family-level transport, routing, recovery, and malformed-input regression coverage.
- Run required pull-request gates once and reserve the exhaustive 15-cell release matrix for
  `main`, reducing duplicate CI without weakening branch protection or exact-cut certification.

## 1.8.5

- Add a Codex `UserPromptSubmit` hook that routes explicit Loom requests through bounded
  protocol-v2 JSON stdin from host to launcher to orchestrator, without request text in a shell,
  argument, environment variable, wrapper, or temporary file.
- Bind injected developer context to the exact UTF-8 request digest and encrypted action-file
  digest, reject malformed or redirected action envelopes, and leave non-Loom prompts silent and
  side-effect free.
- Stop project-shadow detection at the owner-home boundary so a valid global Loom installation is
  not mistaken for a project-local conflict in non-Git projects.

## 1.8.4

- Make interrupted control-plane recovery transactional and receipt-bound across same-volume and
  cross-volume filesystems, with strict v3 validation, fail-closed legacy compatibility, and
  private Windows ACL enforcement.
- Separate operation identity from the full observed world so exact retries remain idempotent while
  lifecycle or repository advancement creates the next authorized operation instead of replaying a
  stale receipt.
- Add explicit verification-only causal scope and generate release evidence after the final test
  inventory, preventing pre-existing implementation from receiving causal credit and stale counts
  from reaching CI.

## 1.8.3

- Bind draft-release certification to the exact successful main quality and compatibility runs.
  A capability skipped on the release host is accepted only when an exact-commit, exact-public-cut
  matrix receipt proves the same test passed elsewhere; uncovered skips, wrong subjects, and local
  failures remain release blockers.

## 1.8.2

- Isolate clean-room temporary and Cargo caches inside the disposable home, and bind the native
  helper test cache to Cargo, Rust, and temporary-path build inputs. This prevents a verified
  clean-room build from contaminating a later release step with incompatible cached bytes.

## 1.8.1

- Import the reliability authority used by the clean-room CLI receipt writer and lock the exact
  successful `--output` path with a regression test, so release attestation cannot pass every
  embedded test and then fail while sealing its final receipt.

## 1.8.0

- Replace the undifferentiated 4,096-entry domain-inspection refusal with one bounded, Git-aware,
  content-bound project-inspection receipt derived from Loom's frozen world observation.
- Preserve request-backed routing under safely summarized structure while mechanically separating
  draft-planning eligibility from G1 and implementation authorization.
- Make direct-source bootstrap receipt-proven and explicitly unattested, retain signed-delivery
  non-downgrade, and verify the installed stable-launcher path in disposable owner environments.
- Supervise Linux Python 3.14 privacy scanning fail-closed, preserve release-mode Rust hardening
  with a bounded compiler stack, isolate destructive reproducibility builds from the shared helper
  cache, and cover POSIX and Windows capability branches across the matrix.
- Canonicalize disposable test-home containment across operating-system path aliases and preserve
  the primary CI diagnostic when later evidence artifacts are legitimately absent after a failure.
- Rebuild native helper reproducibility probes at one source-keyed private target so build paths
  stay deterministic while the immutable shared helper artifact is never deleted or overwritten.
- Give the pinned Rust release compiler a deterministic 64 MiB worker stack so LTO-heavy
  dependency analysis cannot inherit an undersized host setting and panic during proof rebuilds.
- Keep the 30-second fast gate focused on one cheap sentinel per learning boundary while the full
  matrix retains every expensive longitudinal learning case, eliminating cold-runner false blocks.
- Export both native rebuild bytes, validated SBOM hashes, exact source hashes, and builder-bound
  provenance so the six-platform CI artifacts can actually assemble the canonical signed plugin.

## 1.7.0

- Replace hard-coded host paths with one versioned contract that drives detection, project-shadow
  refusal, generated host documentation, and honest support status.
- Serialize launcher, adapter, session, update, activation, rollback, and cleanup changes with
  crash-recoverable receipts; pin runtime and owner-state generations per active session.
- Bind release subjects to schemas, documentation, capability registry, provenance, and prior
  release identity; retain actionable exact-cut failure receipts in every CI outcome.
- Generate release readiness from exact evidence, add body-free local diagnostics and explicitly
  encrypted support export, and keep absent real-host or independent proof visibly unverified.

## 1.6.0

- Add a fixed 17-category, 100-point evidence rubric and deterministic scorer that refuses stale,
  altered, duplicate, wrong-subject, or ineligible evidence instead of inflating a result.
- Bind local score evidence to the exact source tree and observed tool artifacts; keep real-host,
  provider, cross-platform, longitudinal, adoption, and independent-review gaps explicitly withheld.
- Add freshness-bound competitive snapshots with unknown-cell score intervals and identical rubric
  treatment for Loom and comparable projects.

## 1.5.0

- Replace host-specific integration assumptions with closed adapter protocol v2, one stable local
  runtime bridge, exact capability receipts, and transactional adapter migration and rollback.
- Classify five host templates as simulated-conformant while keeping experimental, unsupported,
  real-host, provider, and MCP claims mechanically separate.
- Add disposable multi-host conformance, split-brain refusal, capability-tamper checks, and hostile
  mutations for protocol overlap, host-status inflation, and receipt binding.

## 1.4.0

- Replace the ambiguous five-counter token sum with formula-bound, per-response usage receipt v3
  profiles for OpenAI Responses, Anthropic Messages, Gemini, and unknown hosts.
- Make missing host telemetry honest and non-blocking while rejecting contradictory supplied usage;
  migrate old samples as non-certifying `legacy-ambiguous` history.
- Add a bounded Tier S host capsule, tighter single-work-order limits, deceptive-small promotion
  fixtures, local content-free spans, encrypted performance observations, an offline 20-workload
  corpus, CI performance evidence, and trust-critical accounting mutations.

## 1.3.0

- Add evidence-aware known, partial, unknown, and composite routing with consequence-aware
  subsystem isolation.
- Replace custom-domain `verified` prose with content-bound source, applicability, invariant,
  discovery, plan-contract v2, work-order, freshness, and G1 enforcement.
- Add bounded encrypted unknown-domain learning, idempotent v1 projection receipts, a 240-case
  locked regression corpus, 100,000 scope-firewall traces, and trust-critical mutation gates.

## 1.2.0

- Harden owner-vault convergence, migration activation, recovery freshness, and runtime rollback.
- Add deterministic canonical plugin assets, semantic SBOM/provenance validation, root rotation, and native release gates.
- Make capability skips, CLI contracts, and release evidence mechanically explicit.

## 1.1.0

- Separated immutable Loom runtimes from a stable encrypted owner vault and explicit owner,
  device, runtime, and project identities.
- Added transactional legacy migration, signed staged updates, atomic session pinning, rollback,
  deterministic platform archives, and a marketplace bootstrap that never activates an
  unverifiable payload.
- Added encrypted device pairing and recovery backups, deterministic event merging, permanent
  forgetting propagation, bounded memory lifecycle maintenance, checkpoints, and active-device
  acknowledgement before compaction.
- Added receipt-owned global agent adapters and a stable per-user launcher so supported agents
  share one runtime and owner vault without repository-local installation files.
- Added native OS key-store integration and a narrow Rust cryptographic helper; executable
  adaptations, raw transcripts, credentials, and absolute local paths remain non-transferable.
- Added package-wide privacy scanning and reproducible-build provenance requirements for opaque
  platform binaries and deterministic runtime archives.

## 1.0.0 trust remediation

- Verify exported public cuts independently of Git, reject undeclared post-build files, and rerun
  the firewall after a bytecode-free artifact suite.
- Make documentation inventory drift blocking and correct nested repository-path parsing.
- Retire domain memory automatically according to observed harm, use, help, and recurrence while
  preserving bounded exact-domain rehydration and mandatory safety rules.

## 1.0.0

- Replaced the multi-command method surface with one natural `/loom <request>` entry point.
- Added an automatic, idempotent session runtime with complete world-state fingerprinting.
- Added bounded, instance/project/domain-isolated learning and preference evolution.
- Added exact-domain comparative improvement proof and independent claim reproduction.
- Added fail-closed lifecycle, freshness, chronology, pack-integrity, and release enforcement.
- Added a positive-allowlist public builder, whole-artifact firewall, and receipt-proven installer.
- Added deterministic adaptation evaluation and a generated-inventory standard-library suite.
- Made acceptance and signed external evidence identities immutable and content-bound.
- Separated reproducible local improvement observations from independently attested production claims.
- Blocked explicitly self-reviewed G1 records from authorizing implementation.
- Replaced host-authored repair pass files with Loom-executed, content-bound verification receipts.
- Grounded private publication token policies in excluded source and made public-source scans deny
  any private-protection claim.

Production certification remains blocked until the external evidence listed in
[`docs/limitations.md`](docs/limitations.md) exists.
