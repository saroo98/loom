# Changelog

## Unreleased

## 1.8.26

- Keep plan revision bound to planning intent when the owner's natural revision request also says
  not to implement the plan.
- Expose the deterministic plan review projection through MCP structured content while retaining
  the complete portable Markdown fallback.
- Return an exact work-order completion contract so an implementing agent can capture real
  verification evidence and close only the authorized work order.

## 1.8.25

- Present every completed plan as a deterministic, reviewable inline summary with a contained,
  clickable local plan link and a complete Markdown fallback.
- Add revision-aware plan review with semantic diffs, no-op rejection, immutable encrypted prior
  revisions, replay and forgetting support, and exact displayed-plan start authorization.
- Refuse stale, tampered, or world-drifted plan starts while preserving request, project, contract,
  pack, file, and revision identity across the review flow.
- Keep host presentation capability claims honest: use the portable text and structured-content
  surface unless an official host contract proves richer native controls.
- Preserve complete exact-cut suite evidence outside the bounded supervisor transcript so large
  successful test inventories remain verifiable without weakening process-output limits.

## 1.8.24

- Preserve complete, plain blocked-state sentences in the default owner message.
- Avoid duplicating the stop prefix when the sealed observation already explains that Loom
  stopped, and truncate hostile long observations only at a visible word boundary.
- Add exact regressions for the installed no-project-write response and bounded long summaries.

## 1.8.23

- Honor natural owner wording such as `do not implement it or modify project files` as an
  explicit zero-project-write planning request.
- Stop before creating project-local `plans/` metadata when that prohibition is present.
- Add the exact installed 1.8.22 acceptance request as a regression test and refresh the generated
  final test inventory.

## 1.8.22

- Accept the canonical `verified` success state written by exact-cut receipts when the
  clean-room wrapper validates its durable result.
- Continue to reject missing, malformed, oversized, redirected, failed, or otherwise
  non-verified clean-room receipts.
- Add regression coverage for both the successful canonical receipt and a zero-exit
  subprocess that writes a non-verified result.

## 1.8.21

- Keep the complete clean-room verification receipt in a durable disposable-home file while
  emitting only a bounded summary through the supervised process transcript.
- Validate the durable verification receipt before accepting a clean-room run, preserving the
  existing transcript limit and fail-closed release behavior.
- Add regression coverage proving a successful exact-cut verification cannot be rejected merely
  because its complete JSON receipt exceeds the bounded supervisor transcript.

## 1.8.20

- Add typed Proofline intent atoms that bind exact owner-request spans to work orders,
  verification recipes, evidence, and completion outcomes.
- Reject semantic completion when required proof is missing, stale, wrong-subject, contradictory,
  or unable to trace back to the authorized owner intent.
- Add bounded owner-facing status, explanation, and completion messages that identify the concrete
  result and one plain-language next action without exposing internal lifecycle jargon by default.
- Preserve continuation authority across completion, cancellation, timeout, reopening, recovery,
  and replay while keeping verification execution subject-bound and reproducible.
- Normalize executable identities in verification recipes across POSIX symlink layouts so hosted
  Linux and macOS verification agrees with the canonical runtime command.

## 1.8.19

- Preserve explicit planning intent in long natural-language requests whose prohibitions only
  restrict implementation, publication, deployment, or external access.
- Support bounded planning in clean Git-less projects and carry large plan frontiers without
  truncating their planning method or work-order contract.
- Observe large and ignored project content through bounded world-state evidence instead of
  recursively hashing unrelated workspace copies.
- Keep explicit no-project-write planning requests free of project-local lifecycle metadata.
- Add a deterministic truth-authority radar for stale, contradictory, or wrong-subject evidence.

- Treat healthy nested Git worktrees as independently registered project boundaries and return a
  bounded partial planning observation, without implementation authority, when large ignored local
  directories or complete content hashing cannot be resolved safely.

## 1.8.18

- Preserve signed upgrade compatibility with active runtimes that predate activation-set
  owner-vault resolution, while continuing to use the active runtime as the incoming
  package's trust anchor.
- Reject a malformed trusted owner-vault resolver instead of falling back silently.

## 1.8.17

- Keep the repository-pinned Rust toolchain declaration in the public cut so
  detached clean-room verification selects the same compiler as source and
  native compatibility CI.
- Add a regression assertion that release construction cannot silently omit
  the toolchain authority required by the shipped Rust helper.

## 1.8.16

- Publish the Phase 1–2 control-plane remediation merged through PR #32, including stricter
  routing, lifecycle authority, recovery, path authorization, semantic parity, and
  generated-evidence enforcement.
- Include the public documentation and GitHub Pages refresh merged through PR #33.
- Bind the release to the exact protected `main` commit, six reproducible native helpers,
  threshold-signed package metadata, an SSH-signed immutable tag, and release-subject checksums.
- Keep the machine-authoring tool visible in Codex by advertising a compact, host-portable MCP
  schema. The semantic draft remains bounded strict JSON and is still validated against Loom's
  complete installed plan-draft schema before any planning file is written.
- Add a discovery-budget regression that prevents one oversized tool schema from being silently
  omitted by a real host while the rest of Loom appears healthy.

## 1.8.11

- Refresh the release-maintainer observation of the installed Codex CLI and plugin command surface
  before its evidence deadline. The signed-release gate continues to fail closed when any
  time-bounded operational fact is stale.

## 1.8.10

- Refuse to invent a project type for an underspecified small planning request.
  Loom now returns one bounded scope question without creating a plan pack or escalating a
  placeholder request into unknown-domain planning.
- Add a closed plan-draft schema and machine-owned `loom.author` operation that renders, validates,
  lints, and atomically activates a complete planning pack. Invalid candidates never replace a
  previously valid pack, including across interrupted activation and recovery.
- Accept Codex's valid MCP metadata and omitted zero-argument payloads while preserving closed
  per-tool argument validation, eliminating false `-32602` failures for compatible clients.
- Convert bootstrap failures into bounded MCP errors instead of closing the transport, and preserve
  skill-link plus `/loom` invocation wrappers only in the sealed request while excluding them from
  intent, domain, and placeholder classification.
- Make the enabled plugin the one canonical Codex skill and MCP route. Approved migration retires
  only exact receipt-owned legacy routes, is resumable after interruption, and blocks changed,
  unowned, incomplete, or ambiguous duplicates.
- Consolidate repeated lint and gate diagnostics so a failed pack reports each actionable defect
  once, while retaining the original fail-closed enforcement.
- Make the canonical Codex skill a bounded, self-contained dispatcher that does not reread the
  non-Codex kernel during each invocation. Ordinary planning now uses one invoke call and one
  combined author-and-finalize call while preserving the backward-compatible separate completion
  path.
- Publish explicit invariant-type guidance for unknown-domain authoring. Repository-defined
  side-effect constraints remain correctness rules; safety and regulatory classifications still
  require their pre-existing governing authority and fail with field-specific diagnostics.

## 1.8.9

- Make Codex MCP startup robust when its bundled Python runtime omits platform probe values, while
  retaining fail-closed behavior for explicit unsupported operating systems and architectures.
- Replace oversized Verified hook payloads with a compact request-bound action receipt and a
  read-only `loom.resolve` MCP operation that rechecks action integrity, request identity,
  installation authority, expiry, active state, and current project world before returning the
  public planning frontier.
- Resolve the plugin root deterministically from the installed skill path and enforce one shared
  hook deadline, preventing missing-kernel lookups, duplicate invocation, and compounded timeout
  budgets.
- Add clean-host, transport, tampering, drift, platform-fallback, request-identity, and compact-hook
  regressions for the complete Codex integration path.

## 1.8.8

- Install the stable launcher from the newly verified runtime in a clean process after activation,
  so newly introduced launcher dependencies cannot be omitted by a previous runtime's stale
  adapter module.
- Add a regression that poisons the pre-update adapter import and proves the candidate runtime
  still installs every receipt-bound launcher dependency and produces an importable launcher.

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
- Generate release evidence from exact subjects, add body-free local diagnostics, and add an
  explicitly encrypted support export.

## 1.6.0

- Add deterministic, subject-bound evaluation records that reject stale, altered, duplicate, or
  wrong-subject evidence.
- Bind local evaluation evidence to the exact source tree and observed tool artifacts.

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

Release claims remain bound to their declared evidence class and exact release subject.
