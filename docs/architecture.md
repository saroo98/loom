# Loom 1.6.0 advanced architecture

The public surface remains `/loom <request>`. This document describes the internal engine for
maintainers.

## Trust pipeline

`loom_runtime` resolves identity, surveys the world, classifies intent, tier, and domains, then
seals immutable prepared state. `loom_session` serializes one project invocation, selects scoped
memory and preferences, dispatches work, records outcomes, compacts state, and seals a receipt.
`loom_orchestrator` is the installed host-agent bridge. It verifies the installation before every
new action, opens an authenticated session, records the baseline before authoring, supplies the
default production handler registry, and binds completion to one target survey. Its private,
content-hashed action record enforces a 60-to-3600-second deadline, three-attempt retry ceiling,
terminal cancellation, and safe cleanup only when its newly created draft pack is byte-unchanged.
Planning actions also seal a deterministic plan contract: every artifact decision, required domain
invariant/current fact/real medium, an explicitly defined `loom-lexical-v1` token and character
ceiling, work-order topology, allowed host write scope, and the pre-authoring pack identity.
Plan-contract v3 also seals a bounded planning-intelligence graph. Seven declarative specialist
modules may emit typed atoms only from active task evidence; source material and ambient repository
signals cannot activate them. Every atom is linked to its module digest and evidence edge, and the
Tier-S projection retains only the relevant bounded obligations. Incident, maintenance, milestone,
resume, and selective re-gating helpers use closed state transitions and content-bound receipts.
Completion rejects omitted, extra, or changed rows and missing contract evidence before G1.
`loom_gate`, `loom_lifecycle`, and `loom_lint` provide chronology, freshness, evidence, and pack
integrity enforcement. A passing G1 must declare an independent reviewer and zero open High
findings; an explicitly author-reviewed plan cannot be sealed or authorized. Any unknown at a
trust boundary is a typed block. Declared independence is mechanically required but remains a
host assertion until an external reviewer adapter supplies independent identity proof.

Real-medium verification commands run against a link-free disposable snapshot of the target, not
the owner's working tree. Any mutation of that snapshot invalidates the evidence and the snapshot
is discarded. The original target is fingerprinted before and after capture so concurrent or
absolute-path interference is still detected. This protects ordinary relative-path verification;
it is not a portable host-level process sandbox, so commands still require the same authority and
care as any executable launched by the agent. Successful evidence receives an identity derived
from its canonical content; changing and re-hashing the content while reusing the ID is rejected.
Repair completion accepts only a schema-v2 verification plan with one bounded command per sealed
plan section. The host cannot submit `passed`, an evidence file, or a digest. Loom executes each
command, stores the minimized transcript and world hashes beside the private action record, and
passes only the derived evidence identity into the regate. This is local execution evidence, not
independent attestation or an OS containment claim.

The world fingerprint treats path, entry kind, regular-file content, symlink target, executable
mode, Git HEAD/branch/index, and staged/unstaged/untracked sets as project semantics. Device and
inode identity, mtimes, ownership IDs, archive/indexing flags, platform attributes, and extended
attributes are used only where needed to detect a mid-read race or unsafe entry. They are not
cross-checkout plan semantics and cannot create false drift after an otherwise identical run.

## Memory boundaries

The encrypted owner vault is the only mutable production learning authority. Schema v3 normalizes
memory items, observations, per-memory effects, preference slots, derivation edges, deletion
commitments, policy evaluations, and scope aliases. Legacy JSON modules are import/test
compatibility only; a missing verified crypto helper blocks production learning instead of
silently creating a second store.

Selection is capped at 4 records and 4,096 characters. Active-task domains are derived from the
request; repository structure is recorded only as ambient evidence and cannot activate domain
memory. General, domain, project, component, temporary, and device scopes have exact filters.
Selection is not application and does not refresh usefulness. Technical facts become
`revalidation-required` at their currentness deadline; inactive ordinary learning becomes dormant
and then archived from actual application/effect history.

Admission requires distinct evidence. General inference needs at least 5 observations spanning
3 projects and 2 domains and is limited to transferable categories. Domain inference needs repeat
support across projects or components. Explicit owner statements apply immediately at the narrowest
unambiguous scope, while concurrent stated conflicts quarantine. Autonomy, hard stops, privacy,
deletion, spending, destructive action, legal authority, and safety authority are never inferred.

## Comparative Improvement Proof

Production attribution records selected-only, applied-unverified, verified-helped, verified-hurt,
verified-neutral, ambiguous, and rejected-before-use separately for each memory. Session success
never credits every selected record. Severe verified harm quarantines immediately.

Improvement reports use explicit evidence states and time-uniform confidence sequences. One outcome
is `measurement-started`; observational history is `associated-only`; shadow-only comparison is
`structural-counterfactual-only`; randomized evidence requires a prelogged nonzero propensity.
Every calculation requires all five token categories plus elapsed time. Missing cost or uncertainty
blocks the claim rather than producing a partial “total.” Accumulation alone never qualifies as
improvement, and independent attestation remains a separate release boundary.

## Release Boundary

`loom_release` creates a new destination from a positive allowlist, rejects links and non-regular
entries, scans every output byte and filename through UTF-8/UTF-16 views, refuses unsupported opaque
binary/container formats, and emits a deterministic manifest. Private-owner mode requires at least
one configured token to occur in source material excluded by the positive allowlist, so a dummy-only
policy fails instead of claiming protection. Public-release scan mode explicitly reports that it
does not attest private-source grounding. `verify-cut` independently validates the exported
manifest, rejects undeclared files, runs the cut's suite with bytecode disabled, and repeats the
firewall after validation without requiring Git metadata. `loom_install` installs only into a new directory,
checks receipt-proven hashes, and uninstalls only an unchanged owned set. `loom_release certify`
accepts only fresh, content-bound local evidence for one clean GitHub commit plus fresh external
evidence signed by independently provisioned RSA trust roots. External evidence IDs are derived
from the complete unsigned claim content, must be unique, and cannot be reused for changed content;
every subject must match the exact repository, commit, and public-build hash. Cross-platform evidence must
contain the exact 3-OS by 4-Python matrix; usability must bind clean-environment install and real-
request receipts; hostile review must bind a complete independently reproduced report. It cannot
award 100 unless local checks and all 5 signed external evidence contracts pass. The local
`performance_contracts` check proves only deterministic cache, context, and fixture-budget
invariants. Production actions additionally seal the hashes and byte counts of the exact two static
guidance files, while session receipts can retain provider/model/response/hash provenance for all
five token categories. Neither a caller total nor a local provider receipt substitutes for the
separate independently attested production-performance or production-memory-replay records.

## Runtime and owner vault

The stable launcher under `~/.loom/bin` verifies one immutable runtime manifest and pins a session
to that runtime generation. Marketplace payloads stage beside the active runtime; threshold-signed
metadata, exact hashes, semantic inventory comparison, and a disposable request must all pass
before the pointer changes. A failed or repeatedly unhealthy runtime rolls back to the prior
receipt-owned version.

Mutable owner intelligence lives in an encrypted SQLite vault outside the plugin cache. Owner,
device, runtime, and project identities are separate. Memory bodies, preferences, outcomes,
receipts, private adaptations, transfer payloads, and session-journal details are authenticated
ciphertext. Clear database fields are bounded operational indexes and opaque identifiers. A stable
blind-index key keeps scope and deletion-floor commitments comparable when the data key is
rotated. Device revocation stages a complete re-encrypted vault generation, commits the discarded
event history, changes secure-key slots, and activates atomically; an old data key cannot decrypt
the new generation.

Pairing and recovery transfer encrypted checkpoints in bounded authenticated chunks. The recovery
phrase only unlocks an external backup. Signed device deltas merge under entity-specific rules;
forgetting dominates old copies, contradictory stated preferences quarantine, unknown schemas stay
inactive, and materialized state remains bounded. Receipt-owned adapters for supported Agent Skills
locations call the same stable launcher and roll back completely if any adapter write fails.

## Truth surfaces

`docs/capabilities.json` is the claim registry. A mechanical claim names implementation and tests;
otherwise it is explicitly advisory. `tools/loom_docs.py` checks entry-point version agreement,
links, command sprawl, legacy learning claims, and proof paths. `docs/generated-evidence.json` is
regenerated from repository inventory so changing counts cannot leave hand-authored claims behind.

`tools/loom_adaptation_eval.py` runs disposable, deterministic longitudinal scenarios for domain
switches, aging, project alternation, preference drift, scale bounds, interruption, concurrency,
corruption, identity errors, disabled memory, application-level forgetting, and domain coverage. Its
improvement result includes a minimum-sample longitudinal comparison, paired memory replay, and an
independent reproduction, not an assertion that accumulated state helped. Production host outcomes
may attach a same-request/same-world enabled/disabled pair with distinct provider-response receipts
and real-medium evidence. The orchestrator records it in the real improvement store but labels it
as requiring independent attestation; deterministic evaluator pairs never cross that boundary.

## Proportional-performance plane

Usage receipt v3 treats each provider response attempt as an immutable event. The selected
semantics profile determines whether cache, cache-write, reasoning, and tool counters are subsets,
disjoint components, or governed by the provider total. Only formula-complete event sets produce a
processed total. Retry is represented by multiple attempts, not by a second additive token bucket.
The generic profile is partial by construction. Legacy five-field samples retain their prior claim
but have no normalized total.

Tier S keeps the complete plan contract inside the authenticated action and returns a separate
decision-only projection to the host. The projection is digest-bound and capped at 4,096 bytes;
completion still validates against the full artifact matrix, invariant set, facts, media, budget,
and lifecycle. Static runtime prefix identity, volatile action capsules, owner selection, domain
authority, and provider cache evidence have separate keys and invalidation rules. No cache is a
freshness authority.

The local span primitive uses `perf_counter_ns` and bounded numeric counters. Encrypted usage
observations share the owner vault and project/domain scope of the session outcome. The offline
corpus retains failures and environment facts, reports distributions, and never substitutes
synthetic or local measurements for provider certification. Runtime-wide stage-span export and
live host capability negotiation remain outside the mechanically certified surface.

## Adapter protocol v2

Every connected host receives a small, receipt-owned skill file. It contains no planning logic,
memory, migration code, policy, or cached state. It points to the stable user launcher, and the
launcher alone selects the verified runtime and owner vault. An unowned local Loom skill is treated
as a split-brain condition and blocks connection instead of being overwritten or silently used.

The local bridge uses newline-delimited JSON over standard input and output. The message vocabulary,
field sets, depth, byte size, identifiers, protocol range, capabilities, and error codes are closed
and bounded by `schemas/adapter-message.schema.json` and `contracts/adapter-protocol-v2.json`.
Initialization must negotiate protocol 2 before an invocation can reach the launcher. The bridge
does not listen on a network socket and does not expose vault operations.

Host discovery records the exact executable or configuration marker observed. Discovery is not a
support claim. Codex, Claude Code, Gemini CLI, OpenCode, and Copilot currently have
`simulated-conformant` adapter evidence from disposable profiles. Cursor and generic Agent Skills
locations are experimental; Factory Droid is unsupported. None may be described as real-host
verified until an exact host/version invocation produces the required evidence bundle. The complete
status matrix and evidence boundary are in [Integration ecosystem](integration-ecosystem.md).

## Evidence-bound score plane

`contracts/score-rubric-v1.json` is the only scoring authority. Its 17 category weights total
exactly 100, every category's requirements total 100, and changing either is a rubric-version
change. Evidence records contain no free-form points. They can satisfy only one known requirement
using an allowed evidence class, and they bind the subject tree, source artifact, observation time,
expiry, and canonical digest. Duplicate coverage, altered artifacts, wrong subjects, stale records,
and incompatible evidence classes fail the score operation.

Missing evidence is not an execution failure. It remains a named withheld requirement and lowers
the category and overall result. A provided record that is stale, contradictory, or corrupt is an
execution failure because silently ignoring it would make the result ambiguous. Claimed-only
records never earn points. This keeps local deterministic proof separate from matrix reproduction,
real-host use, provider receipts, longitudinal outcomes, independent review, and public adoption.

Competitive snapshots use the same rubric and exact revisions. Unknown categories remain null and
produce lower and upper score bounds; not-applicable categories are explicitly normalized out.
A stale snapshot or a verified score without a primary source is refused. See
[Cross-cutting scoring](cross-cutting-scoring.md).
