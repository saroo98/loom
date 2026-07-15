# Loom 1.0.0 advanced architecture

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

`loom_memory` separates install, global, domain, and project partitions. Selection has a hard byte
budget and exact domain/project filters. Lifecycle maintenance archives closed project material,
makes domain material dormant on utility-sensitive 7/14/30/90/365-day inactivity bands, reports
the next automatic review, and admits it again only through bounded exact-domain rehydration.
Content-erased tombstones prevent forgotten semantics from silent readmission.

`loom_preferences` separates transferable preferences from domain stacks and task/risk autonomy.
Observed preferences require repeated cross-project evidence; a stated preference takes precedence.
`loom_learning` keeps bounded events and evidence-linked candidates. It is local state, not a
network contribution mechanism. Its storage boundary admits only the controlled transferable
general pairs for confidence calibration, delegation strategy, and question batching; domain
semantics cannot be relabeled as global. Composite sessions write separate outcomes, utility,
signals, and stack observations for every active domain, and reject ambiguous stack attribution
before any learning write.

## Comparative Improvement Proof

`loom_improvement` records controlled measurements automatically from sealed sessions. It keeps
8 early and 8 recent samples per exact metric/domain partition, caps active records, partitions,
evidence identities, and serialized bytes, and never combines domains. Evidence identifiers are
bound permanently to a canonical measurement hash even after the active record is compacted.
Legacy stores whose compacted identities cannot be reconstructed are reset as untrusted proof and
their discarded count is retained; old evidence is never silently credited. A reproducible local
comparison needs 16 longitudinal samples plus 8 paired memory-enabled and memory-disabled replays.
`loom_improvement_audit` independently reimplements the calculation, checks the evidence hash, and
rejects altered claims. Regressions raise an alarm; accumulation alone never qualifies as
improvement. Local evidence is always labeled `local-unattested` and cannot authorize a production
improvement claim; only the independently signed release evidence contract can cross that boundary.

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
invariants. It never substitutes for the separate provider-attested production-performance or
production-memory-replay records.

## Truth surfaces

`docs/capabilities.json` is the claim registry. A mechanical claim names implementation and tests;
otherwise it is explicitly advisory. `tools/loom_docs.py` checks entry-point version agreement,
links, command sprawl, legacy learning claims, and proof paths. `docs/generated-evidence.json` is
regenerated from repository inventory so changing counts cannot leave hand-authored claims behind.

`tools/loom_adaptation_eval.py` runs disposable, deterministic longitudinal scenarios for domain
switches, aging, project alternation, preference drift, scale bounds, interruption, concurrency,
corruption, identity errors, disabled memory, permanent forgetting, and domain coverage. Its
improvement result includes a minimum-sample longitudinal comparison, paired memory replay, and an
independent reproduction, not an assertion that accumulated state helped. Production host outcomes
may attach a same-request/same-world enabled/disabled pair with distinct provider-response receipts
and real-medium evidence. The orchestrator records it in the real improvement store but labels it
as requiring independent attestation; deterministic evaluator pairs never cross that boundary.
