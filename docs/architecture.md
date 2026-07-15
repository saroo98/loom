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
`loom_gate`, `loom_lifecycle`, and `loom_lint` provide chronology, freshness, evidence, and pack
integrity enforcement. Any unknown at a trust boundary is a typed block.

## Memory boundaries

`loom_memory` separates install, global, domain, and project partitions. Selection has a hard byte
budget and exact domain/project filters. Lifecycle maintenance archives closed project material,
makes unused domain material dormant, and admits it again only through bounded rehydration.
Content-erased tombstones prevent forgotten semantics from silent readmission.

`loom_preferences` separates transferable preferences from domain stacks and task/risk autonomy.
Observed preferences require repeated cross-project evidence; a stated preference takes precedence.
`loom_learning` keeps bounded events and evidence-linked candidates. It is local state, not a
network contribution mechanism.

## Comparative Improvement Proof

`loom_improvement` records controlled measurements automatically from sealed sessions. It keeps
8 early and 8 recent samples per exact metric/domain partition, caps the active record window, and
never combines domains. A claim needs 16 longitudinal samples plus 8 paired memory-enabled and
memory-disabled replays. `loom_improvement_audit` independently reimplements the calculation,
checks the evidence hash, and rejects altered claims. Regressions raise an alarm; accumulation alone
never qualifies as improvement.

## Release Boundary

`loom_release` creates a new destination from a positive allowlist, rejects links and non-regular
entries, scans every output byte and filename, and emits a deterministic manifest. It will not build
without explicit private/owner firewall tokens. `loom_install` installs only into a new directory,
checks receipt-proven hashes, and uninstalls only an unchanged owned set. `loom_release certify`
accepts only fresh, content-bound local evidence for one clean GitHub commit plus fresh external
evidence signed by independently provisioned RSA trust roots. Evidence IDs must be unique and every
subject must match the exact repository, commit, and public-build hash. It cannot award 100 unless
local checks and all 3 signed external evidence contracts pass.

## Truth surfaces

`docs/capabilities.json` is the claim registry. A mechanical claim names implementation and tests;
otherwise it is explicitly advisory. `tools/loom_docs.py` checks entry-point version agreement,
links, command sprawl, legacy learning claims, and proof paths. `docs/generated-evidence.json` is
regenerated from repository inventory so changing counts cannot leave hand-authored claims behind.

`tools/loom_adaptation_eval.py` runs disposable, deterministic longitudinal scenarios for domain
switches, aging, project alternation, preference drift, scale bounds, interruption, concurrency,
corruption, identity errors, disabled memory, permanent forgetting, and domain coverage. Its
improvement result includes a minimum-sample longitudinal comparison, paired memory replay, and an
independent reproduction, not an assertion that accumulated state helped.
