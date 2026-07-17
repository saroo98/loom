# Phase 7 Validation Protocols

Phase 7 separates engineering capability from evidence that only another environment, provider,
reviewer, participant, marketplace, or public population can produce. Missing external evidence is
reported as **[UNVERIFIED]**. It is never simulated into a higher evidence class.

## Clean-room evaluation

- Freeze the exact release subject before tasks are selected.
- Use a new VM, hosted runner, or disposable OS account containing only the immutable public cut
  and neutral task fixtures. Exclude the developer repository, `.git`, real owner vault, cached
  skills, prior chats, credentials, expected outputs, and mounted maintainer home directories.
- Predeclare tasks, randomization seed, model/settings, allowed tools, timeouts, reruns, exclusions,
  metrics, stop rules, and analysis. Store that preregistration outside the evaluated artifact.
- `tools/loom_clean_room.py` proves a bounded disposable-home verification run. It is
  `mechanical-local`, not independent, and does not claim network isolation.
- An internal evaluator must label results `blinded internal`. Only an outside evaluator with a
  disclosed independence statement may issue `independently-witnessed` evidence.

## Unfamiliar-user study

Before recruiting, obtain a written ethics determination for the chosen jurisdiction, participant
population, compensation, and publication intent. Predefine installation, invocation, intervention,
receipt comprehension, recovery, abandonment, unsafe-action, help-request, time, and quality
metrics. Randomize comparable Loom and no-Loom tasks. Publish the protocol, anonymized aggregates,
analysis code, environment manifests, deviations, exclusions, and severe-safety stop events.

The implementer cannot award `independent-external`. A complete study receipt must identify the
exact release digest, participant counts and exclusions, evaluator independence, protocol digest,
analysis digest, deviations, and retention policy. One successful participant is useful formative
evidence but is not a population claim.

## Independent audits

Procure two independently staffed workstreams:

1. Rust cryptography, key management, signatures/provenance, vault metadata, pairing, backup, and
   recovery.
2. Hostile systems, supply chain, updater/installer, adapter precedence, migration/state,
   publication firewall, and exact release verification.

The statement of work must name the source commit, public cut, canonical ZIP, helper and SBOM
digests, release verifier, workflows, evidence graph, capability registry, update/migration/
rollback paths, vault protocol, threat model, severity system, conflicts, confidential annex,
public summary, and mandatory Critical/High retest. Release certification requires zero unresolved
Critical or High findings against the final digest.

## Marketplace and adoption

Marketplace approval and delivery are external. After approval, verify the exact delivered package
in clean Codex App, CLI, and IDE profiles, then compare manifest version, package digest, public-cut
root, helper digest, launcher route, installation identity, firewall manifest, and first invocation
with the frozen release subject. A verifier delivered in the first package cannot independently
prove the marketplace that delivered it; subsequent updates can use the prior trusted root.

Adoption evidence is separate from engineering quality. Public repository, release, or marketplace
aggregates must include source, collection time, and limitations for bots, mirrors, CI, caching,
repeat downloads, and inactive installs. Loom performs no automatic analytics request. A private
success receipt may be shared only through an explicit owner request and must contain no stable
owner, device, project, or installation identifier.

## Open decisions and external blockers

- Non-Codex host contracts remain **[UNVERIFIED]** until their current official discovery,
  precedence, headless invocation, and teardown behavior is recorded and expires normally.
- Native CI runner availability and helper byte identity remain **[UNVERIFIED]** until the workflow
  runs twice on each target.
- Provider model, pricing, region, privacy mode, retention, raw fields, sample size, and pilot budget
  must be selected at run time. Paid evidence runs require explicit authorization.
- Tier-S margins and budgets come from preregistered pilots and power analysis, not source-code
  constants.
- Auditor, ethics, recruiting, compensation, domain reviewers, holdout custodian, replication
  partner, marketplace approval, and adoption observations require owner or external coordination.
