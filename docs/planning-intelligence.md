# Planning intelligence contract

Loom keeps one visible surface, `/loom <request>`. Phase 8 adds internal declarative planning
transformers rather than new commands, personas, or agent roles.

## What is mechanically enforced

- Request paths, report titles, and clauses that only identify material to read cannot activate a
  project domain or specialist concern.
- Repository structure is ambient evidence. It may corroborate a domain already named by the active
  request, but it cannot activate one by itself.
- Multi-phase planning plus implementation cannot use the single-outcome Tier-S path.
- Every plan contract carries seven universal lenses: outcome, scope, epistemics,
  consequence/reversibility, dependencies, real-medium acceptance, and release/rollback.
- Specialist modules are closed, immutable JSON. They can emit bounded typed planning atoms but
  cannot execute commands, browse, write project files, change owner state, or authorize work.
- Inactive modules emit no atoms. Tier S allows at most two active modules and eight atoms. Deeper
  plans allow at most seven modules and 24 atoms.
- Every atom is content-bound to its module version and source evidence. Missing provenance edges or
  semantic mutation invalidates the sealed planning-intelligence digest.
- M/L/XL packs persist the exact sealed `plan-contract.json` and a content-bound
  `planning-obligations.json`. Every active obligation is assigned exactly once to one work order
  and one milestone with its structured observation, oracle, evidence, rollback, and freshness
  contract. Lint rejects changed verification text even when an attacker recomputes the sidecar hash.
- Conflict handling automatically chooses a stricter result only for a proved monotone interval,
  set, or retention rule in the same scope. Authority, jurisdiction, intent, current facts, and
  incompatible rules block for the appropriate decision or evidence.
- Incident containment can precede a full remediation plan only when it is reversible. Destructive
  remediation requires explicit authority and preserved evidence.
- Milestone drift re-gates the directed dependency closure and produces an isolation proof for
  unaffected accepted work.
- The release-blocking evaluation includes ordinary, composite, source-material, quoted-example,
  negation, non-software, incident, maintenance, known-domain, and unknown-domain holdouts. Any
  harmful specialist activation, unsafe authorization, provenance loss, or stale-fresh claim fails.

## Internal modules

| Module | Loads when | Main obligation |
|---|---|---|
| outcomes-requirements | Multiple or release-scale outcomes | Trace outcomes to work and observable acceptance |
| interaction-accessibility | A real interactive, visual, audio, spatial, mobile, desktop, or web target exists | Define material states and current accessibility facts |
| architecture-boundaries | A consequential boundary or deep plan exists | Record bounded alternatives and reopen conditions |
| security-privacy-safety | Trust, sensitive data, destructive effect, public exposure, or physical consequence exists | Declare authority and require real controls |
| verification-evidence | Every plan, minimally | Bind risks to observation, oracle, environment, evidence, and recovery |
| reliability-operations | Durable/operated state or explicit reliability work exists | Model partial failure, recovery, and ownership unknowns |
| migration-release | Compatibility, migration, rollout, rollback, or release-scale work exists | Bind compatibility and release gates to exact evidence |

The module split is an engineering policy, not a claim that seven is universally optimal. Loom can
measure overlap and revise the versioned catalogue without changing the owner-facing command.

## What is not claimed

These contracts do not certify professional competence, regulatory compliance, current platform
truth, population-level routing accuracy, human plan usefulness, or generalization to every unseen
domain. Current laws, standards, APIs, and platform behavior still require fresh authoritative
evidence. Unknown high-consequence coverage remains blocked.

## Source of truth

- `contracts/planning-intelligence-v1.json`
- `loom/specialists/catalog.json`
- `schemas/planning-intelligence.schema.json`
- `tools/loom_planning_intelligence.py`
- `tools/loom_program.py`
- `tools/loom_planning_eval.py`
- `tools/test_planning_intelligence.py`
- `tools/test_planning_program.py`
