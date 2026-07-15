# Owner memory contract

Owner memory is local, optional, bounded, and scoped. It exists to reduce repeated decisions, not
to create a permanent dossier.

## Scopes

- **General:** transferable calibration such as review preference, decision batching, or a
  repeatedly measured estimation bias.
- **Domain:** rules that apply only to one exact domain identifier, such as `accounting` or
  `realtime-3d`.
- **Project:** facts and tactics for one canonical project identity. Git projects derive that
  identity from bounded root lineage plus a hashed origin, while non-Git projects use the local
  filesystem object identity. Renaming or moving the same object does not strand its memory; the
  separate target-path hash still changes so the move remains visible.
- **Install:** operational state for one Loom installation. It never transfers to another install.

Selection uses exact scope matching. A website rule is not loaded for accounting or 3D work.
Project memory is not loaded for another project. General memory must be genuinely domain-neutral.
The storage boundary permits only three inferred general signal/decision pairs:
`confidence-error`/`confidence-calibration`, `decision-delegated`/`delegation-strategy`, and
`question-rejected`/`question-batching`. Every other inferred lesson must name an exact domain.
For a composite request, Loom records outcomes independently for every selected domain. A stack
observation must name which active domain it belongs to; ambiguous or foreign-domain observations
fail before any learning state is written.

## Admission and lifecycle

1. Explicit `Remember ...` statements are stored as stated preferences with provenance.
2. Inferred learning requires evidence, confidence, a future decision it can improve, and a scope.
3. Active selection is capped by tier and intent. Relevance must exceed context cost.
4. Closed or unused project/domain records become dormant, then archive according to the local
   retention policy. Dormant records are not loaded unless the exact domain returns.
5. Superseded preferences retain an audit link but are not selected.
6. `Forget ...` writes a reversible local action receipt and removes the record from selection.
7. `use_profile: false` means no owner-profile selection or learning for that project.

Default domain retirement is automatic and utility-sensitive. A harmful rule is reviewed after
7 inactive days, an unused rule after 14, an applied but unproven rule after 30, a rule helped once
after 90, and a repeatedly helpful rule after 365. Session housekeeping reports the next review
time. Retirement makes a record dormant rather than destroying it, and only bounded exact-domain
rehydration can return it. Mandatory safety hard stops are never retired by inactivity.

Memory never enters the public build, planning pack, git history, telemetry, or another install.
Loom has no network transport for owner memory. Local files may still be exposed by the host OS,
backup software, or an agent with filesystem access; those boundaries are documented rather than
claimed as sandboxing.
