# Owner memory contract

Owner memory is local, optional, bounded, and scoped. It exists to reduce repeated decisions, not
to create a permanent dossier.

## Scopes

- **General:** transferable calibration such as review preference, decision batching, or a
  repeatedly measured estimation bias.
- **Domain:** rules that apply only to one exact domain identifier, such as `accounting` or
  `realtime-3d`.
- **Project:** facts and tactics for one canonical project identity.
- **Install:** operational state for one Loom installation. It never transfers to another install.

Selection uses exact scope matching. A website rule is not loaded for accounting or 3D work.
Project memory is not loaded for another project. General memory must be genuinely domain-neutral.

## Admission and lifecycle

1. Explicit `Remember ...` statements are stored as stated preferences with provenance.
2. Inferred learning requires evidence, confidence, a future decision it can improve, and a scope.
3. Active selection is capped by tier and intent. Relevance must exceed context cost.
4. Closed or unused project/domain records become dormant, then archive according to the local
   retention policy. Dormant records are not loaded unless the exact domain returns.
5. Superseded preferences retain an audit link but are not selected.
6. `Forget ...` writes a reversible local action receipt and removes the record from selection.
7. `use_profile: false` means no owner-profile selection or learning for that project.

Memory never enters the public build, planning pack, git history, telemetry, or another install.
Loom has no network transport for owner memory. Local files may still be exposed by the host OS,
backup software, or an agent with filesystem access; those boundaries are documented rather than
claimed as sandboxing.
