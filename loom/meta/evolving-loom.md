# Evolving Loom — release ritual and FEEDBACK triage

How Loom itself changes. Audience: the agent (or human) preparing the next Loom version.
Loom asks target projects for discipline; this file is the same discipline pointed inward.

## The release ritual (every version, in order)

1. **Triage every active FEEDBACK entry first.** New features wait behind known defects.
   Then run `loom_memory.py compact-feedback --loom-root <loom>`: resolved history and
   active overflow move to the ignored `.loom-private/` archive; the active file remains
   bounded. Never delete or publish the archive.
2. **Plan the release as a Loom exercise.** ROADMAP.md holds the outcome list for the
   version (it is the product plan); a full pack is overkill when planner = implementer =
   same session (tier-M collapse), but the outcomes must be written *before* the building.
3. **Build.**
4. **Mechanical checks green** — all of:
   - `python -m unittest discover -s tools -p "test_*.py"` (includes the end-to-end
     pipeline test and a lint of Loom's own `plans/` pack)
   - `python tools/loom_release_check.py --json` (one version, schema/reference/installer
     coherence) and `python tools/loom_audit.py` (the declared no-network source boundary)
   - `python tools/loom_context.py session-tier-s-core --json` and the relevant M+/UI route
     when context-loading files changed; this reports exact bytes/characters and explicitly
     reports tokenizer/cache fields as unknown unless measured elsewhere
   - `loom_lint` self-fixtures pass (they run inside the test suite)
   - **Do not publish volatile numeric claims in current docs.** If a count or timing is needed
     as evidence, capture the exact command, timestamp, scope, and output in a release-evidence
     record from the same session; never copy it forward as a timeless total.
     *(Correction from data: plans/outcomes.md row "Tests: 43 total" — a memory-composed
     count that was wrong by 8; caught pre-commit at v0.4.)*
5. **Battery on the diff.** Contradiction scan between changed and unchanged files is the
   highest-yield pass — new capabilities silently invalidating old text is Loom's own
   biggest defect class (both 0.1 and 0.2 shipped fixes caught exactly there).
6. **Version mechanics:** update the single machine-readable `VERSION`; add the CHANGELOG entry;
   teach `loom_migrate` the prior-version transition; and update ROADMAP statuses honestly —
   including scores that went *down*. `loom_release_check` must prove every template, schema,
   entry point, and installed rendering agrees with `VERSION`; no hand-stamped second source.
7. **Prepare shipping, but do not ship without explicit owner authority.** Run
   `python tools/loom_publish.py --check` to build and test the ownership-marked versioned public
   output. After an owner-authorized local install, run `tools/install.ps1 -Check` or
   `tools/install.sh --check`. Commit, push, publication, and deployment are separate deliberate
   owner actions; none is implied by this ritual or by a clean build.

## FEEDBACK triage playbook

For each entry, classify and act — every entry gets exactly one resolution, appended under
the entry itself (never delete the entry):

| Class | Meaning | Action |
|---|---|---|
| **guidance-bug** | Loom said something wrong or self-contradictory | Fix the file; add the case to examples if it generalizes |
| **missing-coverage** | A real situation no file addresses | Smallest fix that covers it: a section > a new file > a new subsystem |
| **over-prescription** | Loom's rule fought correct judgment | Relax to default+trigger form; check siblings for the same rigidity |
| **tooling-bug** | lint/survey/kickoff/migrate/report/guard misbehaved | Fix + regression test in the same change |
| **wontfix** | Cost exceeds benefit, or violates a principle | Say why under the entry — an unexplained rejection will be re-filed |
| **noise** | No actionable value | One-word close: `✔ <date> noise` — fast and blame-free |

Two entries pointing at the same file from different projects = priority, regardless of
class. Contributions arrive only through explicit owner action and contain controlled
pattern/action values. Triage still judges value, keeps the active queue lean, and compacts
resolved history. One entry contradicting a core principle = suspect the entry first, the principle
second — but actually check.

## Sovereign divergence (D-012)

Every Loom install runs this ritual on **its own** FEEDBACK queue. The ignored installation
UUID binds its outbox and private archive; a different receiver UUID is mechanically refused.
Domain/project memory remains in typed per-instance stores and never becomes a core chapter
without deliberate authored work. Upstream releases are optional owner-requested imports;
automatic fetch/pull is forbidden.

## Rules for changing Loom

- **Core files move slowly.** `core/` changes ripple into every future pack; they need the
  battery run against the *whole* repo, not just the diff.
- **Never break the five labels or the pack layout without a migration.** Packs in the
  wild depend on both; `loom_migrate` carries them forward.
- **Deletions are allowed and healthy.** Guidance nobody's packs ever used is a context
  tax. The artifact-must-have-a-consumer principle applies to Loom's own files.
- **Scores are re-derived, not incremented.** Each release re-scores the ROADMAP category
  table against the 100-definitions; ratchet thinking ("we did work, so +10") is exactly
  the calibration failure Loom exists to prevent.
- **Don't grow the kernel.** START-HERE stays readable in one sitting; new capability gets
  a pointer there, never a chapter.
