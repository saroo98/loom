# Evolving Loom — release ritual and FEEDBACK triage

How Loom itself changes. Audience: the agent (or human) preparing the next Loom version.
Loom asks target projects for discipline; this file is the same discipline pointed inward.

## The release ritual (every version, in order)

1. **Burn down FEEDBACK.md first.** New features wait behind known defects — a planning
   system that ignores its own bug reports teaches agents to do the same. Triage per the
   playbook below until the queue is empty (fixed, or rejected-with-note).
2. **Plan the release as a Loom exercise.** ROADMAP.md holds the outcome list for the
   version (it is the product plan); a full pack is overkill when planner = implementer =
   same session (tier-M collapse), but the outcomes must be written *before* the building.
3. **Build.**
4. **Mechanical checks green** — all of:
   - `python -m unittest discover -s tools -p "test_*.py"` (includes the end-to-end
     pipeline test and a lint of Loom's own `plans/` pack)
   - every schema parses; internal reference sweep finds zero broken paths
   - `loom_lint` self-fixtures pass (they run inside the test suite)
   - **Numeric claims in CHANGELOG/README (test counts, file counts) are quoted from
     command output captured in the same session — never composed from memory.**
     *(Correction from data: plans/outcomes.md row "Tests: 43 total" — a memory-composed
     count that was wrong by 8; caught pre-commit at v0.4.)*
5. **Battery on the diff.** Contradiction scan between changed and unchanged files is the
   highest-yield pass — new capabilities silently invalidating old text is Loom's own
   biggest defect class (both 0.1 and 0.2 shipped fixes caught exactly there).
6. **Version mechanics:** CHANGELOG entry; template `loom_version` stamps bumped;
   `loom_migrate` (v0.4+) taught the migration from the previous version; ROADMAP statuses
   updated honestly — including scores that went *down* on re-assessment.
7. **Ship** (commit, push — the upstream repo stays private), then reinstall the skill
   if it changed (`tools/install.ps1` / `install.sh`). Owners who maintain a public cut:
   `python tools/loom_publish.py --check` must build clean (firewall, links, suite in
   the output tree) before any push to the public artifact — and that push is always a
   deliberate human act, never part of this ritual.

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
| **noise** | No actionable value (auto-contributed era, D-010) | One-word close: `✔ <date> noise` — fast and blame-free; the filter lives here by design |

Two entries pointing at the same file from different projects = priority, regardless of
class. Since contributions arrive unattended (D-010), triage is also the **value filter**:
judge every entry, keep FEEDBACK lean, and enforce the compact format — rewrite bulky
entries down at triage rather than letting clutter compound. One entry contradicting a core principle = suspect the entry first, the principle
second — but actually check.

## Sovereign divergence (D-012)

Every Loom install runs this same ritual on **its own** FEEDBACK queue. Instances diverge
by design: your Loom accretes your domain chapters, your calibration, your triage
judgments — a year in, two Looms should look meaningfully different, and that is success,
not drift. Nothing flows between instances: no central queue, no upstream channel.
Upstream releases (if your install descends from a published cut) are optional imports —
cherry-pick what serves you; never treat divergence from upstream as breakage.

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
