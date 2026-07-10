# User memory — Loom learns each user, privately

The per-user layer: Loom's memory of *how this human works*, accumulated across all their
projects and applied everywhere, silently. It is the personal half of the two-tier learning
loop (`loom/meta/plan-learner-public.md`); the global half stays FEEDBACK + releases.

**The commitments come first:** everything here is plain files on the user's machine, in
`~/.loom/`. The user can read, edit, or delete any of it. Nothing leaves the machine —
`/loom contribute` moves patterns between two private locations on the same machine (user
home → the FEEDBACK queue of *your own* Loom repo, the one `$LOOM` points at), automatically
(D-010; D-012 — every Loom install is owner-operated, so this never crosses to anyone
else's Loom). There is no telemetry, and there never will be.

## Layout — `~/.loom/`

| File | Holds | Written by |
|---|---|---|
| `profile.md` | Standing preferences: autonomy default, routing roster, languages/locales, standing hard-stops, report taste, stack tastes | retro + `/loom profile set` (+ hand-editing, always allowed) |
| `calibration.md` | Cross-project reality data: confidence-vs-outcome by claim class, routing hit-rates, tier/size estimate accuracy, recurring failure shapes | retro (append-mostly) |
| `projects.md` | Pointer index only: project → pack path, status, last retro date | plan + retro |
| `feedback-outbox.md` | Anonymized lesson-shapes queued for Loom-core contribution | retro; drained by `/loom contribute` |

Templates: `templates/user-home/`. First run of any `/loom` command may create the
directory from templates (that act is loggable, not silent — say "created ~/.loom" once).

## The seven rules (each earned; violating any is a FEEDBACK-worthy defect)

1. **Background aggregation, not live mutation.** The user home updates at retro and
   aggregation moments only — never mid-work-order. During work, the pack is the sole
   authority; memory writes wait for the reflective moments.
2. **Relevance-gated defaults, never overrides.** The profile tunes *defaults*. Full
   precedence: **session words > loom.config.json > profile > Loom defaults.** The profile
   never overrides project facts, repo conventions, or anything the requester said —
   in-session words always win.
3. **Silent application.** Never narrate the mechanism: no "per your profile…", no
   "I see from your calibration…", no "as you usually prefer…". Preferences surface as
   good defaults, full stop. If the user asks *why* a default, answer honestly with the
   pointer (`~/.loom/profile.md`, line such-and-such).
4. **Must-actually-write.** "Remember that I…" / "forget the…" MUST produce a real file
   edit before it is acknowledged — acknowledging without writing is lying. The verbs are
   `/loom profile view | set | forget`, and prose requests count the same as verbs.
5. **Sensitivity floor.** Work preferences only. Never: personal attributes, health,
   relationships, moods, secrets (privacy rule 2 applies to memory too), or anything whose
   presence in the file would embarrass the user if read aloud. When in doubt, it stays out.
6. **Staleness on recall.** Profile entries are `[ASSUMPTION]`-class at read time, with the
   file as basis. If the current repo contradicts the profile ("prefers pnpm" but this repo
   uses npm), **the repo wins**, silently; the retro may note the exception. Calibration
   entries carry dates; old entries decay in weight, and the aggregation may retire them.
7. **The off switch is absolute.** `use_profile: false` in the project's loom.config.json,
   or `--no-profile` on any invocation → Loom runs fully stateless: no reads, no writes,
   no outbox entries from that session. No degraded mode, no nagging.

## What flows where (tier boundaries)

- **Retro → profile/calibration (Tier 1):** what the run revealed about *the user* —
  preferences confirmed or contradicted, estimate accuracy, which question styles they
  answered vs ignored. Project-specific facts stay in the project's pack.
- **Retro → outbox (Tier 2 candidate):** project-independent lesson-shapes only, written
  anonymized at capture time (no project names, no paths, no domain nouns) — the same
  standard as FEEDBACK entries.
- **`/loom contribute`:** drains the outbox into the FEEDBACK queue of *your own* Loom
  repo and empties it. **Automatic** at the end of bare `/loom` runs (D-010; kept for
  everyone by D-012 — every install is owner-operated, so unattended contribute never
  crosses an ownership boundary). The mechanical gates are the anonymization sniff
  (lint W21) and the compact 3-line entry format; the *value* judgment happens at
  triage, which may mark entries noise without ceremony. The gates stay even though the
  flow is local, because an owner may choose to make their Loom repo public.

## Entry shapes (keep them boring)

`profile.md` — one keyed line per preference, dated, with provenance:

```markdown
- autonomy_default: A2                     # set 2026-07-10, source: stated
- languages: fa, en                        # set 2026-07-10, source: observed (2 projects)
- hard_stop: never touch live trading accounts   # set 2026-07-10, source: stated
```

`calibration.md` — dated append-mostly observations with counts, not adjectives:

```markdown
- 2026-07-10 | tier estimates: 2/2 held at planned tier (n=2, small sample)
- 2026-07-10 | author maturity-confidence ran ~30pts hot across v0.2–v0.5 (source: Loom self-pack outcomes)
```

Provenance values: `stated` (user said it — strongest), `observed (n projects)` (pattern),
`inferred` (weakest; two contradictions retire it).

## Lint

`loom_lint.py --home [path]` checks the user home: files parse, entries carry dates and
provenance, secret scan (E12) runs on every file, outbox entries pass the anonymization
sniff (project-name-shaped tokens flagged). Run it whenever something feels off; retro
runs it automatically after writing.
