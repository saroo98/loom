# Privacy

## The commitments

1. **Zero telemetry, forever.** Loom sends nothing anywhere: no usage data, no crash
   reports, no analytics, no "anonymous statistics". This is a design commitment, not a
   current limitation — a future version that phones home would not be Loom.
2. **The learning loop is local.** Loom learns its owner through two file locations:
   `~/.loom/` (your profile and calibration) and your Loom repo's `FEEDBACK.md`. Both are
   plain files you can read, edit, or delete. Nothing about you exists anywhere else.
3. **No central collection.** There is no upstream queue, no shared improvement channel,
   no contribution pipeline to this or any other repository. Every install is sovereign.

## The proof

Don't trust the statement — check it:

```bash
grep -rn "http\|socket\|urllib\|requests" tools/*.py
```

The tools are standard-library Python with no network code. The only network activity in
the whole system is `git fetch`/`pull`/`push` against remotes **you** configured, run by
the skill's freshness pulse (ff-only, never merges, skippable) and by you.

## What Loom itself considers private

Loom plans real projects, and plans reveal strategy. Its own rules
([`loom/core/privacy.md`](loom/core/privacy.md)) therefore treat every planning pack as
private: packs stay out of public repos (or in verified-ignored directories), secrets
never appear in plans even as examples, and the linter scans for secret-shaped content
(E12) and identifying tokens in anything queued by the learning loop (W21) on every run.

## If you make your Loom repo public

Your call — it's your Loom. The mechanical gates exist for exactly this case: FEEDBACK
entries are written as anonymized lesson-shapes (no project names, no paths, no domain
nouns), the outbox anonymization sniff flags violations before they land, and your packs
and `~/.loom/` are never part of the Loom repo anyway.
