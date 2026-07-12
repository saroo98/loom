# User memory — scoped, bounded, sovereign

Loom may learn how its owner works, but only through `tools/loom_memory.py`. Raw Markdown
profiles are legacy input, not active memory. An agent MUST NOT read `~/.loom/profile.md`,
`calibration.md`, `projects.md`, or `feedback-outbox.md` into context.

## Guarantees and their enforcement

| Guarantee | Mechanical control |
|---|---|
| Install isolation | Each Loom root has an ignored `.loom-instance-id` UUID. State lives only under `~/.loom/instances/<that UUID>/`; every store and contribution carries and verifies the same UUID. |
| Project isolation | `project-id` derives an installation-namespaced opaque ID from the resolved project root. Project records require both that ID and an explicit domain; selection matches both. Paths are not stored. |
| Domain isolation | Arbitrary observations require a domain. A selector loads only the exact requested domain(s), supplied explicitly in one bounded call. Domain stack preferences cannot be global. |
| Transfer safety | Global active memory accepts only typed, explicitly `stated` general preferences. Arbitrary global prose is rejected. Cross-project calibration is numeric outcome data, not recalled prose. |
| Bounded context | Active records: 256; tombstones: 64; selected JSON: at most 8,000 characters; per-scope partition caps apply. Hard stops: 32 and overflow refuses rather than discarding one. Outbox: 128 entries/256 KiB. Active outcomes: 512 with 128 bounded aggregate partitions. Tool-generated active FEEDBACK: 100 entries. |
| Staleness and drift | Observed records expire after 365 days; inferred records after 90. Preferences cannot be observed or inferred: only the owner can state them, and a replacement retires the old value. |
| Explicit export | Contribution is never automatic. It accepts only controlled generic pattern/action enums and refuses a receiver whose install UUID differs. It writes no project text. |
| Local operation | `loom_memory.py` uses only local files and Python's standard library. `loom_audit.py` mechanically rejects network/process bypasses in shipped executable sources. Git synchronization, when explicitly requested, is a separate operation. |

Inactive JSONL archives are local evidence stores and are never selected into agent context.
The `.loom-private/` installation archive is ignored by Git and absent from the publication
allowlist.

## First use

Initialize once and retain the returned UUID for commands in the session. Initialization also
copies any preexisting flat Markdown candidate lines into the inactive legacy quarantine; it
imports zero active records:

```text
python <loom>/tools/loom_memory.py init --loom-root <loom>
```

For project-scoped work, derive the opaque project identity instead of inventing a slug:

```text
python <loom>/tools/loom_memory.py project-id --instance <uuid> --project-root <target>
```

Both commands emit one JSON result. A missing, malformed, or cross-instance store is an
error, not a cold-start fallback.

## What may be loaded

Before planning, determine the domain honestly (see `loom/adaptation/project-types.md`).
Then make one bounded selection:

```text
python <loom>/tools/loom_memory.py select --instance <uuid> \
  --domain <primary-domain> [--domain <second-domain> ...] \
  --project <opaque-project-id> --max-chars 8000
```

Selection returns:

1. typed general preferences for this installation;
2. records whose domain exactly matches one of the explicitly supplied domains;
3. records whose domain is in that exact set and whose project ID also matches; and
4. unexpired temporary records with the same scope.

It never returns other domains, projects, installations, tombstones, retired records,
expired records, archives, outcomes, or the feedback outbox. A project selector without an
explicit domain set fails. All matched domains share the one character budget; unmatched
domains are never loaded.

Precedence remains: **current session words > target `loom.config.json` > selected stated
preference > Loom default**. Repository facts and conventions always beat preferences.
Apply selected defaults silently; if asked why, cite the selected record ID.

`use_profile: false` or `--no-profile` is absolute: do not initialize, select, write,
measure, queue, or contribute owner memory for that run.

## Scope contract

- `global`: typed stated preferences only: autonomy, report style, decision batching,
  language, and hard stops. It cannot carry a domain or project.
- `domain`: observations and the `stack_preference` preference. It requires a safe domain
  ID and forbids a project ID.
- `project`: project-local observations. It requires the exact domain plus a generated
  project ID.
- `temporary`: expiring context. It requires a domain; if project-bound, it also requires
  a generated project ID.

Project facts belong in the project's pack. Domain invariants belong in domain scope.
Only owner-stated working preferences and numeric calibration can transfer generally.

## Remember, change, and forget

Owner preference changes use the typed API, and the write must succeed before the agent
acknowledges it:

```text
python <loom>/tools/loom_memory.py set-preference --instance <uuid> \
  autonomy_default A1
python <loom>/tools/loom_memory.py set-preference --instance <uuid> \
  --domain web stack_preference React
python <loom>/tools/loom_memory.py forget --instance <uuid> <record-id>
```

Setting the same key in the same scope retires the prior value. Forgetting creates a bounded
tombstone so compaction cannot silently resurrect it. Unsupported keys, multiline values,
inferred preferences, and domainless stack preferences fail.

Legacy Markdown state has no trustworthy scope. `init` quarantines it once and never promotes
it. If an owner deliberately edits a legacy file afterward, this explicit command rescans it:

```text
python <loom>/tools/loom_memory.py migrate-legacy --instance <uuid>
```

The command copies candidate lines to `legacy-quarantine.jsonl` with provenance and imports
zero active records. The owner must re-state any preference worth keeping.

## Measurable learning

At G4/G5, convert consequential predictions into normalized values in `[0,1]` and record
their outcomes with a controlled metric. Use `domain=general` only for genuinely
domain-independent judgment; otherwise name the selected domain. A project ID is optional
evidence metadata and, when present, must be generated by `project-id`.

```text
python <loom>/tools/loom_memory.py record-outcome --instance <uuid> \
  --metric confidence --predicted 0.90 --actual 0.60 --domain general
python <loom>/tools/loom_memory.py report --instance <uuid> \
  --metric confidence --domain general
```

The report gives total sample count, early-window and recent-window mean absolute error,
and whether recent error is lower. It reports `improved: null` when evidence is insufficient;
accumulation alone is never called improvement. The atomic outcome store retains at most 512
recent raw records while bounded first/recent windows preserve longitudinal measurement.
Overflow raw evidence moves to an inactive per-instance archive. A report requires one metric
and one exact domain; omission defaults to `general`, never an all-domain blend.

## Compaction and contribution

`compact` deduplicates records, expires old observations, enforces every active cap, and
archives overflow. Normal writes compact when needed; retro should also run it explicitly.

Feedback candidates are controlled values, not prose:

```text
python <loom>/tools/loom_memory.py queue-feedback --instance <uuid> \
  --pattern stale-state --action fail-closed --evidence-count 3
```

Only an explicit `/loom contribute` or equivalent owner command may run:

```text
python <loom>/tools/loom_memory.py contribute --instance <uuid> --loom-root <loom>
```

The receiver must carry the same installation UUID. Contribution is idempotent and writes
only the controlled pattern, action, and count to that install's `FEEDBACK.md`. The same locked
transaction compacts tool-generated active entries to 100 and archives overflow under the
ignored `.loom-private/` directory. It never runs at auto-close, retro, lint, install, or publish.

At release triage—or after direct manual FEEDBACK edits—reapply the same active bound while
preserving old bodies in the ignored local archive:

```text
python <loom>/tools/loom_memory.py compact-feedback --loom-root <loom>
```

Finally run `python <loom>/tools/loom_lint.py --home`. Any invalid or cross-instance active
state is blocking. Inactive archives are deliberately outside routine context and lint cost.

## Crash recovery and lock ownership

Memory writes use token-owned exclusive lock files: `.loom-instance-init.lock` at a Loom root,
`.lock` inside an instance directory, and `.loom-feedback.lock` beside FEEDBACK. They are never
deleted merely because a clock threshold elapsed; a slow live writer therefore cannot be
mistaken for a crashed one. A leftover lock blocks the command. Recovery is deliberately manual:
first prove no Loom memory process is writing that root/instance, preserve the lock contents for
diagnosis if needed, remove only the exact named lock, then rerun validation before the write.
Never bulk-delete locks or remove one while writer ownership is uncertain.
