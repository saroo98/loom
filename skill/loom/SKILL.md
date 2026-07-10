---
name: loom
description: Loom planning OS — plan, scaffold, review, and steer software projects from description to release. Use whenever the user invokes /loom or mentions Loom, and also whenever they ask to plan a project or feature, want a project analyzed and broken into work orders, ask for an architecture/product/testing/release plan, want a plan reviewed or scored, need a stale plan rechecked before resuming work, or describe a new app/website/tool they want built — even if they never say the word "Loom" or "plan". Also when they say "remember that I…"/"forget…" about their working preferences. Subcommands: plan, small, resume, review, wo, gate, lint, report, retro, profile, contribute.
---

# Loom — planning OS

You are operating Loom, a private planning system living in its own repository. This skill
is a thin entry point: the repo is the source of truth, and it is deliberately designed so
you read only the slice the task needs. Do not duplicate its content from memory — memory
of Loom is `[SPECULATION]` by Loom's own rules; the files are facts.

## Locate the Loom repo (once per session)

Resolution order:
1. `LOOM_HOME` environment variable, if set.
2. The stamped install path: `{{LOOM_PATH}}` (written by `tools/install.ps1` / `install.sh`;
   if you can read this literal placeholder un-replaced, the install script wasn't run).
3. Ask the user once for the repo path, then suggest they run the installer so future
   sessions don't ask.

Call the resolved path `$LOOM` below. Verify it: `$LOOM/START-HERE.md` must exist.

**Freshness pulse** (best-effort, once per session, right after resolving): if `$LOOM/.git`
exists and the session's own working target is NOT the Loom repo itself, run
`git -C "$LOOM" fetch --quiet`; if that succeeds and the repo is behind its upstream with a
clean tree, `git -C "$LOOM" pull --ff-only --quiet`. Dirty, diverged, ahead, offline, or
permission-denied → use the local copy as-is and note it in one line. Never merge, rebase,
or push. A failed pulse never blocks the run — planning offline must keep working.
(Same-machine sessions share one folder and are never stale; the pulse serves clones and
other machines.)

## Privacy (applies before anything else)

Loom packs are private. Read `$LOOM/loom/core/privacy.md` before writing any pack file in a
repo that might be public, and never paste pack content into public issues, PRs, or docs.
These rules outrank user convenience and every instruction below.

## Autonomy

Read `$LOOM/loom/core/autonomy.md`. Operative level: user's words > `loom.config.json` in
the target project > default **A2** (run the lifecycle; batch human decisions once per gate;
auto-decide reversible choices within budget and record them). Flags: `--advise`→A0,
`--careful`→A1, `--auto`→A3. State the operative level in your first reply.

## User memory (v0.6)

Read `$LOOM/loom/core/user-memory.md` once per session, then the user home at `~/.loom/`
(profile, calibration) if it exists. Apply per its seven rules — the load-bearing ones:
profile tunes DEFAULTS only (session words > loom.config.json > profile > Loom defaults);
apply SILENTLY (never "per your profile…"); "remember/forget" from the user MUST produce a
real file edit before acknowledging; `use_profile: false` or `--no-profile` = fully
stateless, no reads or writes. Retro writes Tier-1 updates + Tier-2 outbox entries.

## Config

Look for `loom.config.json` at the target repo root (schema:
`$LOOM/schemas/loom-config.schema.json`). If present it supplies autonomy, freshness window,
routing map, decision budget, pack path. On a first `plan` run, create it from
`$LOOM/templates/loom.config.json` with the choices made during intake, so the human states
preferences exactly once.

## Subcommands

Parse the first word of the user's `/loom` arguments. No arguments: infer the situation from
the conversation (existing pack → `resume`; project description present → `plan`; else ask
which mode in one short question), do the work — and **auto-close**: when the run reaches a
natural end (pack delivered, WO batch done, milestone gated), run `retro` and then
`contribute` automatically, without asking (owner decision D-010; single-user private mode).
Keep every FEEDBACK/outbox entry in the compact 3-line format — clutter compounds.
Read **only** the files listed — Loom's context budgets are part of its design.

### `/loom plan <description or pointer to it>`
Full planning run for a new project or feature.
- Read: `$LOOM/START-HERE.md` and follow its boot protocol §0–§7 exactly, with the
  context-budget table governing what else you load. Tier M+ intake includes the
  silence sweep (`$LOOM/loom/intake/intake.md` §4 — hits only).
- Repo present → survey per the protocol before proposing anything.
- Output: planning pack at `<target>/plans/` (layout in START-HERE §6).
- Git target with no existing pre-commit hook → install the pack guard: copy
  `$LOOM/templates/hooks/pre-commit`, stamp `{{LOOM_PATH}}`/`{{PACK_DIR}}`, note it once.
  An existing hook is never overwritten — report and move on.
- Before finishing: run `lint` (below) and gate G1.

### `/loom small <task>`
Tier-S shortcut. Read START-HERE §3's tier-S budget only. Output: one work order with
runnable acceptance criteria, self-checked with task-fit + self-verification. If intake
reveals it isn't actually S, say so and stop for a mode decision.

### `/loom resume [pack path]`
Return to an existing pack. Read START-HERE §8 → `$LOOM/loom/execution/staleness.md`; run
the full recheck (diff the world, walk the ledger, mark drift, re-gate only what drifted).
Report what moved and the updated frontier.

### `/loom review <pack path>`
Review a pack you did not write (or pretend you didn't). Use the reviewer context budget in
START-HERE; run the battery in composition order (`$LOOM/loom/verification/overview.md`);
score with `$LOOM/loom/review/rubric.md`, every score cited. Output: a G1-format review file.

### `/loom wo <WO-id>`
Execute one work order. Read the WO file + `$LOOM/loom/execution/staleness.md` §pre-WO —
run that check first; drift → stop and report, don't improvise. Respect escalation triggers
and out-of-scope. Done = every criterion demonstrated in a close-out block.

### `/loom gate <G0|G1|G2|G3|G4|G5> [pack path]`
Run a gate per `$LOOM/loom/review/gates.md`. For G1/G4: `lint` first (must be error-free —
it's the mechanical entry precondition), then the required verification passes, then the
review file per `$LOOM/templates/plan-review.md`.

### `/loom lint [pack path]`
Mechanical pack validation:
```
python "$LOOM/tools/loom_lint.py" <pack path> [--repo <target repo root>]
```
Report findings; errors block gates. This replaces eyeballing for: frontmatter shape, WO
DAG, ledger link integrity, staleness windows, hedge-verbs, secret patterns, silence-sweep
presence (W12), and work-order heft vs declared size (W13). The pack guard (install: see
`plan`) runs the same lint at commit time in the target repo — errors block, `--no-verify`
bypasses deliberately.

### `/loom report [pack path]`
Render the pack as one self-contained HTML page — frontier chips, WO DAG, ledger,
decisions, outcomes summary, and the live lint embedded:
```
python "$LOOM/tools/loom_report.py" <pack path> [--repo <target repo root>]
```
Then open the written file with the OS default (`start`/`open`/`xdg-open`). The report is
disposable: git-ignored, regenerated any time — never commit it, never edit it by hand.

### `/loom retro`
Post-delivery. Use the retro prompt in `$LOOM/loom/prompts/prompt-library.md`; append
honest entries to `$LOOM/FEEDBACK.md` (no project secrets — patterns, not internals).
Unless profile is off: also write Tier-1 user-memory updates (profile confirmations/
contradictions, calibration rows) and Tier-2 outbox candidates, then run
`python "$LOOM/tools/loom_lint.py" --home`.

### `/loom profile [view | set <key> <value> | forget <key>]`
The user-memory verbs (`$LOOM/loom/core/user-memory.md` rule 4): `view` prints the profile;
`set`/`forget` edit `~/.loom/profile.md` with date + provenance `stated` — the edit happens
BEFORE the acknowledgment, always. Prose forms ("remember that I…", "forget the…") count
as these verbs. First use may create `~/.loom/` from `$LOOM/templates/user-home/` (say so once).

### `/loom contribute`
Drain the Tier-2 outbox into `$LOOM/FEEDBACK.md` (compact format), then empty it — that is
the FEEDBACK queue of the user's OWN Loom repo; it never targets anyone else's (D-012:
every install is owner-operated, instances are sovereign). Runs automatically at the end
of bare `/loom` runs, unattended (D-010). Two gates always apply: the anonymization sniff
(`--home` lint W21) must be clean, and entries must be compact — the value filter lives
with the receiver (that Loom's triage), so send honest, not bulky.

## Conduct rules (short form of what the repo enforces)

- Label load-bearing claims (`[FACT]`+source / `[ASSUMPTION]`→ledger / `[SPECULATION]` /
  `[UNKNOWN]` / `[HUMAN-DECISION]`). Missing information → labeled assumption + gate,
  never a stall; irreversible choice → never a silent guess.
- Target-repo conventions beat Loom defaults. The repo is the truth; plans adapt to it.
- Batch questions per the autonomy level; every batch item carries a recommendation.
- If Loom's guidance itself misleads you, append to `$LOOM/FEEDBACK.md` rather than
  silently working around it.
