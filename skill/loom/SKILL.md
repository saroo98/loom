---
name: loom
description: Loom planning OS — plan, scaffold, review, and steer projects or deliverables from description to release. Use whenever the user invokes /loom or mentions Loom, and also whenever they ask to plan a project or feature, want a project analyzed and broken into work orders, ask for an architecture/product/testing/release plan, want a plan reviewed or scored, need a stale plan rechecked before resuming work, or describe a new app, tool, research deliverable, data system, firmware/hardware task, or other project they want built — even if they never say the word "Loom" or "plan". Also when they say "remember that I…"/"forget…" about their working preferences. Subcommands: plan, small, resume, review, wo, gate, lint, report, retro, profile, contribute.
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

**Freshness is local and offline by default.** Never fetch, pull, or contact a remote merely
because Loom loaded. Verify the local Loom version/install marker and survey the target's
complete local state. If the user explicitly asks to synchronize Loom, a fetch may inspect
upstream state; a pull still requires an explicit update request and a clean fast-forward.
Network failure never disables local planning, but unknown target state blocks execution.

## Privacy (applies before anything else)

Loom packs are private; never paste pack content into public issues, PRs, or docs. Tier S gets
the operative privacy floor from `small-kernel.md`; M+ loads the full `core/privacy.md` through
START-HERE before writing a pack. Do not preload both. These rules outrank convenience.

## Autonomy

Operative level: user's words > `loom.config.json` in the target project > default **A2**
(run the lifecycle; batch human decisions once per gate; auto-decide reversible choices within
budget and record them). Tier S gets its compact autonomy contract from `small-kernel.md`; M+
loads `core/autonomy.md` through START-HERE. Flags: `--advise`→A0, `--careful`→A1,
`--auto`→A3. State the operative level in your first reply. Do not preload both contracts.

## User memory

For Tier M+, read `$LOOM/loom/core/user-memory.md` once per session. Tier S uses only the
bounded selector rule in `small-kernel.md`. Unless profile use is disabled, run
`loom_memory.py init --loom-root "$LOOM"`, derive the target's opaque `project-id`, and make
one bounded `select` call with the project ID and one repeated `--domain` flag for every
`loom_domain.memory_domains` match. Never read legacy flat
Markdown memory into context. Session words > project config > selected stated preferences
> Loom defaults. Remember/forget requests MUST complete the typed write before acknowledgment.
No contribution is automatic; `/loom contribute` is an explicit owner action.

## Config

Look for `loom.config.json` at the target repo root (schema:
`$LOOM/schemas/loom-config.schema.json`). If present it supplies autonomy, primary/composite
domains, freshness window, routing map, decision budget, and pack path. On a first `plan` run, create it from
`$LOOM/templates/loom.config.json` with the choices made during intake, so the human states
preferences exactly once.

## Subcommands

Parse the first word of the user's `/loom` arguments. No arguments: infer the situation from
the conversation (existing pack → `resume`; project description present → `plan`; else ask
which mode in one short question), do the work, and run `retro` at a natural delivery or
milestone end. Never auto-contribute. Feedback candidates use the controlled structured
outbox; free-form project text is not accepted.
Read **only** the files listed — Loom's context budgets are part of its design. Keep a session
context ledger keyed by path + content hash: never reread an unchanged Loom file in the same
session, and deduplicate files named by more than one route.

### `/loom plan <description or pointer to it>`
Full planning run for a new project or feature.
- Before reading START-HERE, run `loom_tier.py --description <request>`. If it returns S,
  route to `/loom small`; do not load the M+ kernel or create a pack.
- Read: `$LOOM/START-HERE.md` and follow its boot protocol §0–§7 exactly, with the
  context-budget table governing what else you load. Tier M+ intake includes the
  silence sweep (`$LOOM/loom/intake/intake.md` §4 — hits only).
- Repo present → survey per the protocol before proposing anything.
- Output: planning pack at `<target>/plans/` (layout in START-HERE §5).
- Before authoring the plan, record the target baseline with
  `python "$LOOM/tools/loom_gate.py" init <pack> --repo <target>`. A failed or unknown
  survey blocks the run; do not downgrade it to a warning.
- Git target with no existing pre-commit hook → install the pack guard: copy
  `$LOOM/templates/hooks/pre-commit`, stamp `{{LOOM_PATH}}`/`{{PACK_DIR}}`, note it once.
  An existing hook is never overwritten — report and move on.
- Before finishing: run `lint` (below), write the G1 review, seal it with `loom_gate.py
  seal-g1`, then run `loom_gate.py authorize`. Implementation cannot begin before all three
  commands succeed against an unchanged target.

### `/loom small <task>`
Tier-S path. Read **only** `$LOOM/loom/core/small-kernel.md`; it contains the classification,
privacy, epistemic, standalone-WO, chronology, and close-out contract. If the deliverable
renders a UI, additionally read only `$LOOM/loom/execution/design-floor-small.md`. The
`small-init → small-authorize → small-close → small-verify` commands mechanically prove the
WO preceded target changes. Promotion triggers route to `plan`; never stretch Tier S.

### `/loom resume [pack path]`
Return to an existing pack. Read START-HERE §8 → `$LOOM/loom/execution/staleness.md`; run
the full survey and `loom_lint.py --strict-staleness` recheck (diff committed, staged,
unstaged, and untracked state; walk the ledger; mark drift; re-gate only what drifted).
Unknown or invalid state blocks.
Report what moved and the updated frontier.

### `/loom review <pack path>`
Review a pack you did not write (or pretend you didn't). Use the reviewer context budget in
START-HERE; run the battery in composition order (`$LOOM/loom/verification/overview.md`);
score with `$LOOM/loom/review/rubric.md`, every score cited. Output: a G1-format review file.

### `/loom wo <WO-id>`
Execute one work order. Read the WO file + `$LOOM/loom/execution/staleness.md` §pre-WO —
run that check first; drift → stop and report, don't improvise. Respect escalation triggers
and out-of-scope. After every criterion is demonstrated, set the WO done and run
`loom_gate.py close-wo <pack> --repo <target> --wo <file>`; refusal means it is not done.
If the WO renders a UI, also read `$LOOM/loom/execution/design-floor.md` and hold the build
to its floor.

### `/loom gate <G0|G1|G2|G3|G4|G5> [pack path]`
Run a gate per `$LOOM/loom/review/gates.md`. For G1/G4: `lint` first (must be error-free —
it's the mechanical entry precondition), then the required verification passes, then the
review file per `$LOOM/templates/plan-review.md`.

### `/loom lint [pack path]`
Mechanical pack validation:
```
python "$LOOM/tools/loom_lint.py" <pack path> [--repo <target repo root>] [--strict-staleness]
```
Report findings; errors block gates. `--strict-staleness` is mandatory before gates,
resume, kickoff, or execution: warnings about age, dirty state, or unverifiable state become
blocking. Lint enforces required artifacts, ledgers, references, work-order contracts,
frontier parity, gate records, lifecycle authorization, and schema constraints in addition
to syntax and privacy checks.

### `/loom report [pack path]`
Render the pack as one self-contained HTML page — frontier chips, WO DAG, ledger,
decisions, outcomes summary, and the live lint embedded:
```
python "$LOOM/tools/loom_report.py" <pack path> [--repo <target repo root>]
```
Then open the written file with the OS default (`start`/`open`/`xdg-open`). The report is
disposable: git-ignored, regenerated any time — never commit it, never edit it by hand.

### `/loom retro`
Post-delivery. Use the retro prompt in `$LOOM/loom/prompts/prompt-library.md`; close the
pack's outcome ledger. Unless profile is off, record normalized prediction/outcome pairs,
queue only controlled generic feedback candidates, run `loom_memory.py compact`, and then
`python "$LOOM/tools/loom_lint.py" --home`. Never infer or silently update preferences.

### `/loom profile [view | set <key> <value> | forget <key>]`
Use the typed commands in `$LOOM/loom/core/user-memory.md`: `view` makes a bounded `select`;
`set` runs `loom_memory.py set-preference`; `forget` takes the selected record ID and runs
`loom_memory.py forget`. The successful write happens BEFORE acknowledgment. Prose forms
("remember that I…", "forget the…") count as these verbs. Legacy Markdown is quarantined,
never auto-imported.

### `/loom contribute`
Run `loom_memory.py contribute --instance <uuid> --loom-root "$LOOM"` only because the owner
explicitly invoked this subcommand. The receiver marker must match the outbox's installation
UUID. Only controlled pattern/action/count values are written; no free-form project/domain
text can enter this path. A mismatch or invalid entry fails without draining the outbox.

## Conduct rules (short form of what the repo enforces)

- Label load-bearing claims (`[FACT]`+source / `[ASSUMPTION]`→ledger / `[SPECULATION]` /
  `[UNKNOWN]` / `[HUMAN-DECISION]`). Missing information → labeled assumption + gate,
  never a stall; irreversible choice → never a silent guess.
- Target-repo conventions beat Loom defaults. The repo is the truth; plans adapt to it.
- Batch questions per the autonomy level; every batch item carries a recommendation.
- If Loom's guidance itself misleads you, append to `$LOOM/FEEDBACK.md` rather than
  silently working around it.
