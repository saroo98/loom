# Repo survey — handling every starting state

Purpose: know what exists before proposing anything. Applies whenever there is any repo at
all; the "no repo" case is also covered because deciding *that* is part of the survey.

Output for partial/active/legacy repos: a survey document (`plans/survey.md`), facts separated
from inferences, every fact carrying evidence (`file:line`, command output). It carries the
standard artifact frontmatter (`artifact: survey`, `status`, `last_verified` — see
`loom/planning/plan-authoring.md`); `loom_lint` checks it like any other pack artifact.

Start with `python <loom>/tools/loom_survey.py <repo>`. Its state record is distinct from its
bounded architecture inventory: the inventory may stop at 20,000 relevant files and says so,
but the freshness fingerprint never returns a partial success. For Git it binds HEAD plus staged,
unstaged, and untracked Git-visible content; for a non-Git workspace it hashes every non-pack
file. If complete state exceeds the 100,000-file safety bound or any file/Git operation is
indeterminate, the command fails and execution stays blocked. Ignored cache/build output and the
private pack are explicitly excluded from product state.

## State: no repo

There is nothing to survey, but there are decisions to record:
- Where will the project live? (new local dir, new private remote) — usually `[HUMAN-DECISION]`
  if a remote/hosting choice implies accounts or spend; otherwise assume local + note it.
- Single repo or multi? Default: single until proven painful; record as a decision if XL.
- Note explicitly in the Intake Note: `repo: none — greenfield; layout defined in scaffold plan`.

## State: empty repo (exists, no meaningful content)

"Empty" still carries signals. Check, and record as facts:
- Remote settings: private or public? **If public, privacy rule 3 applies to the pack.**
- Default branch name, branch protection, existing CI config, LICENSE, .gitignore.
- README stub — sometimes contains the requester's real intent in one sentence. Quote it.

Then treat as greenfield with those constraints.

## State: partial repo (scaffold or fragments, no working product)

The dangerous one — fragments imply decisions someone already made, but you don't know which
were deliberate.
- Inventory what exists: layout, configs, dependencies declared vs actually used.
- For each fragment, classify: **deliberate choice** (respect it), **tool-generated default**
  (free to change), or **abandoned experiment** (`[UNKNOWN]` — cheap to ask, otherwise assume
  abandoned if it doesn't build).
- Does it build/run/test right now? Record the actual command and its actual output.
- Never silently overwrite fragments. The scaffold plan states what is kept, replaced, or
  deleted — each with a reason.

## State: active repo (working product, ongoing development)

Full survey protocol. Time-box it — a survey that reads every file is a survey that never
ends. Read in this order, stop when additional reading stops changing your conclusions:

1. **Self-descriptions:** README, CONTRIBUTING, AGENTS.md/CLAUDE.md, docs/. These are claims,
   not facts — verify the load-bearing ones ("docs say `make test`; confirmed it runs" →
   `[FACT]`).
2. **Manifests & lockfiles:** languages, frameworks, versions, dependency count and health.
3. **Entry points and wiring:** main/index/app files, DI/config setup, routing tables.
4. **CI/CD config:** what is actually checked and deployed — often truer than the README.
5. **Tests:** where, what kind, do they pass, roughly what they cover.
6. **Complete current state, then history:** preserve the generated `repo_state_hash`; list
   staged, unstaged, and untracked paths; then inspect `git log --oneline -30` and active branches
   for context. History cannot account for local changes.
7. **Danger zones:** auth, payments, migrations, trading/execution logic, anything with
   "don't touch" energy. List them explicitly — work orders will need the list.

Produce:
- **Architecture-as-found** — components and boundaries as they *are*, not as the docs claim.
- **Conventions list** — naming, formatting, error handling, commit style. Work orders
  inherit these; Loom defaults yield (`loom/adaptation/using-loom-well.md`).
- **Health notes** — build status, test status, dependency staleness, obvious hazards. As
  findings with evidence, not editorializing.

## State: legacy / unknown provenance

Active-repo protocol, plus:
- Trust nothing without running it. Docs and code may have diverged years ago.
- Before planning changes to any behavior-critical path, plan **characterization tests**
  (pin current behavior first) — see `loom/planning/testing-plan.md`.
- Expect load-bearing weirdness: things that look wrong but are compensating for something.
  Removing them is a decision, not a cleanup. `[UNKNOWN]` until understood.

## Audit-shaped requests: the scored health card

When the request itself is an audit ("audit this repo", "score the codebase", "how healthy
is this"), the survey is the deliverable's spine and carries a **scored health card**:
5–10 dimensions chosen for the project type (e.g. correctness signals, test posture,
dependency health, security posture, docs freshness, build reproducibility), each scored
0–5 with **every score citing evidence** (file:line, command output), findings feeding
work orders or decision records — never free-floating advice. Dimensions are per-project
judgment; the format (scored, cited, findings→WOs) is the fixed part. *(Pattern earned by
a real audit run, 2026-07-10 — see FEEDBACK.)*

## Survey hygiene

- Every claim in the survey: `[FACT]` with evidence, or labeled inference. "This looks like a
  Django app" is `[SPECULATION]` until manage.py and settings confirm it.
- Secrets encountered during survey: path only, never the value; flag as a finding
  (`loom/core/privacy.md` rule 2).
- Stamp the survey and MANIFEST with both generated values: `repo_head` (when Git exists) and
  `repo_state_hash`. Staleness rechecks compare both (`loom/execution/staleness.md`). Do not copy
  a hash after subsequent product-state edits; re-run the survey.
- A local snapshot cannot prove remote facts current. Record the observed lockfile/manifests and
  the exact real-medium check for dependency advisories, platform APIs, regulations, datasheets,
  research evidence, or other time-sensitive domain authorities. If that check cannot be made,
  label it `[UNKNOWN]` and block any gate that relies on it.
