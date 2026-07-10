# Project instructions — drafting AGENTS.md / CLAUDE.md for the target project

Many target projects will be worked on by agents outside this pack's lifecycle. A project
instructions file (AGENTS.md, CLAUDE.md, GEMINI.md, or the requester's preferred convention)
is how the pack's hard-won knowledge reaches those future sessions. Loom drafts it; the
requester approves it (it speaks with the repo's authority, so its adoption is a
`[HUMAN-DECISION]` — deliver as draft).

Template: `templates/project-instructions-draft.md`.

## When to draft one

Matrix row says ◐ — flip to produce when: the repo will outlive the pack, multiple
agents/models will touch it, or the survey found dangerous or surprising things future
sessions must know. Skip when the requester already maintains one (then: propose a *diff*,
not a replacement).

## What belongs in it

The test: **will a future agent, with zero pack context, act more correctly because of this
line?** Keep it short — instruction files are loaded into every session's context; every
line taxes every future prompt.

1. **Ground truth commands** — build, test, run, lint, release; the verification-commands
   catalog from `testing-plan.md` §2, copied (this is the one place duplication is allowed,
   because instruction files must be self-sufficient — note the master lives in the pack).
2. **Conventions that aren't obvious from the code** — commit style, branch model, "PowerShell
   not bash", formatting exceptions.
3. **Danger zones** — the survey list + pack additions: "trading logic in X — never modify
   without explicit request", "the junction at Y means never edit Z directly".
4. **Pointers, not content, into the pack** — "architecture decisions: plans/decisions.md" if
   the pack stays with the repo (private repos only; else the pointer names where the pack
   lives).
5. **Epistemic floor** — one line worth exporting from Loom: "verify file paths and API
   claims against the repo before acting on them; label guesses as guesses."

## What must NOT go in it

- Secrets or values of any credential/config (`loom/core/privacy.md` rule 2 — instruction
  files get committed and copied carelessly).
- Strategy, unreleased plans, anything from the pack that fails the scrub checklist — if the
  repo is public, the instructions file is public.
- Long prose. Anything over ~2 pages will be skimmed by exactly the agents that most need it.
- Aspirations ("write clean code"). Only enforceable, checkable statements.

## Consistency duty

The instructions file and the pack must not contradict — a future agent obeying the
instructions must never violate the plan. When a decision record changes, grep the
instructions draft for stale echoes (`loom/verification/contradiction-detection.md` lists
this as a standard cross-doc pair). MANIFEST records the instructions file as a dependent
artifact of the plans it summarizes.
