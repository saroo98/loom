<!-- DRAFT — requires requester approval before adoption (it speaks with the repo's
     authority). Guide: loom/execution/project-instructions.md. Target filename per the
     requester's tooling: AGENTS.md / CLAUDE.md / GEMINI.md / …

     Keep under ~2 pages. Every line must change a future agent's behavior. If the repo is
     public, this file is public: privacy scrub before adoption. -->

# <Project> — agent instructions

## Commands (ground truth)
- Build: `<command>`
- Test: `<command>`   <!-- from the pack's verification catalog; master lives in the pack -->
- Run locally: `<command>`
- Lint/format: `<command>`
- Release: <pointer to procedure — not the procedure itself if pack is private>

## Conventions
<!-- Only the non-obvious: commit style, branch model, shell, formatting exceptions. -->

## Danger zones
<!-- Survey list + pack additions. "Never modify X without explicit request" items. -->

## Where decisions live
<!-- Private repo: "plans/decisions.md — read before proposing architecture changes."
     Public repo: name where the private pack lives instead. -->

## Working rules
- Verify file paths and API claims against this repo before acting on them; label guesses
  as guesses.
- <Project-specific rules that earn their context cost.>
