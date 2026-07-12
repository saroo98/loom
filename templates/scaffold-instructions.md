---
artifact: scaffold-instructions
project: "<name>"
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.8.0"
depends_on: [architecture-plan]
---

# Scaffold instructions — <project>

<!-- Guide: loom/execution/scaffolding.md. Self-contained: may be executed by a different,
     cheaper agent. Minimalism rule: only what the first three WOs need + quality bars. -->

## Before you start
- Target directory: <path>; expected starting state: <empty / partial per survey — what to
  keep/replace/delete, each with reason>
- **Resolve current versions at execution time** — versions below were current
  <YYYY-MM-DD> [SPECULATION after that date]:  <tool: version…>

## Steps
<!-- Numbered. Per step: the command, expected outcome, and for generators: what to VERIFY
     and keep/delete afterward (generator output isn't fully predictable — don't pretend). -->

1. <command>
   → expect: <observable result>

## Secrets pattern
<!-- Config names+shapes in repo, values outside; the .gitignore entries that prove it. -->

## G2 verification block (run all; paste outputs into close-out)
- [ ] Clean checkout → build succeeds: `<command>`
- [ ] Format + lint green: `<commands>`
- [ ] Test runner wired (≥1 trivial test passes): `<command>`
- [ ] CI green on the actual service (if selected)
- [ ] Planted dummy secret file is ignored: `git check-ignore <path>` → match

## Close-out (filled by implementer)
<!-- Outputs per check; generator-output deviations from plan (repo is truth — note for
     plan update). -->
