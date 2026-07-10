# Scaffolding — giving a repo its skeleton

Scaffolding is the work that makes feature work orders cheap: directory layout, toolchain,
config, CI, quality bars. It is also where projects acquire permanent accidental decisions —
so it gets a plan, a gate (G2), and restraint.

Template: `templates/scaffold-instructions.md` (the implementer-facing half).

## When to scaffold at all

- Repo none/empty: almost always, but see the minimalism rule below.
- Partial repo: scaffold the *gaps*, respecting the survey's deliberate-vs-generated-vs-
  abandoned classification (`loom/intake/repo-survey.md`). Never silently overwrite fragments.
- Active repo: usually **no scaffold phase** — structure exists; new components follow the
  conventions found by the survey. A "let's restructure while we're here" urge is a
  `[HUMAN-DECISION]`, not a scaffold.

## The minimalism rule

Scaffold only what the **first three work orders need, plus the agreed quality bars.**
Empty directories "for later", speculative abstraction layers, and config for tools nobody
chose yet are anti-scaffold: they encode guesses as structure, and structure is what future
agents trust most blindly.

## The scaffold plan (part of the pack when selected)

1. **Layout** — the directory tree with one line of purpose per entry. A directory without a
   purpose line doesn't get created.
2. **Toolchain decisions** — language version, package manager, build tool, formatter,
   linter, test runner. Each is a mini decision record (options/chosen/why) because these are
   the highest-friction things to change later. Versions stated are `[FACT]` as of the
   stamp date — the scaffold instructions must tell the implementer to resolve current
   versions at execution time, not hardcode from the plan.
3. **Quality bars from day one** — format check, lint, test runner, and (if chosen) CI all
   green **while the repo is still nearly empty**. Bars added later fight accumulated debt;
   bars present from the first commit are free.
4. **Config files** — which exist and what decisions they encode. Secrets pattern established
   here: env/config-file *names* and *shapes* in the repo, values outside it, `.gitignore`
   proving it (`loom/core/privacy.md`).
5. **Seams for what's next** — where the first features plug in, so feature WOs don't start
   with "figure out where this goes".

## Scaffold instructions (for the implementing agent)

A separate, self-contained document (it may be executed by a different, cheaper agent):
exact commands in order, expected outcome per step, and the G2 verification block at the end.
Two honesty rules:

- Commands that generate code (`npm create …`, `dotnet new …`, cookiecutter) produce output
  the instructions can't fully predict — the instructions say what to *verify and keep/delete*
  after generation, not a fictional exact file list.
- Anything network-dependent (registry availability, template versions) is labeled and given
  a fallback.

## Gate G2 — skeleton verified

Pass = command output, not inspection:
- Build/compile succeeds from a clean checkout.
- Format + lint + test commands run green (zero tests passing counts only if the runner
  itself demonstrably works — one trivial test proves the wiring).
- CI (if any) runs green on the actual service.
- `.gitignore` proves the secrets pattern: a planted dummy secret file is ignored
  (`git check-ignore` output).

## Failure modes

- **Framework maximalism** — scaffolding a microservice mesh for a tier-M app. The matrix and
  the minimalism rule exist to stop this.
- **Version hallucination** — pinning versions from memory. Resolve at execution time;
  `loom/verification/hallucination-check.md` treats remembered versions as `[SPECULATION]`.
- **Quality bars deferred** — "we'll add lint later". Later never comes cheaply.
- **Scaffold-plan drift** — generator output differs from the plan and nobody reconciles.
  G2's job; the plan updates to match reality (repo is truth).
