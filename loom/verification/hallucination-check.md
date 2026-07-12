# Hallucination checking

## What it's for

Catching the claims that were **generated, not observed**: API methods that don't exist,
flags that were never real, file paths from a parallel universe, version numbers from
training data, "the library handles that automatically". Models produce these fluently and
in good faith — the check is mechanical skepticism applied to your own memory.

## The core rule

**Anything recalled about the external world is `[SPECULATION]` until verified in-session.**
"External world" = libraries, APIs, tools, CLIs, file layouts, version behavior, platform
policies, model names, prices. No exceptions for confidence — confidence is exactly the
feeling hallucination produces.

This extends to the **live state of the running system**, not just static facts. When
something "should work but doesn't" — a login that fails, a count that drifts — query the
system for its actual state before theorizing about causes (does the record even have a
`passwordHash`? does the documented credential match the real one?). A guessed diagnosis
of live state is a hallucination with a shorter half-life; one query settles it.

## When to use

- Gate G1 on every plan; G2 on scaffold instructions (the densest hallucination habitat:
  commands, flags, versions, template names); G5 on release/rollback procedural steps.
- The moment you write a specific external detail from memory — cheapest at the source.
- Reviewing *another* agent's plan: their fluent specifics get zero benefit of the doubt.

## Evidence to require

A claim graduates to `[FACT]` only via:
- **Command output from this session** (`pip show`, `--help`, `git log`, compiler output).
- **File read this session** (`file:line`).
- **Documentation read this session** (fetched, not remembered — name the page).
- **Requester statement** (quoted).

Not evidence: "I'm quite sure", training-data memory, another unverified document in the
same pack (hallucinations launder themselves through cross-references — follow every chain
to primary evidence once).

## Method — the sweep

1. **Harvest the specifics.** Scan the artifact for: proper nouns of tools/libraries,
   version numbers, CLI commands + flags, API/function names, config keys, file paths, URLs,
   platform policy claims ("stores require X"), quantitative claims about tools.
2. **Classify each:** verified-here (has its source) / verifiable-now / not-verifiable-now.
3. **Verify the verifiable** in batch: run the `--help`s, read the files, check the
   manifests. Minutes, usually.
4. **Label the rest honestly:** `[SPECULATION — verify at WO start]` with the verification
   step written into the consuming WO's preconditions. Scaffold instructions get the
   resolve-at-execution-time treatment for versions (`loom/execution/scaffolding.md`).

## Questions to ask

1. Could I write the *source* for this claim right now? (If the answer is a feeling, no.)
2. Is this specific enough to be falsifiable — and did anything here falsify it?
3. For versions: is this number from the repo's manifest, or from my training data?
4. For APIs: did I read this signature, or does it merely *fit the pattern* of this library?
   (Pattern-fit is the hallucination signature — plausible is the problem, not the defense.)
5. For paths: does `ls`/Glob confirm it exists in *this* repo, or did I assume the
   conventional layout?

## Common failures

- **Version confabulation** — plausible semver from memory. Highest frequency.
- **API smoothing** — the method that *should* exist, given the library's style.
- **Flag invention** — CLI flags composed from other tools' conventions.
- **Doc laundering** — an unverified claim cited to another pack document that also never
  verified it.
- **Stale truth** — was true, at training time; platform/API changed since. (This is why
  even "known" facts about fast-moving platforms get in-session checks before load-bearing use.)
- **Convention projection** — assuming this repo follows the ecosystem's standard layout.

## When confidence is low

That's the designed-for case: low confidence + can verify → verify now; low confidence +
can't verify now → `[SPECULATION]` + a named verification step in the consuming WO, and the
design hedged so the claim's failure isn't catastrophic. What is *never* acceptable: shipping
the claim as fact because it's probably fine. High confidence changes nothing in this
procedure — that's the whole point.

## How to report

```markdown
### F-11 [hallucination] [MED]
- claim: "`sqlite3` CLI ships with Windows" — scaffold.md step 4
- problem: stated as fact, no source; recalled. (It does not ship with Windows.)
- action: add explicit install step to scaffold instructions; re-check the same doc's
  other environment claims (steps 6, 9) — hallucinations cluster
```

The parenthetical correction only when you *have* verified the truth; otherwise the finding
is the missing source, not a counter-claim.

## Application by phase

| Phase | Densest sites |
|---|---|
| Planning | Library capabilities in architecture §4; platform claims in adaptation choices |
| Scaffolding | Commands, flags, template names, versions — sweep the whole instructions doc |
| Implementation | Pre-WO check: the WO's inlined "facts" (staleness + hallucination overlap) |
| Review | Claims added to docs during implementation ("X now handles Y") |
| Release | Store/platform procedure steps; signing/notarization requirements — these change yearly |
| Maintenance | The runbook's commands still exist and still do that; dependency claims re-verified each recheck |
