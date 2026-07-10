# Fact versus speculation separation

## What it's for

Enforcing the labeling discipline of `loom/core/epistemics.md` as an *audit*: is every
load-bearing claim carrying the label it deserves? The other skills use the labels; this one
verifies the labels themselves. It's the compliance pass — mechanical, fast, and the
foundation the rest stand on: a mislabeled pack defeats every downstream check that trusts
its labels.

Division of labor: `hallucination-check.md` hunts *false facts about the external world*;
this skill hunts *mislabeled claims of any kind* — including true ones labeled wrong, and
speculation about the project itself (users, load, futures) that no hallucination check
would flag.

## When to use

- Gate G0 (the Intake Note is mostly inferences — labeling starts correct or never),
  G1, G4.
- After any large writing burst — labels degrade when flow takes over.
- First step when *inheriting* a pack from another agent: audit its labels before trusting
  them; a pack whose FACTs are sourced and whose ledger matches its inline ASSUMPTIONs can
  be trusted fast; one that fails the sample gets treated as unlabeled prose.

## Evidence to require

Per the epistemics contract, mechanically checkable:
- Every `[FACT]` → has a source inline (file:line / command / doc / quote). No source, no fact.
- Every `[ASSUMPTION]` → has a ledger entry, and the ledger entry's `used_in` points back.
- Every `[SPECULATION]` → is not load-bearing for an irreversible step (trace what depends
  on it).
- Every `[UNKNOWN]` → has a resolution path or acceptance.
- Every `[HUMAN-DECISION]` → has a decisions.md record with options + recommendation.

## Method — the source taxonomy pass

For each load-bearing claim, ask *where did this come from?* and check the label matches:

| Origin | Correct label |
|---|---|
| Observed in-session (ran it, read it) | `[FACT]` + source |
| Documented, read in-session | `[FACT]` + doc name |
| Requester said it | `[FACT]` + quote (facts *about the request*, note — the requester can be wrong about the world) |
| Inferred from evidence, unverified | `[ASSUMPTION]` (ledger) |
| Recalled / extrapolated / pattern-fit | `[SPECULATION]` |
| Known gap | `[UNKNOWN]` |
| Requester's call to make | `[HUMAN-DECISION]` |

The audit is a sampling pass at gates (every claim in decision records and contracts; spot-
sample elsewhere) — exhaustive on the load-bearing spine, statistical on the rest.

## Questions to ask

1. Grep the hedge-verbs ("should", "presumably", "typically", "likely has") — each hit is an
   unlabeled claim; what's its true origin?
2. Are there *over*-labels? `[FACT]` stamped on the trivially obvious buries the labels that
   matter (epistemics: label what a reader might act on *and doubt*).
3. Do any facts cite each other in a circle, with no primary source at the bottom?
4. Has requester-said been conflated with true? ("Requester says the API returns JSON" is a
   fact about the conversation; the API's behavior needs its own check before load-bearing use.)
5. Sample five FACTs at random and actually follow their sources. Do they hold? (This is the
   inheritance test, and it also catches your own label rot.)

## Common failures

- **Confident paraphrase promotion** — an ASSUMPTION restated two documents later, without
  its label, now reading as fact. Restatements shed labels; this is the top finding.
- **Ledger orphans** — inline `[ASSUMPTION]` never filed; ledger entries no inline site
  references (both directions break the staleness chain).
- **Source-free FACTs** — usually true claims, lazily stamped. Still defects: the *system*
  is what's being maintained, and one tolerated sourceless FACT licenses the next.
- **Speculation load-bearing by distance** — a SPECULATION correctly labeled in
  architecture.md §5, then a WO builds on that section without inheriting the caveat.
- **Requester-conflation** — see question 4.

## When confidence is low

If you can't determine a claim's origin — it's been restated too many times to trace — label
it at the *weakest plausible origin* (usually `[SPECULATION]`) and re-verify from primary
evidence if anything irreversible depends on it. Provenance amnesia is treated as guilt, not
innocence.

## How to report

```markdown
### F-17 [fact-vs-speculation] [MED]
- claim: "the app must handle ~500 concurrent users" — architecture.md §5, unlabeled
- origin trace: appears first in intake §assumptions as A-002 (basis: agent estimate);
  restated in architecture without label; WO-009 sizes the pool from it
- action: restore label + A-002 reference in architecture §5; add A-002 to WO-009's
  epistemic notes; A-002 risk raised to HIGH (it now sizes infrastructure)
```

## Application by phase

| Phase | Audit focus |
|---|---|
| Intake | Every inference labeled; requester quotes verbatim, not paraphrased into facts |
| Planning | Full pass: decision records + contracts exhaustive, rest sampled; both ledger directions |
| Scaffolding | Toolchain "facts" (overlaps hallucination — report there, relabel here) |
| Implementation | WO epistemic notes present and current; caveats inherited from referenced sections |
| Review | Restatement audit: did implementation-era edits shed labels? Sample-follow five FACTs |
| Release | The readiness checklist's boxes are FACTs-with-evidence, by definition — audit exactly that |
| Maintenance | Inheritance test on the aging pack each recheck |
