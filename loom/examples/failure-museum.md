# Failure museum

Archetypal planning failures — each one real in pattern, anonymized in detail. Every
exhibit: what happened, the moment it became inevitable, and the Loom mechanism that
exists because of it. Read when you want to *feel* why the discipline earns its cost;
cite exhibits in reviews ("this is Exhibit C") to name a failure without a lecture.

---

## Exhibit A — The dropped clause

**What happened:** request said "…and my brother should be able to use it offline." Three
sessions later, a polished online-only app. Every gate passed except the one that re-reads
the original words: the summary written in session 1 said "family shopping app", and every
later check verified against the summary.
**Inevitable when:** the paraphrase replaced the quote.
**Mechanism:** intake quotes verbatim; task-fit at G4 re-reads the **original** request;
long-context roll-call traces every stated goal to a carrier WO.

## Exhibit B — The confident version

**What happened:** plan pinned `library X 4.2` with a config-format example — from memory.
4.x had changed the format; the scaffold agent obediently produced configs the tool
rejected, then "fixed" them by downgrading to 3.x, which conflicted with a peer dependency.
A day lost to one remembered version string.
**Inevitable when:** a training-data recall was written without a label.
**Mechanism:** hallucination check — recalled external details are `[SPECULATION]` until
verified in-session; scaffold instructions resolve versions at execution time.

## Exhibit C — The plausible wrongness

**What happened:** an ambiguous WO ("normalize the user input") routed to a fast-cheap
model. It normalized — plausibly, consistently, and wrongly (stripped the language-specific
codepoints it was supposed to canonicalize *to*). Nothing crashed; reviews saw tidy code.
Found weeks later via user bug reports.
**Inevitable when:** ambiguity was routed downward.
**Mechanism:** routing rule 3 (never route ambiguity down); acceptance criteria as runnable
checks with real fixture content — a fixture with ی/ک variants would have failed loudly.

## Exhibit D — The silent default

**What happened:** nobody decided the database; the agent's fingers typed Postgres because
they always do. Delivered to a requester who wanted a zero-install desktop tool for one
shop PC. The rework touched persistence, packaging, and the installer — the most expensive
possible place to learn the audience.
**Inevitable when:** an audience-shaped choice was made by habit, unrecorded.
**Mechanism:** decision records for expensive-to-reverse choices ("if it's obvious, the
record is three lines"); weak-assumptions escapee hunt, silent-defaults category.

## Exhibit E — The rollback that was a sentence

**What happened:** "In case of problems we roll back to the previous version." The problem
came; the migration had dropped a column; the previous version crashed on the new schema;
the "previous good state" was never named, so the team debated tags mid-incident with
users watching.
**Inevitable when:** the release shipped with a rollback *sentence* instead of a rollback
*plan*.
**Mechanism:** G4 fails without: named target, pre-agreed triggers, data-reversibility
answer per migration (expand-contract), rehearsal evidence.

## Exhibit F — The softening chain

**What happened:** "must sync in real time" (intake) → "syncs frequently" (plan v2) →
"periodic sync, interval configurable" (WO) → a manual refresh button (shipped). Each
restatement was individually defensible; nobody decided the downgrade. Requester noticed
at delivery, with the words from their own first message.
**Inevitable when:** requirements were restated instead of referenced.
**Mechanism:** long-context consistency — scope-softening scan across the time axis;
requirements trace to the quoted intake, not to the nearest paraphrase.

## Exhibit G — The immortal plan

**What happened:** a beautiful three-week-old pack, executed faithfully — against a repo
that two hotfixes and a dependency bump had moved. The implementer "fixed" the repo to
match the plan, reverting one of the hotfixes. Production incident #2 re-fixed it.
**Inevitable when:** the plan was treated as truer than the repo.
**Mechanism:** repo-is-truth divergence rulings; pre-WO staleness check (two minutes);
`loom_survey --since` makes the drift visible as a command; stamps + freshness windows.

## Exhibit H — The merge that ate a week

**What happened:** two agents, parallel WOs, both "just quickly" registered their feature
in the same routing table file. Merge conflict resolved by the second agent — by deleting
the first agent's lines, tests for which didn't exist yet. Discovered when feature one
vanished from the demo.
**Inevitable when:** parallel WOs shared a write path with no rule.
**Mechanism:** `touches` disjointness + lint overlap warning; shared-surface slicing rule
(own file per WO + one serializing wire-up WO); negative acceptance checks
(`git diff --stat` scope).

## Exhibit I — The verification that verified itself

**What happened:** integration tests mocked the payment API — using shapes copied from the
same plan document the client code was generated from. Plan wrong → mock wrong → client
wrong → suite green. First real transaction failed on field casing.
**Inevitable when:** both sides of a boundary inherited one unverified description.
**Mechanism:** contract tests must touch the declared boundary shape from *outside* the
plan (provider docs read in-session, or a real sandbox call); "testing the mock" is the
named failure mode in the testing guide.

---

**Pattern across all exhibits:** none failed at the moment of the mistake — each failed
earlier, at the moment a *label, record, quote, or check was skipped* while everything
still looked fine. That's why Loom's mechanisms live where they do: upstream of the
visible failure, at the skip.
