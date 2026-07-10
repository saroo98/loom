# Product plan

**Consumer:** the planning agent itself (scope control at every later gate) and the requester
(confirms this is the product they meant).
**Produce when:** the matrix says so — essentially, when *what to build* has open questions,
not just *how*. If the requester handed over a complete spec, skip it and say so in MANIFEST.

Template: `templates/product-plan.md`.

## Contents

### 1. Problem & users
Who has what problem, in one paragraph each. Users you invented are `[ASSUMPTION]` —
requesters routinely correct agent guesses about their audience, so surface it early. If the
project targets a specific language community, the audience definition must say so
explicitly here, because it cascades into UI/UX and localization
(`loom/adaptation/localization-playbook.md`).

### 2. Scope ladder
The core scope tool. Four rungs, every candidate feature on exactly one:

- **MUST** — the finish line from intake is not met without it.
- **SHOULD** — v1 is notably weaker without it; cut under pressure.
- **LATER** — explicitly deferred; naming it here prevents scope creep *and* scope anxiety.
- **NEVER** — considered and rejected, with one line why. The most valuable rung: it
  records decisions that would otherwise be re-litigated every session.

Rung assignment for anything user-visible that the requester didn't state: `[ASSUMPTION]` or
`[HUMAN-DECISION]` per the epistemics triggers.

### 3. Success metrics
How the requester will judge the shipped thing — observable, checkable at G4/G5. "Works and
they like it" is not a metric; "installer runs on a clean Windows 11 machine; the three MUST
flows complete without errors" is.

### 4. Constraints & context
Budget, deadline, platform, compliance, language/localization needs — inherited from intake,
refined here.

### 5. Risks (product-level)
Only risks that change scope decisions ("app-store rejection risk → keep IAP out of MUST").
Technical risks belong to the architecture plan.

## Failure modes

- **Ghost requirements** — professional-sounding features nobody asked for. Every MUST traces
  to the requester's words or a ledgered assumption.
- **Metric theater** — metrics no one can measure at gate time.
- **NEVER-rung avoidance** — leaving rejected ideas unrecorded, so they resurrect
  (`loom/verification/long-context-consistency.md` calls this idea necromancy).
