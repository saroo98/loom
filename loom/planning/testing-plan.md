# Testing plan

**Consumer:** implementers (what they must prove per work order), the G3/G4 gates (what
"verified" means), and maintenance (what protects future changes).
**Produce when:** the matrix says so. At tier S–M without special risk, the plan may be one
paragraph inside work orders' acceptance criteria — that's still a testing decision, made
consciously.

Template: `templates/testing-plan.md`.

## Strategy is risk allocation

A testing plan is not a coverage aspiration; it's a statement of **where wrongness hurts most
and what stands guard there**. Start from the risk list:

1. Where does incorrect behavior cost the most? (money paths, data integrity, auth, the
   MUST-rung flows)
2. Where is change most frequent? (churn × risk = test priority)
3. What can only be caught by a human or visual check? (design fidelity, feel — plan for it
   instead of pretending unit tests cover it)

Then allocate: heavy automated coverage on high-risk/high-churn, characterization tests
around legacy behavior you must not disturb, thin smoke coverage elsewhere, explicit manual
checklists for the human-judgment residue.

## Contents

### 1. Test level policy
Which levels exist and what belongs in each (unit / integration / end-to-end / manual).
Default shape: many fast unit tests on logic, integration tests on each contract from
`contracts.md` (both directions: does the server honor it, does the client tolerate the
declared errors), a handful of e2e over the MUST flows, manual checklist for look-and-feel.
Adjust per project type — `loom/adaptation/project-types.md` lists the peculiarities (e.g.,
MQL5 EAs: tester-based verification; Android: device-matrix smoke tests).

### 2. Verification commands catalog
The exact commands that mean "green" for this project (`npm test`, `pytest -q`,
`.\build.ps1 -Test`, compile-log parser, …), recorded once. **Work orders reference these
commands by name in acceptance criteria** — never re-invent them per order. If no such
command exists yet, creating it is one of the first work orders.

### 3. Coverage stance
A sentence per area, honest, not a global percentage: "sizing math: exhaustive unit tests
including boundary cases; UI components: render + state tests only; generated boilerplate:
none, and why that's fine."

### 4. Characterization tests (legacy/existing repos)
Before modifying behavior-critical code you didn't write: pin current behavior with tests
that assert *what is*, not *what should be* — then refactor against them. The survey's danger
zones list (`repo-survey.md`) is the input. Skipping this on a danger zone requires a
decision record.

### 5. Test data & environments
Where test data comes from (fixtures/factories/anonymized — **never production secrets or
personal data**), what services are faked vs real, and how CI runs it all. If CI doesn't
exist, decide whether it enters scope (usually a SHOULD at tier L).

### 6. The deliverable smoke battery (anything UI-shaped, any tier — including S)
A test *plan* can be skipped at tier S; proving the deliverable cannot. The battery is
cheap, scripted, and runs in the artifact's real medium before handoff:

1. **Static self-checks, scripted — never eyeballed.** A throwaway script beats reading:
   tag/brace balance, duplicate ids, every local asset reference resolves, every
   fragment link has a matching target. Minutes to write; kills whole defect classes.
2. **Probe the served artifact, don't admire it.** Serve locally and *measure*: horizontal
   overflow as a number (scroll width vs client width) at phone/tablet/desktop widths;
   layout collapse verified from computed styles per breakpoint; console clean; the
   things that should resolve (fonts, animations, dynamic state) actually resolved.
3. **Behavior by dispatched events, not by looks.** Fill the form with a test value and
   submit it — assert the visible outcome and the reset. Click the toggle — assert the
   state attribute, not the pixels. Press Escape — assert closed. If it has behavior,
   the check is an event plus an assertion.
4. **A probe that fails changes the code, then the WHOLE battery reruns.** A fix without
   a re-run is a new unverified claim.

The battery's findings are close-out evidence (paste the probe outputs). Skipping the
battery on a shippable UI is a decision record, not a default.

## Failure modes

- **Coverage theater** — a percentage target driving trivial tests while money paths go bare.
- **Testing the mock** — integration tests that only prove the fake agrees with itself.
  Contract tests must touch the declared boundary shape.
- **Green-by-vacuity** — "all tests pass" where tests don't exist. Gates require the
  commands catalog to be non-empty for anything above tier S.
- **Manual checks unplanned** — visual/UX verification left implicit, then skipped. If a
  human must look at it, the plan says who looks at what, when.
