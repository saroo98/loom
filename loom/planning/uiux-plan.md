# UI/UX plan (including responsive design)

**Consumer:** implementers building screens, and reviewers judging "does this match intent".
**Produce when:** any human-facing UI exists. For websites/marketing sites this plan is the
center of gravity and may absorb the architecture plan (declare the merge in MANIFEST).

Template: `templates/uiux-plan.md`.

## Contents

### 1. Users & platforms
Which humans, on which devices, in which languages/scripts. Language and script direction are
**structural**, not cosmetic: an RTL requirement discovered after layout work multiplies the
UI cost. Any non-English audience → answer the seven questions in
`loom/adaptation/localization-playbook.md` here (plus your Loom's per-language deep-dive
for that audience, if one has been earned). Resolve before the flows section — assumption
A-xxx with `verify_by: before first UI work order`.

### 2. Screen inventory & flows
- Every screen/page/view, one line each: name (glossary-stable), purpose, primary action.
- The 2–5 flows that matter (the MUST rungs of the product plan), as screen sequences:
  `Browse → Detail → Add to list → Confirm`.
- **Every screen has four states: empty, loading, error, populated.** Naming only the
  populated state is the most common UI planning failure — the other three are where
  implementers invent inconsistent behavior.

### 3. Responsive strategy
Decisions, not aspirations:
- Breakpoints — named, with values, and *what changes at each* ("nav collapses to drawer
  below `md`"). A breakpoint table nobody maps to layout changes is decoration.
- Direction: mobile-first or desktop-first, chosen from the audience facts, recorded as a
  decision.
- Touch targets, minimum supported viewport, and what is *not* supported ("no layout below
  320px — NEVER rung").
- For RTL audiences: mirroring policy (what flips, what doesn't — see the localization
  playbook's standing rules).

### 4. Design tokens & components
- Tokens: color roles, type scale, spacing scale — as a table implementers copy. Actual
  values may be `[HUMAN-DECISION]` (brand taste) with your recommendation prefilled.
- Component inventory: the ~dozen components the screens decompose into, each with its states.
  This is what makes work orders atomic — "build the Card component per uiux.md §4" is
  executable; "make it look good" is not.

### 5. Accessibility baseline
Pick the baseline and state it (e.g., "WCAG 2.1 AA for keyboard nav + contrast; screen-reader
depth is LATER rung"). An unstated baseline means "none, discovered at review".

### 6. Content & tone
Voice, terminology (glossary-stable), placeholder policy. **Real-content rule:** test layouts
with realistic content in the target language — Arabic-script RTL text, long German words,
whatever the audience implies. Lorem ipsum hides every overflow bug that matters.

## Handoff form

Implementers get: screen list + flow diagrams + token table + component inventory + states.
They do **not** need pixel-perfect mocks unless the requester supplies them; describe layout
in structure ("two-column above `md`, stacked below; detail pane is a sheet on mobile") and
let the implementer implement. If a specific look *is* the requirement (brand work), that's
image/mock territory — attach or generate references, don't describe a picture in prose.

## Failure modes

- Populated-state-only planning (see §2).
- Breakpoints as ritual — values listed, no layout consequences attached.
- Token drift — tokens defined, then hardcoded values in work orders. Orders must reference
  tokens by name.
- Fictional-content layouts — see the real-content rule.
- RTL as afterthought — see §1; retrofitting direction is the single most expensive UI rework.
