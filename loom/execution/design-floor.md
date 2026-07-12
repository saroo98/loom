# Design floor — the craft any interface must clear

**Consumer:** whoever *builds* a human-facing UI — an implementer at any tier, including a
single Tier-S work order with no pack. **Load when:** the deliverable renders anything a person
sees or operates.

This is **execution craft, not a planning artifact.** `planning/uiux-plan.md` decides *what*
screens exist and in what flow; this file decides whether each one is *built well*. It loads
even when there is no pack, because the small, interactive, "just one file" build is exactly
where craft gets dropped and generic, incomplete, or dishonest UI ships. A capable builder
still produces template output when no one names the craft — naming it is this file's whole job.

Every rule is a **floor to exceed, never a template to copy.** The goal is a *bespoke* result;
§10 is the test that you got one. When two rules collide, **§7 (honesty) outranks everything.**

## 1. Color as roles, not hues
- **Name every color for its job, never its appearance** — `surface`, `text`, `muted`,
  `border`, `accent`, `on-accent`, `danger`, `focus`, `result-*` — not "teal" or "gray-500".
  Hue-names leak the wrong color into the wrong meaning and turn a theme change into scattered edits.
- **One action color; a separate danger family.** The accent carries selection, primary action,
  and focus; destructive/invalid gets its own family. Reusing the accent for errors makes state ambiguous.
- **A strong and a soft form of each semantic color.** Strong for text/fills/borders, soft tint
  for supporting backgrounds. A strong color as every background is loud; a pale tint as text fails contrast.
- **A materially different surface owns its foreground roles.** A dark or saturated result panel
  defines its own text/muted/border/focus *against itself* — never reuse global foregrounds on it.
- **Atmosphere is not information.** Gradients, glows, shadows are decorative tokens that never
  carry state. The interface must stay fully readable with every one of them removed.

## 2. Themes are recomposed, never inverted
- **Build each theme as its own contrast composition from shared role names.** Dark mode is a
  second lighting model: chromatic near-black (not pure `#000`), lifted surfaces, borders visible
  but not glowing, a brighter accent with dark ink on top. Numeric inversion breaks hierarchy and
  makes saturated colors vibrate.
- **Hierarchy survives the switch.** Write the intended order of attention; verify it in grayscale
  in *both* themes. A theme that reverses importance is two unrelated designs.
- **System preference seeds the default; an explicit choice persists; the toggle names the theme it
  switches *to*.** A storage failure must not break the control.

## 3. Contrast is measured, not eyeballed
- **Floors, fixed before you pick values:** ≥ **4.5:1** enabled normal text · ≥ **3:1** large
  display text · ≥ **3:1** enabled control borders, meaningful icons, and focus rings — each against
  its *actual adjacent* color, in every theme and state.
- **Audit the weakest legitimate pairing** — hints, captions, placeholder, text-on-accent, the
  inverse panel — not the headline example. The quietest enabled token is the real floor; record it.
- **Never a low-contrast placeholder as the only label.** Placeholders vanish on input; every field
  keeps a visible, programmatic label. A placeholder is a format hint at most, and still readable.
- **Color never carries state alone** — pair it with a word, icon, or shape; verify the state in grayscale.

## 4. Typography with functional bands
- **A short scale where each step is a job,** with deliberate *discontinuities*: metadata, label/body,
  section title, the single narrative headline, the one computed answer — the largest jump reserved for
  the fact the user came for. An even modular scale flattens priority into noise.
- **Weight before shrinking.** Establish secondary hierarchy with weight and tone; do not drop help
  text to unreadable sizes. Keep the number of *perceived* weights small.
- **Tighten only large display; protect reading text** with generous leading (~1.5) and a comfortable
  measure (~45–65 characters). Guidance sits *beside* the control it governs, never in a distant block.
- **Numbers are data.** Tabular lining figures anywhere values update in place or align in a column.
  Format currency/percent through the runtime's locale formatter and *parse with the same locale model*;
  compute in a stable internal unit (money: the smallest integer unit), format only at the boundary.
  Hand-built money strings mishandle symbol, grouping, precision, and rounding.

## 5. Layout: action, then consequence
- **Layout mirrors the task sentence** — input/action space first, a distinct outcome space second;
  preserve that order across breakpoints. A uniform card grid makes every block compete equally.
- **High-consequence output gets prominence *and* proof:** one dominant answer plus a compact
  derivation next to it, so the number can be checked. A big number with no provenance can't be trusted.
- **One spatial rhythm** from a base interval — tightest gap inside a component, larger gap between
  decisions — with documented optical corrections only. Spacing signals grouping *before* borders do.
- **Breakpoints from content stress, not device names** — resize until labels wrap or controls crowd,
  then break just before. **Every interactive target ≥ 44×44 CSS px** (measure the rendered box; include
  compact selects and icon buttons). Cap the useful width; keep fluid gutters.

## 6. The full state grammar
Design *every* interactive element across its whole grammar before polishing the default:
**default · hover · focus · focus-visible · active · disabled · empty · error · success** (plus
**loading** wherever data is fetched). Naming only the populated/default state is the most common UI failure.
- **Default reveals affordance and hides no costly bias** — no pre-selected expensive option.
- **Hover is a preview, gated to hover-capable input** (a capability query); never hide essential info behind it.
- **Focus identifies the whole control** (`:focus-within` for a composite); **focus-visible is an
  unmistakable, offset, surface-aware ring** on every control, never clipped by overflow.
- **Disabled only when the outcome is truly impossible/invalid,** with the fix inferable nearby — and a
  disabled-looking control must never still fire.
- **Empty is not zero** (§7). **Error invalidates everything downstream** (§7). **Success confirms the
  result *and* the next available action.**
- **Distinguish "not finished yet" from "wrong":** delay required-field errors until blur; reject
  impossible characters or ranges immediately.

## 7. Honest interaction — the rule that outranks polish
> **Every displayed claim is derivable from current accepted input; every transformation is visible or
> disclosed; every reported effect actually happened.**
- **Model input as tagged states — empty · partial · invalid · valid — before calculating.** Missing,
  zero, and invalid are three states with three different corrections; never collapse them into one.
- **Bound every domain input and disclose the bound** — the range near the control, the *same* constants
  for validation and message. Reject ambiguous input; never silently coerce or clamp what the user typed.
- **Invalid upstream clears or visibly strands every dependent output and disables dependent actions.**
  A stale answer beside changed input lets the interface look current while lying.
- **Confirm effects, not attempts.** "Saved"/"Copied" appears only after the effect succeeds; failure is a
  visible, announced state. Saying it on click is a direct lie.
- **Disclose relabel / convert / filter / round.** A changed currency symbol states that no exchange
  occurred; precision that can't be represented asks for correction rather than silently rounding.
- **Privacy or behavior claims only when the architecture makes them true** — verify dependencies and
  network requests before writing "local" or "private".

## 8. Motion explains change — or it is removed
- **Duration by perceptual distance:** ~140 ms contact feedback (hover/press/color) · ~220 ms local
  state change and reveals · under ~450 ms only for spatial or quantitative change (a bar growing). One
  duration for everything makes small controls feel sluggish or large changes feel abrupt.
- **Restrained ease-out** — immediate departure, soft arrival; bounce only if the product truly means it.
  **Animate the state relationship and name it; if a motion explains nothing, delete it.**
- **Nothing animates continuously, and no content waits on an animation.** Render the final state
  immediately and layer motion on top; keep decorative elements static.
- **Reduced motion is a mode, not a shorter duration** — a global guard *plus* explicit checks around any
  scripted animation. State must be obvious without movement.

## 9. Completeness vs gold-plating — the scope rule for interfaces
> **Table stakes make the promised task work safely across realistic users and states. Gold-plating adds
> an adjacent capability, choice, or ornament that starts a second domain, workflow, or remote dependency.**
- **Ship the whole *smallest* journey:** normal use **+ recovery/correction + repeat/reset + accessible
  feedback.** A happy-path-only build demos an algorithm; it is not a usable product. On self-contained,
  low-risk deliverables this completeness is **required, not scope creep — do not cut it.**
- **A quality dimension is table stakes when it decides whether the *same task* works for a different user
  or context** — localization, responsiveness, keyboard, contrast, reduced motion. Treating these as
  extras turns a finished-looking widget into a narrow prototype.
- **Decline features that open a second domain model, remote dependency, or policy decision** unless the
  core promise needs them (tax rules, accounts, saved history, exchange rates, payments). Score each
  candidate: does it prevent a broken state or close the immediate loop? If neither, cut it.

This test **refines**, does not repeal, the scope-ladder discipline (`intake/artifact-matrix.md`,
`execution/work-orders.md`): still cut the truly adjacent feature — but a self-contained UI's own recovery,
repeat, and accessibility paths are *inside* the promise, and cutting them as "extra" is the failure this
rule exists to stop.

## 10. Bespoke, not generic — and how to prove it
- **Derive composition and voice from the task's own verbs,** not interchangeable decoration. Give the
  interface's two main cognitive modes (e.g. compose / review) distinct spatial and tonal treatment
  instead of repeating identical cards.
- **One memorable move; everything else subordinate.** A single dominant idea — a receipt-like proof
  panel, an oversized outcome — plus a small formal idea repeated at different scales makes identity;
  scattered gradients and pill badges do not.
- **Microcopy earns its place** by orienting emotion, preventing a false inference, or aiding recovery.
  Cut any sentence that changes none of understanding, confidence, or the next action.
- **The generic test — run it before calling a UI done:**
  1. **Substitution** — swap the product noun for "weather" / "inventory". If every major element still
     fits unchanged, it is under-designed.
  2. **State-specificity** — the design's quality must exist in the empty / error / long-content / narrow /
     keyboard-focus / reduced-motion states, not only the hero screenshot.
  3. **Delete-one-detail** — name each gradient, badge, icon, animation, and line of copy's role; delete
     the roleless.
  4. **Grayscale squint** — one clear starting point, one obvious sequence, one dominant answer.
  5. **Hostile content** — shortest, longest, zero, maximum, localized, and invalid values; layout and
     claims must hold.

## 11. Accessibility floor (non-negotiable; spans the whole build)
Native semantics matched to the content (a `main` landmark, `form`, `fieldset`/`legend`, real `button`s,
`output`, a list for a collection) **before** any ARIA. A visible **and** programmatic label for every
input; errors linked and `aria-invalid` toggled from the *same* validation the visuals use. Full
**keyboard** operation in logical order with domain keys (arrows within a group), no traps. Visible focus
on every control. The contrast floors of §3. **Non-color state cues always.** **44px** targets with
separation. A **restrained live region** announcing the settled result (debounced), with action
confirmations kept separate. **Reflow with no horizontal loss at 320–390 px and under zoom.** Reduced
motion honored. Accessibility is *acceptance criteria*, not a final annotation pass. Web floor detail:
`planning/uiux-plan.md` §5.

## 12. Render and observe — no criterion is met until you have looked
§1–11 are *what to build*; this is the gate that proves you built it. Every rule above is
checkable two ways — by reading the code, or by looking at the running interface — and the
defects that matter most are invisible to the first. A shattered panel, an overlapping control, a
detached border, a grid that never applied, text clipped at a narrow width, an unreadable state in
the *other* theme: the source can be correct token-by-token while the rendered result is broken.
"The CSS specifies X" is a claim about the source, not about what the user sees.
- **Open the artifact in a real browser and look — before any acceptance criterion is called met.**
- **Look at every state, not the happy path:** empty, populated, error, success, disabled/loading —
  each *rendered*, not imagined.
- **Look at every context that changes layout:** the widest supported width, the *narrowest*
  (≤ 360px), and *both* themes. Composition bugs hide at the edges, not in the default screenshot.
- **Record what you saw, not what the code says.** In the close-out: "rendered at 1280 and 360,
  light and dark, all four states — no overlap, clipping, or detached elements" is a check; "the
  CSS sets the grid" is not. A screenshot or one concrete observation per state is the evidence.
- The *medium* is project-specific — a web page renders in a browser, a native screen in its
  simulator — but the law is universal (`loom/verification/self-verification.md` step 6: observe
  the running artifact, never certify from source). Your instance's calibration accrues the
  render-only defect shapes it has already been burned by; feed each one to `FEEDBACK.md` so it
  becomes a named pre-ship check next time, specific to the work you actually do.

## The floor — the checklist a work order can cite
A UI work order's acceptance criteria should be able to name these by number.
1. **One core promise;** every field, result, and action serves it — the rest is cut (§9).
2. **Every state designed** (§6), transitions included.
3. **Tokens by role; each theme recomposed** (§1–2).
4. **Contrast measured** — 4.5:1 / 3:1, weakest pairing audited (§3).
5. **Short type + spacing scales, each step a job; numbers tabular and locale-formatted** (§4).
6. **Action separated from a dominant, proven result** (§5).
7. **Recompose for narrow screens; 44px targets; reflow, no horizontal scroll** (§5, §11).
8. **Empty ≠ zero; invalid strands every dependent claim and action** (§6–7).
9. **Truthful transformations and effects — confirm success only after it happens** (§7).
10. **Motion only explains change; a real reduced-motion path** (§8).
11. **Ship the smallest whole journey; cut only second-domain features** (§9).
12. **Character from the task; pass the substitution and hostile-content tests** (§10).
13. **Accessibility floor met as criteria, not annotation** (§11).
14. **Rendered and observed** — opened in a real browser, every state seen at the widest width,
    ≤ 360px, and both themes; observations (not code claims) recorded in the close-out (§12).

## Failure modes
- **Floor skipped at Tier S** — the small/interactive build is where craft is dropped and generic output
  ships. This file loads at *every* tier for that reason.
- **Default-state-only design** — quality in the hero screenshot, nothing in empty/error/narrow (§6).
- **Token drift** — roles defined, then hardcoded hues appear in the work order. Cite tokens by name (§1).
- **Completeness cut as scope** — the recovery, repeat, and accessible paths are the product, not extras (§9).
- **Polish over honesty** — a beautiful interface that shows a stale or fabricated result has shipped a
  defect, not a feature. §7 outranks every other rule here.
- **Certified from source, never rendered** — every criterion ticked by reading the code while the
  page was visibly broken on screen (an inline element styled as a card and never set to block; a
  grid rule written but never applied; a panel that shatters at 360px). §12 exists because this is
  the single most common way a fully floor-compliant build still ships broken.
