# Tier-S UI floor — compact real-medium checklist

Load only when the Tier-S deliverable renders a human-facing UI. Cite the applicable numbers
in the work order. This is a floor, not a request to add features.

1. **Honest promise.** Every visible control performs the effect it claims. If persistence,
   submission, payment, or navigation is absent, remove the control or label/disable it
   truthfully. Placeholder copy cannot impersonate a fact.
2. **Complete core journey.** Plan normal use, empty/initial, loading if asynchronous,
   success, validation/error, retry/recovery, repeat/reset, disabled, focus, and selected
   states that the small promise actually has. Empty is not zero; an old result cannot remain
   visible as if it belongs to a failed/new request.
3. **Composition, not defaults.** Establish hierarchy, spacing rhythm, readable line length,
   alignment, and deliberate type/color roles. Dark/light themes are separately composed, not
   mechanically inverted. Bespoke visual treatment must not replace clarity.
4. **Measured accessibility.** Normal text contrast ≥4.5:1; large text and essential UI
   graphics ≥3:1. Semantic controls have names, keyboard order works, focus is visible, targets
   are usable, status/error feedback is announced without relying on color alone.
5. **Narrow and wide reality.** Observe at the intended wide size and at ≤360 CSS px (plus
   any target-specific breakpoints). No horizontal clipping, overlap, hidden action, unreadable
   type, or pointer-only affordance. Check long/translated text when locale is in scope.
6. **Motion restraint.** Motion communicates state, uses compositor-friendly properties where
   applicable, never strands content if script fails, and honors reduced-motion. The useful
   end state must remain understandable with motion off.
7. **Real-medium evidence.** Open the running artifact—not a source preview. Exercise every
   applicable state and actual event; inspect console/runtime errors; check both themes if
   shipped; record widths/devices and what was observed. Source, unit tests, or a screenshot of
   one idle state cannot certify interaction or responsiveness.
8. **Scope negative.** Record what was deliberately not added. A complete smallest journey is
   table stakes; a second workflow, account system, remote dependency, or invented domain is
   gold-plating and triggers promotion/replanning.
