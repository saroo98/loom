---
artifact: uiux-plan
project: "<name>"
tier: <M|L|XL>
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.7.0"
depends_on: [intake, product-plan?]
---

# UI/UX plan — <project>

<!-- Guide: loom/planning/uiux-plan.md. If this absorbs the architecture plan (websites),
     declare it in MANIFEST and add the §2/§3 architecture content here. -->

## Decisions (summary)

## 1. Users & platforms
<!-- Devices, viewports, languages, SCRIPT DIRECTION. RTL possible → resolve now; read
     loom/adaptation/localization-playbook.md before §2. -->

## 2. Screen inventory & flows
| Screen | Purpose | Primary action |
|---|---|---|

Flows (MUST rungs): `<Screen> → <Screen> → …`

<!-- EVERY screen: empty / loading / error / populated states. -->

## 3. Responsive strategy
<!-- Direction (mobile-first?) as a decision from audience facts. Breakpoints WITH what
     changes at each. Touch targets, min viewport, explicit non-support. RTL mirroring
     policy if applicable. -->

| Breakpoint | Value | What changes |
|---|---|---|

## 4. Design tokens & components
<!-- Token table (color roles / type scale / spacing). Values may be [HUMAN-DECISION] with
     recommendation prefilled. Component inventory with states — work orders reference
     tokens/components BY NAME. -->

## 5. Accessibility baseline
<!-- Named baseline + explicitly deferred parts. Unstated = none. -->

## 6. Content & tone
<!-- Voice, terminology (glossary), REAL-CONTENT rule: test layouts with realistic
     target-language content — fixture location named here. -->

## Verification hooks
<!-- e.g. "fixture renders at all breakpoints without overflow"; "audience/device
     assumptions A-xxx still hold". -->
