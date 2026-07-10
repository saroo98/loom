---
artifact: testing-plan
project: "<name>"
tier: <M|L|XL>
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.7.0"
depends_on: [contracts?, survey?]
---

# Testing plan — <project>

<!-- Guide: loom/planning/testing-plan.md. Strategy = risk allocation, not coverage
     aspiration. -->

## Risk map
<!-- Where does wrongness hurt most? Where is churn highest? What needs human eyes? -->

## 1. Test level policy
<!-- Which levels exist, what belongs in each — adjusted per project type
     (loom/adaptation/project-types.md). -->

## 2. Verification commands catalog
<!-- THE commands that mean "green". Work orders reference these by name. If none exist
     yet, creating them is an early WO. -->

| Name | Command | Green means |
|---|---|---|

## 3. Coverage stance
<!-- One honest sentence per area — not a global %. -->

## 4. Characterization tests (existing/legacy repos)
<!-- Danger zones (survey list) → pin current behavior before modifying. Skipping one =
     decision record. -->

## 5. Test data & environments
<!-- Fixtures/factories — never production secrets or personal data. Faked vs real
     services. CI integration or the decision not to have it. -->

## Verification hooks
<!-- e.g. "catalog commands all exist and run (mechanical sweep at G2/G3)". -->
