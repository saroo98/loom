---
artifact: security-plan
project: "<name>"
tier: <M|L|XL>
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.8.0"
depends_on: [architecture-plan, contracts?]
---

# Security plan — <project>

<!-- Guide: loom/planning/security-plan.md. Produce when: auth, payments, personal data,
     or public network exposure. Threats bound to THIS system's surfaces, right-sized. -->

## Decisions (summary)

## 1. Assets & trust boundaries
<!-- What's worth protecting; where trust changes level. Names must match architecture §2. -->

## 2. Threat table
| Boundary/surface | Threat | Realistic? Why | Mitigation (decided) | Residual risk |
|---|---|---|---|---|

## 3. AuthN/AuthZ
<!-- Identity mechanism, session/token lifetime+storage, authz table, account recovery
     (plan recovery like login — it's the same door). -->

## 4. Data protection
<!-- PII inventory + what is deliberately NOT stored; at rest/in transit; key management
     (mechanisms, never values); retention & deletion paths. -->

## 5. Input & abuse handling
<!-- Validation per input boundary; rate limits; uploads; unicode/bidi if RTL audience. -->

## 6. Dependencies & supply chain
<!-- Lockfile policy; adoption checks; update cadence lives in maintenance plan. -->

## 7. Hooks
- Testing: abuse cases for top threats → <test names / WO-ids>
- Release checklist additions: <items>
- Incident basics (maintenance): noticed how / first steps / who's told

## Verification hooks
<!-- e.g. "lint secret scan green on pack and repo config samples"; "authz table matches
     implemented middleware (grep check)"; "abuse tests exist and run in CI". -->
