---
artifact: architecture-plan
project: "<name>"
tier: <M|L|XL>
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.8.0"
depends_on: [intake, survey?]
---

# Architecture plan — <project>

<!-- Guide: loom/planning/architecture-plan.md. Tier M: this may be one page — keep the
     decision records, cut everything else first. -->

## Decisions (summary)
<!-- Every D-id this plan introduces, one sentence each. Full records in decisions.md;
     this plan may inline the records instead — pick ONE home and say which. -->

## 1. Context sketch
```
<ASCII: system, users, external systems — ≤10 boxes>
```

## 2. Components & boundaries
<!-- Per component: name (glossary!), one-sentence responsibility, may-call/called-by,
     data OWNED. One owner per datum. -->

| Component | Responsibility | Calls | Owns |
|---|---|---|---|

## 3. Decision records
<!-- Expensive-to-reverse choices: language, framework, store, API style, auth, hosting.
     Format per decisions.md template. Silent defaults on non-obvious calls = defect. -->

## 4. Cross-cutting concerns
<!-- Only where a real decision exists: errors, config/secrets (names+shapes, NEVER values),
     logging, auth, i18n/RTL (mandatory if RTL audience), persistence/migrations. -->

## 5. Failure modes
<!-- What breaks first, and what the design does / explicitly doesn't do. Capacity numbers
     carry labels. -->

## 6. Delta plan (existing repos only)
<!-- Current → target as shippable intermediate states. Big-bang rewrite = [HUMAN-DECISION]. -->

## Verification hooks
<!-- e.g. "boundaries hold: no imports from X into Y (grep check)"; "A-004 load assumption
     still plausible per metrics". -->
