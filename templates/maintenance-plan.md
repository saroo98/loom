---
artifact: maintenance-plan
project: "<name>"
tier: <L|XL>
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.7.0"
depends_on: [release-rollback]
---

# Maintenance plan — <project>

<!-- Guide: loom/planning/maintenance-plan.md. Reader: an agent or human months from now
     with zero session context. -->

## 1. Ownership & escalation
<!-- Who owns runtime health / updates / user reports. -->

## 2. Runbook
<!-- 5–10 real operations, imperative, copy-pasteable, EACH EXECUTED ONCE before handoff
     (note where evidence lives). Restore actually tested. Credential rotation: procedure
     only, no values. -->

| Operation | Command / steps | Last executed |
|---|---|---|

## 3. Monitoring & signals
<!-- Concrete signals + where to look. Thresholds echo rollback triggers. -->

## 4. Dependency & platform policy
<!-- Cadence, pin rules, and the decay clocks with actual dates (certs, store policies,
     API deprecations). -->

## 5. Evolution guardrails
<!-- Binding decision records; frozen contracts; danger zones; the repo-is-truth rule;
     where the instructions file lives. -->

## 6. Deprecation & end-of-life
<!-- Retirement conditions; what must be preserved (data export, final backup). -->

## Verification hooks
<!-- e.g. "runbook commands still exist and succeed (each recheck)". -->
