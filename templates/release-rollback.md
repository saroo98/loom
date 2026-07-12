---
artifact: release-rollback
project: "<name>"
tier: <M|L|XL>
status: draft
last_verified: <YYYY-MM-DD>
loom_version: "0.8.0"
depends_on: [testing-plan?, contracts?]
---

# Release & rollback — <project>

<!-- Guide: loom/planning/release-rollback.md. Written to be executed under stress:
     imperative, numbered, no narrative. No tested rollback path → G4 fail. -->

## 1. Release readiness checklist
- [ ] Verification catalog green: <names>
- [ ] MUST flows manually confirmed: <who/when>
- [ ] Version bumped + changelog
- [ ] Open [HUMAN-DECISION] affecting release: none
- [ ] Privacy scrub on public-facing content

## 2. Release procedure
<!-- Numbered, environment-explicit, THIS project's actual steps. Every migration named;
     expand-contract question answered per migration. -->

## 3. Staged exposure
<!-- Stages + named widen-criteria between them. All-or-nothing platform → compensating
     pre-release pass described. -->

## 4. Rollback plan
- Target (named): <tag/version/artifact + where it's verified runnable>
- Triggers (pre-agreed): <observable conditions>
- Procedure: <numbered steps>
- Data reversibility: <per migration — what happens to writes during the bad window>
- Time-to-rollback: <honest estimate>
- Rollback verification: <same smoke checks as release>
- Rehearsed: <where/when — tier L+: before first release>

## 5. Comms
<!-- Who is told what, on success and failure. One line each. -->

## Verification hooks
<!-- e.g. "rollback target still runnable"; "trigger thresholds still match monitoring". -->
