# Security plan

**Consumer:** implementers touching auth/data/exposed surfaces (what they must enforce),
reviewers at G4 (what to attack), maintenance (what to keep watching).
**Produce when:** the matrix modifier fires — authentication, payments, personal data, or
public network exposure. A local single-user tool with no network gets a skip line, not a
ritual document.

Template: `templates/security-plan.md`.

## Scope stance

This is *defensive planning for the project being built* — trust boundaries, protections,
and abuse handling. It is not a pentest plan and not a compliance audit; if the requester
needs those, that's scope for specialists and a `[HUMAN-DECISION]`.

## Contents

### 1. Assets & trust boundaries
What is worth protecting (user data, credentials, money paths, availability, reputation) and
where trust changes level: every network edge, every auth transition, every place user input
enters, every third-party integration. One diagram or list; boundaries here must agree with
the architecture plan's component boundaries — same names, same edges.

### 2. Threat table
Per boundary, the realistic abuses — a STRIDE-flavored sweep without the ceremony:

| Boundary/surface | Threat | Realistic? Why | Mitigation (decided, not aspired) | Residual risk |
|---|---|---|---|---|

"Realistic?" is the honesty column: a family restaurant site's threat model is spam bots and
defacement, not nation-states. Over-modeling wastes the budget exactly like over-planning.
Threat plausibility claims follow epistemics — label them.

### 3. AuthN/AuthZ decisions
Decision records (or references to architecture ones): identity mechanism, session/token
lifetimes and storage, password/credential policy, authorization model (who may do what —
as a table if more than trivial), account recovery. Recovery flows are the classically
under-planned attack surface; plan them with the same care as login.

### 4. Data protection
- PII inventory: what personal data exists, where it lives, why it's needed (data not
  collected is the cheapest protection — say what you deliberately don't store).
- At rest / in transit decisions; key management (**names and mechanisms, never values** —
  `loom/core/privacy.md`).
- Retention and deletion: what gets deleted when; user deletion path if user data exists.

### 5. Input & abuse handling
Validation strategy at each input boundary (injection classes relevant to the stack);
rate limiting / abuse throttling decisions; file upload rules if any; the bidi/unicode note
for RTL projects (`loom/adaptation/localization-playbook.md` — unisolated bidi is spoofing
surface).

### 6. Dependency & supply chain stance
Lockfiles committed; update policy reference (maintenance plan owns cadence); what gets
audited before adoption (new dependency = at minimum: maintained? typosquat check? license?).
Bundled *assets* (fonts, icons, images) get the same gate as code dependencies: a
user-supplied asset is not a licensed asset. Verify provenance as a `[FACT]` before
anything ships publicly — a font's own name-table (copyright / foundry / license URL)
answers "do we have the rights?" more reliably than the owner's say-so, and gating the
public merge on that fact, not on assurance, is what catches an unshippable proprietary
file before launch rather than after.

### 7. Hooks into the other artifacts
- Testing plan: abuse cases as test cases for the top threats (at least the money and auth
  rows) — security asserted but never exercised is speculation.
- Release plan: security-relevant checklist items (secrets not in artifacts, debug endpoints
  off).
- Maintenance plan: incident basics — how a compromise would be noticed, first three steps,
  and who is told (one paragraph beats a binder nobody opens).

## Failure modes

- **Checklist cosplay** — generic OWASP recitation with no binding to this system's actual
  boundaries. Every threat row names a real surface from §1.
- **Recovery-flow amnesia** — see §3.
- **Mitigations in the subjunctive** — "inputs should be sanitized". Decided mechanism +
  enforcement point, or it doesn't count.
- **Secrets discipline planned, not proven** — the scaffold's `git check-ignore` test and
  lint's secret scan (E12) exist; reference them as the enforcement.
- **Threat-model inflation** — see §2's honesty column. Right-sizing applies to fear too.
