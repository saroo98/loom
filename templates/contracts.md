---
artifact: contracts
project: "<name>"
tier: <M|L|XL>
status: draft            # draft | gated | frozen | stale — frozen changes only via decision record
last_verified: <YYYY-MM-DD>
loom_version: "0.8.0"
depends_on: [architecture-plan?]
---

# Contracts — <project>

<!-- Guide: loom/planning/contracts.md. If machine schemas (OpenAPI/JSON Schema/.proto)
     exist in the target repo, THEY are normative and this doc is the index — one home. -->

## 1. Data contracts
<!-- Per boundary-crossing/persisted entity: fields, types, nullability, UNITS, timezones,
     OWNER. ID strategy stated once. -->

## 2. API contracts
| Method+Path / command | Auth | Request | Response | Errors |
|---|---|---|---|---|

<!-- Error cases are part of the contract. Pagination/sorting/filtering conventions: once,
     globally, here. -->

## 3. Runtime contracts
<!-- Env/config: name, type, default, required — NEVER values of secrets. Process model.
     Queue/event message shapes (§1 rules) + delivery guarantees. Desktop: filesystem/
     registry/permissions assumptions. -->

## 4. Compatibility & versioning
<!-- Additive vs breaking; expand-contract as default protocol; external-consumer
     versioning = [HUMAN-DECISION] if applicable. -->

## Freeze log
| Contract | Frozen at | Unfreeze decision |
|---|---|---|

## Verification hooks
<!-- e.g. "renderer + editor both pass contract test suite X"; "schema file and this index
     agree (diff check)". -->
