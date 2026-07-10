# Contracts — data, API, and runtime

**Consumer:** every implementer whose work order touches a boundary, and every agent
integrating with the system later. Contracts are the highest-leverage planning artifact for
multi-agent work: two agents who share a contract can work in parallel without talking.
**Produce when:** any boundary exists that another work order, service, or agent consumes.

Template: `templates/contracts.md`.

## Contents

### 1. Data contracts
The entities that cross boundaries or get persisted. Per entity: fields, types, nullability,
units, and **owner** (the one component allowed to write it — echoes architecture §2).

- Units and timezones inline in field descriptions (`amount_minor_units: int — cents, not
  dollars`; `created_at: UTC ISO-8601`). Ambiguous units are the classic silent-corruption bug.
- ID strategy stated once (uuid v4 / auto-increment / prefixed public IDs) and reused.

### 2. API contracts
For each endpoint/command/IPC surface, a table row minimum:

| Method+Path / command | Auth | Request | Response | Errors |
|---|---|---|---|---|
| `POST /api/lists` | session | `{name: str≤100}` | `201 {list}` | `400 invalid`, `401`, `409 duplicate name` |

- **Error cases are part of the contract.** An endpoint whose plan names only the happy path
  will grow inconsistent errors per implementer.
- Pagination, sorting, and filtering conventions: decided once, globally, referenced.
- If the project warrants machine-checkable schemas (OpenAPI, JSON Schema, .proto), the
  contract plan says **where they live in the target repo** and declares them the source of
  truth, with this document as the index. Don't maintain two normative copies —
  that's a contradiction generator.

### 3. Runtime contracts
The agreements between the software and its environment:
- Config & env vars: name, type, default, required-ness. Names and shapes only — **values of
  secrets never appear** (`loom/core/privacy.md`).
- Process model: what runs (services, jobs, schedulers), how it's started, what it assumes
  exists (DB reachable, dir writable).
- Queues/events if any: message shapes are data contracts (§1 rules apply), delivery
  guarantees stated (`at-least-once — consumers must be idempotent`).
- Filesystem/registry/OS integration for desktop apps: paths written, permissions assumed.

### 4. Compatibility & versioning rules
- What may change without coordination (additive fields, new endpoints) vs what is breaking.
- Breaking-change protocol: expand-contract (add new, migrate, remove old) as default;
  anything else is a decision record.
- For public/external APIs: versioning scheme is a `[HUMAN-DECISION]` if consumers exist
  beyond the requester's control.

## Contract-first workflow

When work orders on both sides of a boundary will run in parallel, freeze the contract
*before* either order starts, and mark it `status: frozen` in frontmatter. A frozen contract
changes only through a decision record + notification to both orders (their staleness
pre-check catches it — `loom/execution/staleness.md`).

## Failure modes

- **Happy-path contracts** — no error shapes. See §2.
- **Two sources of truth** — prose contract and schema file drifting apart. Pick one normative
  home.
- **Implicit units/timezones** — see §1.
- **Contracts nobody froze** — parallel orders against a moving boundary; the merge is where
  the plan dies.
- **Secret values as examples** — use `<PLACEHOLDER>`; privacy rule 2.
