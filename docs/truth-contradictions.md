# Loom truth contradictions

Mode: **shadow**
Evaluated at: `2026-07-28T12:00:00Z`
Next invalidation: `none`

Unsafe evidence is downgraded in every mode. Shadow mode changes only whether non-safety contradictions fail CI.

| Fact | Reason | Governing source | Affected claims | Repair |
| --- | --- | --- | --- | --- |
| `expected-subject-set` | EXPECTED_SUBJECT_UNAVAILABLE | `expected-subjects` | claim:capabilities, claim:readiness, projection:public-docs | `downgrade-claim` |

## Advisory prose

- `README.md`: Version prose is advisory because this location is not a registered structured projection. (`UNREGISTERED_VERSION_PROSE`)
- `docs/roadmap-v3.md`: Version prose is advisory because this location is not a registered structured projection. (`UNREGISTERED_VERSION_PROSE`)

Report digest: `9c6a34e863f8fc86783ea17f3edcdb22e5bf88cc1bad0faa35ce59c50e57d494`
