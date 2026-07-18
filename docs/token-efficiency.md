# Token efficiency and performance truth

Loom separates correctness from measurement. A host that exposes no trustworthy usage data may
complete work; the receipt says `unavailable` and cannot certify token performance. Supplied data
that is malformed, contradictory, incomplete while claiming completeness, or identity-reused is
rejected.

Usage receipt v3 records every model response attempt as an event. Cache reads, cache writes,
reasoning, tool traffic, and retries are never blindly added. Each provider profile declares which
counters are subsets, disjoint components, or governed only by the provider total. Existing v1/v2
five-counter records remain readable as `legacy-ambiguous`; their old declared sum is historical
only and never drives certification or automatic budgets.

Tier S is the proportional fast path. It remains one lifecycle and one work order, with at most
five declared touches, one atomic outcome, 3,000 characters, 40 lines, 900 lexical tokens, a
4,096-byte dynamic host capsule, and 512 characters of selected owner memory. Unknown coverage,
consequential changes, new boundaries, irreversible work, multiple outcomes, or insufficient
verification promote the task before authorization.

Local spans use monotonic durations and bounded numeric counters. They never contain prompts,
repository bodies, memory statements, secrets, or telemetry. Provider prompt caching is optional
host behavior, never a correctness dependency or freshness authority.

Cache behavior is governed by `contracts/cache-classes-v1.json`. Static guidance, host adapters,
project routing, domain authority, owner selection, and provider prefixes have distinct generation
keys. A dependency change invalidates only its descendants. Every cache receipt declares
`authorizes_execution: false`; live world-state and lifecycle gates are always re-evaluated.
