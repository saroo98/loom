# Plan authoring

A planning artifact exists only when a named consumer needs it to make a named decision. Use the
artifact matrix to produce, adapt, or explicitly skip each candidate.

Every produced artifact has frontmatter status and `last_verified`, cites assumptions/decisions,
and contains only information relevant to its consumer. Repeating the intake in several files is
not depth. Tier S uses one compact work order; larger tiers add artifacts only as risk and
coordination require.

Before G1, verify cross-artifact references, assumption usage, domain invariants, acceptance
media, rollback, and work-order dependency/touch boundaries. Freeze the plan only after the G1
review passes. After target or time drift, mark affected artifacts stale and regate them; never
refresh a date without rerunning the named verification.
