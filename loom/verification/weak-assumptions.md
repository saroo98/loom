# Weak-assumption audit

Review every open assumption before G1 and before any work order that consumes it.

Flag an assumption when its basis is circular, stale, anonymous, contradicted, outside the
author's domain, or weaker than the consequence it supports. High-risk assumptions require a
named verification method and owner. Cross-reference `used_in` against actual artifacts; an
unlisted consumer is a lint failure, not an informal exception.

The audit passes only when each load-bearing assumption is verified, explicitly accepted by the
proper authority, or converted to `[UNKNOWN]` that blocks the affected work. Never lower risk or
rewrite wording merely to clear the gate.
