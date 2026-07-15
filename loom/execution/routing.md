# Capability routing

Work orders name a capability class, never a vendor or model. The local `routing_map` resolves the
class at execution time.

| Class | Use for |
|---|---|
| `frontier-reasoning` | novel architecture, difficult tradeoffs, uncertain high-consequence work |
| `strong-coding` | implementation with meaningful integration or correctness risk |
| `fast-cheap` | bounded mechanical edits with complete acceptance checks |
| `specialist` | domain work whose invariants require demonstrated specialist capability |
| `human` | authority, judgment, credentials, physical actions, or irreversible approval |

Routing does not authorize an action. Hard stops, owner authority, lifecycle gates, declared
touches, and acceptance evidence still apply. If a mapped capability is unavailable, stop and
reroute; do not silently downgrade. Record the mapping and date in the pack so later execution can
explain which capability was intended without freezing a model name into the methodology.
