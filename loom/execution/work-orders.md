# Work-order contract

A work order is the smallest independently executable and verifiable unit of implementation.

It must name intent, context, preconditions, bounded task, checked acceptance criteria, out of
scope, escalation triggers, epistemic notes, routing class, dependencies, and declared `touches`.
Status begins `ready` only after G1 authorization. The implementer claims one work order, performs
only its declared scope, and records real-medium close-out evidence.

Completion is mechanical: status is `done`, every criterion is checked, current acceptance
evidence validates, at least one declared target changed after authorization, no undeclared target
changed, and the lifecycle gate records hashes and changed paths. Existing deliverables and prose
claims cannot receive causal plan credit.
