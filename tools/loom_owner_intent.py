#!/usr/bin/env python3
"""Pure state-derived planning disposition for Loom owner requests."""

from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass


OPERATIONS = {
    "plan", "execute", "review", "status", "cancel", "recover", "unknown",
}
GENERATION_PHASES = {
    None,
    "absent",
    "reviewable",
    "active",
    "invalid",
    "terminal-completed",
    "terminal-cancelled",
    "terminal-superseded",
    "terminal-quarantined",
}
STATE_ERRORS = {
    None, "STALE_LIFECYCLE", "STALE_TIME", "INVALID_LIFECYCLE",
    "CORRUPT_LIFECYCLE",
}
PROHIBITIONS = {
    "implementation", "mutation", "project-write", "repair", "continuation",
    "new-work",
}
RELATIONS = {
    "new", "revise-exact", "start-exact", "continue-active",
    "repair-active", "read-only", "cancel-generation",
    "supersede-generation", "quarantine-generation", "unclear",
}
MODES = {
    "direct", "candidate-successor", "current-world-replan",
    "inline-recovery",
}
TERMINAL_PHASES = {
    "terminal-completed", "terminal-cancelled", "terminal-superseded",
    "terminal-quarantined",
}
STALE_ERRORS = {"STALE_LIFECYCLE", "STALE_TIME"}
INVALID_ERRORS = {"INVALID_LIFECYCLE", "CORRUPT_LIFECYCLE"}


@dataclass(frozen=True)
class PlanningDisposition:
    relation: str
    mode: str
    preserve_current: bool
    reason_code: str

    def __post_init__(self):
        if not isinstance(self.relation, str) or self.relation not in RELATIONS:
            raise ValueError("planning disposition relation is unknown")
        if not isinstance(self.mode, str) or self.mode not in MODES:
            raise ValueError("planning disposition mode is unknown")
        if type(self.preserve_current) is not bool:
            raise ValueError("planning disposition preservation flag is invalid")
        if not isinstance(self.reason_code, str) \
                or not self.reason_code \
                or not self.reason_code[0].isalpha() \
                or not self.reason_code[0].isupper() \
                or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                       for character in self.reason_code):
            raise ValueError("planning disposition reason code is invalid")


def resolve_planning_disposition(
    *,
    primary_operation: str,
    generation_phase: str | None,
    state_error: str | None,
    prohibitions: Sequence[str],
    exact_reference: bool,
) -> PlanningDisposition:
    """Select one planning mode solely from closed controls and observed state."""
    if not isinstance(primary_operation, str) or primary_operation not in OPERATIONS:
        raise ValueError("planning disposition operation is unknown")
    if primary_operation != "plan":
        raise ValueError("planning disposition requires a planning operation")
    if generation_phase is not None and not isinstance(generation_phase, str) \
            or generation_phase not in GENERATION_PHASES:
        raise ValueError("planning disposition generation phase is unknown")
    if state_error is not None and not isinstance(state_error, str) \
            or state_error not in STATE_ERRORS:
        raise ValueError("planning disposition state error is unknown")
    if type(exact_reference) is not bool:
        raise ValueError("planning disposition exact-reference flag is invalid")
    if isinstance(prohibitions, (str, bytes, Mapping, Set)) \
            or not isinstance(prohibitions, Sequence):
        raise ValueError("planning disposition prohibitions are invalid")
    closed_prohibitions = tuple(prohibitions)
    if any(not isinstance(item, str) for item in closed_prohibitions) \
            or len(closed_prohibitions) != len(set(closed_prohibitions)) \
            or any(item not in PROHIBITIONS for item in closed_prohibitions):
        raise ValueError("planning disposition prohibition is unknown")

    if "project-write" in closed_prohibitions or "mutation" in closed_prohibitions:
        return PlanningDisposition(
            "unclear", "inline-recovery", True, "PROJECT_WRITES_PROHIBITED")
    if state_error in INVALID_ERRORS or generation_phase == "invalid":
        return PlanningDisposition(
            "unclear", "inline-recovery", True, "INVALID_LIFECYCLE")
    if exact_reference:
        if generation_phase == "reviewable" and state_error is None:
            return PlanningDisposition(
                "revise-exact", "candidate-successor", True,
                "EXACT_REVISION")
        if generation_phase in {"reviewable", "active"} \
                and state_error in STALE_ERRORS:
            return PlanningDisposition(
                "revise-exact", "current-world-replan", True,
                "STALE_EXACT_REVISION")
        return PlanningDisposition(
            "revise-exact", "inline-recovery", True,
            "EXACT_REVISION_UNAVAILABLE")
    if state_error in STALE_ERRORS:
        if generation_phase in {"reviewable", "active"}:
            return PlanningDisposition(
                "supersede-generation", "current-world-replan", True,
                "CURRENT_WORLD_REPLAN")
        return PlanningDisposition(
            "unclear", "inline-recovery", True, "STALE_STATE_UNRESOLVED")
    if generation_phase in {None, "absent"} or generation_phase in TERMINAL_PHASES:
        return PlanningDisposition("new", "direct", False, "DIRECT_PLAN")
    if generation_phase in {"reviewable", "active"}:
        return PlanningDisposition(
            "supersede-generation", "candidate-successor", True,
            "CANDIDATE_SUCCESSOR")
    return PlanningDisposition(
        "unclear", "inline-recovery", True, "STATE_UNAVAILABLE")
