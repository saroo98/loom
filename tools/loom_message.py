#!/usr/bin/env python3
"""Closed, bounded owner-message envelopes for Loom's one-command surface."""

import re


STATES = {
    "progress", "completed", "decision-needed", "blocked", "stale",
    "uncertain", "promoted", "failed",
}
CONSEQUENCES = {"ordinary", "material", "high", "critical"}
VERIFICATION = {"pending", "verified", "blocked", "failed", "unknown"}
FRESHNESS = {"current", "stale", "unknown", "not-applicable"}
INTERVENTIONS = {"decision-needed", "blocked", "stale", "uncertain", "failed"}
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_HUMAN_CHARS = 600


class MessageError(ValueError):
    pass


def _text(value, label, *, maximum=240, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > maximum \
            or "\n" in value or "\r" in value:
        raise MessageError(f"{label} is invalid")
    return value.strip()


def _render(value):
    first = (
        f"{value['summary']} Consequence: {value['consequence']}; "
        f"verification: {value['verification']}; freshness: {value['freshness']}; "
        f"reversible: {'yes' if value['reversible'] else 'no'}."
    )
    if value["state"] in INTERVENTIONS:
        second = (
            f"Decision: {value['decision']} Recommended: {value['recommendation']} "
            f"Next: {value['next_action']} Receipt: {value['receipt_id']}."
        )
    else:
        second = f"Next: {value['next_action']} Receipt: {value['receipt_id']}."
    return first + "\n" + second


def validate(value):
    fields = {
        "schema_version", "state", "consequence", "verification", "freshness",
        "reversible", "summary", "decision", "recommendation", "next_action",
        "receipt_id", "human",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("state") not in STATES \
            or value.get("consequence") not in CONSEQUENCES \
            or value.get("verification") not in VERIFICATION \
            or value.get("freshness") not in FRESHNESS \
            or type(value.get("reversible")) is not bool \
            or not isinstance(value.get("receipt_id"), str) \
            or not SAFE_ID.fullmatch(value["receipt_id"]):
        raise MessageError("owner message fields are invalid")
    _text(value["summary"], "summary")
    _text(value["next_action"], "next action")
    intervention = value["state"] in INTERVENTIONS
    if intervention:
        _text(value["decision"], "decision")
        _text(value["recommendation"], "recommendation")
    elif value["decision"] is not None or value["recommendation"] is not None:
        raise MessageError("non-intervention message cannot contain an owner decision")
    human = value.get("human")
    if not isinstance(human, str) or not human.strip() \
            or len(human) > MAX_HUMAN_CHARS or "\r" in human \
            or human.count("\n") > 1 or human != _render(value):
        raise MessageError("owner message exceeds two lines")
    return value


def build(*, state, consequence, verification, freshness, reversible, summary,
          next_action, receipt_id, decision=None, recommendation=None):
    summary = _text(summary, "summary")
    next_action = _text(next_action, "next action")
    decision = _text(decision, "decision", nullable=True)
    recommendation = _text(recommendation, "recommendation", nullable=True)
    value = {
        "schema_version": 1, "state": state, "consequence": consequence,
        "verification": verification, "freshness": freshness,
        "reversible": bool(reversible), "summary": summary,
        "decision": decision, "recommendation": recommendation,
        "next_action": next_action, "receipt_id": receipt_id,
        "human": "",
    }
    value["human"] = _render(value)
    return validate(value)


def from_session(*, status, code, tier, owner_input_required, reversible_action_ids,
                 detail, receipt_id):
    """Project a sealed session result into one safe owner-facing envelope."""
    if status not in {"completed", "blocked", "interrupted"} \
            or tier not in {"S", "M", "L", "XL"} \
            or type(owner_input_required) is not bool \
            or not isinstance(reversible_action_ids, (list, tuple)):
        raise MessageError("session message inputs are invalid")
    consequence = {"S": "ordinary", "M": "material", "L": "high", "XL": "critical"}[tier]
    low = str(code).casefold()
    if status == "completed":
        state = "promoted" if "promot" in low else "completed"
        verification = "verified"
        freshness = "current"
        summary = "Loom completed the safe verified frontier."
        next_action = "Continue with the next safe frontier when ready."
        decision = recommendation = None
    else:
        preference_conflict = "preference-conflict" in low
        state = ("decision-needed" if preference_conflict else
                 "stale" if "stale" in low or "regate" in low else
                 "failed" if status == "interrupted" else
                 "decision-needed" if owner_input_required else "blocked")
        verification = "failed" if status == "interrupted" else "blocked"
        freshness = "stale" if state == "stale" else "unknown"
        if preference_conflict:
            summary = "Two stated preferences conflict, so Loom did not choose one silently."
            decision = "State which preference should apply to this work."
            recommendation = "Keep both conflicting preferences inactive until you choose."
            next_action = "Reply with the preference to retain, or leave this work unchanged."
        else:
            summary = "Loom stopped before the affected work could continue."
            decision = "Choose whether to resolve the reported block and continue."
            recommendation = "Keep the affected work stopped and inspect the sealed receipt."
            next_action = "Resolve the single blocking decision or leave the work unchanged."
    return build(
        state=state, consequence=consequence, verification=verification,
        freshness=freshness, reversible=bool(reversible_action_ids),
        summary=summary, decision=decision, recommendation=recommendation,
        next_action=next_action, receipt_id=receipt_id)
