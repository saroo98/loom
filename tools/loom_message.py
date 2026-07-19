#!/usr/bin/env python3
"""Closed, bounded owner-message envelopes for Loom's one-command surface."""

import re

import loom_block_reason


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
UNDO_STATUSES = {"available", "not-applicable", "unavailable", "unknown"}
TRANSITIONAL_UNDO_STATUSES = {"available", "not-available", "not-needed", "unknown"}


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
    changes = ("unknown" if value["changes_made"] is None else
               "made" if value["changes_made"] else "none")
    first = (
        f"{value['summary']} Consequence: {value['consequence']}; "
        f"verification: {value['verification']}; freshness: {value['freshness']}; "
        f"changes: {changes}; undo: {value['undo_status']}."
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
    if isinstance(value, dict) and value.get("schema_version") == 1:
        return _validate_legacy(value)
    if isinstance(value, dict) and value.get("schema_version") == 2:
        return _validate_v2(value)
    fields = {
        "schema_version", "state", "consequence", "verification", "freshness",
        "changes_made", "undo_status", "summary", "decision", "recommendation", "next_action",
        "receipt_id", "human",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 3 \
            or value.get("state") not in STATES \
            or value.get("consequence") not in CONSEQUENCES \
            or value.get("verification") not in VERIFICATION \
            or value.get("freshness") not in FRESHNESS \
            or (value.get("changes_made") is not None
                and type(value.get("changes_made")) is not bool) \
            or value.get("undo_status") not in UNDO_STATUSES \
            or not isinstance(value.get("receipt_id"), str) \
            or not SAFE_ID.fullmatch(value["receipt_id"]):
        raise MessageError("owner message fields are invalid")
    if (value["changes_made"] is False and value["undo_status"] != "not-applicable") \
            or (value["changes_made"] is None and value["undo_status"] != "unknown") \
            or (value["changes_made"] is True and value["undo_status"] not in {
                "available", "unavailable"}):
        raise MessageError("owner message change and undo status disagree")
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


def build(*, state, consequence, verification, freshness, changes_made, undo_status, summary,
          next_action, receipt_id, decision=None, recommendation=None):
    summary = _text(summary, "summary")
    next_action = _text(next_action, "next action")
    decision = _text(decision, "decision", nullable=True)
    recommendation = _text(recommendation, "recommendation", nullable=True)
    value = {
        "schema_version": 3, "state": state, "consequence": consequence,
        "verification": verification, "freshness": freshness,
        "changes_made": changes_made, "undo_status": undo_status, "summary": summary,
        "decision": decision, "recommendation": recommendation,
        "next_action": next_action, "receipt_id": receipt_id,
        "human": "",
    }
    value["human"] = _render(value)
    return validate(value)


def from_session(*, status, code, intent, tier, owner_input_required, reversible_action_ids,
                 detail, receipt_id, block_reason=None):
    """Project a sealed session result into one safe owner-facing envelope."""
    if status not in {"completed", "blocked", "interrupted"} \
            or intent not in {
                "plan", "resume", "execute", "review", "repair", "close", "status",
                "remember", "forget", "why", "undo"} \
            or tier not in {"S", "M", "L", "XL"} \
            or type(owner_input_required) is not bool \
            or not isinstance(reversible_action_ids, (list, tuple)):
        raise MessageError("session message inputs are invalid")
    consequence = {"S": "ordinary", "M": "material", "L": "high", "XL": "critical"}[tier]
    low = str(code).casefold()
    normalized_detail = " ".join(str(detail or "").split())[:180].strip()
    if status == "completed":
        if block_reason is not None:
            raise MessageError("completed session cannot carry a block reason")
        state = "promoted" if "promot" in low else "completed"
        verification = "verified"
        freshness = "current"
        summary = "Loom completed the safe verified frontier."
        next_action = "Continue with the next safe frontier when ready."
        decision = recommendation = None
        changes_made = intent in {
            "plan", "execute", "repair", "close", "remember", "forget", "undo"}
        undo_status = ("available" if reversible_action_ids else
                       "unavailable" if changes_made else "not-applicable")
    else:
        preference_conflict = "preference-conflict" in low
        state = ("decision-needed" if preference_conflict else
                 "stale" if "stale" in low or "regate" in low else
                 "failed" if status == "interrupted" else
                 "decision-needed" if owner_input_required else "blocked")
        verification = "failed" if status == "interrupted" else "blocked"
        freshness = "stale" if state == "stale" else "unknown"
        if block_reason is not None:
            try:
                loom_block_reason.validate(block_reason)
            except loom_block_reason.BlockReasonError as exc:
                raise MessageError(f"session block reason is invalid: {exc}") from exc
            location = f" at {block_reason['safe_path']}" \
                if block_reason["safe_path"] else ""
            summary = f"Loom stopped{location}: {block_reason['observed']}"[:240].rstrip()
            decision = "No implementation or fallback is authorized by this receipt."
            recommendation = "Follow the receipt's exact bounded next action."
            next_action = block_reason["next_action"]
        elif preference_conflict:
            summary = "Two stated preferences conflict, so Loom did not choose one silently."
            decision = "State which preference should apply to this work."
            recommendation = "Keep both conflicting preferences inactive until you choose."
            next_action = "Reply with the preference to retain, or leave this work unchanged."
        else:
            summary = (f"Loom stopped: {normalized_detail}"
                       if normalized_detail else
                       "Loom stopped before the affected work could continue.")
            decision = "Choose whether to resolve the reported block and continue."
            recommendation = "Keep the affected work stopped and inspect the sealed receipt."
            next_action = "Resolve the single blocking decision or leave the work unchanged."
        if status == "interrupted":
            changes_made, undo_status = None, "unknown"
        else:
            changes_made, undo_status = False, "not-applicable"
    return build(
        state=state, consequence=consequence, verification=verification,
        freshness=freshness, changes_made=changes_made, undo_status=undo_status,
        summary=summary, decision=decision, recommendation=recommendation,
        next_action=next_action, receipt_id=receipt_id)


def _validate_v2(value):
    fields = {
        "schema_version", "state", "consequence", "verification", "freshness",
        "changes_made", "undo_status", "summary", "decision", "recommendation",
        "next_action", "receipt_id", "human",
    }
    if set(value) != fields or value.get("schema_version") != 2 \
            or value.get("state") not in STATES \
            or value.get("consequence") not in CONSEQUENCES \
            or value.get("verification") not in VERIFICATION \
            or value.get("freshness") not in FRESHNESS \
            or (value.get("changes_made") is not None
                and type(value.get("changes_made")) is not bool) \
            or value.get("undo_status") not in TRANSITIONAL_UNDO_STATUSES \
            or not isinstance(value.get("receipt_id"), str) \
            or not SAFE_ID.fullmatch(value["receipt_id"]):
        raise MessageError("transitional owner message fields are invalid")
    if (value["changes_made"] is False and value["undo_status"] != "not-needed") \
            or (value["changes_made"] is None and value["undo_status"] != "unknown") \
            or (value["changes_made"] is True and value["undo_status"] not in {
                "available", "not-available"}):
        raise MessageError("transitional owner message change and undo status disagree")
    _text(value["summary"], "summary")
    _text(value["next_action"], "next action")
    intervention = value["state"] in INTERVENTIONS
    if intervention:
        _text(value["decision"], "decision")
        _text(value["recommendation"], "recommendation")
    elif value["decision"] is not None or value["recommendation"] is not None:
        raise MessageError("transitional non-intervention message has an owner decision")
    if not isinstance(value.get("human"), str) or value["human"] != _render(value):
        raise MessageError("transitional owner message rendering is invalid")
    return value


def v2_from_session(*, status, code, intent, tier, owner_input_required,
                    reversible_action_ids, detail, receipt_id):
    """Reconstruct the short-lived v2 projection for sealed receipt compatibility."""
    current = from_session(
        status=status, code=code, intent=intent, tier=tier,
        owner_input_required=owner_input_required,
        reversible_action_ids=reversible_action_ids, detail=detail,
        receipt_id=receipt_id, block_reason=None)
    value = dict(current)
    value["schema_version"] = 2
    value["undo_status"] = {
        "not-applicable": "not-needed", "unavailable": "not-available",
    }.get(value["undo_status"], value["undo_status"])
    value["human"] = _render(value)
    return _validate_v2(value)


def v2_build(*, state, consequence, verification, freshness, changes_made,
             undo_status, summary, next_action, receipt_id, decision=None,
             recommendation=None):
    """Reconstruct a v2 action message only to authenticate existing actions."""
    value = {
        "schema_version": 2, "state": state, "consequence": consequence,
        "verification": verification, "freshness": freshness,
        "changes_made": changes_made, "undo_status": undo_status,
        "summary": _text(summary, "summary"),
        "decision": _text(decision, "decision", nullable=True),
        "recommendation": _text(recommendation, "recommendation", nullable=True),
        "next_action": _text(next_action, "next action"),
        "receipt_id": receipt_id, "human": "",
    }
    value["human"] = _render(value)
    return _validate_v2(value)


def _legacy_render(value):
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


def _validate_legacy(value):
    fields = {
        "schema_version", "state", "consequence", "verification", "freshness",
        "reversible", "summary", "decision", "recommendation", "next_action",
        "receipt_id", "human",
    }
    if set(value) != fields or value.get("schema_version") != 1 \
            or value.get("state") not in STATES \
            or value.get("consequence") not in CONSEQUENCES \
            or value.get("verification") not in VERIFICATION \
            or value.get("freshness") not in FRESHNESS \
            or type(value.get("reversible")) is not bool \
            or not isinstance(value.get("receipt_id"), str) \
            or not SAFE_ID.fullmatch(value["receipt_id"]):
        raise MessageError("legacy owner message fields are invalid")
    _text(value["summary"], "summary")
    _text(value["next_action"], "next action")
    intervention = value["state"] in INTERVENTIONS
    if intervention:
        _text(value["decision"], "decision")
        _text(value["recommendation"], "recommendation")
    elif value["decision"] is not None or value["recommendation"] is not None:
        raise MessageError("legacy non-intervention message cannot contain an owner decision")
    if not isinstance(value.get("human"), str) or value["human"] != _legacy_render(value):
        raise MessageError("legacy owner message rendering is invalid")
    return value


def legacy_from_session(*, status, code, tier, owner_input_required,
                        reversible_action_ids, detail, receipt_id):
    """Reconstruct a v1 owner message only to authenticate historical receipts."""
    consequence = {"S": "ordinary", "M": "material", "L": "high", "XL": "critical"}[tier]
    low = str(code).casefold()
    if status == "completed":
        state = "promoted" if "promot" in low else "completed"
        verification, freshness = "verified", "current"
        summary = "Loom completed the safe verified frontier."
        next_action = "Continue with the next safe frontier when ready."
        decision = recommendation = None
    else:
        conflict = "preference-conflict" in low
        state = ("decision-needed" if conflict else "stale" if "stale" in low or "regate" in low
                 else "failed" if status == "interrupted" else
                 "decision-needed" if owner_input_required else "blocked")
        verification = "failed" if status == "interrupted" else "blocked"
        freshness = "stale" if state == "stale" else "unknown"
        if conflict:
            summary = "Two stated preferences conflict, so Loom did not choose one silently."
            decision = "State which preference should apply to this work."
            recommendation = "Keep both conflicting preferences inactive until you choose."
            next_action = "Reply with the preference to retain, or leave this work unchanged."
        else:
            summary = "Loom stopped before the affected work could continue."
            decision = "Choose whether to resolve the reported block and continue."
            recommendation = "Keep the affected work stopped and inspect the sealed receipt."
            next_action = "Resolve the single blocking decision or leave the work unchanged."
    value = {
        "schema_version": 1, "state": state, "consequence": consequence,
        "verification": verification, "freshness": freshness,
        "reversible": bool(reversible_action_ids), "summary": summary,
        "decision": decision, "recommendation": recommendation,
        "next_action": next_action, "receipt_id": receipt_id, "human": "",
    }
    value["human"] = _legacy_render(value)
    return _validate_legacy(value)
