#!/usr/bin/env python3
"""Bounded human receipts and reversible adaptation controls for Loom."""

import re
import json
from pathlib import Path

import loom_memory


MAX_RENDER_CHARS = 800


class TransparencyError(RuntimeError):
    pass


def compact_receipt(value):
    """Translate sealed structured state into the eight questions an owner cares about."""
    required = {
        "intent", "tier", "domains", "status", "code", "reversible_action_ids",
        "outcome_ids", "adaptation_receipts", "archived_count", "uncertainty_codes",
        "owner_input_required", "user_message",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        raise TransparencyError("sealed receipt lacks transparency fields")
    domains = ", ".join(value["domains"][:3]) or "unknown domain"
    understood = f"{value['intent']} work for {domains}, size {value['tier']}"
    if value["status"] == "completed":
        did = value["user_message"] or "Completed the safe part of this request."
    else:
        did = value["user_message"] or "Stopped before an unsafe or uncertain change."
    changed_count = len(value["reversible_action_ids"])
    learned_count = (len(value["outcome_ids"]) + len(value["adaptation_receipts"])
                     + len(value.get("improvement_evidence_ids", [])))
    uncertainties = list(value["uncertainty_codes"])
    owner_needed = bool(value["owner_input_required"])
    return {
        "understood": understood,
        "did": did,
        "changed": (f"{changed_count} reversible adaptation"
                    f"{'s' if changed_count != 1 else ''}"),
        "learned": (f"{learned_count} evidence-backed update"
                    f"{'s' if learned_count != 1 else ''}"),
        "archived": f"{int(value['archived_count'])} inactive context records",
        "uncertain": ", ".join(uncertainties) if uncertainties else "nothing material",
        "owner_input_needed": owner_needed,
        "next": ("One owner decision is needed." if owner_needed
                 else "Continue with the next safe frontier when ready."),
    }


def render_compact_receipt(receipt):
    labels = (
        ("Understood", "understood"), ("Did", "did"), ("Changed", "changed"),
        ("Learned", "learned"), ("Archived", "archived"),
        ("Uncertain", "uncertain"), ("Next", "next"),
    )
    text = "\n".join(f"{label}: {receipt[key]}" for label, key in labels)
    if len(text) > MAX_RENDER_CHARS:
        raise TransparencyError("compact receipt exceeded its owner-facing bound")
    return text


def explain_receipt(value):
    """Explain one sealed decision using only bounded identifiers and sealed evidence."""
    required = {
        "intent", "status", "code", "receipt_hash", "world_fingerprint",
        "selected_memory_ids", "outcome_ids",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        raise TransparencyError("receipt cannot support an evidence explanation")
    memory = ", ".join(value["selected_memory_ids"][:8]) or "none"
    outcomes = ", ".join(value["outcome_ids"][:8]) or "none"
    return (
        f"I chose {value['intent']} and finished as {value['status']} ({value['code']}). "
        f"Sealed evidence receipt: {value['receipt_hash']}. "
        f"World evidence: {value['world_fingerprint']}. "
        f"Memory IDs used: {memory}. Other records were excluded by scope, lifecycle state, "
        f"or the bounded context limit; their contents remain private. "
        f"Outcome IDs recorded: {outcomes}."
    )


def _memory_reference(text, records):
    identifiers = re.findall(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        str(text).lower())
    by_id = {item.get("id"): item for item in records if isinstance(item, dict)}
    if identifiers:
        if len(set(identifiers)) != 1 or identifiers[0] not in by_id:
            raise TransparencyError("memory reference is unknown or ambiguous")
        return identifiers[0]
    words = set(re.findall(r"[a-z0-9][a-z0-9._-]+", str(text).lower())) - {
        "forget", "that", "this", "memory", "remember", "about", "please",
    }
    ranked = []
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        searchable = " ".join(str(item.get(key, "")) for key in (
            "statement", "preference_key", "preference_value"))
        overlap = len(words & set(re.findall(
            r"[a-z0-9][a-z0-9._-]+", searchable.lower())))
        if overlap:
            ranked.append((overlap, item["id"]))
    ranked.sort(reverse=True)
    if not ranked or len(ranked) > 1 and ranked[0][0] == ranked[1][0]:
        raise TransparencyError("memory reference is unknown or ambiguous")
    return ranked[0][1]


def forget_memory(home, instance_id, text, selected_records):
    """Resolve one bounded reference, perform the durable write, then return success."""
    record_id = _memory_reference(text, selected_records)
    if not loom_memory.forget(home, instance_id, record_id):
        raise TransparencyError("memory was not available to forget")
    forgotten = loom_memory.inspect_record(home, instance_id, record_id)
    if forgotten != {"id": record_id, "status": "forgotten", "content_erased": True}:
        raise TransparencyError("forget write did not seal content erasure")
    return {"written": True, "memory_id": record_id,
            "message": f"Forgot memory {record_id}."}


def profile_summary(home, instance_id, *, max_chars=1200):
    """Return only bounded global owner memory, never dormant domain/project material."""
    if type(max_chars) is not int or not 128 <= max_chars <= 4000:
        raise TransparencyError("profile summary bound is invalid")
    records = loom_memory.select(
        home, instance_id, domain=None, project_id=None,
        max_chars=min(4000, max_chars * 2))
    lines = ["What Loom currently remembers about you:"]
    for item in records:
        if item.get("scope") != "global":
            continue
        if item.get("category") == "preference":
            line = f"- {item['preference_key']}: {item['preference_value']}"
        else:
            line = f"- {item['statement']} ({item['provenance']}, {item['confidence']:.2f})"
        candidate = "\n".join(lines + [line])
        if len(candidate) > max_chars:
            break
        lines.append(line)
    if len(lines) == 1:
        lines.append("- Nothing transferable has been retained yet.")
    return "\n".join(lines)


class ActionLedger:
    """Bounded, instance-local record of adaptations that can be undone once."""

    MAX_ACTIONS = 128
    TARGET_FIELDS = {"key", "domain", "task_class", "risk_class", "subject"}

    def __init__(self, home, instance_id):
        loom_memory.validate_instance(home, instance_id)
        self.instance_id = instance_id
        self.directory = Path(home) / "instances" / instance_id
        self.path = self.directory / "reversible-actions.json"
        self.lock = self.directory / ".reversible-actions.lock"

    def _empty(self):
        return {"schema_version": 1, "instance_id": self.instance_id, "actions": []}

    def _read(self):
        if not self.path.exists():
            return self._empty()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise TransparencyError(f"reversible action ledger is corrupt: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "actions"} \
                or value.get("schema_version") != 1 \
                or value.get("instance_id") != self.instance_id \
                or not isinstance(value.get("actions"), list) \
                or len(value["actions"]) > self.MAX_ACTIONS:
            raise TransparencyError("reversible action ledger contract is invalid")
        for action in value["actions"]:
            if not isinstance(action, dict) or set(action) != {
                    "action_id", "kind", "target", "evidence_ids", "status", "created_at"} \
                    or action.get("kind") != "preference" \
                    or action.get("status") not in {"active", "undoing", "undone"} \
                    or not isinstance(action.get("target"), dict) \
                    or set(action["target"]) != self.TARGET_FIELDS:
                raise TransparencyError("reversible action entry is invalid")
        return value

    def record(self, *, action_id, kind, target, evidence_ids):
        if not isinstance(action_id, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,127}", action_id) \
                or kind != "preference" or not isinstance(target, dict) \
                or set(target) != self.TARGET_FIELDS \
                or not isinstance(evidence_ids, list) or not evidence_ids:
            raise TransparencyError("reversible action inputs are invalid")
        with loom_memory.FileLock(self.lock):
            store = self._read()
            existing = next((item for item in store["actions"]
                             if item["action_id"] == action_id), None)
            if existing is not None:
                if existing["target"] != target or existing["evidence_ids"] != evidence_ids:
                    raise TransparencyError("action id is already bound to other evidence")
                return json.loads(json.dumps(existing))
            action = {"action_id": action_id, "kind": kind,
                      "target": dict(target), "evidence_ids": list(evidence_ids),
                      "status": "active", "created_at": loom_memory._now()}
            store["actions"] = (store["actions"] + [action])[-self.MAX_ACTIONS:]
            loom_memory._atomic_json(self.path, store)
            return json.loads(json.dumps(action))

    def undo_latest(self, preferences):
        with loom_memory.FileLock(self.lock):
            store = self._read()
            action = next((item for item in reversed(store["actions"])
                           if item["status"] == "active"), None)
            if action is None:
                if any(item["status"] == "undoing" for item in store["actions"]):
                    raise TransparencyError("undo recovery is required before another adaptation")
                raise TransparencyError("no reversible adaptation is available")
            action["status"] = "undoing"
            loom_memory._atomic_json(self.path, store)
            target = action["target"]
            receipt = preferences.undo(
                key=target["key"], domain=target["domain"],
                task_class=target["task_class"], risk_class=target["risk_class"],
                subject=target["subject"])
            action["status"] = "undone"
            loom_memory._atomic_json(self.path, store)
            return {"action_id": action["action_id"], "written": True,
                    "message": f"Undid the latest adaptation. {receipt['message']}"}
