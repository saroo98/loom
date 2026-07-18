#!/usr/bin/env python3
"""Deterministic continuation-authority policy for Loom actions."""

import hashlib
import json


CONSEQUENCES = {"ordinary", "material", "high", "critical"}
FACT_FIELDS = {
    "reversible", "destructive", "inside_scope", "external_effect", "cost",
    "privileged", "privacy_expanding", "legal_or_safety_judgment", "uncertain",
    "currently_evidenced", "verifiable_before_harm", "consequence",
}


class AuthorityError(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")).hexdigest()


def validate_facts(value):
    if not isinstance(value, dict) or set(value) != FACT_FIELDS \
            or value.get("consequence") not in CONSEQUENCES \
            or any(type(value.get(field)) is not bool
                   for field in FACT_FIELDS - {"consequence"}):
        raise AuthorityError("continuation authority facts are invalid")
    return value


def decide(facts, *, owner_authorized=False):
    facts = dict(validate_facts(facts))
    if type(owner_authorized) is not bool:
        raise AuthorityError("owner authority flag is invalid")
    blockers = []
    checks = (
        (not facts["reversible"], "irreversible"),
        (facts["destructive"], "destructive"),
        (not facts["inside_scope"], "outside-scope"),
        (facts["external_effect"], "external-effect"),
        (facts["cost"], "cost"),
        (facts["privileged"], "privileged"),
        (facts["privacy_expanding"], "privacy-expanding"),
        (facts["legal_or_safety_judgment"], "legal-or-safety-judgment"),
        (facts["uncertain"], "uncertain"),
        (not facts["currently_evidenced"], "evidence-not-current"),
        (not facts["verifiable_before_harm"], "not-verifiable-before-harm"),
        (facts["consequence"] != "ordinary", "consequential"),
    )
    blockers = [reason for blocked, reason in checks if blocked]
    if not blockers:
        mode = "automatic"
        rationale = "reversible, scoped, ordinary, current, and verifiable before harm"
        undo = "revert the bounded local action using its receipt"
    elif owner_authorized:
        mode = "explicit-authority"
        rationale = "the owner request explicitly authorizes a non-automatic action"
        undo = None
    else:
        mode = "decision-needed"
        rationale = "one or more automatic-continuation conditions are not proved"
        undo = None
    body = {
        "schema_version": 1, "mode": mode, "facts": facts,
        "blockers": blockers, "owner_authorized": owner_authorized,
        "rationale": rationale, "undo": undo,
    }
    return {**body, "authority_digest": _digest(body)}


def validate(value):
    fields = {
        "schema_version", "mode", "facts", "blockers", "owner_authorized",
        "rationale", "undo", "authority_digest",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("mode") not in {
                "automatic", "explicit-authority", "decision-needed"} \
            or type(value.get("owner_authorized")) is not bool \
            or not isinstance(value.get("blockers"), list) \
            or len(value["blockers"]) != len(set(value["blockers"])) \
            or not isinstance(value.get("rationale"), str) or not value["rationale"] \
            or value.get("authority_digest") != _digest({
                key: value[key] for key in fields - {"authority_digest"}}):
        raise AuthorityError("continuation authority receipt is invalid")
    validate_facts(value["facts"])
    expected = decide(value["facts"], owner_authorized=value["owner_authorized"])
    if value != expected:
        raise AuthorityError("continuation authority receipt does not match policy")
    return value


def facts_for_intent(intent, *, stale=False):
    """Fail-closed production defaults; host-specific effects may only add blockers."""
    if intent not in {
            "plan", "resume", "execute", "review", "repair", "close", "status",
            "remember", "forget", "why", "undo"}:
        raise AuthorityError("intent is invalid")
    automatic = intent in {"plan", "resume", "review", "repair", "status", "why"}
    destructive = intent == "forget"
    unknown_effect = intent in {"execute", "close", "remember", "forget", "undo"}
    return {
        "reversible": automatic,
        "destructive": destructive,
        "inside_scope": True,
        "external_effect": intent == "execute",
        "cost": False,
        "privileged": intent == "execute",
        "privacy_expanding": intent == "remember",
        "legal_or_safety_judgment": False,
        "uncertain": unknown_effect,
        "currently_evidenced": not stale,
        "verifiable_before_harm": automatic,
        "consequence": "ordinary" if automatic else "material",
    }
