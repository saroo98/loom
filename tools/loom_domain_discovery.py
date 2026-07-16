#!/usr/bin/env python3
"""Bounded, resumable discovery planning without a Loom network client."""

import datetime as dt

import loom_domain_contract


MAX_QUESTIONS = 8
MAX_RETRIEVAL_ROUNDS = 2
MAX_SOURCES = 20
MAX_INVARIANTS = 32
MAX_CAPSULE_CHARS = 8192

QUESTIONS = (
    ("target", "What exact object, process, population, or physical system is changing?"),
    ("harm", "Who or what can be harmed, and what is the worst credible irreversible result?"),
    ("applicability", "Which jurisdiction, product class, environment, version, or revision applies?"),
    ("authority", "Which authority classes govern the decision?"),
    ("invariants", "Which conditions must remain true before, during, and after the change?"),
    ("failure", "Which failure modes must the release prevent or recover from?"),
    ("medium", "What real medium can verify each material invariant?"),
    ("escalation", "Which unknowns require owner, qualified expert, regulator, vendor, or physical-test evidence?"),
)


class DomainDiscoveryError(ValueError):
    pass


def _questions(route, answers):
    answers = answers or {}
    if not isinstance(answers, dict) or set(answers) - {item[0] for item in QUESTIONS}:
        raise DomainDiscoveryError("discovery answers contain unknown fields")
    missing = []
    for key, text in QUESTIONS:
        if not isinstance(answers.get(key), str) or not answers[key].strip():
            missing.append({"id": key, "question": text})
    consequence = route["consequence"]["class"]
    limit = 4 if consequence == "ordinary" else 6 if consequence == "material" else 8
    return missing[:limit]


def create_receipt(route, *, answers=None, sources=None, invariants=None,
                   retrieval_rounds=0, status=None, created_at=None):
    loom_domain_contract.validate_route(route)
    sources = list(sources or []); invariants = list(invariants or [])
    if len(sources) > MAX_SOURCES or len(invariants) > MAX_INVARIANTS:
        raise DomainDiscoveryError("discovery evidence exceeds its hard bound")
    if type(retrieval_rounds) is not int or not 0 <= retrieval_rounds <= MAX_RETRIEVAL_ROUNDS:
        raise DomainDiscoveryError("discovery retrieval rounds exceed their hard bound")
    pending = _questions(route, answers)
    if status is None:
        status = "needs-owner" if pending else "collecting-evidence"
    if status not in {"needs-owner", "collecting-evidence", "gate-ready", "unsupported",
                      "interrupted", "conflicted"}:
        raise DomainDiscoveryError("discovery status is invalid")
    created_at = created_at or dt.datetime.now(dt.timezone.utc).isoformat().replace(
        "+00:00", "Z")
    body = {
        "schema_version": 1, "route_digest": route["route_digest"],
        "status": status, "questions": pending,
        "answers": dict(answers or {}),
        "retrieval_requests": [{
            "claim": item, "authority_classes": [], "scope": {},
            "output_contract": "domain-source.schema.json",
        } for item in route["missing_knowledge"][:MAX_SOURCES]],
        "retrieval_rounds": retrieval_rounds,
        "source_ids": [item["source_id"] for item in sources],
        "invariant_ids": [item["invariant_id"] for item in invariants],
        "budgets": {"questions": MAX_QUESTIONS, "retrieval_rounds": MAX_RETRIEVAL_ROUNDS,
                    "sources": MAX_SOURCES, "invariants": MAX_INVARIANTS,
                    "capsule_characters": MAX_CAPSULE_CHARS},
        "usage": {"questions": len(pending), "retrieval_rounds": retrieval_rounds,
                  "sources": len(sources), "invariants": len(invariants)},
        "created_at": created_at,
    }
    receipt = loom_domain_contract.seal(
        "domain-discovery-v1", body, id_field="discovery_id", id_prefix="dsc")
    if len(loom_domain_contract.canonical_bytes(receipt).decode("utf-8")) > MAX_CAPSULE_CHARS:
        raise DomainDiscoveryError("discovery capsule exceeds 8192 characters")
    return receipt


def owner_message(route, receipt):
    if receipt["status"] == "needs-owner" and receipt["questions"]:
        return "I need one bounded domain decision: " + receipt["questions"][0]["question"]
    if receipt["status"] == "unsupported":
        return "Loom cannot prove the authority or real verification medium required for this branch."
    if route["coverage_state"] == "partial":
        return "Loom has partial coverage and is discovering only the uncovered subsystem rules."
    return "Loom does not yet have reliable coverage and is checking the required domain evidence."


def resume(previous, route, **updates):
    if previous.get("route_digest") != route.get("route_digest"):
        raise DomainDiscoveryError("discovery route changed; re-gating is required")
    return create_receipt(
        route, answers=updates.get("answers", previous.get("answers")),
        sources=updates.get("sources", []), invariants=updates.get("invariants", []),
        retrieval_rounds=updates.get("retrieval_rounds", previous["retrieval_rounds"]),
        status=updates.get("status", previous["status"]),
        created_at=previous["created_at"])
