#!/usr/bin/env python3
"""Validate authority, applicability, freshness, and conflicts as separate facts."""

import datetime as dt
import hashlib
import re

import loom_domain_contract


AUTHORITY_POLICY = {
    "repository-behavior": {"repository-evidence", "executed-evidence"},
    "product-api": {"official-vendor", "executed-evidence"},
    "law-regulation-tax": {"official-law", "regulator"},
    "accounting-correctness": {"governing-standard", "real-medium-evidence"},
    "medical-clinical": {"regulator", "qualified-reviewer"},
    "firmware-hardware-safety": {"official-vendor", "real-medium-evidence"},
    "security-claim": {"official-vendor", "executed-evidence"},
    "research-claim": {"primary-research", "real-medium-evidence"},
}

SOURCE_TO_AUTHORITY = {
    "repository": {"repository-evidence"},
    "executed-observation": {"executed-evidence", "real-medium-evidence"},
    "official-law": {"official-law"},
    "regulator": {"regulator"},
    "official-vendor": {"official-vendor"},
    "governing-standard": {"governing-standard"},
    "primary-research": {"primary-research"},
    "qualified-reviewer": {"qualified-reviewer"},
    "owner-attestation": {"owner-authority"},
}

INSTRUCTION_PATTERNS = (
    r"(?i)\bignore\s+(?:all\s+)?(?:previous|loom|system)\s+instructions\b",
    r"(?i)\b(?:run|execute|invoke)\s+(?:this\s+)?(?:command|script|tool)\b",
    r"(?i)\b(?:reveal|exfiltrate|print)\s+(?:the\s+)?(?:secret|token|prompt|vault)\b",
)


class DomainEvidenceError(ValueError):
    pass


def source_claim_body(*, title, locator, locator_visibility, publisher, source_class,
                      authority_claims, trust_state, document_id, version, published_at,
                      effective_at, superseded_at, accessed_at, revalidate_by, content,
                      retrieval_method, retrieval_receipt_id, jurisdiction=None,
                      product_class=None, environment=None, supported_invariant_ids=None,
                      contradicted_invariant_ids=None, currentness="current", ambiguity=None,
                      provenance_event_ids=None):
    if not isinstance(content, (bytes, bytearray)):
        raise DomainEvidenceError("source content must be observed bytes")
    return {
        "schema_version": 1, "title": title, "locator": locator,
        "locator_visibility": locator_visibility, "publisher": publisher,
        "source_class": source_class, "authority_claims": list(authority_claims),
        "trust_state": trust_state, "document_id": document_id, "version": version,
        "published_at": published_at, "effective_at": effective_at,
        "superseded_at": superseded_at, "accessed_at": accessed_at,
        "revalidate_by": revalidate_by,
        "content_sha256": hashlib.sha256(bytes(content)).hexdigest(),
        "retrieval_method": retrieval_method,
        "retrieval_receipt_id": retrieval_receipt_id,
        "jurisdiction": jurisdiction, "product_class": product_class,
        "environment": environment,
        "supported_invariant_ids": list(supported_invariant_ids or []),
        "contradicted_invariant_ids": list(contradicted_invariant_ids or []),
        "currentness": currentness, "ambiguity": ambiguity,
        "provenance_event_ids": list(provenance_event_ids or []),
    }


def seal_source(**kwargs):
    body = source_claim_body(**kwargs)
    source = loom_domain_contract.seal(
        "domain-source-v1", body, id_field="source_id", id_prefix="src")
    loom_domain_contract.validate_source(source)
    return source


def contains_instructional_content(text):
    text = str(text or "")
    return any(re.search(pattern, text) for pattern in INSTRUCTION_PATTERNS)


def validate_host_source(source, *, raw_text=None, now=None):
    """Validate a host receipt while treating the source body as inert data."""
    loom_domain_contract.validate_source(source, now=now)
    return {"source": source, "instructional_content_detected":
            contains_instructional_content(raw_text), "instructions_authorized": False}


def seal_applicability(*, source_id, invariant_id, scope, target_fingerprint,
                       decision, evidence, checked_at, revalidate_on):
    body = {
        "schema_version": 1, "source_id": source_id,
        "invariant_id": invariant_id, "scope": scope,
        "target_fingerprint": target_fingerprint, "decision": decision,
        "evidence": list(evidence), "checked_at": checked_at,
        "revalidate_on": list(revalidate_on),
    }
    receipt = loom_domain_contract.seal(
        "domain-applicability-v1", body,
        id_field="applicability_id", id_prefix="app")
    loom_domain_contract.validate_applicability(receipt)
    return receipt


def evaluate_authority(invariant, sources):
    required = set(invariant.get("authority_requirements", []))
    observed, invalid = set(), []
    for source in sources:
        loom_domain_contract.validate_source(source)
        observed.update(SOURCE_TO_AUTHORITY.get(source["source_class"], set()))
        # A source may describe what it claims; it cannot mint an authority class.
        invalid.extend(item for item in source["authority_claims"]
                       if item not in loom_domain_contract.AUTHORITY_CLASSES)
    missing = sorted(required - observed)
    return {"satisfied": not missing and not invalid, "observed": sorted(observed),
            "missing": missing, "invalid_claims": sorted(set(invalid))}


def evaluate_applicability(invariant, receipts, target_fingerprint):
    by_id = {item["applicability_id"]: item for item in receipts}
    missing, inapplicable = [], []
    for receipt_id in invariant.get("applicability_receipt_ids", []):
        receipt = by_id.get(receipt_id)
        if receipt is None:
            missing.append(receipt_id); continue
        loom_domain_contract.validate_applicability(receipt)
        if receipt["target_fingerprint"] != target_fingerprint \
                or receipt["invariant_id"] != invariant["invariant_id"] \
                or receipt["decision"] != "applicable":
            inapplicable.append(receipt_id)
    return {"satisfied": not missing and not inapplicable,
            "missing": missing, "inapplicable": inapplicable}


def evaluate_currentness(invariant, sources, *, now=None, offline=False):
    now = now or dt.datetime.now(dt.timezone.utc)
    deadline = loom_domain_contract.parse_time(
        invariant["freshness"]["revalidate_by"], "invariant revalidate_by")
    stale_sources = []
    for source in sources:
        try:
            loom_domain_contract.validate_source(source, now=now)
        except loom_domain_contract.DomainContractError:
            stale_sources.append(source.get("source_id", "unknown"))
        if source.get("currentness") != "current":
            stale_sources.append(source.get("source_id", "unknown"))
    expired = deadline < now
    high = invariant["consequence"]["class"] in {"high", "critical"}
    blocked = bool(stale_sources or expired) and (high or offline)
    return {"current": not stale_sources and not expired, "blocked": blocked,
            "offline": bool(offline), "stale_sources": sorted(set(stale_sources)),
            "deadline_expired": expired}


def detect_conflicts(invariant, sources):
    supporting = set(invariant.get("supporting_source_ids", []))
    contradicting = set(invariant.get("contradicting_source_ids", []))
    for source in sources:
        if invariant["invariant_id"] in source.get("supported_invariant_ids", []):
            supporting.add(source["source_id"])
        if invariant["invariant_id"] in source.get("contradicted_invariant_ids", []):
            contradicting.add(source["source_id"])
    return {"conflicted": bool(supporting and contradicting),
            "supporting": sorted(supporting), "contradicting": sorted(contradicting)}
