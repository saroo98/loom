#!/usr/bin/env python3
"""Closed, canonical contracts for Loom's unknown-domain intelligence."""

import datetime as dt
import hashlib
import json
import math
import re


SCHEMA_VERSION = 1
POLICY_VERSION = "domain-intelligence-v1"
ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}-[0-9a-f]{16,64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+ -]{0,255}$")

COVERAGE_STATES = {
    "known", "partial", "unknown", "conflicted", "stale", "unsupported",
}
CONSEQUENCE_CLASSES = {"ordinary", "material", "high", "critical"}
EVIDENCE_STATES = {
    "candidate", "supported", "gate-ready", "conflicted", "stale",
    "superseded", "quarantined",
}
INVARIANT_TYPES = {
    "correctness", "safety", "regulatory", "interface", "release", "verification",
}
SOURCE_CLASSES = {
    "repository", "executed-observation", "official-law", "regulator",
    "official-vendor", "governing-standard", "primary-research",
    "qualified-reviewer", "owner-attestation", "secondary-discovery",
    "shipped-adapter",
}
TRUST_STATES = {"trusted-local", "trusted-authority", "untrusted-data"}
AUTHORITY_CLASSES = {
    "repository-evidence", "executed-evidence", "official-law", "regulator",
    "official-vendor", "governing-standard", "primary-research",
    "qualified-reviewer", "owner-authority", "real-medium-evidence",
}


class DomainContractError(ValueError):
    pass


def _reject_noncanonical_numbers(value):
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DomainContractError("non-finite numbers are not canonical JSON")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise DomainContractError("negative zero is not accepted by Loom canonical JSON")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DomainContractError("canonical JSON object keys must be strings")
            _reject_noncanonical_numbers(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_noncanonical_numbers(item)


def canonical_bytes(value):
    """Return deterministic UTF-8 JSON after rejecting ambiguous number forms."""
    _reject_noncanonical_numbers(value)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DomainContractError(f"value is not strict canonical JSON: {exc}") from exc


def digest(prefix, value):
    if not isinstance(prefix, str) or not prefix:
        raise DomainContractError("digest prefix is required")
    return "sha256:" + hashlib.sha256(
        prefix.encode("ascii") + b"\x00" + canonical_bytes(value)).hexdigest()


def content_id(prefix, value):
    return f"{prefix}-{digest(prefix, value)[7:31]}"


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise DomainContractError(f"{label} fields are unknown or missing")


def _bounded_text(value, label, *, maximum=512, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum \
            or (not allow_empty and not value.strip()):
        raise DomainContractError(f"{label} is invalid or oversized")
    return value


def _safe_id(value, label, *, pattern=DOMAIN_RE):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DomainContractError(f"{label} is invalid")
    return value


def _unique_strings(values, label, *, maximum, pattern=None):
    if not isinstance(values, list) or len(values) > maximum \
            or len(values) != len(set(values)):
        raise DomainContractError(f"{label} must be a bounded unique list")
    for item in values:
        if not isinstance(item, str) or not item or len(item) > 256 \
                or (pattern is not None and pattern.fullmatch(item) is None):
            raise DomainContractError(f"{label} contains an invalid value")
    return values


def parse_time(value, label, *, optional=False):
    if value is None and optional:
        return None
    _bounded_text(value, label, maximum=40)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DomainContractError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise DomainContractError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_scope(scope):
    fields = {
        "project_id", "component", "jurisdiction", "product_class", "environment",
        "version_range", "effective_period",
    }
    _exact(scope, fields, "domain scope")
    for key, value in scope.items():
        if value is not None:
            _bounded_text(value, f"scope {key}", maximum=128)
    return scope


def validate_source(value, *, now=None):
    fields = {
        "schema_version", "source_id", "title", "locator", "locator_visibility",
        "publisher", "source_class", "authority_claims", "trust_state",
        "document_id", "version", "published_at", "effective_at", "superseded_at",
        "accessed_at", "revalidate_by", "content_sha256", "retrieval_method",
        "retrieval_receipt_id", "jurisdiction", "product_class", "environment",
        "supported_invariant_ids", "contradicted_invariant_ids", "currentness",
        "ambiguity", "provenance_event_ids", "canonical_digest",
    }
    _exact(value, fields, "domain source")
    if value["schema_version"] != SCHEMA_VERSION:
        raise DomainContractError("domain source schema_version is invalid")
    _safe_id(value["source_id"], "source_id", pattern=ID_RE)
    for key in ("title", "publisher", "document_id", "retrieval_method",
                "retrieval_receipt_id"):
        _bounded_text(value[key], key, maximum=256)
    if value["locator_visibility"] not in {"public", "encrypted-private"}:
        raise DomainContractError("source locator visibility is invalid")
    if value["locator_visibility"] == "encrypted-private" \
            and not value["locator"].startswith("receipt:"):
        raise DomainContractError("private source locators must be opaque receipts")
    _bounded_text(value["locator"], "source locator", maximum=512)
    if value["source_class"] not in SOURCE_CLASSES \
            or value["trust_state"] not in TRUST_STATES:
        raise DomainContractError("source class or trust state is invalid")
    _unique_strings(value["authority_claims"], "source authority claims", maximum=8)
    for key in ("version", "jurisdiction", "product_class", "environment", "ambiguity"):
        if value[key] is not None:
            _bounded_text(value[key], key, maximum=256)
    for key in ("published_at", "effective_at", "superseded_at", "accessed_at",
                "revalidate_by"):
        parse_time(value[key], key, optional=True)
    if not isinstance(value["content_sha256"], str) \
            or re.fullmatch(r"[0-9a-f]{64}", value["content_sha256"]) is None:
        raise DomainContractError("source content hash is invalid")
    _unique_strings(value["supported_invariant_ids"], "supported invariant IDs",
                    maximum=128, pattern=ID_RE)
    _unique_strings(value["contradicted_invariant_ids"], "contradicted invariant IDs",
                    maximum=128, pattern=ID_RE)
    _unique_strings(value["provenance_event_ids"], "source provenance IDs", maximum=64)
    if value["currentness"] not in {"current", "stale", "superseded", "unknown"}:
        raise DomainContractError("source currentness is invalid")
    body = dict(value)
    claimed = body.pop("canonical_digest")
    expected = digest("domain-source-v1", body)
    if claimed != expected:
        raise DomainContractError("source canonical digest mismatch")
    if now is not None and value["revalidate_by"] is not None \
            and parse_time(value["revalidate_by"], "revalidate_by") < now:
        if value["currentness"] == "current":
            raise DomainContractError("expired source cannot claim currentness")
    return value


def validate_applicability(value):
    fields = {
        "schema_version", "applicability_id", "source_id", "invariant_id", "scope",
        "target_fingerprint", "decision", "evidence", "checked_at",
        "revalidate_on", "canonical_digest",
    }
    _exact(value, fields, "domain applicability")
    if value["schema_version"] != SCHEMA_VERSION:
        raise DomainContractError("applicability schema_version is invalid")
    _safe_id(value["applicability_id"], "applicability_id", pattern=ID_RE)
    _safe_id(value["source_id"], "source_id", pattern=ID_RE)
    _safe_id(value["invariant_id"], "invariant_id", pattern=ID_RE)
    validate_scope(value["scope"])
    if not isinstance(value["target_fingerprint"], str) \
            or re.fullmatch(r"[0-9a-f]{64}", value["target_fingerprint"]) is None:
        raise DomainContractError("applicability target fingerprint is invalid")
    if value["decision"] not in {"applicable", "inapplicable", "unknown"}:
        raise DomainContractError("applicability decision is invalid")
    _unique_strings(value["evidence"], "applicability evidence", maximum=16)
    parse_time(value["checked_at"], "applicability checked_at")
    _unique_strings(value["revalidate_on"], "applicability triggers", maximum=16)
    body = dict(value)
    claimed = body.pop("canonical_digest")
    if claimed != digest("domain-applicability-v1", body):
        raise DomainContractError("applicability canonical digest mismatch")
    return value


def validate_invariant(value, *, sources=None, applicability=None, now=None):
    fields = {
        "schema_version", "invariant_id", "statement", "invariant_type",
        "domain_ids", "subsystem_ids", "scope", "consequence",
        "authority_requirements", "supporting_source_ids", "contradicting_source_ids",
        "applicability_receipt_ids", "verification", "freshness", "evidence_state",
        "provenance_event_ids", "canonical_digest",
    }
    _exact(value, fields, "domain invariant")
    if value["schema_version"] != SCHEMA_VERSION:
        raise DomainContractError("domain invariant schema_version is invalid")
    _safe_id(value["invariant_id"], "invariant_id", pattern=ID_RE)
    _bounded_text(value["statement"], "invariant statement", maximum=512)
    if value["invariant_type"] not in INVARIANT_TYPES:
        raise DomainContractError("invariant type is invalid")
    _unique_strings(value["domain_ids"], "invariant domains", maximum=16,
                    pattern=DOMAIN_RE)
    if not value["domain_ids"]:
        raise DomainContractError("invariant requires at least one domain")
    _unique_strings(value["subsystem_ids"], "invariant subsystems", maximum=32)
    validate_scope(value["scope"])
    _exact(value["consequence"], {"class", "failure"}, "invariant consequence")
    if value["consequence"]["class"] not in CONSEQUENCE_CLASSES:
        raise DomainContractError("invariant consequence class is invalid")
    _bounded_text(value["consequence"]["failure"], "invariant failure", maximum=512)
    _unique_strings(value["authority_requirements"], "authority requirements", maximum=8)
    if any(item not in AUTHORITY_CLASSES for item in value["authority_requirements"]):
        raise DomainContractError("invariant authority requirement is unknown")
    for key in ("supporting_source_ids", "contradicting_source_ids",
                "applicability_receipt_ids"):
        _unique_strings(value[key], key, maximum=128, pattern=ID_RE)
    _exact(value["verification"], {"required_real_medium", "acceptance_target"},
           "invariant verification")
    _bounded_text(value["verification"]["required_real_medium"],
                  "required real medium", maximum=256)
    _bounded_text(value["verification"]["acceptance_target"],
                  "acceptance target", maximum=256)
    _exact(value["freshness"], {"policy_id", "as_of", "revalidate_by",
                                "revision_identity"}, "invariant freshness")
    _bounded_text(value["freshness"]["policy_id"], "freshness policy", maximum=64)
    parse_time(value["freshness"]["as_of"], "freshness as_of")
    deadline = parse_time(value["freshness"]["revalidate_by"], "freshness revalidate_by")
    if value["freshness"]["revision_identity"] is not None:
        _bounded_text(value["freshness"]["revision_identity"],
                      "freshness revision identity", maximum=128)
    if value["evidence_state"] not in EVIDENCE_STATES:
        raise DomainContractError("invariant evidence state is invalid")
    _unique_strings(value["provenance_event_ids"], "invariant provenance IDs", maximum=64)
    body = dict(value)
    claimed = body.pop("canonical_digest")
    if claimed != digest("domain-invariant-v1", body):
        raise DomainContractError("invariant canonical digest mismatch")
    if value["evidence_state"] == "gate-ready":
        if not value["authority_requirements"] or not value["supporting_source_ids"] \
                or not value["applicability_receipt_ids"]:
            raise DomainContractError(
                "gate-ready invariant requires authority, sources, and applicability")
        if value["contradicting_source_ids"]:
            raise DomainContractError("contradicted invariant cannot be gate-ready")
        if now is not None and deadline < now:
            raise DomainContractError("stale invariant cannot be gate-ready")
        source_map = {item["source_id"]: item for item in (sources or [])}
        app_map = {item["applicability_id"]: item for item in (applicability or [])}
        if sources is not None:
            for source_id in value["supporting_source_ids"]:
                if source_id not in source_map:
                    raise DomainContractError("gate-ready invariant source is unavailable")
                validate_source(source_map[source_id], now=now)
        if applicability is not None:
            for receipt_id in value["applicability_receipt_ids"]:
                receipt = app_map.get(receipt_id)
                if receipt is None or receipt["decision"] != "applicable" \
                        or receipt["invariant_id"] != value["invariant_id"]:
                    raise DomainContractError(
                        "gate-ready invariant applicability is unavailable")
                validate_applicability(receipt)
    return value


def validate_route(value):
    fields = {
        "schema_version", "policy_version", "coverage_state", "composition",
        "active_task_domains", "memory_domains", "ambient_domains", "candidates",
        "rejected_alternatives", "missing_knowledge", "consequence", "subsystems",
        "graph_digest", "route_digest",
    }
    _exact(value, fields, "domain route")
    if value["schema_version"] != SCHEMA_VERSION or value["policy_version"] != POLICY_VERSION:
        raise DomainContractError("domain route version is invalid")
    if value["coverage_state"] not in COVERAGE_STATES \
            or type(value["composition"]) is not bool:
        raise DomainContractError("domain route coverage is invalid")
    for key in ("active_task_domains", "memory_domains", "ambient_domains"):
        _unique_strings(value[key], key, maximum=16, pattern=DOMAIN_RE)
    if not set(value["memory_domains"]).issubset(value["active_task_domains"]):
        raise DomainContractError("memory domains must be active task domains")
    if not isinstance(value["candidates"], list) or len(value["candidates"]) > 32:
        raise DomainContractError("domain candidates exceed their bound")
    candidate_fields = {"domain", "coverage", "evidence", "source", "rank"}
    for item in value["candidates"]:
        _exact(item, candidate_fields, "domain candidate")
        _safe_id(item["domain"], "candidate domain")
        if item["coverage"] not in COVERAGE_STATES \
                or type(item["rank"]) is not int or item["rank"] < 1:
            raise DomainContractError("domain candidate fields are invalid")
        _unique_strings(item["evidence"], "candidate evidence", maximum=16)
        if item["source"] not in {"request", "owner", "host-proposal", "adapter"}:
            raise DomainContractError("domain candidate source is invalid")
    _unique_strings(value["rejected_alternatives"], "rejected alternatives", maximum=32)
    _unique_strings(value["missing_knowledge"], "missing knowledge", maximum=32)
    _exact(value["consequence"], {"class", "categories", "evidence"},
           "route consequence")
    if value["consequence"]["class"] not in CONSEQUENCE_CLASSES:
        raise DomainContractError("route consequence class is invalid")
    _unique_strings(value["consequence"]["categories"], "consequence categories", maximum=16)
    _unique_strings(value["consequence"]["evidence"], "consequence evidence", maximum=16)
    if not isinstance(value["subsystems"], list) or len(value["subsystems"]) > 32:
        raise DomainContractError("route subsystems exceed their bound")
    for subsystem in value["subsystems"]:
        _exact(subsystem, {"id", "domains", "coverage", "consequence", "blocked"},
               "route subsystem")
        _bounded_text(subsystem["id"], "subsystem id", maximum=64)
        _unique_strings(subsystem["domains"], "subsystem domains", maximum=16,
                        pattern=DOMAIN_RE)
        if subsystem["coverage"] not in COVERAGE_STATES \
                or subsystem["consequence"] not in CONSEQUENCE_CLASSES \
                or type(subsystem["blocked"]) is not bool:
            raise DomainContractError("route subsystem state is invalid")
    if not isinstance(value["graph_digest"], str) or not DIGEST_RE.fullmatch(value["graph_digest"]):
        raise DomainContractError("route graph digest is invalid")
    body = dict(value)
    claimed = body.pop("route_digest")
    if claimed != digest("domain-route-v1", body):
        raise DomainContractError("domain route digest mismatch")
    return value


def validate_discovery(value):
    fields = {
        "schema_version", "discovery_id", "route_digest", "status", "questions",
        "answers", "retrieval_requests", "retrieval_rounds", "source_ids",
        "invariant_ids", "budgets", "usage", "created_at", "canonical_digest",
    }
    _exact(value, fields, "domain discovery receipt")
    if value["schema_version"] != SCHEMA_VERSION:
        raise DomainContractError("domain discovery schema_version is invalid")
    _safe_id(value["discovery_id"], "discovery_id", pattern=ID_RE)
    if not DIGEST_RE.fullmatch(value["route_digest"]):
        raise DomainContractError("discovery route digest is invalid")
    if value["status"] not in {"needs-owner", "collecting-evidence", "gate-ready",
                                "unsupported", "interrupted", "conflicted"}:
        raise DomainContractError("discovery status is invalid")
    if not isinstance(value["questions"], list) or len(value["questions"]) > 8:
        raise DomainContractError("discovery questions exceed their bound")
    for question in value["questions"]:
        _exact(question, {"id", "question"}, "discovery question")
        _bounded_text(question["id"], "question id", maximum=32)
        _bounded_text(question["question"], "question", maximum=512)
    if not isinstance(value["answers"], dict) or len(value["answers"]) > 8:
        raise DomainContractError("discovery answers exceed their bound")
    for key, answer in value["answers"].items():
        _bounded_text(key, "answer key", maximum=32)
        _bounded_text(answer, "answer", maximum=1024)
    if not isinstance(value["retrieval_requests"], list) \
            or len(value["retrieval_requests"]) > 20:
        raise DomainContractError("retrieval requests exceed their bound")
    if type(value["retrieval_rounds"]) is not int \
            or not 0 <= value["retrieval_rounds"] <= 2:
        raise DomainContractError("retrieval round count is invalid")
    _unique_strings(value["source_ids"], "discovery source IDs", maximum=20,
                    pattern=ID_RE)
    _unique_strings(value["invariant_ids"], "discovery invariant IDs", maximum=32,
                    pattern=ID_RE)
    expected_budgets = {"questions": 8, "retrieval_rounds": 2, "sources": 20,
                        "invariants": 32, "capsule_characters": 8192}
    if value["budgets"] != expected_budgets:
        raise DomainContractError("discovery hard budgets changed")
    _exact(value["usage"], {"questions", "retrieval_rounds", "sources", "invariants"},
           "discovery usage")
    limits = {"questions": 8, "retrieval_rounds": 2, "sources": 20, "invariants": 32}
    if any(type(value["usage"][key]) is not int
           or not 0 <= value["usage"][key] <= maximum
           for key, maximum in limits.items()):
        raise DomainContractError("discovery usage exceeds its hard budget")
    parse_time(value["created_at"], "discovery created_at")
    body = dict(value); claimed = body.pop("canonical_digest")
    if claimed != digest("domain-discovery-v1", body):
        raise DomainContractError("discovery canonical digest mismatch")
    return value


def seal(kind, body, *, id_field=None, id_prefix=None, digest_field="canonical_digest"):
    if not isinstance(body, dict) or digest_field in body \
            or (id_field is not None and id_field in body):
        raise DomainContractError("seal body contains a computed field")
    value = dict(body)
    identity_body = dict(body)
    if id_field is not None:
        value[id_field] = content_id(id_prefix, identity_body)
    digest_body = dict(value)
    value[digest_field] = digest(kind, digest_body)
    return value
