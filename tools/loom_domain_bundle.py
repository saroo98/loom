#!/usr/bin/env python3
"""Machine authority for discovered-domain evidence bundles."""

import loom_domain_contract
import loom_domain_evidence


class DomainBundleError(ValueError):
    pass


FIELDS = {
    "schema_version", "route", "discovery", "target_fingerprint", "sources",
    "applicability", "invariants", "created_at", "bundle_digest",
}


def seal(*, route, discovery, target_fingerprint, sources, applicability, invariants,
         created_at):
    body = {
        "schema_version": 1, "route": route, "discovery": discovery,
        "target_fingerprint": target_fingerprint, "sources": list(sources),
        "applicability": list(applicability), "invariants": list(invariants),
        "created_at": created_at,
    }
    value = {**body, "bundle_digest": loom_domain_contract.digest(
        "domain-bundle-v1", body)}
    validate(value)
    return value


def validate(value, *, now=None, offline=False):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise DomainBundleError("DOMAIN_BUNDLE_FIELDS: fields are unknown or missing")
    if value["schema_version"] != 1:
        raise DomainBundleError("DOMAIN_BUNDLE_VERSION: schema version is unsupported")
    try:
        loom_domain_contract.validate_route(value["route"])
        loom_domain_contract.validate_discovery(value["discovery"])
        loom_domain_contract.parse_time(value["created_at"], "bundle created_at")
    except loom_domain_contract.DomainContractError as exc:
        raise DomainBundleError(f"DOMAIN_BUNDLE_CONTRACT: {exc}") from exc
    if value["discovery"]["route_digest"] != value["route"]["route_digest"]:
        raise DomainBundleError("DOMAIN_ROUTE_CHANGED: discovery route digest differs")
    target = value["target_fingerprint"]
    if not isinstance(target, str) or len(target) != 64 \
            or any(character not in "0123456789abcdef" for character in target):
        raise DomainBundleError("DOMAIN_TARGET_INVALID: target fingerprint is invalid")
    if not isinstance(value["sources"], list) or len(value["sources"]) > 20 \
            or not isinstance(value["applicability"], list) \
            or len(value["applicability"]) > 64 \
            or not isinstance(value["invariants"], list) \
            or not 1 <= len(value["invariants"]) <= 32:
        raise DomainBundleError("DOMAIN_BUNDLE_BOUNDS: evidence exceeds a hard bound")
    source_ids, content_hashes = set(), set()
    try:
        for source in value["sources"]:
            loom_domain_contract.validate_source(source, now=now)
            if source["source_id"] in source_ids:
                raise DomainBundleError("DOMAIN_SOURCE_DUPLICATE: source ID is duplicated")
            if source["content_sha256"] in content_hashes:
                raise DomainBundleError(
                    "DOMAIN_SOURCE_CIRCULAR: duplicate source content cannot mint authority")
            source_ids.add(source["source_id"]); content_hashes.add(source["content_sha256"])
        app_ids = set()
        for receipt in value["applicability"]:
            loom_domain_contract.validate_applicability(receipt)
            if receipt["applicability_id"] in app_ids:
                raise DomainBundleError(
                    "DOMAIN_APPLICABILITY_DUPLICATE: applicability receipt is duplicated")
            if receipt["target_fingerprint"] != target:
                raise DomainBundleError(
                    "DOMAIN_APPLICABILITY_TARGET: receipt targets another project state")
            app_ids.add(receipt["applicability_id"])
        invariant_ids = set()
        covered_domains = set()
        for invariant in value["invariants"]:
            loom_domain_contract.validate_invariant(
                invariant, sources=value["sources"],
                applicability=value["applicability"], now=now)
            if invariant["invariant_id"] in invariant_ids:
                raise DomainBundleError("DOMAIN_INVARIANT_DUPLICATE: invariant is duplicated")
            if invariant["evidence_state"] != "gate-ready":
                raise DomainBundleError(
                    f"DOMAIN_INVARIANT_NOT_READY: {invariant['invariant_id']}")
            authority = loom_domain_evidence.evaluate_authority(invariant, value["sources"])
            applies = loom_domain_evidence.evaluate_applicability(
                invariant, value["applicability"], target)
            current = loom_domain_evidence.evaluate_currentness(
                invariant, value["sources"], now=now, offline=offline)
            conflict = loom_domain_evidence.detect_conflicts(invariant, value["sources"])
            if not authority["satisfied"]:
                raise DomainBundleError(
                    f"DOMAIN_AUTHORITY_MISSING: {invariant['invariant_id']}")
            if not applies["satisfied"]:
                raise DomainBundleError(
                    f"DOMAIN_APPLICABILITY_MISSING: {invariant['invariant_id']}")
            if not current["current"]:
                raise DomainBundleError(
                    f"DOMAIN_FRESHNESS_EXPIRED: {invariant['invariant_id']}")
            if conflict["conflicted"]:
                raise DomainBundleError(
                    f"DOMAIN_CONFLICT_UNRESOLVED: {invariant['invariant_id']}")
            invariant_ids.add(invariant["invariant_id"])
            covered_domains.update(invariant["domain_ids"])
    except loom_domain_contract.DomainContractError as exc:
        raise DomainBundleError(f"DOMAIN_EVIDENCE_INVALID: {exc}") from exc
    if set(value["discovery"]["source_ids"]) != source_ids \
            or set(value["discovery"]["invariant_ids"]) != invariant_ids:
        raise DomainBundleError("DOMAIN_DISCOVERY_INVENTORY: receipt inventory differs")
    required = set(value["route"]["active_task_domains"]) - set(
        value["route"]["memory_domains"])
    if not required.issubset(covered_domains):
        raise DomainBundleError(
            "DOMAIN_COVERAGE_INCOMPLETE: uncovered active domain has no gate-ready invariant")
    if value["discovery"]["status"] != "gate-ready":
        raise DomainBundleError("DOMAIN_DISCOVERY_NOT_READY: receipt is not gate-ready")
    body = dict(value); claimed = body.pop("bundle_digest")
    if claimed != loom_domain_contract.digest("domain-bundle-v1", body):
        raise DomainBundleError("DOMAIN_BUNDLE_DIGEST: bundle digest mismatch")
    return value
