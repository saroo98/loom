#!/usr/bin/env python3
"""Compile shipped and discovered domain knowledge into one sealed invariant form."""

import datetime as dt

import loom_domain_contract
import loom_domain_evidence


class DomainInvariantError(ValueError):
    pass


EMPTY_SCOPE = {
    "project_id": None, "component": None, "jurisdiction": None,
    "product_class": None, "environment": None, "version_range": None,
    "effective_period": None,
}


def candidate_body(*, statement, invariant_type, domain_ids, subsystem_ids, scope,
                   consequence_class, failure, authority_requirements,
                   supporting_source_ids, contradicting_source_ids,
                   applicability_receipt_ids, required_real_medium, acceptance_target,
                   freshness_policy, as_of, revalidate_by, revision_identity=None,
                   evidence_state="candidate", provenance_event_ids=None):
    return {
        "schema_version": 1, "statement": statement,
        "invariant_type": invariant_type, "domain_ids": list(domain_ids),
        "subsystem_ids": list(subsystem_ids), "scope": dict(scope),
        "consequence": {"class": consequence_class, "failure": failure},
        "authority_requirements": list(authority_requirements),
        "supporting_source_ids": list(supporting_source_ids),
        "contradicting_source_ids": list(contradicting_source_ids),
        "applicability_receipt_ids": list(applicability_receipt_ids),
        "verification": {"required_real_medium": required_real_medium,
                         "acceptance_target": acceptance_target},
        "freshness": {"policy_id": freshness_policy, "as_of": as_of,
                      "revalidate_by": revalidate_by,
                      "revision_identity": revision_identity},
        "evidence_state": evidence_state,
        "provenance_event_ids": list(provenance_event_ids or []),
    }


def seal_candidate(**kwargs):
    body = candidate_body(**kwargs)
    identity = {key: body[key] for key in (
        "schema_version", "statement", "invariant_type", "domain_ids",
        "subsystem_ids", "scope", "consequence", "authority_requirements",
        "verification", "freshness")}
    invariant = {**body, "invariant_id": loom_domain_contract.content_id(
        "inv", identity)}
    invariant["canonical_digest"] = loom_domain_contract.digest(
        "domain-invariant-v1", invariant)
    loom_domain_contract.validate_invariant(invariant)
    return invariant


def compile_shipped(domain_id, adapter, guidance, *, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    as_of = now.isoformat().replace("+00:00", "Z")
    revalidate = (now + dt.timedelta(days=14)).isoformat().replace("+00:00", "Z")
    verification = list(guidance[2]) or ["domain-real-medium execution"]
    result = []
    for index, statement in enumerate(adapter["invariants"]):
        result.append(seal_candidate(
            statement=statement, invariant_type="correctness",
            domain_ids=[domain_id], subsystem_ids=[f"domain-{domain_id}"],
            scope=EMPTY_SCOPE, consequence_class="material",
            failure=f"{domain_id} release violates {statement}",
            authority_requirements=["repository-evidence", "real-medium-evidence"],
            supporting_source_ids=[], contradicting_source_ids=[],
            applicability_receipt_ids=[],
            required_real_medium=verification[index % len(verification)],
            acceptance_target=f"prove {statement} for the sealed target",
            freshness_policy="target-and-source-v1", as_of=as_of,
            revalidate_by=revalidate, evidence_state="candidate"))
    return result


def promote_gate_ready(invariant, *, sources, applicability, target_fingerprint, now=None,
                       offline=False):
    """Return a new sealed record only after every independent evidence dimension passes."""
    loom_domain_contract.validate_invariant(invariant)
    authority = loom_domain_evidence.evaluate_authority(invariant, sources)
    applies = loom_domain_evidence.evaluate_applicability(
        invariant, applicability, target_fingerprint)
    current = loom_domain_evidence.evaluate_currentness(
        invariant, sources, now=now, offline=offline)
    conflicts = loom_domain_evidence.detect_conflicts(invariant, sources)
    if not authority["satisfied"] or not applies["satisfied"] \
            or not current["current"] or conflicts["conflicted"]:
        state = ("conflicted" if conflicts["conflicted"] else
                 "stale" if not current["current"] else "supported")
        return {"status": "blocked", "evidence_state": state,
                "authority": authority, "applicability": applies,
                "currentness": current, "conflicts": conflicts}
    promoted = {key: value for key, value in invariant.items()
                if key != "canonical_digest"}
    promoted["evidence_state"] = "gate-ready"
    promoted["canonical_digest"] = loom_domain_contract.digest(
        "domain-invariant-v1", promoted)
    loom_domain_contract.validate_invariant(
        promoted, sources=sources, applicability=applicability, now=now)
    return {"status": "gate-ready", "invariant": promoted,
            "authority": authority, "applicability": applies,
            "currentness": current, "conflicts": conflicts}


def verify_bound_invariant(expected, observed):
    loom_domain_contract.validate_invariant(expected)
    loom_domain_contract.validate_invariant(observed)
    if expected["invariant_id"] != observed["invariant_id"] \
            or expected["canonical_digest"] != observed["canonical_digest"]:
        raise DomainInvariantError("bound invariant identity or digest changed")
    return {"status": "verified", "invariant_id": expected["invariant_id"],
            "canonical_digest": expected["canonical_digest"]}
