"""Deterministic Phase 3 fixtures shared by local contract tests."""

import datetime as dt

import loom_domain
import loom_domain_bundle
import loom_domain_discovery
import loom_domain_evidence
import loom_domain_invariants


NOW = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
STAMP = "2030-01-01T00:00:00Z"
FUTURE = "2030-02-01T00:00:00Z"
TARGET = "a" * 64
SCOPE = {
    "project_id": "p-test", "component": "control", "jurisdiction": "GB",
    "product_class": "test-rig", "environment": "lab", "version_range": "1.x",
    "effective_period": "2030",
}


def source(source_class, title, content, authority_claims=None):
    return loom_domain_evidence.seal_source(
        title=title, locator=f"https://example.invalid/{title}",
        locator_visibility="public", publisher="Fixture authority",
        source_class=source_class, authority_claims=list(authority_claims or []),
        trust_state="trusted-authority", document_id=title, version="1",
        published_at=STAMP, effective_at=STAMP, superseded_at=None,
        accessed_at=STAMP, revalidate_by=FUTURE, content=content.encode("utf-8"),
        retrieval_method="host-provided fixture",
        retrieval_receipt_id=f"receipt-{title}", jurisdiction="GB",
        product_class="test-rig", environment="lab", currentness="current")


def gate_ready_bundle():
    route = loom_domain.select_domains(
        "Plan a quantum optics safety control for a laboratory rig")["domain_contract"]
    vendor = source("official-vendor", "vendor", "official limits")
    observed = source("executed-observation", "observation", "real rig test")
    first = loom_domain_invariants.seal_candidate(
        statement="laser exposure remains below the sealed safe operating limit",
        invariant_type="safety", domain_ids=["quantum-optics"],
        subsystem_ids=["domain-quantum-optics"], scope=SCOPE,
        consequence_class="high", failure="unsafe optical exposure",
        authority_requirements=["official-vendor", "real-medium-evidence"],
        supporting_source_ids=[vendor["source_id"], observed["source_id"]],
        contradicting_source_ids=[], applicability_receipt_ids=[],
        required_real_medium="instrumented physical rig measurement",
        acceptance_target="measured exposure remains below the sealed limit",
        freshness_policy="vendor-revision-v1", as_of=STAMP,
        revalidate_by=FUTURE, revision_identity="vendor-1")
    applicability = loom_domain_evidence.seal_applicability(
        source_id=vendor["source_id"], invariant_id=first["invariant_id"],
        scope=SCOPE, target_fingerprint=TARGET, decision="applicable",
        evidence=["model and revision match"], checked_at=STAMP,
        revalidate_on=["model-change", "revision-change", "jurisdiction-change"])
    candidate = loom_domain_invariants.seal_candidate(
        statement=first["statement"], invariant_type="safety",
        domain_ids=["quantum-optics"], subsystem_ids=["domain-quantum-optics"],
        scope=SCOPE, consequence_class="high", failure="unsafe optical exposure",
        authority_requirements=["official-vendor", "real-medium-evidence"],
        supporting_source_ids=[vendor["source_id"], observed["source_id"]],
        contradicting_source_ids=[],
        applicability_receipt_ids=[applicability["applicability_id"]],
        required_real_medium="instrumented physical rig measurement",
        acceptance_target="measured exposure remains below the sealed limit",
        freshness_policy="vendor-revision-v1", as_of=STAMP,
        revalidate_by=FUTURE, revision_identity="vendor-1")
    promoted = loom_domain_invariants.promote_gate_ready(
        candidate, sources=[vendor, observed], applicability=[applicability],
        target_fingerprint=TARGET, now=NOW)
    invariant = promoted["invariant"]
    answers = {key: "fixture answer" for key, _ in loom_domain_discovery.QUESTIONS}
    receipt = loom_domain_discovery.create_receipt(
        route, answers=answers, sources=[vendor, observed], invariants=[invariant],
        retrieval_rounds=1, status="gate-ready", created_at=STAMP)
    return loom_domain_bundle.seal(
        route=route, discovery=receipt, target_fingerprint=TARGET,
        sources=[vendor, observed], applicability=[applicability],
        invariants=[invariant], created_at=STAMP)
