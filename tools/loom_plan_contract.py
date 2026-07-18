#!/usr/bin/env python3
"""Idempotent, receipt-bearing plan-contract migrations."""

import hashlib
import json

import loom_domain
import loom_domain_contract
import loom_domain_invariants
import loom_planning_intelligence
import loom_project_inspection


class PlanContractMigrationError(ValueError):
    pass


V1_FIELDS = {
    "schema_version", "request_hash", "survey_hash", "tier", "domains",
    "pack_baseline_hash", "pack_root", "allowed_host_write_paths", "artifact_matrix",
    "required_domain_invariants", "current_facts_to_verify", "verification_media",
    "budget", "work_order_topology", "completion_gates", "contract_hash",
}


def _hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")).hexdigest()


def migrate_v1(value, *, route, created_at):
    if not isinstance(value, dict) or set(value) != V1_FIELDS \
            or value.get("schema_version") != 1:
        raise PlanContractMigrationError("legacy plan contract fields are invalid")
    body = dict(value); claimed = body.pop("contract_hash")
    if claimed != _hash(body):
        raise PlanContractMigrationError("legacy plan contract hash mismatch")
    loom_domain_contract.validate_route(route)
    if route["active_task_domains"] != value["domains"]:
        raise PlanContractMigrationError("legacy domains differ from the sealed v2 route")
    normalized = []
    for domain_id in value["domains"]:
        adapter = loom_domain.CATALOG.get(domain_id)
        if adapter is not None:
            normalized.extend(loom_domain_invariants.compile_shipped(
                domain_id, adapter, loom_domain.GUIDANCE[domain_id],
                now=__import__("datetime").datetime.fromisoformat(
                    created_at.replace("Z", "+00:00"))))
    migrated = {
        **{key: item for key, item in value.items()
           if key not in {"schema_version", "contract_hash"}},
        "schema_version": 2, "domain_route": route,
        "route_digest": route["route_digest"],
        "composition_graph_digest": route["graph_digest"],
        "target_fingerprint": value["survey_hash"],
        "domain_invariants": normalized,
        "domain_discovery": {
            "required": route["coverage_state"] != "known",
            "human_projection": "domain-discovery.md",
            "machine_bundle": "domain-discovery.json", "maximum_sources": 20,
            "maximum_invariants": 32, "maximum_retrieval_rounds": 2,
        },
    }
    migrated["contract_hash"] = _hash(migrated)
    receipt_body = {
        "schema_version": 1, "source_contract_hash": claimed,
        "target_contract_hash": migrated["contract_hash"],
        "route_digest": route["route_digest"],
        "status": ("revalidation-required" if migrated["domain_discovery"]["required"]
                   else "compatible-known"),
        "semantic_changes": [
            "added content-bound route and composition identity",
            "compiled shipped invariants into normalized candidate records",
            "unknown/custom evidence remains inactive until a v2 bundle passes G1",
        ],
    }
    return {"contract": migrated, "migration_receipt": {
        **receipt_body, "receipt_digest": loom_domain_contract.digest(
            "plan-contract-migration-v1-v2", receipt_body)}}


def migrate_v2(value, *, request):
    """Project a sealed v2 contract into v3 without changing its domain semantics."""
    if not isinstance(value, dict) or value.get("schema_version") != 2 \
            or "planning_intelligence" in value:
        raise PlanContractMigrationError("v2 plan contract fields are invalid")
    body = dict(value); claimed = body.pop("contract_hash", None)
    if not isinstance(claimed, str) or claimed != _hash(body):
        raise PlanContractMigrationError("v2 plan contract hash mismatch")
    try:
        intelligence = loom_planning_intelligence.compile_intelligence(
            request, tier=value["tier"], route=value["domain_route"])
    except loom_planning_intelligence.PlanningIntelligenceError as exc:
        raise PlanContractMigrationError(str(exc)) from exc
    migrated = {**body, "schema_version": 3,
                "planning_intelligence": intelligence}
    gates = list(migrated["completion_gates"])
    if "planning-intelligence" not in gates:
        gates.append("planning-intelligence")
    migrated["completion_gates"] = gates
    migrated["contract_hash"] = _hash(migrated)
    receipt_body = {
        "schema_version": 1, "source_contract_hash": claimed,
        "target_contract_hash": migrated["contract_hash"],
        "planning_intelligence_digest": intelligence["intelligence_digest"],
        "status": "revalidation-required",
        "semantic_changes": [
            "added bounded specialist module activation",
            "added provenance-bound planning atoms",
            "requires affected plan obligations to be revalidated before execution",
        ],
    }
    return {"contract": migrated, "migration_receipt": {
        **receipt_body, "receipt_digest": loom_domain_contract.digest(
            "plan-contract-migration-v2-v3", receipt_body)}}


def migrate_v3(value, *, project_inspection):
    """Bind a sealed v3 contract to typed structural coverage for v4 authorization."""
    if not isinstance(value, dict) or value.get("schema_version") != 3 \
            or "project_inspection" in value or "inspection_obligations" in value:
        raise PlanContractMigrationError("v3 plan contract fields are invalid")
    body = dict(value)
    claimed = body.pop("contract_hash", None)
    if not isinstance(claimed, str) or claimed != _hash(body):
        raise PlanContractMigrationError("v3 plan contract hash mismatch")
    try:
        loom_project_inspection.validate(project_inspection)
    except loom_project_inspection.InspectionError as exc:
        raise PlanContractMigrationError(str(exc)) from exc
    if project_inspection["survey_hash"] != value["survey_hash"]:
        raise PlanContractMigrationError(
            "project inspection does not describe the v3 contract survey")
    route = dict(value["domain_route"])
    try:
        loom_domain_contract.validate_route(route)
    except loom_domain_contract.DomainContractError as exc:
        raise PlanContractMigrationError(str(exc)) from exc
    if route["schema_version"] != 1:
        raise PlanContractMigrationError("v3 contract route is not a legacy v1 route")
    route.pop("route_digest")
    route["schema_version"] = loom_domain_contract.ROUTE_SCHEMA_VERSION
    capsule = loom_project_inspection.capsule(project_inspection)
    route["project_inspection"] = capsule
    route["route_digest"] = loom_domain_contract.digest("domain-route-v2", route)
    loom_domain_contract.validate_route(route)
    obligations = [
        {"path": item["path"], "reason": item["reason"],
         "potential_authorities": list(item["potential_authorities"])}
        for item in project_inspection["unresolved_roots"]]
    migrated = {
        **body,
        "schema_version": 4,
        "domain_route": route,
        "route_digest": route["route_digest"],
        "project_inspection": capsule,
        "inspection_obligations": obligations,
    }
    gates = list(migrated["completion_gates"])
    if obligations and "project-inspection" not in gates:
        gates.insert(0, "project-inspection")
    migrated["completion_gates"] = gates
    migrated["contract_hash"] = _hash(migrated)
    receipt_body = {
        "schema_version": 1,
        "source_contract_hash": claimed,
        "target_contract_hash": migrated["contract_hash"],
        "inspection_receipt_digest": project_inspection["receipt_digest"],
        "route_digest": route["route_digest"],
        "status": "revalidation-required",
        "semantic_changes": [
            "bound the plan to typed project-inspection evidence",
            "made unresolved structural authority an explicit completion gate",
            "requires a current complete receipt before G1 or implementation",
        ],
    }
    return {"contract": migrated, "migration_receipt": {
        **receipt_body, "receipt_digest": loom_domain_contract.digest(
            "plan-contract-migration-v3-v4", receipt_body)}}
