#!/usr/bin/env python3
"""Compile bounded declarative specialist guidance into sealed planning atoms."""

import json
import re
from pathlib import Path

import loom_domain_contract
import loom_domain
import loom_program


SCHEMA_VERSION = 1
POLICY_VERSION = "planning-intelligence-v1"
TIERS = {"S", "M", "L", "XL"}
STATES = {"draft", "active", "deprecated", "superseded", "revoked"}
KINDS = {
    "constraint", "recommendation", "question", "alternative",
    "current-fact-query", "unknown-blocker", "risk", "decision-requirement",
    "artifact-requirement", "work-order-constraint", "verification-obligation",
    "release-gate",
}
UNIVERSAL_LENSES = [
    "outcome", "scope", "epistemics", "consequence-reversibility",
    "dependencies", "acceptance-medium", "release-rollback",
]
VERIFICATION_DEFAULTS = {
    "risk": "obligation omitted, asserted, or stale",
    "failure_mode": "affected branch proceeds without decision-grade evidence",
    "environment": "declared target environment",
    "fixture_data": "task-bound evidence or declared representative fixture",
    "oracle": "observable result independent of the implementation claim",
    "rollback_signal": "failure blocks the gate and reopens linked work",
    "freshness": "reverify after target, dependency, authority, or fact drift",
}
MODULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class PlanningIntelligenceError(ValueError):
    pass


def _catalog_path():
    return Path(__file__).resolve().parent.parent / "loom" / "specialists" / "catalog.json"


def _module_digest(module):
    return loom_domain_contract.digest("planning-specialist-module-v1", module)


def load_catalog(path=None):
    source = Path(path) if path is not None else _catalog_path()
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanningIntelligenceError(f"specialist catalog is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "policy_version", "modules"} \
            or value["schema_version"] != SCHEMA_VERSION \
            or value["policy_version"] != POLICY_VERSION \
            or not isinstance(value["modules"], list) \
            or len(value["modules"]) != 7:
        raise PlanningIntelligenceError("specialist catalog contract is invalid")
    seen = set()
    module_fields = {"id", "version", "state", "activation", "limitations", "atoms"}
    activation_fields = {"always", "tiers", "domains", "patterns"}
    atom_fields = {"id", "kind", "statement", "gate_effect", "real_medium"}
    for module in value["modules"]:
        if not isinstance(module, dict) or set(module) != module_fields \
                or not isinstance(module["id"], str) or not MODULE_ID.fullmatch(module["id"]) \
                or module["id"] in seen \
                or not isinstance(module["version"], str) \
                or not SEMVER.fullmatch(module["version"]) \
                or module["state"] not in STATES:
            raise PlanningIntelligenceError("specialist module identity is invalid")
        seen.add(module["id"])
        activation = module["activation"]
        if not isinstance(activation, dict) or set(activation) != activation_fields \
                or type(activation["always"]) is not bool \
                or not isinstance(activation["tiers"], list) \
                or len(activation["tiers"]) != len(set(activation["tiers"])) \
                or not set(activation["tiers"]).issubset(TIERS) \
                or not isinstance(activation["domains"], list) \
                or len(activation["domains"]) != len(set(activation["domains"])) \
                or not all(isinstance(item, str) and item for item in activation["domains"]) \
                or not isinstance(activation["patterns"], list) \
                or not all(isinstance(item, str) and 1 <= len(item) <= 80
                           for item in activation["patterns"]):
            raise PlanningIntelligenceError("specialist activation contract is invalid")
        if not isinstance(module["limitations"], list) or not module["limitations"] \
                or not all(isinstance(item, str) and 1 <= len(item) <= 200
                           for item in module["limitations"]):
            raise PlanningIntelligenceError("specialist limitations are invalid")
        if not isinstance(module["atoms"], list) or not 1 <= len(module["atoms"]) <= 4:
            raise PlanningIntelligenceError("specialist atom bound is invalid")
        atom_ids = set()
        for atom in module["atoms"]:
            if not isinstance(atom, dict) or set(atom) != atom_fields \
                    or not isinstance(atom["id"], str) \
                    or not MODULE_ID.fullmatch(atom["id"]) or atom["id"] in atom_ids \
                    or atom["kind"] not in KINDS \
                    or not isinstance(atom["statement"], str) \
                    or not 1 <= len(atom["statement"]) <= 320 \
                    or atom["gate_effect"] not in {
                        "none", "plan", "affected-branch", "acceptance", "release",
                        "consequence-dependent"} \
                    or not isinstance(atom["real_medium"], str) \
                    or not 1 <= len(atom["real_medium"]) <= 200:
                raise PlanningIntelligenceError("specialist atom contract is invalid")
            atom_ids.add(atom["id"])
    return value


def _positive_pattern_hits(text, patterns):
    hits = []
    for pattern in patterns:
        match = re.search(r"\b" + re.escape(pattern) + r"\b", text, re.IGNORECASE)
        if match is None:
            continue
        prefix = text[max(0, match.start() - 80):match.start()]
        if re.search(r"\b(?:do not|don't|never|without|exclude|omit|avoid)\b[^.!?;]{0,60}$",
                     prefix, re.IGNORECASE):
            continue
        hits.append("request:" + pattern)
    return hits


def _verification_for(module_id, template):
    safe_id = (module_id + "-" + template["id"]).replace(":", "-")
    return {
        "observation_method": template["real_medium"],
        "evidence_artifact": f"plans/evidence/{safe_id}.json",
    }


def expanded_verification(intelligence, atom):
    defaults = intelligence.get("verification_defaults")
    verification = atom.get("verification")
    if defaults != VERIFICATION_DEFAULTS or not isinstance(verification, dict):
        raise PlanningIntelligenceError("planning verification profile is invalid")
    return {**defaults, **verification}


def render_for_host(value):
    """Return the bounded, relevant-only planning projection shown to the host."""
    validate(value)
    program = value["program"]
    rendered_program = None if program is None else {
        "lifecycle_mode": program["lifecycle_mode"],
        "milestones": [{"id": item["id"], "outcome": item["outcome"],
                        "exit_evidence": item["exit_evidence"]}
                       for item in program["milestone_graph"]["milestones"]],
        "edges": program["milestone_graph"]["edges"],
        "program_digest": program["program_digest"],
    }
    obligations = []
    for atom in value["atoms"]:
        verification = expanded_verification(value, atom)
        obligations.append({
            "id": atom["atom_id"], "kind": atom["kind"],
            "statement": atom["statement"], "gate_effect": atom["gate_effect"],
            "observation": verification["observation_method"],
            "oracle": verification["oracle"],
            "evidence": verification["evidence_artifact"],
        })
    return {
        "schema_version": 1, "intelligence_digest": value["intelligence_digest"],
        "lifecycle": value["lifecycle_route"], "program": rendered_program,
        "obligations": obligations,
    }


def compile_intelligence(description, *, tier, route, catalog_path=None):
    if not isinstance(description, str) or not description.strip() or tier not in TIERS:
        raise PlanningIntelligenceError("description and tier are required")
    try:
        loom_domain_contract.validate_route(route)
    except loom_domain_contract.DomainContractError as exc:
        raise PlanningIntelligenceError(str(exc)) from exc
    catalog = load_catalog(catalog_path)
    domains = set(route["active_task_domains"])
    consequence = route["consequence"]["class"]
    active, dormant, atoms = [], [], []
    max_modules = 2 if tier == "S" else 7
    max_atoms = 8 if tier == "S" else 24
    for module in catalog["modules"]:
        if module["state"] != "active":
            dormant.append(module["id"])
            continue
        activation = module["activation"]
        evidence = []
        if activation["always"]:
            evidence.append("policy:universal-verification")
        evidence.extend("domain:" + item for item in sorted(
            domains & set(activation["domains"])))
        if tier in activation["tiers"]:
            evidence.append("tier:" + tier)
        evidence.extend(_positive_pattern_hits(
            loom_domain.task_language(description), activation["patterns"]))
        if module["id"] == "security-privacy-safety" and consequence in {"high", "critical"}:
            evidence.append("consequence:" + consequence)
        evidence = sorted(set(evidence))[:8]
        if not evidence:
            dormant.append(module["id"])
            continue
        if len(active) >= max_modules:
            raise PlanningIntelligenceError(
                "active specialist modules exceed the tier bound; promote the plan")
        digest = _module_digest(module)
        atom_ids = []
        for template in module["atoms"]:
            atom_id = module["id"] + ":" + template["id"]
            atom_ids.append(atom_id)
            atoms.append({
                "atom_id": atom_id, "module_id": module["id"],
                "kind": template["kind"], "statement": template["statement"],
                "scope": "active-task", "consequence": consequence,
                "evidence": evidence,
                "provenance": f"module:{module['id']}@{module['version']}#{digest}",
                "gate_effect": template["gate_effect"],
                "required_real_medium": template["real_medium"],
                "verification": _verification_for(module["id"], template),
            })
        active.append({
            "id": module["id"], "version": module["version"],
            "content_digest": digest, "evidence": evidence, "atom_ids": atom_ids,
        })
    if len(atoms) > max_atoms:
        raise PlanningIntelligenceError(
            "planning atoms exceed the tier bound; promote or narrow the plan")
    text = loom_domain.task_language(description)
    if re.search(r"\b(?:incident|outage|breach|production down|emergency containment)\b",
                 text, re.IGNORECASE):
        lifecycle_route = {"mode": "incident", "evidence": ["request:incident-response"]}
    elif re.search(
            r"\b(?:dependency update|deprecat(?:e|ion)|data repair|certificate rotation|"
            r"security patch|operational configuration|resume maintenance)\b",
            text, re.IGNORECASE):
        lifecycle_route = {"mode": "maintenance", "evidence": ["request:maintenance"]}
    else:
        lifecycle_route = {"mode": "project", "evidence": ["policy:default-project"]}
    program = loom_program.build_program(
        description, tier=tier, lifecycle_mode=lifecycle_route["mode"])
    graph_body = {
        "nodes": [item["atom_id"] for item in atoms],
        "edges": sorted([
            {"from": item["module_id"], "to": item["atom_id"], "kind": "emits"}
            for item in atoms
        ], key=lambda item: (item["from"], item["to"])),
        "conflicts": [],
    }
    composition = {**graph_body, "graph_digest": loom_domain_contract.digest(
        "planning-atom-graph-v1", graph_body)}
    body = {
        "schema_version": SCHEMA_VERSION, "policy_version": POLICY_VERSION,
        "universal_lenses": list(UNIVERSAL_LENSES),
        "verification_defaults": dict(VERIFICATION_DEFAULTS),
        "evidence_roles": loom_domain.request_clause_roles(description),
        "lifecycle_route": lifecycle_route,
        "program": program,
        "active_modules": active, "dormant_modules": sorted(dormant),
        "atoms": atoms, "composition": composition,
    }
    return {**body, "intelligence_digest": loom_domain_contract.digest(
        "planning-intelligence-v1", body)}


def validate(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "policy_version", "universal_lenses", "lifecycle_route",
            "verification_defaults", "evidence_roles", "program", "active_modules", "dormant_modules",
            "atoms", "composition",
            "intelligence_digest"}:
        raise PlanningIntelligenceError("planning intelligence fields are invalid")
    body = dict(value); claimed = body.pop("intelligence_digest")
    if claimed != loom_domain_contract.digest("planning-intelligence-v1", body):
        raise PlanningIntelligenceError("planning intelligence digest mismatch")
    if value["schema_version"] != SCHEMA_VERSION \
            or value["policy_version"] != POLICY_VERSION \
            or value["universal_lenses"] != UNIVERSAL_LENSES \
            or value["verification_defaults"] != VERIFICATION_DEFAULTS:
        raise PlanningIntelligenceError("planning intelligence identity is invalid")
    lifecycle = value["lifecycle_route"]
    roles = value["evidence_roles"]
    if not isinstance(roles, list) or len(roles) > 32 \
            or [item.get("index") for item in roles] != list(range(len(roles))) \
            or any(not isinstance(item, dict) or set(item) != {
                "index", "role", "clause_digest", "evidence"}
                or item["role"] not in {
                    "target", "constraint", "source-material", "excluded", "context"}
                or not isinstance(item["clause_digest"], str)
                or not item["clause_digest"].startswith("sha256:")
                for item in roles):
        raise PlanningIntelligenceError("planning evidence roles are invalid")
    if not isinstance(lifecycle, dict) or set(lifecycle) != {"mode", "evidence"} \
            or lifecycle["mode"] not in {"project", "incident", "maintenance"} \
            or not isinstance(lifecycle["evidence"], list) \
            or not 1 <= len(lifecycle["evidence"]) <= 8:
        raise PlanningIntelligenceError("planning lifecycle route is invalid")
    try:
        loom_program.validate_program(value["program"])
    except loom_program.ProgramError as exc:
        raise PlanningIntelligenceError(str(exc)) from exc
    # Reuse the compiler's closed catalogue constraints for module and atom identities.
    catalog = load_catalog()
    allowed = {item["id"] for item in catalog["modules"]}
    active_ids = [item.get("id") for item in value["active_modules"]]
    if len(active_ids) != len(set(active_ids)) or not set(active_ids).issubset(allowed) \
            or not set(value["dormant_modules"]).issubset(allowed) \
            or set(active_ids) & set(value["dormant_modules"]) \
            or set(active_ids) | set(value["dormant_modules"]) != allowed:
        raise PlanningIntelligenceError("specialist lifecycle partition is invalid")
    if len(value["atoms"]) > 24:
        raise PlanningIntelligenceError("planning atom bound is exceeded")
    atom_ids = [item.get("atom_id") for item in value["atoms"]]
    declared = [atom_id for item in value["active_modules"]
                for atom_id in item.get("atom_ids", [])]
    if len(atom_ids) != len(set(atom_ids)) or atom_ids != declared:
        raise PlanningIntelligenceError("planning atom identity or ordering is invalid")
    atom_fields = {"atom_id", "module_id", "kind", "statement", "scope",
                   "consequence", "evidence", "provenance", "gate_effect",
                   "required_real_medium", "verification"}
    verification_fields = {"observation_method", "evidence_artifact"}
    for item in value["atoms"]:
        verification = item.get("verification")
        if set(item) != atom_fields or not isinstance(verification, dict) \
                or set(verification) != verification_fields \
                or any(not isinstance(field, str) or not field.strip()
                       for field in verification.values()):
            raise PlanningIntelligenceError(
                "planning atom verification is missing, tautological, or invalid")
        expanded = expanded_verification(value, item)
        if expanded["observation_method"].casefold() == item["statement"].casefold() \
                or expanded["oracle"].casefold() == item["statement"].casefold():
            raise PlanningIntelligenceError(
                "planning atom verification is missing, tautological, or invalid")
    composition = value["composition"]
    if not isinstance(composition, dict) or set(composition) != {
            "nodes", "edges", "conflicts", "graph_digest"} \
            or composition["nodes"] != atom_ids or composition["conflicts"]:
        raise PlanningIntelligenceError("planning atom composition is invalid")
    graph_body = {key: composition[key] for key in ("nodes", "edges", "conflicts")}
    if composition["graph_digest"] != loom_domain_contract.digest(
            "planning-atom-graph-v1", graph_body):
        raise PlanningIntelligenceError("planning atom graph digest mismatch")
    expected_edges = sorted([
        {"from": item["module_id"], "to": item["atom_id"], "kind": "emits"}
        for item in value["atoms"]
    ], key=lambda item: (item["from"], item["to"]))
    if composition["edges"] != expected_edges:
        raise PlanningIntelligenceError("planning atom provenance edges are incomplete")
    return value


def resolve_conflict(left, right, *, conflict_type, relation, same_scope,
                     current_fact_required=False, qualified_authority_required=False):
    """Return the only safe deterministic conflict disposition.

    Automatic resolution is limited to a proved monotone stricter relation in one scope.
    Authority, jurisdiction, intent, and unknown ordering never resolve by arbitrary priority.
    """
    if not isinstance(left, str) or not left or not isinstance(right, str) or not right \
            or conflict_type not in {
                "boolean", "interval", "set", "version", "retention", "authority",
                "jurisdiction", "intent"} \
            or relation not in {"identical", "stricter-left", "stricter-right", "incompatible"} \
            or type(same_scope) is not bool \
            or type(current_fact_required) is not bool \
            or type(qualified_authority_required) is not bool:
        raise PlanningIntelligenceError("planning conflict contract is invalid")
    if relation == "identical":
        disposition = "deduplicate-preserve-provenance"
    elif current_fact_required:
        disposition = "current-fact-block"
    elif qualified_authority_required or conflict_type in {"authority", "jurisdiction"}:
        disposition = "qualified-authority-block"
    elif same_scope and conflict_type in {"interval", "set", "retention"} \
            and relation in {"stricter-left", "stricter-right"}:
        disposition = relation
    elif conflict_type == "intent":
        disposition = "owner-decision-block"
    else:
        disposition = "incompatible-block"
    body = {"schema_version": 1, "left": left, "right": right,
            "conflict_type": conflict_type, "relation": relation,
            "same_scope": same_scope, "current_fact_required": current_fact_required,
            "qualified_authority_required": qualified_authority_required,
            "disposition": disposition}
    return {**body, "conflict_digest": loom_domain_contract.digest(
        "planning-conflict-v1", body)}
