#!/usr/bin/env python3
"""Bounded milestone, resume, incident, and maintenance planning state machines."""

import json
import re

import loom_domain_contract


MAX_MILESTONES = 64
MAX_EDGES = 128
MAX_RESUME_CHARS = 8192
IDENTITY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EFFORT = {"xs", "s", "m", "l", "xl"}
EDGE_KINDS = {"blocks", "depends-on", "optional", "parallel", "external"}

INCIDENT_TRANSITIONS = {
    "detected": {"triaged"},
    "triaged": {"contained", "evidence-preserved"},
    "contained": {"evidence-preserved"},
    "evidence-preserved": {"diagnosed"},
    "diagnosed": {"remediation-planned"},
    "remediation-planned": {"fixed", "rolled-back"},
    "fixed": {"verified"},
    "rolled-back": {"verified"},
    "verified": {"retrospective-complete"},
    "retrospective-complete": set(),
}
MAINTENANCE_TRANSITIONS = {
    "proposed": {"assessed"}, "assessed": {"authorized", "blocked"},
    "authorized": {"active"}, "active": {"verified", "rolled-back"},
    "verified": {"complete"}, "rolled-back": {"verified"},
    "blocked": {"assessed"}, "complete": set(),
}
MAINTENANCE_CLASSES = {
    "dependency-update", "migration", "deprecation", "data-repair",
    "security-patch", "certificate-key", "operational-configuration",
}


class ProgramError(ValueError):
    pass


def _digest(label, value):
    return loom_domain_contract.digest(label, value)


def _identity_key(value):
    return tuple((1, int(part)) if part.isdigit() else (0, part)
                 for part in re.split(r"(\d+)", value))


def build_milestone_graph(milestones, edges):
    if not isinstance(milestones, list) or not 1 <= len(milestones) <= MAX_MILESTONES \
            or not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise ProgramError("milestone graph exceeds its bound")
    expected = {"id", "outcome", "effort", "integration_points", "risks",
                "exit_evidence", "fact_ttls"}
    normalized, ids = [], set()
    for item in milestones:
        if not isinstance(item, dict) or set(item) != expected \
                or not isinstance(item["id"], str) or not IDENTITY.fullmatch(item["id"]) \
                or item["id"] in ids or item["effort"] not in EFFORT \
                or not isinstance(item["outcome"], str) or not item["outcome"].strip():
            raise ProgramError("milestone contract is invalid")
        for field in ("integration_points", "risks", "exit_evidence"):
            if not isinstance(item[field], list) or len(item[field]) > 16 \
                    or not all(isinstance(value, str) and value.strip()
                               for value in item[field]):
                raise ProgramError("milestone evidence is invalid or unbounded")
        if not isinstance(item["fact_ttls"], dict) or len(item["fact_ttls"]) > 16 \
                or any(not isinstance(key, str) or not key.strip()
                       or type(value) is not int or value < 0
                       for key, value in item["fact_ttls"].items()):
            raise ProgramError("milestone fact freshness contract is invalid")
        ids.add(item["id"]); normalized.append(dict(item))
    edge_fields = {"from", "to", "kind"}
    normalized_edges, seen = [], set()
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != edge_fields \
                or edge["from"] not in ids or edge["to"] not in ids \
                or edge["from"] == edge["to"] or edge["kind"] not in EDGE_KINDS:
            raise ProgramError("milestone dependency is invalid")
        identity = (edge["from"], edge["to"], edge["kind"])
        if identity in seen:
            raise ProgramError("milestone dependency is duplicated")
        seen.add(identity); normalized_edges.append(dict(edge))
    adjacency = {item: set() for item in ids}
    for edge in normalized_edges:
        if edge["kind"] != "optional":
            adjacency[edge["from"]].add(edge["to"])
    visiting, visited = set(), set()
    def visit(node):
        if node in visiting:
            raise ProgramError("milestone dependency graph contains a cycle")
        if node in visited:
            return
        visiting.add(node)
        for target in sorted(adjacency[node]):
            visit(target)
        visiting.remove(node); visited.add(node)
    for node in sorted(ids):
        visit(node)
    enriched = []
    effort_points = {"xs": (1, 1), "s": (1, 2), "m": (2, 5),
                     "l": (5, 13), "xl": (13, 21)}
    for item in normalized:
        material = dict(item)
        minimum, maximum = effort_points[item["effort"]]
        material["effort_interval"] = {
            "minimum": minimum, "maximum": maximum, "unit": "relative-point"}
        material["impact_cone_hash"] = _digest("planning-milestone-v1", item)
        enriched.append(material)
    body = {"schema_version": 1,
            "milestones": sorted(enriched, key=lambda item: _identity_key(item["id"])),
            "edges": sorted(normalized_edges,
                            key=lambda item: (item["from"], item["to"], item["kind"]))}
    return {**body, "graph_digest": _digest("planning-milestone-graph-v1", body)}


def validate_milestone_graph(graph):
    if not isinstance(graph, dict) or set(graph) != {
            "schema_version", "milestones", "edges", "graph_digest"} \
            or graph.get("schema_version") != 1:
        raise ProgramError("milestone graph fields are invalid")
    source = []
    for item in graph.get("milestones", []):
        if not isinstance(item, dict) or set(item) != {
                "id", "outcome", "effort", "effort_interval", "integration_points",
                "risks", "exit_evidence", "fact_ttls", "impact_cone_hash"}:
            raise ProgramError("milestone contract is invalid")
        source.append({key: item[key] for key in (
            "id", "outcome", "effort", "integration_points", "risks",
            "exit_evidence", "fact_ttls")})
    if build_milestone_graph(source, graph.get("edges")) != graph:
        raise ProgramError("milestone graph digest mismatch or generated fields mismatch")
    return graph


def build_program(description, *, tier, lifecycle_mode):
    """Compile a bounded production program only when the request needs one."""
    if tier not in {"S", "M", "L", "XL"} \
            or lifecycle_mode not in {"project", "incident", "maintenance"}:
        raise ProgramError("planning program inputs are invalid")
    text = str(description or "")
    phase_ids = []
    clusters = re.finditer(
        r"(?i)\b(?:phase|stage)\s+"
        r"(\d{1,2}(?:\s*(?:,|and|&)\s*(?:(?:phase|stage)\s+)?\d{1,2})*)",
        text)
    for cluster in clusters:
        for number in re.findall(r"\d{1,2}", cluster.group(1)):
            identity = "phase-" + number
            if identity not in phase_ids:
                phase_ids.append(identity)
    needs_program = tier in {"L", "XL"} or len(phase_ids) > 1
    if not needs_program:
        return None
    if not phase_ids:
        phase_ids = (["contain", "remediate", "verify"] if lifecycle_mode == "incident"
                     else ["assess", "change", "verify"] if lifecycle_mode == "maintenance"
                     else ["plan", "implement", "verify"])
    if len(phase_ids) > MAX_MILESTONES:
        raise ProgramError("named phase count exceeds the milestone bound")
    milestones = [{
        "id": identity,
        "outcome": identity.replace("-", " ") + " complete",
        "effort": "m", "integration_points": [],
        "risks": ["dependency evidence incomplete"],
        "exit_evidence": ["observable milestone evidence"],
        "fact_ttls": {},
    } for identity in phase_ids]
    edges = [
        {"from": phase_ids[index], "to": phase_ids[index + 1], "kind": "depends-on"}
        for index in range(len(phase_ids) - 1)
    ]
    graph = build_milestone_graph(milestones, edges)
    body = {
        "schema_version": 1, "lifecycle_mode": lifecycle_mode,
        "initial_state": {"project": "planned", "incident": "detected",
                          "maintenance": "proposed"}[lifecycle_mode],
        "milestone_graph": graph,
    }
    return {**body, "program_digest": _digest("planning-program-v1", body)}


def validate_program(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "lifecycle_mode", "initial_state", "milestone_graph",
            "program_digest"} or value.get("schema_version") != 1:
        raise ProgramError("planning program fields are invalid")
    expected_state = {"project": "planned", "incident": "detected",
                      "maintenance": "proposed"}.get(value.get("lifecycle_mode"))
    if value.get("initial_state") != expected_state:
        raise ProgramError("planning program lifecycle state is invalid")
    validate_milestone_graph(value["milestone_graph"])
    body = dict(value); claimed = body.pop("program_digest")
    if claimed != _digest("planning-program-v1", body):
        raise ProgramError("planning program digest mismatch")
    return value


def affected_milestones(graph, seeds):
    validate_milestone_graph(graph)
    claimed = graph["graph_digest"]
    ids = {item["id"] for item in graph["milestones"]}
    affected = set(seeds)
    if not affected or not affected.issubset(ids):
        raise ProgramError("drift seeds are invalid")
    adjacency = {item: set() for item in ids}
    for edge in graph["edges"]:
        if edge["kind"] != "optional":
            adjacency[edge["from"]].add(edge["to"])
    frontier = sorted(affected, key=_identity_key)
    while frontier:
        current = frontier.pop(0)
        for target in sorted(adjacency[current]):
            if target not in affected:
                affected.add(target); frontier.append(target)
    receipt = {"graph_digest": claimed,
               "seeds": sorted(seeds, key=_identity_key),
               "affected": sorted(affected, key=_identity_key),
               "isolated": sorted(ids - affected, key=_identity_key)}
    return {**receipt, "impact_cone_digest": _digest("planning-impact-cone-v1", receipt)}


def validate_impact_receipt(value):
    fields = {"graph_digest", "seeds", "affected", "isolated", "impact_cone_digest"}
    if not isinstance(value, dict) or set(value) != fields \
            or any(not isinstance(value[name], list)
                   or value[name] != sorted(set(value[name]), key=_identity_key)
                   for name in ("seeds", "affected", "isolated")) \
            or not set(value["seeds"]).issubset(value["affected"]) \
            or set(value["affected"]) & set(value["isolated"]):
        raise ProgramError("planning impact receipt is invalid")
    body = dict(value); claimed = body.pop("impact_cone_digest")
    if claimed != _digest("planning-impact-cone-v1", body):
        raise ProgramError("planning impact receipt digest mismatch")
    return value


def resume_capsule(graph, *, current_milestone, frontier, open_decisions,
                   blockers, stale_facts, accepted_isolated_evidence):
    closure = affected_milestones(graph, [current_milestone])
    body = {
        "schema_version": 1, "graph_digest": graph["graph_digest"],
        "current_milestone": current_milestone,
        "frontier": list(frontier), "open_decisions": list(open_decisions),
        "blockers": list(blockers), "stale_facts": list(stale_facts),
        "accepted_isolated_evidence": list(accepted_isolated_evidence),
        "impact_cone_digest": closure["impact_cone_digest"],
    }
    if any(not isinstance(value, list) or len(value) > 32 \
           or not all(isinstance(item, str) and item.strip() for item in value)
           for value in (body["frontier"], body["open_decisions"], body["blockers"],
                         body["stale_facts"], body["accepted_isolated_evidence"])):
        raise ProgramError("resume capsule content is invalid or unbounded")
    capsule = {**body, "capsule_digest": _digest("planning-resume-capsule-v1", body)}
    if len(json.dumps(capsule, sort_keys=True, separators=(",", ":"))) > MAX_RESUME_CHARS:
        raise ProgramError("resume capsule exceeds its bound")
    return capsule


def transition(mode, current, target, *, reversible=False, authority=False,
               evidence_preserved=False, maintenance_class=None):
    if mode == "incident":
        transitions = INCIDENT_TRANSITIONS
        if current == "triaged" and target == "contained" and not reversible:
            raise ProgramError("emergency containment must be reversible")
        if target in {"fixed", "rolled-back"} and not authority:
            raise ProgramError("incident remediation requires explicit authority")
        if target in {"diagnosed", "remediation-planned", "fixed", "rolled-back"} \
                and not evidence_preserved:
            raise ProgramError("incident evidence must be preserved before remediation")
    elif mode == "maintenance":
        transitions = MAINTENANCE_TRANSITIONS
        if maintenance_class not in MAINTENANCE_CLASSES:
            raise ProgramError("maintenance class is invalid")
        if target == "authorized" and not authority:
            raise ProgramError("maintenance authorization is missing")
    else:
        raise ProgramError("planning lifecycle mode is invalid")
    if current not in transitions or target not in transitions[current]:
        raise ProgramError("planning lifecycle transition is invalid")
    body = {"schema_version": 1, "mode": mode, "from": current, "to": target,
            "reversible": bool(reversible), "authority": bool(authority),
            "evidence_preserved": bool(evidence_preserved),
            "maintenance_class": maintenance_class}
    return {**body, "transition_digest": _digest("planning-lifecycle-transition-v1", body)}
