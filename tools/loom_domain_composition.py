#!/usr/bin/env python3
"""Consequence-aware subsystem composition for Loom domain routes."""

import re

import loom_domain_contract


MAX_SUBSYSTEMS = 32
MAX_EDGES = 64

CONSEQUENCE_PATTERNS = (
    ("critical", "human-safety", (
        r"\b(?:death|fatal|life[- ]critical|life[- ]support|patient harm|collision avoidance|explosive)\b",
    )),
    ("high", "physical-safety", (
        r"\b(?:medical|clinical|firmware|hardware|industrial|robot|vehicle|vessel|power system)\b",
    )),
    ("high", "regulated-or-financial", (
        r"\b(?:tax|accounting|bookkeep|regulated|legal|compliance|credential|security[- ]critical)\b",
    )),
    ("material", "durable-data-or-contract", (
        r"\b(?:migration|database|ledger|public api|payment|backfill|release|production)\b",
    )),
)

BOUNDARY_PATTERNS = (
    r"\bwith\b", r"\bintegrat(?:e|es|ion|ing)\b", r"\bcontrols?\b",
    r"\bcheckout\b", r"\btax\b", r"\bpayment\b", r"\bshared\b",
)


class DomainCompositionError(ValueError):
    pass


def classify_consequence(description):
    text = str(description or "").casefold()
    rank = {"ordinary": 0, "material": 1, "high": 2, "critical": 3}
    selected = "ordinary"
    categories, evidence = [], []
    for consequence, category, patterns in CONSEQUENCE_PATTERNS:
        hits = [pattern for pattern in patterns if re.search(pattern, text, re.I)]
        if hits:
            categories.append(category)
            evidence.extend(hits)
            if rank[consequence] > rank[selected]:
                selected = consequence
    return {"class": selected, "categories": sorted(set(categories)),
            "evidence": sorted(set(evidence))}


def _normalize_subsystems(domains, coverage_by_domain, consequence, proposals):
    if proposals is None:
        return sorted([{
            "id": f"domain-{domain_id}", "domains": [domain_id],
            "coverage": coverage_by_domain[domain_id],
            "consequence": consequence["class"],
            "blocked": coverage_by_domain[domain_id] != "known",
        } for domain_id in domains], key=lambda item: item["id"])
    if not isinstance(proposals, list) or not 1 <= len(proposals) <= MAX_SUBSYSTEMS:
        raise DomainCompositionError("subsystem proposal is invalid or exceeds its bound")
    result, seen = [], set()
    fields = {"id", "domains", "coverage", "consequence", "blocked"}
    for item in proposals:
        if not isinstance(item, dict) or set(item) != fields:
            raise DomainCompositionError("subsystem proposal fields are unknown or missing")
        if not isinstance(item["id"], str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", item["id"]) or item["id"] in seen:
            raise DomainCompositionError("subsystem identity is invalid or duplicated")
        if not isinstance(item["domains"], list) or not item["domains"] \
                or len(item["domains"]) > 16 or len(item["domains"]) != len(set(item["domains"])) \
                or not set(item["domains"]).issubset(domains):
            raise DomainCompositionError("subsystem domains are invalid")
        if item["coverage"] not in loom_domain_contract.COVERAGE_STATES \
                or item["consequence"] not in loom_domain_contract.CONSEQUENCE_CLASSES \
                or type(item["blocked"]) is not bool:
            raise DomainCompositionError("subsystem state is invalid")
        seen.add(item["id"]); result.append(dict(item))
    if set(domains) != {domain for item in result for domain in item["domains"]}:
        raise DomainCompositionError("subsystem proposal omits an active domain")
    return sorted(result, key=lambda item: item["id"])


def build_graph(description, domains, coverage_by_domain, *, subsystems=None, edges=None):
    if not isinstance(domains, list) or not 1 <= len(domains) <= 16 \
            or len(domains) != len(set(domains)):
        raise DomainCompositionError("composition requires bounded unique domains")
    if not isinstance(coverage_by_domain, dict) or set(coverage_by_domain) != set(domains) \
            or any(value not in loom_domain_contract.COVERAGE_STATES
                   for value in coverage_by_domain.values()):
        raise DomainCompositionError("coverage map must exactly match active domains")
    consequence = classify_consequence(description)
    nodes = _normalize_subsystems(domains, coverage_by_domain, consequence, subsystems)
    ids = {item["id"] for item in nodes}
    if edges is None:
        has_boundary = any(re.search(pattern, str(description or ""), re.I)
                           for pattern in BOUNDARY_PATTERNS)
        edges = []
        if has_boundary and len(nodes) > 1:
            anchor = nodes[0]["id"]
            edges = [{"from": anchor, "to": item["id"], "kind": "shared-interface",
                      "consequence": max(
                          (nodes[0]["consequence"], item["consequence"]),
                          key=("ordinary", "material", "high", "critical").index),
                      "blocked": nodes[0]["blocked"] or item["blocked"]}
                     for item in nodes[1:]]
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise DomainCompositionError("composition edges exceed their bound")
    normalized_edges, seen_edges = [], set()
    edge_fields = {"from", "to", "kind", "consequence", "blocked"}
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != edge_fields \
                or edge["from"] not in ids or edge["to"] not in ids \
                or edge["from"] == edge["to"] \
                or edge["kind"] not in {"data-flow", "control-flow", "material-flow",
                                         "shared-interface", "depends-on"} \
                or edge["consequence"] not in loom_domain_contract.CONSEQUENCE_CLASSES \
                or type(edge["blocked"]) is not bool:
            raise DomainCompositionError("composition edge is invalid")
        identity = (edge["from"], edge["to"], edge["kind"])
        if identity in seen_edges:
            raise DomainCompositionError("composition edge is duplicated")
        seen_edges.add(identity); normalized_edges.append(dict(edge))
    body = {"schema_version": 1, "nodes": nodes,
            "edges": sorted(normalized_edges,
                            key=lambda item: (item["from"], item["to"], item["kind"])),
            "consequence": consequence}
    return {**body, "graph_digest": loom_domain_contract.digest(
        "domain-composition-v1", body)}


def affected_branches(graph, changed_node_ids):
    """Return the bounded dependency closure affected by changed evidence.

    Propagation follows directed dependency/interface edges only.  Unconnected branches
    remain untouched, which is the positive isolation proof required for branch-local
    progress.
    """
    if not isinstance(graph, dict) or set(graph) != {
            "schema_version", "nodes", "edges", "consequence", "graph_digest"}:
        raise DomainCompositionError("composition graph fields are unknown or missing")
    body = dict(graph); claimed = body.pop("graph_digest")
    if claimed != loom_domain_contract.digest("domain-composition-v1", body):
        raise DomainCompositionError("composition graph digest mismatch")
    node_ids = {item["id"] for item in graph["nodes"]}
    changed = set(changed_node_ids)
    if not changed or not changed.issubset(node_ids):
        raise DomainCompositionError("changed subsystem set is invalid")
    adjacency = {node_id: set() for node_id in node_ids}
    for edge in graph["edges"]:
        adjacency[edge["from"]].add(edge["to"])
    frontier = sorted(changed)
    affected = set(changed)
    while frontier:
        current = frontier.pop(0)
        for target in sorted(adjacency[current]):
            if target not in affected:
                affected.add(target); frontier.append(target)
        if len(affected) > MAX_SUBSYSTEMS:
            raise DomainCompositionError("composition traversal exceeded its bound")
    return {
        "affected": sorted(affected),
        "isolated": sorted(node_ids - affected),
        "proof": loom_domain_contract.digest(
            "domain-branch-isolation-v1",
            {"graph_digest": graph["graph_digest"], "changed": sorted(changed),
             "affected": sorted(affected)}),
    }
