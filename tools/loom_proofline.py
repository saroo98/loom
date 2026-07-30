#!/usr/bin/env python3
"""Deterministic, authority-derived Proofline projections.

Proofline does not grant authority. It projects exact request, plan, work-order,
and evidence identities into bounded material-intent and proof-graph records.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import PurePosixPath


LEDGER_SCHEMA_VERSION = 1
GRAPH_SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_ATOMS = 128
MAX_NODES = 1024
MAX_EDGES = 4096
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
WO_RE = re.compile(r"^WO-[0-9]{3,}$")
TOKEN_RE = re.compile(r"[a-z0-9]+")
STOP_WORDS = frozenset({
    "about", "after", "again", "against", "also", "before", "being", "could",
    "current", "does", "each", "from", "have", "into", "make", "must", "only",
    "project", "request", "should", "that", "their", "them", "then", "there",
    "these", "this", "through", "when", "where", "which", "with", "would",
})
AMBIGUITY_MARKERS = frozenset({
    "appropriate", "best", "better", "clean", "easy", "efficient", "elegant",
    "fast", "good", "great", "ideal", "improve", "modern", "nice", "perfect",
    "proper", "quick", "robust", "safe", "simple", "some", "soon",
})
EDGE_TYPES = frozenset({
    "authorizes", "derived-from", "implements", "requires", "verifies",
})
NODE_TYPES = frozenset({
    "acceptance", "authority", "current-fact", "intent-atom",
    "verification-medium", "work-order",
})
POLICY_CLASSES = frozenset({
    "generated", "ignored", "project", "unrelated", "vendored",
})


class ProoflineError(ValueError):
    pass


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _text(value, label, maximum, *, nullable=False):
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum \
            or "\x00" in value:
        raise ProoflineError(f"{label} is invalid")
    return value


def _tokens(value):
    return {
        item for item in TOKEN_RE.findall(value.casefold())
        if len(item) >= 3 and item not in STOP_WORDS
    }


def _escaped(value, index):
    backslashes = 0
    index -= 1
    while index >= 0 and value[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _merge_ranges(ranges):
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _code_ranges(request):
    """Return closed Markdown code spans and fences as protected ranges."""
    ranges = []
    index = 0
    length = len(request)
    while index < length:
        if request[index] != "`" or _escaped(request, index):
            index += 1
            continue
        opening = index
        while index < length and request[index] == "`":
            index += 1
        fence_length = index - opening
        closing = index
        while closing < length:
            if request[closing] != "`" or _escaped(request, closing):
                closing += 1
                continue
            end = closing
            while end < length and request[end] == "`":
                end += 1
            if end - closing == fence_length:
                ranges.append((opening, end))
                index = end
                break
            closing = end
        else:
            raise ProoflineError(
                "sealed request contains an unterminated Markdown code span")
    return ranges


def _quote_ranges(request, code_ranges):
    """Protect matched quoted text without treating apostrophes as delimiters."""
    ranges = []
    code_index = 0
    index = 0
    length = len(request)
    pairs = {'"': '"', "'": "'", "\u201c": "\u201d", "\u2018": "\u2019"}
    while index < length:
        while code_index < len(code_ranges) \
                and code_ranges[code_index][1] <= index:
            code_index += 1
        if code_index < len(code_ranges) \
                and code_ranges[code_index][0] <= index \
                < code_ranges[code_index][1]:
            index = code_ranges[code_index][1]
            continue
        opening = request[index]
        closing_character = pairs.get(opening)
        if closing_character is None or _escaped(request, index):
            index += 1
            continue
        if opening == "'" and index > 0 and index + 1 < length \
                and request[index - 1].isalnum() \
                and request[index + 1].isalnum():
            index += 1
            continue
        closing = index + 1
        while closing < length:
            protected = next((
                item for item in code_ranges
                if item[0] <= closing < item[1]), None)
            if protected is not None:
                closing = protected[1]
                continue
            if request[closing] == closing_character \
                    and not _escaped(request, closing):
                if opening != "'" or closing + 1 == length \
                        or not request[closing + 1].isalnum():
                    ranges.append((index, closing + 1))
                    index = closing + 1
                    break
            closing += 1
        else:
            index += 1
    return ranges


def _protected_ranges(request):
    code = _code_ranges(request)
    return _merge_ranges([*code, *_quote_ranges(request, code)])


def _segments(request):
    encoded = request.encode("utf-8")
    if not encoded or len(encoded) > MAX_REQUEST_BYTES or "\x00" in request:
        raise ProoflineError("sealed request is outside the Proofline bound")
    values = []
    index = 0
    length = len(request)
    boundaries = []
    protected = _protected_ranges(request)
    protected_index = 0
    while index < length:
        while protected_index < len(protected) \
                and protected[protected_index][1] <= index:
            protected_index += 1
        if protected_index < len(protected) \
                and protected[protected_index][0] <= index \
                < protected[protected_index][1]:
            index = protected[protected_index][1]
            continue
        character = request[index]
        if character in "\r\n":
            boundaries.append(index)
            index += 1
            if character == "\r" and index < length and request[index] == "\n":
                index += 1
            continue
        if character in "!?;" or (
                character == "."
                and (index + 1 == length or request[index + 1].isspace())):
            end = index + 1
            while end < length and request[end] == character:
                end += 1
            boundaries.append(end)
            index = end
            continue
        index += 1
    boundaries.append(length)
    segment_start = 0
    for boundary in boundaries:
        text = request[segment_start:boundary]
        left = len(text) - len(text.lstrip())
        right = len(text.rstrip())
        start = segment_start + left
        end = segment_start + right
        if start >= end:
            segment_start = boundary
            while segment_start < length and request[segment_start] in "\r\n":
                segment_start += 1
            continue
        values.append((start, end, request[start:end]))
        segment_start = boundary
        while segment_start < length and request[segment_start] in "\r\n":
            segment_start += 1
    if not values:
        values = [(0, len(request), request)]
    if len(values) > MAX_ATOMS:
        raise ProoflineError("sealed request exceeds the material-intent atom bound")
    return values


def _authority(kind, identity, subject_digest):
    if kind not in {"plan-contract", "sealed-request"} \
            or not isinstance(identity, str) or not ID_RE.fullmatch(identity) \
            or not isinstance(subject_digest, str) or not SHA_RE.fullmatch(subject_digest):
        raise ProoflineError("material intent authority is invalid")
    return {
        "kind": kind,
        "authority_id": identity,
        "subject_digest": subject_digest,
    }


def _work_order_text(work_order):
    return " ".join([
        work_order["title"], work_order["outcome"],
        *work_order["tasks"], *work_order["acceptance"],
        *work_order["negative_acceptance"], *work_order["touches"],
    ])


def build_material_ledger(*, request, plan_contract, semantic_draft):
    """Derive immutable material atoms from exact source spans.

    Lexical assignment is permitted only when one work order has a unique
    positive score. Ties and zero-overlap segments remain unresolved.
    """
    if not isinstance(plan_contract, dict) \
            or not SHA_RE.fullmatch(str(plan_contract.get("request_hash", ""))) \
            or not SHA_RE.fullmatch(str(plan_contract.get("contract_hash", ""))):
        raise ProoflineError("plan contract identity is unavailable")
    if hashlib.sha256(request.encode("utf-8")).hexdigest() \
            != plan_contract["request_hash"]:
        raise ProoflineError("sealed request differs from the plan contract")
    work_orders = semantic_draft.get("work_orders") \
        if isinstance(semantic_draft, dict) else None
    if not isinstance(work_orders, list) or not work_orders \
            or len(work_orders) > 64:
        raise ProoflineError("semantic work orders are unavailable")
    wo_tokens = {}
    wo_by_id = {}
    for work_order in work_orders:
        identity = work_order.get("id")
        if not isinstance(identity, str) or not WO_RE.fullmatch(identity) \
                or identity in wo_by_id:
            raise ProoflineError("work-order identity is invalid")
        wo_by_id[identity] = work_order
        wo_tokens[identity] = _tokens(_work_order_text(work_order))
    consequence = (
        plan_contract.get("domain_route", {}).get("consequence", {}).get("class"))
    if consequence not in {"ordinary", "material", "high", "critical"}:
        consequence = {
            "S": "ordinary", "M": "material", "L": "high", "XL": "critical",
        }.get(plan_contract.get("tier"), "material")
    request_authority = _authority(
        "sealed-request", "owner-request", plan_contract["request_hash"])
    plan_authority = _authority(
        "plan-contract", "sealed-plan-contract", plan_contract["contract_hash"])
    atoms = []
    for index, (start, end, source_text) in enumerate(_segments(request), 1):
        source_tokens = _tokens(source_text)
        scores = {
            identity: len(source_tokens & tokens)
            for identity, tokens in wo_tokens.items()
        }
        best = max(scores.values(), default=0)
        winners = sorted(identity for identity, score in scores.items() if score == best)
        markers = sorted(source_tokens & AMBIGUITY_MARKERS)
        resolved = best > 0 and len(winners) == 1 and not markers
        work_order_id = winners[0] if resolved else None
        reasons = []
        if best == 0:
            reasons.append("no-unique-plan-binding")
        elif len(winners) != 1:
            reasons.append("multiple-plan-bindings")
        if markers:
            reasons.append("qualitative-term-needs-acceptance-target")
        normalized = " ".join(source_text.split())
        source_digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        atom_body = {
            "atom_id": f"intent-{index:03d}",
            "source": {
                "kind": "sealed-request",
                "subject_digest": plan_contract["request_hash"],
                "start": start,
                "end": end,
                "text_sha256": source_digest,
            },
            "normalized_meaning": normalized,
            "ambiguity": {
                "state": "resolved" if resolved else "unresolved",
                "reasons": reasons,
            },
            "consequence": consequence,
            "consumer": (
                f"work-order:{work_order_id}" if resolved else "owner-review"),
            "decision_effect": (
                "include-in-sealed-plan" if resolved
                else "resolve-before-completion-claim"),
            "scope": (
                list(wo_by_id[work_order_id]["touches"]) if resolved else []),
            "work_order": work_order_id,
            "authority": plan_authority if resolved else request_authority,
        }
        atoms.append({
            **atom_body,
            "content_digest": digest(atom_body),
        })
    body = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "request_sha256": plan_contract["request_hash"],
        "plan_contract_sha256": plan_contract["contract_hash"],
        "derivation": {
            "algorithm": "loom-material-intent-v1",
            "source": "exact-request-spans-and-unique-work-order-token-overlap",
            "authority_effect": "none",
        },
        "atoms": atoms,
    }
    value = {**body, "ledger_sha256": digest(body)}
    validate_material_ledger(value, request=request)
    return value


def validate_material_ledger(value, *, request=None):
    required = {
        "schema_version", "request_sha256", "plan_contract_sha256",
        "derivation", "atoms", "ledger_sha256",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != LEDGER_SCHEMA_VERSION \
            or not SHA_RE.fullmatch(str(value.get("request_sha256", ""))) \
            or not SHA_RE.fullmatch(str(value.get("plan_contract_sha256", ""))) \
            or not isinstance(value.get("atoms"), list) \
            or not 1 <= len(value["atoms"]) <= MAX_ATOMS:
        raise ProoflineError("material intent ledger is invalid")
    derivation = value["derivation"]
    if derivation != {
            "algorithm": "loom-material-intent-v1",
            "source": "exact-request-spans-and-unique-work-order-token-overlap",
            "authority_effect": "none"}:
        raise ProoflineError("material intent derivation is invalid")
    if request is not None \
            and hashlib.sha256(request.encode("utf-8")).hexdigest() \
            != value["request_sha256"]:
        raise ProoflineError("material intent request subject changed")
    seen = set()
    previous_end = -1
    for atom in value["atoms"]:
        fields = {
            "atom_id", "source", "normalized_meaning", "ambiguity",
            "consequence", "consumer", "decision_effect", "scope",
            "work_order", "authority", "content_digest",
        }
        if not isinstance(atom, dict) or set(atom) != fields \
                or not ID_RE.fullmatch(str(atom.get("atom_id", ""))) \
                or atom["atom_id"] in seen \
                or atom.get("consequence") not in {
                    "ordinary", "material", "high", "critical"} \
                or not isinstance(atom.get("scope"), list) \
                or len(atom["scope"]) > 32 \
                or len(atom["scope"]) != len(set(atom["scope"])) \
                or (atom.get("work_order") is not None
                    and not WO_RE.fullmatch(str(atom["work_order"]))):
            raise ProoflineError("material intent atom is invalid")
        seen.add(atom["atom_id"])
        source = atom["source"]
        if not isinstance(source, dict) or set(source) != {
                "kind", "subject_digest", "start", "end", "text_sha256"} \
                or source["kind"] != "sealed-request" \
                or source["subject_digest"] != value["request_sha256"] \
                or type(source["start"]) is not int or type(source["end"]) is not int \
                or not 0 <= source["start"] < source["end"] \
                or source["start"] < previous_end \
                or not SHA_RE.fullmatch(str(source["text_sha256"])):
            raise ProoflineError("material intent source span is invalid")
        previous_end = source["end"]
        if request is not None:
            exact = request[source["start"]:source["end"]]
            if hashlib.sha256(exact.encode("utf-8")).hexdigest() \
                    != source["text_sha256"]:
                raise ProoflineError("material intent source span changed")
            if atom["normalized_meaning"] != " ".join(exact.split()):
                raise ProoflineError("material intent source meaning changed")
        ambiguity = atom["ambiguity"]
        if not isinstance(ambiguity, dict) or set(ambiguity) != {"state", "reasons"} \
                or ambiguity["state"] not in {"resolved", "unresolved"} \
                or not isinstance(ambiguity["reasons"], list) \
                or len(ambiguity["reasons"]) > 8 \
                or any(not isinstance(item, str) or not item
                       for item in ambiguity["reasons"]) \
                or (ambiguity["state"] == "resolved" and ambiguity["reasons"]) \
                or (ambiguity["state"] == "unresolved" and not ambiguity["reasons"]) \
                or (ambiguity["state"] == "resolved" and atom["work_order"] is None) \
                or (ambiguity["state"] == "unresolved" and atom["work_order"] is not None):
            raise ProoflineError("material intent ambiguity state is invalid")
        _text(atom["normalized_meaning"], "normalized meaning", 4096)
        _text(atom["consumer"], "consumer", 160)
        _text(atom["decision_effect"], "decision effect", 160)
        _authority(
            atom["authority"].get("kind"),
            atom["authority"].get("authority_id"),
            atom["authority"].get("subject_digest"))
        expected = {
            key: item for key, item in atom.items() if key != "content_digest"}
        if atom["content_digest"] != digest(expected):
            raise ProoflineError("material intent atom digest mismatch")
    if request is not None:
        expected_spans = [
            (start, end) for start, end, unused in _segments(request)]
        observed_spans = [
            (atom["source"]["start"], atom["source"]["end"])
            for atom in value["atoms"]]
        if observed_spans != expected_spans:
            raise ProoflineError("material intent segmentation changed")
    if value["ledger_sha256"] != digest({
            key: item for key, item in value.items() if key != "ledger_sha256"}):
        raise ProoflineError("material intent ledger digest mismatch")
    return value


def _node(identity, node_type, subject_digest, authority, payload_digest):
    if not ID_RE.fullmatch(identity) or node_type not in NODE_TYPES \
            or not SHA_RE.fullmatch(subject_digest) \
            or not SHA_RE.fullmatch(payload_digest):
        raise ProoflineError("Proofline node is invalid")
    body = {
        "node_id": identity,
        "node_type": node_type,
        "subject_digest": subject_digest,
        "governing_authority": authority,
        "payload_sha256": payload_digest,
    }
    return {**body, "node_sha256": digest(body)}


def _edge(identity, edge_type, source, target, authority, subjects):
    if not ID_RE.fullmatch(identity) or edge_type not in EDGE_TYPES \
            or not ID_RE.fullmatch(source) or not ID_RE.fullmatch(target) \
            or not isinstance(subjects, list) or not subjects \
            or any(not SHA_RE.fullmatch(str(item)) for item in subjects):
        raise ProoflineError("Proofline edge is invalid")
    body = {
        "edge_id": identity,
        "edge_type": edge_type,
        "source": source,
        "target": target,
        "governing_authority": authority,
        "subject_digests": sorted(set(subjects)),
    }
    return {**body, "edge_sha256": digest(body)}


def build_graph(*, ledger, plan_contract, semantic_draft, assignments):
    validate_material_ledger(ledger)
    if ledger["plan_contract_sha256"] != plan_contract.get("contract_hash"):
        raise ProoflineError("Proofline plan subject changed")
    if not isinstance(assignments, dict) \
            or assignments.get("plan_contract_hash") != plan_contract["contract_hash"] \
            or re.fullmatch(
                r"^sha256:[0-9a-f]{64}$",
                str(assignments.get("assignment_digest", ""))) is None:
        raise ProoflineError("planning assignments are unavailable")
    plan_authority = _authority(
        "plan-contract", "sealed-plan-contract", plan_contract["contract_hash"])
    request_authority = _authority(
        "sealed-request", "owner-request", plan_contract["request_hash"])
    nodes = [
        _node(
            "authority:request", "authority", plan_contract["request_hash"],
            request_authority, plan_contract["request_hash"]),
        _node(
            "authority:plan", "authority", plan_contract["contract_hash"],
            plan_authority, plan_contract["contract_hash"]),
    ]
    edges = []
    wo_nodes = {}
    for work_order in semantic_draft["work_orders"]:
        identity = "work-order:" + work_order["id"].casefold()
        wo_nodes[work_order["id"]] = identity
        nodes.append(_node(
            identity, "work-order", digest(work_order), plan_authority,
            digest(work_order)))
        edges.append(_edge(
            f"edge:plan-authorizes-{work_order['id'].casefold()}",
            "authorizes", "authority:plan", identity, plan_authority,
            [plan_contract["contract_hash"], digest(work_order)]))
        for index, criterion in enumerate(work_order["acceptance"], 1):
            acceptance_id = (
                f"acceptance:{work_order['id'].casefold()}:{index:02d}")
            criterion_digest = hashlib.sha256(
                criterion.encode("utf-8")).hexdigest()
            nodes.append(_node(
                acceptance_id, "acceptance", criterion_digest,
                plan_authority, criterion_digest))
            edges.append(_edge(
                f"edge:{work_order['id'].casefold()}-requires-{index:02d}",
                "requires", identity, acceptance_id, plan_authority,
                [plan_contract["contract_hash"], criterion_digest]))
    for atom in ledger["atoms"]:
        identity = "atom:" + atom["atom_id"]
        nodes.append(_node(
            identity, "intent-atom", atom["content_digest"],
            atom["authority"], atom["content_digest"]))
        edges.append(_edge(
            f"edge:{atom['atom_id']}-from-request", "derived-from",
            identity, "authority:request", request_authority,
            [ledger["request_sha256"], atom["content_digest"]]))
        if atom["work_order"] is not None:
            edges.append(_edge(
                f"edge:{atom['atom_id']}-implemented-by-{atom['work_order'].casefold()}",
                "implements", wo_nodes[atom["work_order"]], identity,
                plan_authority,
                [atom["content_digest"], plan_contract["contract_hash"]]))
    for index, fact in enumerate(plan_contract.get("current_facts_to_verify", []), 1):
        fact_digest = digest(fact)
        nodes.append(_node(
            f"current-fact:{index:03d}", "current-fact", fact_digest,
            plan_authority, fact_digest))
    for index, medium in enumerate(plan_contract.get("verification_media", []), 1):
        medium_digest = digest(medium)
        nodes.append(_node(
            f"verification-medium:{index:03d}", "verification-medium",
            medium_digest, plan_authority, medium_digest))
    body = {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "ledger_sha256": ledger["ledger_sha256"],
        "plan_contract_sha256": plan_contract["contract_hash"],
        "assignment_digest": assignments["assignment_digest"],
        "authority_effect": "none",
        "nodes": sorted(nodes, key=lambda item: item["node_id"]),
        "edges": sorted(edges, key=lambda item: item["edge_id"]),
    }
    value = {**body, "graph_sha256": digest(body)}
    validate_graph(value)
    return value


def validate_graph(value):
    required = {
        "schema_version", "ledger_sha256", "plan_contract_sha256",
        "assignment_digest", "authority_effect", "nodes", "edges",
        "graph_sha256",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != GRAPH_SCHEMA_VERSION \
            or value.get("authority_effect") != "none" \
            or any(not SHA_RE.fullmatch(str(value.get(key, ""))) for key in (
                "ledger_sha256", "plan_contract_sha256")) \
            or re.fullmatch(
                r"^sha256:[0-9a-f]{64}$",
                str(value.get("assignment_digest", ""))) is None \
            or not isinstance(value.get("nodes"), list) \
            or not 1 <= len(value["nodes"]) <= MAX_NODES \
            or not isinstance(value.get("edges"), list) \
            or len(value["edges"]) > MAX_EDGES:
        raise ProoflineError("Proofline graph is invalid")
    nodes = {}
    for node in value["nodes"]:
        if not isinstance(node, dict) or set(node) != {
                "node_id", "node_type", "subject_digest",
                "governing_authority", "payload_sha256", "node_sha256"} \
                or node["node_id"] in nodes \
                or node["node_type"] not in NODE_TYPES \
                or not ID_RE.fullmatch(str(node["node_id"])) \
                or not SHA_RE.fullmatch(str(node["subject_digest"])) \
                or not SHA_RE.fullmatch(str(node["payload_sha256"])) \
                or node["node_sha256"] != digest({
                    key: item for key, item in node.items()
                    if key != "node_sha256"}):
            raise ProoflineError("Proofline graph node is invalid")
        _authority(
            node["governing_authority"].get("kind"),
            node["governing_authority"].get("authority_id"),
            node["governing_authority"].get("subject_digest"))
        nodes[node["node_id"]] = node
    seen_edges = set()
    adjacency = {identity: [] for identity in nodes}
    for edge in value["edges"]:
        if not isinstance(edge, dict) or set(edge) != {
                "edge_id", "edge_type", "source", "target",
                "governing_authority", "subject_digests", "edge_sha256"} \
                or edge["edge_id"] in seen_edges \
                or edge["edge_type"] not in EDGE_TYPES \
                or edge["source"] not in nodes or edge["target"] not in nodes \
                or not isinstance(edge["subject_digests"], list) \
                or not edge["subject_digests"] \
                or edge["subject_digests"] != sorted(set(edge["subject_digests"])) \
                or any(not SHA_RE.fullmatch(str(item))
                       for item in edge["subject_digests"]) \
                or edge["edge_sha256"] != digest({
                    key: item for key, item in edge.items()
                    if key != "edge_sha256"}):
            raise ProoflineError("Proofline graph edge is invalid")
        _authority(
            edge["governing_authority"].get("kind"),
            edge["governing_authority"].get("authority_id"),
            edge["governing_authority"].get("subject_digest"))
        seen_edges.add(edge["edge_id"])
        adjacency[edge["source"]].append(edge["target"])
    visiting = set()
    visited = set()

    def visit(identity):
        if identity in visiting:
            raise ProoflineError("Proofline graph contains a cycle")
        if identity in visited:
            return
        visiting.add(identity)
        for target in sorted(adjacency[identity]):
            visit(target)
        visiting.remove(identity)
        visited.add(identity)

    for identity in sorted(nodes):
        visit(identity)
    if value["graph_sha256"] != digest({
            key: item for key, item in value.items() if key != "graph_sha256"}):
        raise ProoflineError("Proofline graph digest mismatch")
    return value


def path_matches(pattern, path):
    """Conservative POSIX path matching for authorized touch patterns."""
    if not isinstance(pattern, str) or not isinstance(path, str):
        raise ProoflineError("path match inputs are invalid")
    normalized_pattern = pattern.replace("\\", "/")
    normalized_path = path.replace("\\", "/")
    pattern_path = PurePosixPath(normalized_pattern)
    path_value = PurePosixPath(normalized_path)
    if pattern_path.is_absolute() or path_value.is_absolute() \
            or ".." in pattern_path.parts or ".." in path_value.parts:
        raise ProoflineError("path match inputs are unsafe")
    return fnmatch.fnmatchcase(normalized_path, normalized_pattern)


def classify_path(path, policies):
    if not isinstance(policies, dict) or set(policies) != POLICY_CLASSES:
        raise ProoflineError("path policies are incomplete")
    matched = [
        kind for kind, patterns in policies.items()
        if any(path_matches(pattern, path) for pattern in patterns)
    ]
    if len(matched) > 1:
        return "unknown"
    return matched[0] if matched else "project"
