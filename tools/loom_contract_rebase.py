#!/usr/bin/env python3
"""Advisory-only preservation analysis after repository or domain drift."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

import loom_lint
import loom_proofline


SCHEMA_VERSION = 1
POLICY_ID = "loom-contract-rebase-policy-v1"
CONSEQUENCES = {"ordinary", "material", "high", "critical"}
DOMAIN_STATES = {"consistent", "conflicted", "unknown"}
WORLD_COVERAGE = {"complete", "incomplete"}
SUBJECT_TYPES = {
    "current-fact", "domain-invariant", "evidence", "intent-atom",
    "path-effect", "verification-recipe", "work-order",
}
REASON_CODES = {
    "authorized-path-changed", "consequence-changed",
    "disjoint-changed-paths", "domain-rule-conflicted",
    "domain-state-unknown", "evidence-freshness-not-reproved",
    "fact-dependency-not-proved", "material-intent-unresolved",
    "subject-invalidated", "verification-dependency-not-proved",
    "work-order-dependency-unknown", "world-coverage-incomplete",
}
RULE_IDS = {
    "disjoint-authorized-path-v1", "identical-content-subject-v1",
}


class RebaseError(ValueError):
    pass


def load_policy(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RebaseError(f"contract rebase policy is unreadable: {exc}") from exc
    fields = {
        "schema_version", "policy_id", "mode", "monotone_rules",
        "automatic_authority", "fresh_action_required", "rollback",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("policy_id") != POLICY_ID \
            or value.get("mode") != "advisory" \
            or value.get("automatic_authority") != "never" \
            or value.get("fresh_action_required") is not True \
            or not isinstance(value.get("monotone_rules"), list):
        raise RebaseError("contract rebase policy is invalid")
    expected = {"disjoint-authorized-path-v1", "identical-content-subject-v1"}
    if {item.get("rule_id") for item in value["monotone_rules"]} != expected:
        raise RebaseError("contract rebase monotone rules are invalid")
    return value


def _row(subject_id, subject_type, reason_code, rule_id=None):
    return {
        "subject_id": subject_id,
        "subject_type": subject_type,
        "reason_code": reason_code,
        "rule_id": rule_id,
    }


def _affected(patterns, changed_paths):
    return any(
        loom_proofline.path_matches(pattern, path)
        for pattern in patterns for path in changed_paths)


def evaluate(*, ledger, graph, work_orders, changed_paths, prior_consequence,
             current_consequence, world_coverage_complete, domain_state,
             policy):
    loom_proofline.validate_material_ledger(ledger)
    loom_proofline.validate_graph(graph)
    if graph["ledger_sha256"] != ledger["ledger_sha256"]:
        raise RebaseError("contract rebase subjects differ")
    if prior_consequence not in CONSEQUENCES \
            or current_consequence not in CONSEQUENCES \
            or type(world_coverage_complete) is not bool \
            or domain_state not in DOMAIN_STATES:
        raise RebaseError("contract rebase state is invalid")
    if not isinstance(changed_paths, list) \
            or len(changed_paths) != len(set(changed_paths)):
        raise RebaseError("contract rebase changed paths are invalid")
    normalized_paths = []
    for path in changed_paths:
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if not isinstance(path, str) or not path or "\\" in path \
                or pure.is_absolute() or ".." in pure.parts \
                or pure.as_posix() != path:
            raise RebaseError("contract rebase path is unsafe")
        normalized_paths.append(path)
    normalized_paths.sort()
    work_order_map = {}
    for item in work_orders:
        if not isinstance(item, dict) or set(item) != {"id", "touches"} \
                or not loom_proofline.WO_RE.fullmatch(str(item["id"])) \
                or not isinstance(item["touches"], list) \
                or not item["touches"] \
                or any(not isinstance(pattern, str) or not pattern
                       for pattern in item["touches"]) \
                or item["id"] in work_order_map:
            raise RebaseError("contract rebase work order is invalid")
        work_order_map[item["id"]] = item["touches"]
    preserved = []
    invalidated = []
    unknown = []
    decisions = []
    consequence_changed = prior_consequence != current_consequence
    global_decision = (
        consequence_changed or not world_coverage_complete
        or domain_state != "consistent")
    global_reason = (
        "consequence-changed" if consequence_changed else
        "world-coverage-incomplete" if not world_coverage_complete else
        "domain-rule-conflicted" if domain_state == "conflicted" else
        "domain-state-unknown")
    for identity, touches in sorted(work_order_map.items()):
        if global_decision:
            decisions.append(_row(identity, "work-order", global_reason))
        elif _affected(touches, normalized_paths):
            invalidated.append(_row(
                identity, "work-order", "authorized-path-changed"))
        else:
            preserved.append(_row(
                identity, "work-order", "disjoint-changed-paths",
                "disjoint-authorized-path-v1"))
    for atom in ledger["atoms"]:
        identity = atom["atom_id"]
        if atom["work_order"] is None:
            decisions.append(_row(
                identity, "intent-atom", "material-intent-unresolved"))
            continue
        touches = work_order_map.get(atom["work_order"])
        if touches is None:
            unknown.append(_row(
                identity, "intent-atom", "work-order-dependency-unknown"))
        elif global_decision:
            decisions.append(_row(identity, "intent-atom", global_reason))
        elif _affected(touches, normalized_paths):
            invalidated.append(_row(
                identity, "intent-atom", "authorized-path-changed"))
        else:
            preserved.append(_row(
                identity, "intent-atom", "disjoint-changed-paths",
                "disjoint-authorized-path-v1"))
    for node in graph["nodes"]:
        node_type = node["node_type"]
        if node_type == "current-fact":
            target = decisions if global_decision else unknown
            target.append(_row(
                node["node_id"], "current-fact",
                global_reason if global_decision else "fact-dependency-not-proved"))
        elif node_type == "verification-medium":
            unknown.append(_row(
                node["node_id"], "verification-recipe",
                "verification-dependency-not-proved"))
    for identity, touches in sorted(work_order_map.items()):
        if global_decision:
            decisions.extend([
                _row(f"path:{identity}", "path-effect", global_reason),
                _row(f"evidence:{identity}", "evidence", global_reason),
            ])
        elif _affected(touches, normalized_paths):
            invalidated.extend([
                _row(f"path:{identity}", "path-effect", "authorized-path-changed"),
                _row(f"evidence:{identity}", "evidence", "subject-invalidated"),
            ])
        else:
            preserved.append(_row(
                f"path:{identity}", "path-effect", "disjoint-changed-paths",
                "disjoint-authorized-path-v1"))
            unknown.append(_row(
                f"evidence:{identity}", "evidence",
                "evidence-freshness-not-reproved"))
    body = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": policy["policy_id"],
        "mode": "advisory",
        "prior_graph_sha256": graph["graph_sha256"],
        "changed_paths": normalized_paths,
        "prior_consequence": prior_consequence,
        "current_consequence": current_consequence,
        "world_coverage": "complete" if world_coverage_complete else "incomplete",
        "domain_state": domain_state,
        "preserved": sorted(preserved, key=lambda item: (
            item["subject_type"], item["subject_id"])),
        "invalidated": sorted(invalidated, key=lambda item: (
            item["subject_type"], item["subject_id"])),
        "unknown": sorted(unknown, key=lambda item: (
            item["subject_type"], item["subject_id"])),
        "decision_required": sorted(decisions, key=lambda item: (
            item["subject_type"], item["subject_id"])),
        "implementation_authorized": False,
        "fresh_action_required": True,
        "authority_effect": "none",
    }
    value = {**body, "report_sha256": loom_proofline.digest(body)}
    validate(value)
    return value


def validate(value):
    fields = {
        "schema_version", "policy_id", "mode", "prior_graph_sha256",
        "changed_paths", "prior_consequence", "current_consequence",
        "world_coverage", "domain_state", "preserved", "invalidated",
        "unknown", "decision_required", "implementation_authorized",
        "fresh_action_required", "authority_effect", "report_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("policy_id") != POLICY_ID \
            or value.get("mode") != "advisory" \
            or value.get("prior_consequence") not in CONSEQUENCES \
            or value.get("current_consequence") not in CONSEQUENCES \
            or value.get("world_coverage") not in WORLD_COVERAGE \
            or value.get("domain_state") not in DOMAIN_STATES \
            or value.get("implementation_authorized") is not False \
            or value.get("fresh_action_required") is not True \
            or value.get("authority_effect") != "none" \
            or not isinstance(value.get("prior_graph_sha256"), str) \
            or len(value["prior_graph_sha256"]) != 64 \
            or not isinstance(value.get("changed_paths"), list) \
            or len(value["changed_paths"]) != len(set(value["changed_paths"])) \
            or any(not isinstance(value.get(key), list)
                   for key in ("preserved", "invalidated", "unknown",
                               "decision_required")):
        raise RebaseError("contract rebase report is invalid")
    for path in value["changed_paths"]:
        pure = PurePosixPath(path) if isinstance(path, str) else None
        if not isinstance(path, str) or not path or "\\" in path \
                or pure.is_absolute() or ".." in pure.parts \
                or pure.as_posix() != path:
            raise RebaseError("contract rebase path is unsafe")
    body = dict(value)
    observed = body.pop("report_sha256", None)
    if observed != loom_proofline.digest(body):
        raise RebaseError("contract rebase report digest changed")
    identities = []
    for state in ("preserved", "invalidated", "unknown", "decision_required"):
        for row in value[state]:
            if not isinstance(row, dict) \
                    or set(row) != {
                        "subject_id", "subject_type", "reason_code", "rule_id"} \
                    or not isinstance(row["subject_id"], str) \
                    or not row["subject_id"] \
                    or row["subject_type"] not in SUBJECT_TYPES \
                    or row["reason_code"] not in REASON_CODES \
                    or row["rule_id"] not in RULE_IDS | {None}:
                raise RebaseError("contract rebase row is invalid")
            identities.append((row["subject_type"], row["subject_id"]))
    if len(identities) != len(set(identities)):
        raise RebaseError("contract rebase subject appears in multiple states")
    return value


def work_orders_from_pack(pack):
    pack = Path(pack)
    paths = [pack / "WO-001.md"] if (pack / "WO-001.md").is_file() \
        else sorted((pack / "work-orders").glob("WO-*.md"))
    rows = []
    for path in paths:
        frontmatter, _ = loom_lint.parse_frontmatter(
            path.read_text(encoding="utf-8"))
        touches = frontmatter["touches"]
        rows.append({
            "id": frontmatter["id"],
            "touches": touches if isinstance(touches, list) else [touches],
        })
    return rows
