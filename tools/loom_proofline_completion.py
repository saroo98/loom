#!/usr/bin/env python3
"""Shadow semantic completion and monotone orphan-change evaluation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

import loom_lifecycle
import loom_lint
import loom_proofline


SCHEMA_VERSION = 1
POLICY_ID = "loom-proofline-policy-v1"
MAX_CHANGED_PATHS = 100000


class CompletionError(ValueError):
    pass


def _load_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CompletionError(f"{label} is unreadable: {exc}") from exc


def load_policy(path):
    value = _load_json(path, "Proofline policy")
    return validate_policy(value)


def validate_policy(value):
    required = {
        "schema_version", "policy_id", "mode", "path_classes",
        "promoted_predicates", "advisory_predicates", "thresholds", "rollback",
    }
    path_classes = {"generated", "vendored", "ignored", "unrelated"}
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != 1 \
            or value.get("policy_id") != POLICY_ID \
            or value.get("mode") not in {"shadow", "enforced-monotone-only"} \
            or not isinstance(value.get("path_classes"), dict) \
            or set(value["path_classes"]) != path_classes \
            or any(not isinstance(patterns, list) or len(patterns) > 64
                   for patterns in value["path_classes"].values()) \
            or value.get("promoted_predicates") != [
                "exact-unauthorized-project-path"] \
            or not isinstance(value.get("advisory_predicates"), list) \
            or not isinstance(value.get("thresholds"), dict) \
            or set(value["thresholds"]) != {
                "minimum_cases", "maximum_false_positives",
                "maximum_false_negatives"} \
            or value["thresholds"]["minimum_cases"] < 1 \
            or value["thresholds"]["maximum_false_positives"] != 0 \
            or value["thresholds"]["maximum_false_negatives"] != 0:
        raise CompletionError("Proofline policy is invalid")
    return value


def _safe_path(value):
    if not isinstance(value, str) or not value or len(value) > 1000 \
            or "\\" in value:
        raise CompletionError("changed path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise CompletionError("changed path is unsafe")
    return path.as_posix()


def _path_class(path, policy, explicit_classes):
    if path in explicit_classes:
        value = explicit_classes[path]
        if value not in {"generated", "ignored", "project", "unrelated", "vendored"}:
            raise CompletionError("explicit path class is invalid")
        return value
    matched = [
        kind for kind, patterns in policy["path_classes"].items()
        if any(loom_proofline.path_matches(pattern, path) for pattern in patterns)
    ]
    return matched[0] if len(matched) == 1 else "unknown" if matched else "project"


def evaluate(*, ledger, graph, policy, changed_paths, authorized_touches,
             completed_work_orders=None, evidence_ids=None, lifecycle_sha256=None,
             explicit_path_classes=None):
    loom_proofline.validate_material_ledger(ledger)
    loom_proofline.validate_graph(graph)
    if graph["ledger_sha256"] != ledger["ledger_sha256"]:
        raise CompletionError("Proofline ledger and graph subjects differ")
    if not isinstance(changed_paths, list) \
            or len(changed_paths) > MAX_CHANGED_PATHS \
            or len(changed_paths) != len(set(changed_paths)):
        raise CompletionError("changed paths are invalid")
    changed_paths = sorted(_safe_path(path) for path in changed_paths)
    if not isinstance(authorized_touches, list) \
            or len(authorized_touches) > 2048 \
            or any(not isinstance(item, str) or not item
                   for item in authorized_touches):
        raise CompletionError("authorized touch patterns are invalid")
    completed = set(completed_work_orders or [])
    if any(not isinstance(item, str) or not loom_proofline.WO_RE.fullmatch(item)
           for item in completed):
        raise CompletionError("completed work-order identities are invalid")
    evidence = dict(evidence_ids or {})
    if set(evidence) - completed \
            or any(not isinstance(items, list) or any(
                not isinstance(item, str) or not item.startswith("sha256-")
                for item in items) for items in evidence.values()):
        raise CompletionError("completion evidence identities are invalid")
    explicit_classes = dict(explicit_path_classes or {})
    path_rows = []
    orphans = []
    for path in changed_paths:
        path_class = _path_class(path, policy, explicit_classes)
        matches = sorted(
            pattern for pattern in authorized_touches
            if loom_proofline.path_matches(pattern, path))
        if path_class == "project":
            authorization = "authorized" if matches else "orphan"
            reason = (
                "authorized-touch-match" if matches
                else "exact-unauthorized-project-path")
        elif path_class == "unknown":
            authorization = "unknown"
            reason = "path-class-conflict"
        else:
            authorization = "excluded-advisory"
            reason = f"{path_class}-path-relevance-advisory"
        if authorization == "orphan":
            orphans.append(path)
        path_rows.append({
            "path": path, "class": path_class,
            "authorization": authorization,
            "matched_patterns": matches,
            "reason_code": reason,
        })
    coverage = []
    for atom in ledger["atoms"]:
        work_order = atom["work_order"]
        if work_order is None:
            state = "unknown"
            reasons = ["material-intent-ambiguity-unresolved"]
            ids = []
        elif work_order not in completed:
            state = "pending"
            reasons = ["work-order-not-completed"]
            ids = []
        elif not evidence.get(work_order):
            state = "unknown"
            reasons = ["qualifying-real-medium-evidence-unavailable"]
            ids = []
        else:
            state = "evidence-present"
            reasons = ["semantic-completion-remains-advisory"]
            ids = sorted(set(evidence[work_order]))
        coverage.append({
            "atom_id": atom["atom_id"], "work_order": work_order,
            "state": state, "evidence_ids": ids,
            "reason_codes": reasons, "semantic_claim": "advisory",
        })
    if orphans and policy["mode"] == "enforced-monotone-only":
        gate = {
            "state": "failed",
            "reason_codes": ["exact-unauthorized-project-path"],
            "orphan_paths": orphans,
        }
    elif any(item["authorization"] == "unknown" for item in path_rows):
        gate = {
            "state": "advisory",
            "reason_codes": ["path-class-conflict"],
            "orphan_paths": orphans,
        }
    else:
        gate = {
            "state": "passed",
            "reason_codes": [],
            "orphan_paths": [],
        }
    body = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": POLICY_ID,
        "mode": policy["mode"],
        "ledger_sha256": ledger["ledger_sha256"],
        "graph_sha256": graph["graph_sha256"],
        "lifecycle_sha256": lifecycle_sha256,
        "intent_coverage": coverage,
        "path_evaluation": path_rows,
        "gate": gate,
        "limitations": [
            "Path authorization cannot prove semantic completion.",
            "Material intent completion remains advisory until outcome-specific evidence is compiled.",
        ],
    }
    value = {**body, "report_sha256": loom_proofline.digest(body)}
    validate_report(value)
    return value


def validate_report(value):
    required = {
        "schema_version", "policy_id", "mode", "ledger_sha256",
        "graph_sha256", "lifecycle_sha256", "intent_coverage",
        "path_evaluation", "gate", "limitations", "report_sha256",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("policy_id") != POLICY_ID \
            or value.get("mode") not in {"shadow", "enforced-monotone-only"} \
            or any(not isinstance(value.get(key), str)
                   or len(value[key]) != 64
                   or any(char not in "0123456789abcdef" for char in value[key])
                   for key in ("ledger_sha256", "graph_sha256")) \
            or (value.get("lifecycle_sha256") is not None
                and (not isinstance(value["lifecycle_sha256"], str)
                     or len(value["lifecycle_sha256"]) != 64)) \
            or not isinstance(value.get("intent_coverage"), list) \
            or not isinstance(value.get("path_evaluation"), list) \
            or not isinstance(value.get("limitations"), list) \
            or not isinstance(value.get("gate"), dict) \
            or set(value["gate"]) != {"state", "reason_codes", "orphan_paths"} \
            or value["gate"]["state"] not in {"passed", "failed", "advisory"}:
        raise CompletionError("Proofline completion report is invalid")
    body = dict(value)
    observed = body.pop("report_sha256", None)
    if observed != loom_proofline.digest(body):
        raise CompletionError("Proofline completion report digest changed")
    return value


def _work_orders(pack):
    paths = [pack / "WO-001.md"] if (pack / "WO-001.md").is_file() \
        else sorted((pack / "work-orders").glob("WO-*.md"))
    touches = []
    for path in paths:
        frontmatter, _body = loom_lint.parse_frontmatter(
            path.read_text(encoding="utf-8"))
        touches.extend(frontmatter.get("touches", []))
    return paths, sorted(set(touches))


def evaluate_pack(pack, repo, *, policy_path):
    pack = Path(pack)
    repo = Path(repo)
    ledger = _load_json(
        pack / "proofline" / "material-intent-ledger.json",
        "material intent ledger")
    graph = _load_json(
        pack / "proofline" / "proof-graph.json", "Proofline graph")
    policy = load_policy(policy_path)
    lifecycle_path = (
        pack / ".loom-small-lifecycle.json"
        if (pack / ".loom-small-lifecycle.json").is_file()
        else pack / "lifecycle.json")
    lifecycle = _load_json(lifecycle_path, "lifecycle")
    lifecycle_sha256 = hashlib.sha256(lifecycle_path.read_bytes()).hexdigest()
    _paths, touches = _work_orders(pack)
    changed = []
    completed = []
    evidence = {}
    if lifecycle_path.name == ".loom-small-lifecycle.json":
        completion_rows = [
            item for item in lifecycle.get("events", [])
            if item.get("event") == "small-completed"]
        for completion in completion_rows:
            identity = completion["work_order"]
            completed.append(identity)
            changed.extend(completion["changed_paths"])
            evidence_path = pack / "evidence" / f"{identity}.json"
            if hashlib.sha256(evidence_path.read_bytes()).hexdigest() \
                    != completion["acceptance_evidence_sha256"]:
                raise CompletionError("compact completion evidence digest changed")
            receipt = loom_lifecycle.validate_acceptance_evidence(
                pack, identity, repo=repo)
            evidence.setdefault(identity, []).append(receipt["evidence_id"])
    else:
        for completion in lifecycle.get("work_order_completions", []):
            identity = completion["work_order"]
            completed.append(identity)
            changed.extend(completion["changed_paths"])
            evidence_path = pack / completion["acceptance_evidence"]
            if hashlib.sha256(evidence_path.read_bytes()).hexdigest() \
                    != completion["acceptance_evidence_sha256"]:
                raise CompletionError("completion evidence digest changed")
            receipt = loom_lifecycle.validate_acceptance_evidence(
                pack, identity, repo=repo)
            evidence.setdefault(identity, []).append(receipt["evidence_id"])
    return evaluate(
        ledger=ledger, graph=graph, policy=policy,
        changed_paths=sorted(set(changed)), authorized_touches=touches,
        completed_work_orders=completed, evidence_ids=evidence,
        lifecycle_sha256=lifecycle_sha256)


def evaluate_corpus(corpus, policy):
    if not isinstance(corpus, dict) \
            or corpus.get("schema_version") != 1 \
            or corpus.get("frozen_before_evaluation") is not True \
            or not isinstance(corpus.get("cases"), list):
        raise CompletionError("Proofline corpus is invalid")
    false_positives = []
    false_negatives = []
    rows = []
    # Corpus exercises the path predicate directly; it does not need graph nodes.
    for case in corpus["cases"]:
        path = _safe_path(case["path"])
        path_class = _path_class(path, policy, {})
        matches = [
            pattern for pattern in case["touches"]
            if loom_proofline.path_matches(pattern, path)]
        observed = (
            "authorized" if path_class == "project" and matches else
            "orphan" if path_class == "project" else
            "excluded-advisory" if path_class != "unknown" else "unknown")
        rows.append({"id": case["id"], "expected": case["expected"], "observed": observed})
        if observed == "orphan" and case["expected"] != "orphan":
            false_positives.append(case["id"])
        if observed != "orphan" and case["expected"] == "orphan":
            false_negatives.append(case["id"])
    thresholds = policy["thresholds"]
    passed = (
        len(rows) >= thresholds["minimum_cases"]
        and len(false_positives) <= thresholds["maximum_false_positives"]
        and len(false_negatives) <= thresholds["maximum_false_negatives"])
    return {
        "schema_version": 1, "corpus_id": corpus["corpus_id"],
        "case_count": len(rows), "false_positives": false_positives,
        "false_negatives": false_negatives, "passed": passed, "rows": rows,
    }
