#!/usr/bin/env python3
"""Deterministic release-blocking evaluation for planning intelligence."""

import argparse
import hashlib
import json
import random
import time
from pathlib import Path

import loom_domain
import loom_domain_contract
import loom_planning_intelligence
import loom_tier


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "planning-intelligence" / "corpus.json"


class PlanningEvaluationError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def load(path=DEFAULT_CORPUS):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "policy_version", "seed", "variants_per_case", "cases"} \
            or value["schema_version"] != 1 \
            or value["policy_version"] != "planning-intelligence-evaluation-v1" \
            or type(value["seed"]) is not int \
            or value["variants_per_case"] != 4 \
            or not isinstance(value["cases"], list) or len(value["cases"]) < 16:
        raise PlanningEvaluationError("planning evaluation corpus contract is invalid")
    case_fields = {"id", "split", "request", "expected_domains", "expected_tier",
                   "expected_lifecycle", "required_modules", "forbidden_modules"}
    ids = set()
    for case in value["cases"]:
        if not isinstance(case, dict) or set(case) != case_fields \
                or case["id"] in ids or case["split"] not in {
                    "development", "calibration", "release-holdout"}:
            raise PlanningEvaluationError("planning evaluation case is invalid")
        ids.add(case["id"])
    return value


def _variant(request, index, rng):
    wrappers = [
        "{request}",
        "Request: {request}",
        "Task: {request}",
        "Current target request: {request}",
    ]
    order = list(range(len(wrappers)))
    rng.shuffle(order)
    return wrappers[order[index]].format(request=request)


def run(path=DEFAULT_CORPUS):
    corpus = load(path)
    rng = random.Random(corpus["seed"])
    failures = []
    harmful_activation = unsafe_authorization = provenance_loss = stale_fresh = 0
    unnecessary_questions = decision_atoms = context_bytes = 0
    context_sizes = []; tier_s_context_sizes = []; sealed_sizes = []
    split_counts = {}
    holdout_identities = []
    started = time.perf_counter()
    for case in corpus["cases"]:
        split_counts[case["split"]] = split_counts.get(case["split"], 0) \
            + corpus["variants_per_case"]
        if case["split"] == "release-holdout":
            holdout_identities.append(case["id"])
        for index in range(corpus["variants_per_case"]):
            request = _variant(case["request"], index, rng)
            route_result = loom_domain.select_domains(request)
            route = route_result["domain_contract"]
            tier = loom_tier.classify(
                request, domains=route["active_task_domains"])["tier"]
            if route["coverage_state"] != "known" and tier == "S":
                tier = "M"
            try:
                intelligence = loom_planning_intelligence.compile_intelligence(
                    request, tier=tier, route=route)
                loom_planning_intelligence.validate(intelligence)
            except loom_planning_intelligence.PlanningIntelligenceError as exc:
                failures.append({"case": case["id"], "variant": index,
                                 "failures": ["compiler:" + str(exc)],
                                 "domains": route["active_task_domains"], "tier": tier,
                                 "active_modules": []})
                continue
            actual_domains = route["active_task_domains"]
            active = {item["id"] for item in intelligence["active_modules"]}
            missing = sorted(set(case["required_modules"]) - active)
            forbidden = sorted(set(case["forbidden_modules"]) & active)
            wrong = []
            if actual_domains != case["expected_domains"]:
                wrong.append("domains")
            if tier != case["expected_tier"]:
                wrong.append("tier")
            if intelligence["lifecycle_route"]["mode"] != case["expected_lifecycle"]:
                wrong.append("lifecycle")
            if missing:
                wrong.append("missing-modules:" + ",".join(missing))
            if forbidden:
                wrong.append("harmful-modules:" + ",".join(forbidden))
            harmful_activation += len(forbidden)
            unsafe_authorization += int(
                route_result["requires_domain_discovery"] and route_result["g1_status"] != "blocked")
            expected_edges = len(intelligence["atoms"])
            provenance_loss += int(len(intelligence["composition"]["edges"]) != expected_edges)
            stale_fresh += int(any(
                atom["kind"] == "current-fact-query" and not
                loom_planning_intelligence.expanded_verification(
                    intelligence, atom)["freshness"]
                for atom in intelligence["atoms"]))
            unnecessary_questions += sum(
                atom["kind"] == "question" for atom in intelligence["atoms"])
            decision_atoms += sum(
                atom["kind"] in {"decision-requirement", "alternative"}
                for atom in intelligence["atoms"])
            sealed_sizes.append(len(loom_domain_contract.canonical_bytes(intelligence)))
            rendered = loom_planning_intelligence.render_for_host(intelligence)
            context_size = len(loom_domain_contract.canonical_bytes(rendered))
            context_bytes += context_size; context_sizes.append(context_size)
            if tier == "S":
                tier_s_context_sizes.append(context_size)
            budget = 4096 if tier == "S" else 8192
            if context_size > budget:
                wrong.append(f"context-budget:{context_size}>{budget}")
            if wrong:
                failures.append({"case": case["id"], "variant": index,
                                 "failures": wrong, "domains": actual_domains,
                                 "tier": tier, "active_modules": sorted(active)})
    case_count = len(corpus["cases"]) * corpus["variants_per_case"]
    holdout_digest = "sha256:" + hashlib.sha256(
        _canonical(sorted(holdout_identities)).encode("ascii")).hexdigest()
    report = {
        "schema_version": 1, "policy_version": corpus["policy_version"],
        "case_count": case_count, "split_counts": split_counts,
        "holdout_identity_digest": holdout_digest,
        "critical_harmful_activations": harmful_activation,
        "unsafe_authorizations": unsafe_authorization,
        "provenance_losses": provenance_loss,
        "stale_fresh_claims": stale_fresh,
        "unnecessary_question_atoms": unnecessary_questions,
        "decision_atoms": decision_atoms,
        "mean_context_bytes": context_bytes // max(1, case_count),
        "maximum_context_bytes": max(context_sizes, default=0),
        "maximum_tier_s_context_bytes": max(tier_s_context_sizes, default=0),
        "maximum_sealed_contract_bytes": max(sealed_sizes, default=0),
        "failures": failures[:64],
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }
    report["passed"] = not failures and not any((
        harmful_activation, unsafe_authorization, provenance_loss, stale_fresh)) \
        and report["maximum_context_bytes"] <= 8192 \
        and report["maximum_tier_s_context_bytes"] <= 4096
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    report = run(args.corpus)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
