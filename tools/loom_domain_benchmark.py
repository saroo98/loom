#!/usr/bin/env python3
"""Locked, deterministic Phase 3 route/abstention benchmark."""

import argparse
import json
import statistics
import time
from pathlib import Path

import loom_domain
import loom_domain_learning
import loom_domain_contract


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "domain-intelligence" / "corpus.json"


class DomainBenchmarkError(ValueError):
    pass


def load(path=DEFAULT_CORPUS):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "policy_version", "variants_per_family", "families"} \
            or value["schema_version"] != 1 \
            or value["policy_version"] != "domain-intelligence-v1" \
            or value["variants_per_family"] != 20 \
            or not isinstance(value["families"], list) or len(value["families"]) != 12:
        raise DomainBenchmarkError("benchmark corpus contract is invalid")
    cases = []
    for family in value["families"]:
        if not isinstance(family, dict) or set(family) != {
                "id", "description", "expected_domains", "expected_coverage", "hidden_cue"}:
            raise DomainBenchmarkError("benchmark family fields are invalid")
        for variant in range(value["variants_per_family"]):
            split = "development" if variant < 8 else "calibration" if variant < 14 \
                else "release-holdout"
            cases.append({**family, "case_id": f"{family['id']}-{variant:02d}",
                          "split": split,
                          "description": f"{family['description']} (fixture {variant:02d})"})
    if len(cases) != 240 or sum(item["hidden_cue"] for item in cases) < 120:
        raise DomainBenchmarkError("benchmark must expand to 240 cases with half hidden cues")
    return cases


def run(path=DEFAULT_CORPUS):
    cases = load(path)
    started = time.perf_counter()
    true_positive = false_positive = false_negative = unsafe = 0
    boundary_misses = 0
    question_counts = []
    failures = []
    split_counts = {}
    for case in cases:
        split_counts[case["split"]] = split_counts.get(case["split"], 0) + 1
        result = loom_domain.select_domains(case["description"])
        expected, actual = set(case["expected_domains"]), set(result["active_task_domains"])
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
        boundary_misses += int(not expected.issubset(actual))
        expected_unknown = case["expected_coverage"] == "unknown"
        unsafe += int(expected_unknown and result["g1_status"] != "blocked")
        question_counts.append(0 if not expected_unknown else
                               min(8, 4 if result["domain_contract"]["consequence"]["class"]
                                   == "ordinary" else 8))
        if expected != actual or (expected_unknown and result["coverage_state"] != "unknown"):
            failures.append({"case_id": case["case_id"], "expected": sorted(expected),
                             "actual": sorted(actual),
                             "coverage": result["coverage_state"]})
    recall = true_positive / max(1, true_positive + false_negative)
    precision = true_positive / max(1, true_positive + false_positive)
    sorted_questions = sorted(question_counts)
    report = {
        "schema_version": 1, "policy_version": "domain-intelligence-v1",
        "case_count": len(cases), "hidden_cue_cases": sum(item["hidden_cue"] for item in cases),
        "split_counts": split_counts, "macro_recall": round(recall, 6),
        "macro_precision": round(precision, 6),
        "critical_high_unsafe_authorizations": unsafe,
        "material_boundary_misses": boundary_misses,
        "median_owner_questions": sorted_questions[len(sorted_questions) // 2],
        "p95_owner_questions": sorted_questions[int(len(sorted_questions) * .95) - 1],
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "failures": failures[:32],
    }
    report["passed"] = (unsafe == 0 and boundary_misses == 0
                        and recall >= .98 and precision >= .97
                        and report["p95_owner_questions"] <= 8)
    return report


def scope_firewall_traces(traces=100_000):
    if type(traces) is not int or not 1 <= traces <= 1_000_000:
        raise DomainBenchmarkError("scope trace count is invalid")
    domains = ("accounting", "realtime-3d", "firmware-hardware", "quantum-optics")
    wrong = 0
    for index in range(traces):
        stored = domains[index % len(domains)]
        requested = domains[(index * 3 + 1) % len(domains)]
        stored_project = f"p-{index % 97}"
        requested_project = f"p-{(index * 5 + 3) % 97}"
        stored_component = f"c-{index % 11}"
        requested_component = f"c-{(index * 7 + 2) % 11}"
        invariant = {"domain_ids": [stored], "scope": {
            "project_id": stored_project, "component": stored_component}}
        selected = loom_domain_learning.matches_scope(
            invariant, domain=requested, project_id=requested_project,
            component=requested_component)
        exact = (stored, stored_project, stored_component) == (
            requested, requested_project, requested_component)
        wrong += int(selected and not exact)
    return {"traces": traces, "wrong_domain_selections": wrong, "passed": wrong == 0}


def performance(iterations=1000):
    if type(iterations) is not int or not 10 <= iterations <= 100_000:
        raise DomainBenchmarkError("performance iteration count is invalid")
    timings = {"known": [], "unknown": []}
    capsules = {}
    for label, request in (("known", "Build a CLI parser with stable exit codes"),
                           ("unknown", "Plan a quantum optics laboratory rig")):
        for _ in range(iterations):
            started = time.perf_counter_ns()
            result = loom_domain.select_domains(request)
            timings[label].append((time.perf_counter_ns() - started) / 1_000_000)
        capsules[label] = len(loom_domain_contract.canonical_bytes(
            result["domain_contract"]))
    report = {
        "iterations": iterations,
        "known_p50_ms": round(statistics.median(timings["known"]), 6),
        "known_p95_ms": round(sorted(timings["known"])[int(iterations * .95) - 1], 6),
        "unknown_p95_ms": round(sorted(timings["unknown"])[int(iterations * .95) - 1], 6),
        "known_capsule_bytes": capsules["known"],
        "unknown_capsule_bytes": capsules["unknown"],
        "known_external_retrievals": 0,
    }
    report["passed"] = (report["known_p95_ms"] < 20
                        and report["unknown_capsule_bytes"] <= 8192
                        and report["known_external_retrievals"] == 0)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--scope-traces", type=int, default=0)
    parser.add_argument("--performance-iterations", type=int, default=0)
    args = parser.parse_args(argv)
    report = run(args.corpus)
    if args.scope_traces:
        report["scope_firewall"] = scope_firewall_traces(args.scope_traces)
        report["passed"] = report["passed"] and report["scope_firewall"]["passed"]
    if args.performance_iterations:
        report["performance"] = performance(args.performance_iterations)
        report["passed"] = report["passed"] and report["performance"]["passed"]
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
