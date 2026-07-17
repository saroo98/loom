#!/usr/bin/env python3
"""Deterministic, offline Loom performance corpus runner."""

import argparse
import hashlib
import json
import os
import platform
import random
import statistics
import tempfile
import time
from pathlib import Path

import loom_survey
import loom_tier


def _percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction + .999)))]


def _fixture(root, workload):
    target = root / workload["id"]
    target.mkdir()
    for index in range(workload["files"]):
        bucket = target / f"d{index // 1000:02d}"
        bucket.mkdir(exist_ok=True)
        (bucket / f"f{index:05d}.txt").write_text(
            f"loom-performance-fixture:{workload['id']}:{index}\n", encoding="utf-8")
    return target


def run(corpus, *, iterations=30, warmups=5, seed=404, include_scale=False):
    corpus = json.loads(Path(corpus).read_text(encoding="utf-8"))
    workloads = corpus["workloads"]
    if not include_scale:
        workloads = [item for item in workloads if item["files"] <= 1000]
    results = []
    with tempfile.TemporaryDirectory(prefix="loom-benchmark-") as temp:
        root = Path(temp).resolve()
        fixtures = {item["id"]: _fixture(root, item) for item in workloads}
        order = [item["id"] for item in workloads]
        random.Random(seed).shuffle(order)
        by_id = {item["id"]: item for item in workloads}
        for workload_id in order:
            workload, target = by_id[workload_id], fixtures[workload_id]
            samples, failures = [], []
            for index in range(warmups + iterations):
                started = time.perf_counter_ns()
                try:
                    state = loom_survey.repo_state(target)
                    decision = loom_tier.classify(workload["request"], files=workload["files"])
                    elapsed = time.perf_counter_ns() - started
                    if index >= warmups:
                        samples.append(elapsed)
                except Exception as exc:
                    if index >= warmups:
                        failures.append({"sample": index - warmups,
                                         "code": type(exc).__name__})
            median = int(statistics.median(samples)) if samples else None
            results.append({"workload_id": workload_id,
                "fixture_sha256": hashlib.sha256("".join(sorted(
                    path.relative_to(target).as_posix() + ":" +
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in target.rglob("*") if path.is_file())).encode()).hexdigest(),
                "file_count": workload["files"], "sample_count": len(samples),
                "failure_count": len(failures), "failures": failures,
                "p50_ns": median, "p95_ns": _percentile(samples, .95) if samples else None,
                "worst_ns": max(samples) if samples else None,
                "mad_ns": int(statistics.median(abs(item - median) for item in samples))
                    if samples else None,
                "tier": decision["tier"] if samples else None,
                "state_hash_observed": bool(samples and state.state_hash)})
    body = {"schema_version": 1, "measurement_kind": "observed-local-offline",
        "seed": seed, "warmups": warmups, "iterations": iterations,
        "environment": {"os": platform.system(), "architecture": platform.machine(),
                        "python": platform.python_version(),
                        "filesystem_root": Path(os.getcwd()).anchor},
        "results": sorted(results, key=lambda item: item["workload_id"])}
    body["receipt_sha256"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return body


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(
        Path(__file__).parent.parent / "benchmarks" / "performance" / "corpus.json"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--seed", type=int, default=404)
    parser.add_argument("--include-scale", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.iterations <= 1000 or not 0 <= args.warmups <= 100:
        parser.error("iteration bounds are invalid")
    output = Path(args.output).resolve()
    if output.exists() and (output.is_symlink() or not output.is_file()):
        parser.error("output must be a regular file path")
    output.parent.mkdir(parents=True, exist_ok=True)
    receipt = run(args.corpus, iterations=args.iterations, warmups=args.warmups,
                  seed=args.seed, include_scale=args.include_scale)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output)
    print(json.dumps({"status": "ok", "output": str(output),
                      "receipt_sha256": receipt["receipt_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
