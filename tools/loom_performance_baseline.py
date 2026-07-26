#!/usr/bin/env python3
"""Preregister and collect an honest local foundation-performance baseline."""

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path


class BaselineError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _subject_environment():
    return {
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python": ".".join(str(item) for item in sys.version_info[:3]),
        "measurement_boundary": "local-runtime-and-wrapper-separated",
    }


def _run_subject(root, workloads):
    workload_json = json.dumps(workloads, sort_keys=True, separators=(",", ":"))
    script = textwrap.dedent(
        """
        import datetime as dt
        import json
        import subprocess
        import tempfile
        import time
        import uuid
        from pathlib import Path

        import loom_performance
        import loom_runtime

        workloads = json.loads(WORKLOAD_JSON)

        def git(root, *args):
            return subprocess.run(
                ["git", "-C", str(root), *args], check=True,
                capture_output=True, text=True, encoding="utf-8")

        routes = {}
        with tempfile.TemporaryDirectory() as temp:
            outer = Path(temp)
            for index, workload in enumerate(workloads):
                root = outer / ("case-" + str(index))
                project = root / "project"
                project.mkdir(parents=True)
                declared = workload["files"]
                for file_index in range(max(1, declared)):
                    path = project / "src" / f"file-{file_index:05d}.txt"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("fixture\\n", encoding="utf-8")
                if workload.get("git", True):
                    git(project, "init")
                    git(project, "add", ".")
                    git(project, "-c", "user.name=Loom Baseline",
                        "-c", "user.email=baseline@example.invalid",
                        "commit", "-m", "baseline")
                if workload.get("dirty"):
                    (project / "dirty-untracked.txt").write_text(
                        "dirty\\n", encoding="utf-8")
                instance = str(uuid.uuid5(
                    uuid.NAMESPACE_URL, "loom:baseline:instance:" + workload["id"]))
                invocation = str(uuid.uuid5(
                    uuid.NAMESPACE_URL, "loom:baseline:invocation:" + workload["id"]))
                started = time.perf_counter_ns()
                outcome = {}
                try:
                    prepared = loom_runtime.prepare_invocation(
                        workload["request"], instance_id=instance,
                        invocation_id=invocation, cwd=project,
                        owner_home=root / "owner",
                        now=dt.datetime(2026, 7, 26, 12, tzinfo=dt.timezone.utc))
                    outcome = {
                        "status": "prepared",
                        "tier": prepared.route_contract["tier"],
                        "intent": prepared.route_contract["intent"],
                        "inspection_state": prepared.route_contract[
                            "project_inspection_state"],
                    }
                except loom_runtime.RuntimeBlocked as exc:
                    outcome = {
                        "status": "blocked",
                        "code": str(exc.code),
                    }
                routes[workload["id"]] = {
                    "elapsed_ns": time.perf_counter_ns() - started,
                    **outcome,
                }
        print(json.dumps({
            "operations": loom_performance.run_observed_benchmarks(),
            "request_routes": routes,
        }, sort_keys=True, separators=(",", ":")))
        """).replace("WORKLOAD_JSON", repr(workload_json))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "COMSPEC": os.environ.get("COMSPEC", ""),
        "PATHEXT": os.environ.get("PATHEXT", ""),
        "TEMP": os.environ.get("TEMP", ""),
        "TMP": os.environ.get("TMP", ""),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PYTHONNOUSERSITE": "1",
    }
    started = time.perf_counter_ns()
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=str(root / "tools"), env=env, capture_output=True, text=True,
        timeout=300, check=False)
    wrapper_elapsed_ns = time.perf_counter_ns() - started
    if result.returncode != 0:
        raise BaselineError(
            "subject benchmark failed: "
            + " ".join(result.stderr.split())[:400])
    try:
        return json.loads(result.stdout), wrapper_elapsed_ns
    except json.JSONDecodeError as exc:
        raise BaselineError("subject benchmark output is invalid") from exc


def collect(root, *, source_commit, runs, warmups, tolerance):
    root = Path(root).resolve()
    if not root.is_dir() or not (root / "benchmarks" / "performance" / "corpus.json").is_file():
        raise BaselineError("baseline subject root is invalid")
    if not isinstance(source_commit, str) or len(source_commit) != 40 \
            or any(character not in "0123456789abcdef" for character in source_commit):
        raise BaselineError("baseline source commit is invalid")
    if type(runs) is not int or runs < 3 or runs > 31 \
            or type(warmups) is not int or warmups < 1 or warmups > 10 \
            or type(tolerance) not in {int, float} or not 0 < tolerance <= 1:
        raise BaselineError("baseline preregistration is invalid")
    corpus_raw = (root / "benchmarks" / "performance" / "corpus.json").read_bytes()
    try:
        corpus = json.loads(corpus_raw)
    except json.JSONDecodeError as exc:
        raise BaselineError("performance corpus is invalid") from exc
    workloads = corpus.get("workloads") if isinstance(corpus, dict) else None
    if not isinstance(workloads, list) or not workloads:
        raise BaselineError("performance corpus is empty")
    ids = [item.get("id") for item in workloads if isinstance(item, dict)]
    required = {
        "doc-typo", "warm-session", "project-switch", "stale-resume",
        "year-owner", "unknown-domain", "single-ui-incident",
    }
    if len(ids) != len(workloads) or len(ids) != len(set(ids)) \
            or not required.issubset(ids):
        raise BaselineError("performance corpus lacks required foundation cases")
    for _ in range(warmups):
        _run_subject(root, workloads)
    observed = [_run_subject(root, workloads) for _ in range(runs)]
    observations = [item[0] for item in observed]
    wrapper_samples = [item[1] for item in observed]
    scenario_names = sorted(observations[0]["operations"]["scenarios"])
    if any(sorted(item["operations"]["scenarios"]) != scenario_names
           for item in observations):
        raise BaselineError("baseline scenario inventory changed between runs")
    results = []
    for name in scenario_names:
        values = [item["operations"]["scenarios"][name] for item in observations]
        elapsed = [item["elapsed_ns"] for item in values]
        median = statistics.median(elapsed)
        spread = ((max(elapsed) - min(elapsed)) / median) if median else 0.0
        stable = spread <= tolerance
        results.append({
            "id": name,
            "measurement_class": "local-runtime-operation",
            "samples": elapsed,
            "p50_runtime_ns": int(_percentile(elapsed, 0.50)),
            "p95_runtime_ns": int(_percentile(elapsed, 0.95)),
            "relative_spread": spread,
            "within_preregistered_tolerance": stable,
            "non_time_metrics": {
                key: values[0][key] for key in sorted(values[0])
                if key != "elapsed_ns"
            },
            "non_time_metrics_stable": all(
                {key: item[key] for key in item if key != "elapsed_ns"}
                == {key: values[0][key] for key in values[0] if key != "elapsed_ns"}
                for item in values),
        })
    route_names = [item["id"] for item in workloads]
    if any(sorted(item["request_routes"]) != sorted(route_names)
           for item in observations):
        raise BaselineError("request-route inventory changed between runs")
    for name in route_names:
        values = [item["request_routes"][name] for item in observations]
        elapsed = [item["elapsed_ns"] for item in values]
        median = statistics.median(elapsed)
        spread = ((max(elapsed) - min(elapsed)) / median) if median else 0.0
        results.append({
            "id": name,
            "measurement_class": "request-preparation",
            "samples": elapsed,
            "p50_runtime_ns": int(_percentile(elapsed, 0.50)),
            "p95_runtime_ns": int(_percentile(elapsed, 0.95)),
            "relative_spread": spread,
            "within_preregistered_tolerance": spread <= tolerance,
            "non_time_metrics": {
                key: values[0][key] for key in sorted(values[0])
                if key != "elapsed_ns"
            },
            "non_time_metrics_stable": all(
                {key: item[key] for key in item if key != "elapsed_ns"}
                == {key: values[0][key] for key in values[0]
                    if key != "elapsed_ns"}
                for item in values),
        })
    preregistration = {
        "runs": runs, "warmups": warmups, "relative_spread_tolerance": tolerance,
        "required_cases": sorted(required),
        "corpus_sha256": hashlib.sha256(corpus_raw).hexdigest(),
    }
    body = {
        "schema_version": 2,
        "baseline_id": str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"loom:performance:{source_commit}:{preregistration['corpus_sha256']}")),
        "source_commit": source_commit,
        "environment": _subject_environment(),
        "preregistration": preregistration,
        "corpus": [{
            "id": item["id"],
            "request_sha256": hashlib.sha256(
                item["request"].encode("utf-8")).hexdigest(),
            "declared_file_count": item["files"],
        } for item in workloads],
        "results": results,
        "wrapper_process": {
            "samples": wrapper_samples,
            "p50_elapsed_ns": int(_percentile(wrapper_samples, 0.50)),
            "p95_elapsed_ns": int(_percentile(wrapper_samples, 0.95)),
            "includes": [
                "python-process-startup", "fixture-construction",
                "git-fixture-operations", "all-request-preparations",
                "local-runtime-operations",
            ],
        },
        "measurement_boundaries": {
            "local_runtime": "observed",
            "wrapper_process": "observed",
            "provider_response": "unavailable",
            "provider_queue": "unavailable",
            "complete_wall_time": "unavailable",
        },
        "provider_native": {
            "status": "unavailable",
            "reason": "No provider-attested response and queue receipts were supplied.",
        },
        "all_local_metrics_stable": all(
            item["within_preregistered_tolerance"]
            and item["non_time_metrics_stable"] for item in results),
    }
    body["receipt_sha256"] = _hash(body)
    return body


def validate(value):
    fields = {
        "schema_version", "baseline_id", "source_commit", "environment",
        "preregistration", "corpus", "results", "wrapper_process",
        "measurement_boundaries", "provider_native",
        "all_local_metrics_stable", "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 2 \
            or value.get("receipt_sha256") != _hash({
                key: item for key, item in value.items() if key != "receipt_sha256"}):
        raise BaselineError("performance baseline receipt is invalid")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--tolerance", type=float, default=0.50)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = collect(
            args.root, source_commit=args.source_commit, runs=args.runs,
            warmups=args.warmups, tolerance=args.tolerance)
        validate(result)
        output = Path(args.output).resolve()
        if output.exists():
            raise BaselineError("baseline output already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (BaselineError, OSError, UnicodeError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({
        "status": "passed", "baseline_id": result["baseline_id"],
        "receipt_sha256": result["receipt_sha256"],
        "all_local_metrics_stable": result["all_local_metrics_stable"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
