#!/usr/bin/env python3
"""Evaluate preregistered Tier-S speed only after quality non-inferiority."""

import argparse
import hashlib
import json
import math
from pathlib import Path


CONDITIONS = {"naked", "fast-cold", "fast-warm", "full-cold", "full-warm"}
STAGES = {"host_launch_ms", "loom_discovery_ms", "request_acceptance_ms",
          "first_output_ms", "plan_sealed_ms", "work_order_ready_ms",
          "receipt_persisted_ms", "teardown_ms"}


class TierSStudyError(RuntimeError):
    pass


def _percentile(values, percentile):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def evaluate(rows, *, quality_margin=None):
    if not isinstance(rows, list) or not rows or len(rows) > 10000 \
            or quality_margin is not None and (
                type(quality_margin) not in {int, float} or quality_margin < 0):
        raise TierSStudyError("Tier-S study input is invalid")
    cells = {}
    seen = set()
    for row in rows:
        required = {"sample_id", "task_id", "condition", "quality_score", "unsafe",
                    "timed_out", "total_tokens", "tool_calls", "questions", "stages"}
        if not isinstance(row, dict) or set(row) != required \
                or row["condition"] not in CONDITIONS or row["sample_id"] in seen \
                or type(row["quality_score"]) not in {int, float} \
                or not 0 <= row["quality_score"] <= 100 \
                or type(row["unsafe"]) is not bool or type(row["timed_out"]) is not bool \
                or row["total_tokens"] is not None and (
                    type(row["total_tokens"]) is not int or row["total_tokens"] < 0) \
                or type(row["tool_calls"]) is not int or row["tool_calls"] < 0 \
                or type(row["questions"]) is not int or row["questions"] < 0 \
                or not isinstance(row["stages"], dict) or set(row["stages"]) != STAGES \
                or any(type(value) not in {int, float} or value < 0
                       for value in row["stages"].values()):
            raise TierSStudyError("Tier-S study row is invalid")
        seen.add(row["sample_id"]); cells.setdefault(row["condition"], []).append(row)
    summaries = {}
    for condition, values in sorted(cells.items()):
        completion = [sum(row["stages"].values()) for row in values]
        tokens = [row["total_tokens"] for row in values if row["total_tokens"] is not None]
        summaries[condition] = {
            "samples": len(values), "failures": sum(
                row["unsafe"] or row["timed_out"] for row in values),
            "mean_quality": round(sum(row["quality_score"] for row in values) / len(values), 3),
            "p50_completion_ms": _percentile(completion, .5),
            "p95_completion_ms": _percentile(completion, .95),
            "p95_total_tokens": _percentile(tokens, .95) if tokens else None,
        }
    eligible = False
    reason = "quality margin is not preregistered"
    if quality_margin is not None and "naked" in summaries and "fast-warm" in summaries:
        delta = summaries["naked"]["mean_quality"] - summaries["fast-warm"]["mean_quality"]
        eligible = delta <= quality_margin and summaries["fast-warm"]["failures"] == 0
        reason = "non-inferiority passed" if eligible else "quality or safety non-inferiority failed"
    body = {"schema_version": 1, "quality_margin": quality_margin,
            "fast_path_eligible": eligible, "decision_reason": reason,
            "conditions": summaries}
    return {**body, "study_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    parser.add_argument("--quality-margin", type=float)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        rows = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
        result = evaluate(rows, quality_margin=args.quality_margin)
    except (OSError, UnicodeError, json.JSONDecodeError, TierSStudyError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    print(json.dumps({"status": "evaluated", "fast_path_eligible": result["fast_path_eligible"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
