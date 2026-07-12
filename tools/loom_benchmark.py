#!/usr/bin/env python3
"""Validate and aggregate complete, explicitly defined agent-run token usage."""

import argparse
import json
import math
import sys
from pathlib import Path

FIELDS = (
    "fresh_input_tokens", "cache_creation_input_tokens",
    "cache_read_input_tokens", "output_tokens",
)


class UsageError(RuntimeError):
    pass


def summarize(payload, weights=None):
    if payload.get("schema_version") != 1:
        raise UsageError("usage schema_version must be 1")
    if not isinstance(payload.get("run_id"), str) or not payload["run_id"].strip():
        raise UsageError("run_id is required")
    responses = payload.get("responses")
    if not isinstance(responses, list) or not responses:
        raise UsageError("responses must be a non-empty list")
    try:
        wall_seconds = float(payload["wall_seconds"])
    except (KeyError, TypeError, ValueError) as exc:
        raise UsageError("wall_seconds is required and must be numeric") from exc
    if not math.isfinite(wall_seconds) or wall_seconds < 0:
        raise UsageError("wall_seconds must be finite and non-negative")
    totals = {field: 0 for field in FIELDS}
    for index, response in enumerate(responses):
        if not isinstance(response, dict):
            raise UsageError(f"response {index} must be an object")
        missing = [field for field in FIELDS if field not in response]
        extra = set(response) - set(FIELDS)
        if missing or extra:
            raise UsageError(
                f"response {index} fields mismatch; missing={missing}, extra={sorted(extra)}")
        for field in FIELDS:
            value = response[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise UsageError(f"response {index} {field} must be a non-negative integer")
            totals[field] += value
    processed = sum(totals.values())
    billed = None
    if weights is not None:
        if set(weights) != set(FIELDS):
            raise UsageError("billing-equivalent weights must cover all four token fields")
        if not all(isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
                   for value in weights.values()):
            raise UsageError("billing-equivalent weights must be finite and non-negative")
        billed = sum(totals[field] * float(weights[field]) for field in FIELDS)
    return {
        "schema_version": 1,
        "run_id": payload["run_id"],
        "response_count": len(responses),
        **totals,
        "processed_token_events": processed,
        "provider_billed_equivalent": billed,
        "billing_weights": weights,
        "wall_seconds": wall_seconds,
        "definitions": {
            "processed_token_events": "sum of four mutually exclusive reported usage fields; not a price",
            "provider_billed_equivalent": "null unless all caller-supplied provider weights are present",
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("usage_json")
    parser.add_argument("--fresh-input-weight", type=float)
    parser.add_argument("--cache-creation-weight", type=float)
    parser.add_argument("--cache-read-weight", type=float)
    parser.add_argument("--output-weight", type=float)
    args = parser.parse_args(argv)
    raw_weights = (
        args.fresh_input_weight, args.cache_creation_weight,
        args.cache_read_weight, args.output_weight,
    )
    if any(value is not None for value in raw_weights) \
            and not all(value is not None for value in raw_weights):
        print(json.dumps({
            "status": "error",
            "error": "all four billing weights are required when any is supplied",
        }))
        return 1
    weights = (dict(zip(FIELDS, raw_weights))
               if all(value is not None for value in raw_weights) else None)
    try:
        payload = json.loads(Path(args.usage_json).read_text(encoding="utf-8"))
        result = summarize(payload, weights)
    except (OSError, UnicodeError, json.JSONDecodeError, UsageError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "ok", "result": result},
                     sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
