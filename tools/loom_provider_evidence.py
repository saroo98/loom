#!/usr/bin/env python3
"""Project usage v3 into honest provider-native or host-observed evidence."""

import argparse
import hashlib
import json
from pathlib import Path

import loom_usage


class ProviderEvidenceError(RuntimeError):
    pass


def capture(bundle, *, privacy_mode, region=None, cache_condition="unknown"):
    if not isinstance(privacy_mode, str) or not privacy_mode or len(privacy_mode) > 128 \
            or region is not None and (not isinstance(region, str) or len(region) > 128) \
            or cache_condition not in {"cold", "warm", "mixed", "unknown"}:
        raise ProviderEvidenceError("provider evidence context is invalid")
    try:
        normalized = loom_usage.normalize_bundle(bundle)
    except loom_usage.UsageError as exc:
        raise ProviderEvidenceError(str(exc)) from exc
    events = normalized["events"]
    provider_native = normalized["measurement_source"] == "provider" \
        and normalized["measurement_status"] == "provider-complete" \
        and events and all(item["response_id"] and item["raw_response_sha256"]
                           and not item["semantics_profile"].startswith("generic-")
                           for item in events)
    evidence_class = "provider-native" if provider_native else "host-observed"
    limitations = [] if provider_native else [
        "Raw provider identity or complete provider semantics are unavailable; this is not provider-native."]
    fields = {}
    for event in events:
        for name, value in event["raw_counters"].items():
            fields.setdefault(name, {"availability": "present" if value is not None else "unavailable",
                                     "relationship": event["relationships"].get(name, "provider-specific")})
    attempts = sum(item["attempt_number"] for item in events)
    body = {
        "schema_version": 1, "evidence_class": evidence_class,
        "provider": events[0]["provider"] if events else "unavailable",
        "models": sorted(set(item["model"] for item in events)),
        "response_ids": sorted(item["response_id"] for item in events if item["response_id"]),
        "raw_response_digests": sorted(set(
            item["raw_response_sha256"] for item in events if item["raw_response_sha256"])),
        "raw_field_inventory": {key: fields[key] for key in sorted(fields)},
        "privacy_mode": privacy_mode, "region": region,
        "cache_condition": cache_condition,
        "retry_count": max(0, attempts - len(events)),
        "processed_total_tokens": normalized["processed_total_tokens"],
        "limitations": limitations,
    }
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    parser.add_argument("--privacy-mode", required=True)
    parser.add_argument("--region")
    parser.add_argument("--cache-condition", default="unknown",
                        choices=["cold", "warm", "mixed", "unknown"])
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        value = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
        result = capture(value, privacy_mode=args.privacy_mode,
                         region=args.region, cache_condition=args.cache_condition)
    except (OSError, UnicodeError, json.JSONDecodeError, ProviderEvidenceError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    print(json.dumps({"status": "captured", "evidence_class": result["evidence_class"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
