#!/usr/bin/env python3
"""Independent stdlib reproducer for a sealed Loom improvement claim."""

import argparse
import hashlib
import json
import math
import re
import uuid
from pathlib import Path


METRICS = {
    "prediction-calibration-error": "lower",
    "rework-rate": "lower",
    "verification-escape-rate": "lower",
    "incorrect-tier-rate": "lower",
    "planning-overhead-ratio": "lower",
    "human-decision-round-trips": "lower",
    "unused-artifact-rate": "lower",
    "wo-reopen-rate": "lower",
    "drift-caught-before-execution-rate": "higher",
    "release-rollback-rate": "lower",
    "memory-help-rate": "higher",
    "memory-hurt-rate": "lower",
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
UNBOUNDED_METRICS = {"human-decision-round-trips"}


def _digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _mean(values):
    return round(math.fsum(values) / len(values), 12) if values else None


def _number(metric, value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) \
        and math.isfinite(float(value)) and float(value) >= 0 \
        and (metric in UNBOUNDED_METRICS or float(value) <= 1)


def _reproduce(bundle):
    metric, domain, direction = bundle["metric"], bundle["domain"], bundle["direction"]
    thresholds = bundle["thresholds"]
    window = thresholds["window"]
    minimum_samples = thresholds["minimum_longitudinal_samples"]
    minimum_pairs = thresholds["minimum_replay_pairs"]
    regression_delta = thresholds["regression_delta"]
    longitudinal_evidence = bundle["evidence"]["longitudinal"]
    sample_count = longitudinal_evidence["sample_count"]
    early = [float(item["value"]) for item in longitudinal_evidence["early"]]
    recent = [float(item["value"]) for item in longitudinal_evidence["recent"]]
    if sample_count < minimum_samples:
        longitudinal = {
            "status": "insufficient-evidence", "sample_count": sample_count,
            "required_sample_count": minimum_samples,
            "early_sample_count": min(sample_count, window),
            "recent_sample_count": min(max(0, sample_count - window), window),
            "early_mean": None, "recent_mean": None,
        }
    else:
        early_mean, recent_mean = _mean(early), _mean(recent)
        improvement_delta = (early_mean - recent_mean if direction == "lower"
                             else recent_mean - early_mean)
        if improvement_delta > 0:
            status = "improved"
        elif improvement_delta <= -regression_delta:
            status = "regressed"
        else:
            status = "no-change"
        longitudinal = {
            "status": status, "sample_count": sample_count,
            "required_sample_count": minimum_samples,
            "early_sample_count": len(early), "recent_sample_count": len(recent),
            "early_mean": early_mean, "recent_mean": recent_mean,
            "improvement_delta": improvement_delta,
        }
    pairs = bundle["evidence"]["replay_pairs"]
    pair_count = bundle["evidence"]["replay_pair_count"]
    if pair_count < minimum_pairs:
        replay = {"status": "insufficient-evidence", "pair_count": pair_count,
                  "required_pair_count": minimum_pairs,
                  "enabled_mean": None, "disabled_mean": None}
    else:
        enabled_mean = _mean([float(item["enabled"]["value"]) for item in pairs])
        disabled_mean = _mean([float(item["disabled"]["value"]) for item in pairs])
        improved = (enabled_mean < disabled_mean if direction == "lower"
                    else enabled_mean > disabled_mean)
        replay = {"status": "improved" if improved else "not-improved",
                  "pair_count": pair_count, "required_pair_count": minimum_pairs,
                  "enabled_mean": enabled_mean, "disabled_mean": disabled_mean}
    local_improvement_observed = longitudinal["status"] == "improved" \
        and replay["status"] == "improved"
    if local_improvement_observed:
        claim_status = "requires-independent-attestation"
    elif longitudinal["status"] == "insufficient-evidence":
        claim_status = "insufficient-longitudinal-evidence"
    elif replay["status"] == "insufficient-evidence":
        claim_status = "insufficient-replay"
    else:
        claim_status = "not-improved"
    return {
        "schema_version": 1, "metric": metric, "direction": direction,
        "domain": domain,
        "scope": "general-calibration" if domain == "general" else "exact-domain",
        "longitudinal": longitudinal, "replay": replay,
        "local_improvement_observed": local_improvement_observed,
        "attestation_status": "local-unattested",
        "improvement_claim_allowed": False,
        "claim_status": claim_status,
        "regression_alarm": longitudinal["status"] == "regressed",
    }


def audit_bundle(bundle):
    findings = []
    required = {"schema_version", "instance_id", "metric", "domain", "direction",
                "thresholds", "evidence", "evidence_sha256", "claim"}
    if not isinstance(bundle, dict) or set(bundle) != required:
        return {"status": "failed", "reproduced": False,
                "findings": [{"code": "BUNDLE_SHAPE_INVALID"}], "report": None}
    try:
        if bundle["schema_version"] != 1 \
                or str(uuid.UUID(bundle["instance_id"])) != bundle["instance_id"] \
                or bundle["metric"] not in METRICS \
                or bundle["direction"] != METRICS[bundle["metric"]] \
                or not isinstance(bundle["domain"], str) \
                or not ID_RE.fullmatch(bundle["domain"]):
            raise ValueError
        thresholds = bundle["thresholds"]
        if set(thresholds) != {"window", "minimum_longitudinal_samples",
                              "minimum_replay_pairs", "regression_delta"} \
                or thresholds["window"] != 8 \
                or thresholds["minimum_longitudinal_samples"] != 16 \
                or thresholds["minimum_replay_pairs"] != 8 \
                or thresholds["regression_delta"] != 0.05:
            raise ValueError
        if set(bundle["evidence"]) != {
                "longitudinal", "replay_pairs", "replay_pair_count"} \
                or not isinstance(bundle["evidence"]["replay_pair_count"], int) \
                or bundle["evidence"]["replay_pair_count"] < 0:
            raise ValueError
        longitudinal = bundle["evidence"]["longitudinal"]
        if set(longitudinal) != {"sample_count", "early", "recent"} \
                or not isinstance(longitudinal["sample_count"], int) \
                or len(longitudinal["early"]) > 8 or len(longitudinal["recent"]) > 8:
            raise ValueError
        for sample in longitudinal["early"] + longitudinal["recent"]:
            if set(sample) != {"value", "evidence_id", "recorded_at"} \
                    or not _number(bundle["metric"], sample["value"]):
                raise ValueError
        replay_ids = set()
        for pair in bundle["evidence"]["replay_pairs"]:
            if set(pair) != {"replay_id", "enabled", "disabled"} \
                    or pair["replay_id"] in replay_ids:
                raise ValueError
            replay_ids.add(pair["replay_id"])
            for cohort in ("enabled", "disabled"):
                if set(pair[cohort]) != {"value", "evidence_id"} \
                        or not _number(bundle["metric"], pair[cohort]["value"]):
                    raise ValueError
        if len(bundle["evidence"]["replay_pairs"]) \
                != min(bundle["evidence"]["replay_pair_count"], 8):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        findings.append({"code": "BUNDLE_CONTENT_INVALID"})
        return {"status": "failed", "reproduced": False,
                "findings": findings, "report": None}
    sealed = {key: bundle[key] for key in (
        "metric", "domain", "direction", "thresholds", "evidence")}
    if bundle["evidence_sha256"] != _digest(sealed):
        findings.append({"code": "EVIDENCE_HASH_MISMATCH"})
    report = _reproduce(bundle)
    if bundle["claim"] != report:
        findings.append({"code": "CLAIM_MISMATCH"})
    return {"status": "passed" if not findings else "failed",
            "reproduced": not findings, "findings": findings, "report": report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    args = parser.parse_args(argv)
    path = Path(args.bundle).resolve()
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read audit bundle: {exc}") from exc
    result = audit_bundle(bundle)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
