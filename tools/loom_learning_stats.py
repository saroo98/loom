#!/usr/bin/env python3
"""Conservative, time-uniform owner-learning evidence calculations."""

from __future__ import annotations

import hashlib
import json
import math


class LearningStatisticsError(RuntimeError):
    pass


TOKEN_CATEGORIES = (
    "input_tokens", "cache_read_tokens", "output_tokens", "tool_tokens", "retry_tokens")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def bounded_confidence_sequence(values, *, alpha=0.05):
    """Anytime-valid Hoeffding sequence for observations in [0, 1]."""
    if not isinstance(values, list) or not values:
        raise LearningStatisticsError("confidence sequence requires observations")
    if not 0 < alpha < 1 or any(
            isinstance(item, bool) or not isinstance(item, (int, float))
            or not math.isfinite(float(item)) or not 0 <= float(item) <= 1
            for item in values):
        raise LearningStatisticsError("confidence sequence inputs are invalid")
    count = len(values)
    mean = math.fsum(float(item) for item in values) / count
    # Allocate alpha across every possible inspection time. The sum of
    # alpha/(n(n+1)) is alpha, so optional stopping does not inflate coverage.
    alpha_n = alpha / (count * (count + 1))
    radius = math.sqrt(math.log(2 / alpha_n) / (2 * count))
    return {
        "count": count, "mean": mean, "lower": max(0.0, mean - radius),
        "upper": min(1.0, mean + radius), "alpha": alpha,
        "method": "time-uniform-hoeffding-alpha-spending-v1",
    }


def paired_effect_sequence(differences, *, alpha=0.05):
    if not isinstance(differences, list) or not differences:
        raise LearningStatisticsError("paired effects require observations")
    if any(isinstance(item, bool) or not isinstance(item, (int, float))
           or not math.isfinite(float(item)) or not -1 <= float(item) <= 1
           for item in differences):
        raise LearningStatisticsError("paired effect must be bounded to [-1,1]")
    normalized = [(float(item) + 1) / 2 for item in differences]
    interval = bounded_confidence_sequence(normalized, alpha=alpha)
    return {**interval, "mean": interval["mean"] * 2 - 1,
            "lower": interval["lower"] * 2 - 1,
            "upper": interval["upper"] * 2 - 1}


def normalize_cost(cost):
    if not isinstance(cost, dict) or set(cost) != {*TOKEN_CATEGORIES, "elapsed_seconds"}:
        raise LearningStatisticsError("complete five-category token and elapsed cost is required")
    if any(type(cost[key]) is not int or cost[key] < 0 for key in TOKEN_CATEGORIES) \
            or isinstance(cost["elapsed_seconds"], bool) \
            or not isinstance(cost["elapsed_seconds"], (int, float)) \
            or not math.isfinite(float(cost["elapsed_seconds"])) \
            or cost["elapsed_seconds"] < 0:
        raise LearningStatisticsError("learning cost is invalid")
    return {**cost, "total_tokens": sum(cost[key] for key in TOKEN_CATEGORIES)}


def evaluate(*, observations, paired_effects, randomized, propensities,
             materiality, harm_threshold, severe_harm, cost):
    cost = normalize_cost(cost)
    if isinstance(materiality, bool) or not isinstance(materiality, (int, float)) \
            or not 0 <= materiality <= 1 \
            or isinstance(harm_threshold, bool) \
            or not isinstance(harm_threshold, (int, float)) \
            or not 0 <= harm_threshold <= 1:
        raise LearningStatisticsError("materiality and harm thresholds are invalid")
    if severe_harm:
        state, interval = "quarantined-harm", None
    elif not observations and not paired_effects:
        state, interval = "no-outcomes", None
    elif len(observations) + len(paired_effects) == 1:
        state, interval = "measurement-started", None
    elif not paired_effects:
        state, interval = "associated-only", bounded_confidence_sequence(observations)
    else:
        if randomized:
            if not isinstance(propensities, list) or len(propensities) != len(paired_effects) \
                    or any(isinstance(item, bool) or not isinstance(item, (int, float))
                           or not 0 < float(item) <= 1 for item in propensities):
                raise LearningStatisticsError(
                    "randomized evaluation requires one nonzero logged propensity per pair")
        elif propensities not in (None, []):
            raise LearningStatisticsError("propensities are only valid for randomized evidence")
        interval = paired_effect_sequence(paired_effects)
        if interval["upper"] <= -harm_threshold:
            state = "regression-observed"
        elif randomized and interval["lower"] >= materiality:
            state = "causal-local-evidence"
        elif not randomized:
            state = "structural-counterfactual-only"
        elif interval["lower"] >= materiality:
            state = "benefit-observed-local"
        else:
            state = "benefit-uncertain"
    result = {
        "schema_version": 1, "evidence_state": state, "interval": interval,
        "materiality": float(materiality), "harm_threshold": float(harm_threshold),
        "randomized": bool(randomized), "sample_count": len(observations),
        "pair_count": len(paired_effects), "cost": cost,
    }
    result["sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
    return result
