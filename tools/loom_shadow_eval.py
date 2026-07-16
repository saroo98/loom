#!/usr/bin/env python3
"""Bounded, contamination-resistant shadow evaluation policy for owner learning."""

from __future__ import annotations

import hashlib
import json


class ShadowEvaluationError(RuntimeError):
    pass


PROTECTED_CATEGORIES = {
    "owner-preference", "hard-stop", "safety", "current-fact", "domain-invariant",
    "privacy", "deletion", "spending", "destructive-action", "legal", "tax",
    "release", "credential", "migration", "backup", "rollback", "freshness",
}


def _hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")).hexdigest()


def eligible(memory, *, tier, structurally_equivalent, propensity):
    if not isinstance(memory, dict) or not isinstance(memory.get("category"), str):
        raise ShadowEvaluationError("memory eligibility input is invalid")
    if tier == "S":
        return {"eligible": False, "reason": "small-tier-disabled"}
    if memory["category"] in PROTECTED_CATEGORIES:
        return {"eligible": False, "reason": "protected-category"}
    if not structurally_equivalent:
        return {"eligible": False, "reason": "structural-parity-unproved"}
    if isinstance(propensity, bool) or not isinstance(propensity, (int, float)) \
            or not 0 < float(propensity) <= 1:
        return {"eligible": False, "reason": "propensity-missing"}
    return {"eligible": True, "reason": "ordinary-process-heuristic"}


def seal_pair(*, request, world, plan_contract, provider, model_policy, rubric,
              enabled_response_id, disabled_response_id, enabled_response,
              disabled_response, memory_ids, propensity, rolling_tokens,
              shadow_tokens, tier):
    required_text = {
        "provider": provider, "model_policy": model_policy,
        "enabled_response_id": enabled_response_id,
        "disabled_response_id": disabled_response_id,
    }
    if any(not isinstance(value, str) or not value for value in required_text.values()):
        raise ShadowEvaluationError("provider and distinct response identities are required")
    if enabled_response_id == disabled_response_id:
        raise ShadowEvaluationError("shadow responses must be independently generated")
    if type(rolling_tokens) is not int or type(shadow_tokens) is not int \
            or rolling_tokens < 0 or shadow_tokens < 0 \
            or shadow_tokens > max(0, rolling_tokens * 2 // 100):
        raise ShadowEvaluationError("shadow evaluation exceeds the 2 percent token budget")
    if tier == "S":
        raise ShadowEvaluationError("small-tier shadow evaluation is disabled by default")
    if not isinstance(memory_ids, list) or not memory_ids:
        raise ShadowEvaluationError("shadow evaluation requires selected memory identities")
    pair = {
        "schema_version": 1, "request_hash": _hash(request), "world_hash": _hash(world),
        "plan_contract_hash": _hash(plan_contract), "provider": provider,
        "model_policy_hash": _hash(model_policy), "rubric_hash": _hash(rubric),
        "enabled_response_id": enabled_response_id,
        "disabled_response_id": disabled_response_id,
        "enabled_response_hash": _hash(enabled_response),
        "disabled_response_hash": _hash(disabled_response),
        "memory_ids": sorted(memory_ids), "propensity": propensity,
        "shadow_tokens": shadow_tokens, "rolling_tokens": rolling_tokens,
        "evidence_state": "structural-counterfactual-only",
    }
    pair["pair_hash"] = _hash(pair)
    return pair
