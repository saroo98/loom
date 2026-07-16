#!/usr/bin/env python3
"""Claim-specific re-gating for a sealed domain bundle."""

import datetime as dt

import loom_domain_bundle
import loom_domain_contract
import loom_domain_evidence


def regate(bundle, *, target_fingerprint, now=None, offline=False):
    now = now or dt.datetime.now(dt.timezone.utc)
    retained, revalidate, blocked = [], [], []
    source_map = {item["source_id"]: item for item in bundle["sources"]}
    app_map = {item["applicability_id"]: item for item in bundle["applicability"]}
    for invariant in bundle["invariants"]:
        inv_id = invariant["invariant_id"]
        apps = [app_map[item] for item in invariant["applicability_receipt_ids"]
                if item in app_map]
        target_changed = any(item["target_fingerprint"] != target_fingerprint for item in apps)
        current = loom_domain_evidence.evaluate_currentness(
            invariant, [source_map[item] for item in invariant["supporting_source_ids"]
                        if item in source_map], now=now, offline=offline)
        if target_changed:
            revalidate.append({"invariant_id": inv_id, "reason": "target-fingerprint-changed"})
        elif not current["current"]:
            blocked.append({"invariant_id": inv_id, "reason": "freshness-expired"})
        else:
            retained.append({"invariant_id": inv_id,
                             "canonical_digest": invariant["canonical_digest"]})
    body = {
        "schema_version": 1, "bundle_digest": bundle["bundle_digest"],
        "target_fingerprint": target_fingerprint,
        "checked_at": now.isoformat().replace("+00:00", "Z"),
        "offline": bool(offline), "retained": retained,
        "revalidate": revalidate, "blocked": blocked,
    }
    return {**body, "regate_digest": loom_domain_contract.digest(
        "domain-regate-v1", body)}
