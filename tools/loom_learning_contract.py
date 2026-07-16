#!/usr/bin/env python3
"""Load and verify Loom's single owner-learning v3 truth contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


class LearningContractError(RuntimeError):
    pass


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "owner-learning-v3.json"


def load_contract(path=CONTRACT_PATH):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LearningContractError(f"owner-learning contract is unreadable: {exc}") from exc
    required = {
        "schema_version", "payload_schema_version", "authority", "scopes",
        "legacy_scope_aliases", "categories", "lifecycle_states", "attribution_states",
        "evidence_states", "transitions", "promotion", "bounds", "claims", "privacy",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise LearningContractError("owner-learning contract fields are unknown or missing")
    if value["schema_version"] != 3 or value["payload_schema_version"] != 3:
        raise LearningContractError("owner-learning contract version is not v3")
    states = set(value["lifecycle_states"])
    if set(value["transitions"]) != states:
        raise LearningContractError("every lifecycle state must define transitions")
    for source, targets in value["transitions"].items():
        if not isinstance(targets, list) or not set(targets) <= states or source in targets:
            raise LearningContractError(f"invalid lifecycle transition set for {source}")
    if value["transitions"].get("forgotten") != []:
        raise LearningContractError("forgotten must be terminal")
    if value["privacy"].get("telemetry") is not False \
            or value["privacy"].get("cloud_account") is not False:
        raise LearningContractError("sovereignty contract must fail closed")
    return value


CONTRACT = load_contract()
SCOPES = frozenset(CONTRACT["scopes"])
LIFECYCLE_STATES = frozenset(CONTRACT["lifecycle_states"])
ATTRIBUTION_STATES = frozenset(CONTRACT["attribution_states"])
EVIDENCE_STATES = frozenset(CONTRACT["evidence_states"])
BOUNDS = dict(CONTRACT["bounds"])


def check_runtime():
    import loom_vault
    mismatches = []
    if loom_vault.VAULT_SCHEMA_VERSION != CONTRACT["schema_version"]:
        mismatches.append("vault schema version")
    if loom_vault.PAYLOAD_SCHEMA_VERSION != CONTRACT["payload_schema_version"]:
        mismatches.append("payload schema version")
    if loom_vault.ATTRIBUTION_STATUSES != ATTRIBUTION_STATES:
        mismatches.append("attribution states")
    if loom_vault.EVIDENCE_STATES != EVIDENCE_STATES:
        mismatches.append("evidence states")
    if loom_vault.MAX_ACTIVE_RECORDS != BOUNDS["active_memory_items"]:
        mismatches.append("active memory bound")
    if loom_vault.MAX_EVENTS != BOUNDS["events"]:
        mismatches.append("event bound")
    if mismatches:
        raise LearningContractError("runtime contract drift: " + ", ".join(mismatches))
    return {"status": "ok", "schema_version": 3, "checks": 6}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    result = check_runtime() if args.check else CONTRACT
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
