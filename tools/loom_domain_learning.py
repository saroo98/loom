#!/usr/bin/env python3
"""Store declarative unknown-domain state through the encrypted owner vault."""

import datetime as dt
import re

import loom_domain_contract


ENTITY_TYPES = {
    "source": "domain-source", "applicability": "domain-applicability",
    "invariant": "domain-invariant", "adapter": "domain-adapter",
    "discovery-utility": "domain-discovery-utility",
}
EXECUTABLE_KEYS = {
    "command", "commands", "script", "code", "tool", "tool_definition",
    "callback", "env", "shell", "executable",
}


class DomainLearningError(ValueError):
    pass


def _reject_executable(value, path="payload"):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() in EXECUTABLE_KEYS:
                raise DomainLearningError(f"executable field is forbidden: {path}.{key}")
            _reject_executable(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_executable(item, f"{path}[{index}]")
    elif isinstance(value, str) and re.search(
            r"(?i)(?:^|\s)(?:powershell|pwsh|bash|cmd\.exe|sh\s+-c|python\s+-c)\b", value):
        raise DomainLearningError("executable-looking text cannot become active domain learning")


def store(vault, kind, value, *, source_sequence):
    if kind not in ENTITY_TYPES:
        raise DomainLearningError("unknown domain learning entity kind")
    _reject_executable(value)
    if kind == "source":
        loom_domain_contract.validate_source(value); entity_id = value["source_id"]
    elif kind == "applicability":
        loom_domain_contract.validate_applicability(value)
        entity_id = value["applicability_id"]
    elif kind == "invariant":
        loom_domain_contract.validate_invariant(value); entity_id = value["invariant_id"]
        if value["evidence_state"] not in {"candidate", "supported", "gate-ready",
                                           "conflicted", "stale", "superseded", "quarantined"}:
            raise DomainLearningError("invariant learning state is invalid")
    else:
        if not isinstance(value, dict) or not isinstance(value.get("id"), str):
            raise DomainLearningError("domain learning entity requires an id")
        if kind == "adapter" and (set(value) != {
                "id", "domain_ids", "invariant_ids", "status", "revalidate_by"}
                or not isinstance(value["domain_ids"], list)
                or not isinstance(value["invariant_ids"], list)
                or value["status"] not in {"candidate", "active", "dormant", "archived"}
                or not isinstance(value["revalidate_by"], str)):
            raise DomainLearningError("domain adapter materialization is not declarative")
        entity_id = value["id"]
    return vault.put_entity(
        ENTITY_TYPES[kind], entity_id, value, source_sequence=source_sequence)


def matches_scope(invariant, *, domain, project_id=None, component=None):
    scope = invariant["scope"]
    return (domain in invariant["domain_ids"]
            and (scope["project_id"] is None or scope["project_id"] == project_id)
            and (scope["component"] is None or scope["component"] == component))


def select_active_invariants(vault, *, domain, project_id=None, component=None, now=None,
                             limit=32):
    if not isinstance(domain, str) or not domain \
            or type(limit) is not int or not 1 <= limit <= 32:
        raise DomainLearningError("domain invariant selection inputs are invalid")
    now = now or dt.datetime.now(dt.timezone.utc)
    result = []
    for item in vault.list_entities(ENTITY_TYPES["invariant"], limit=128):
        value = item["value"]
        try:
            loom_domain_contract.validate_invariant(value)
        except loom_domain_contract.DomainContractError:
            continue
        if value["evidence_state"] != "gate-ready" \
                or not matches_scope(value, domain=domain, project_id=project_id,
                                     component=component):
            continue
        deadline = loom_domain_contract.parse_time(
            value["freshness"]["revalidate_by"], "invariant revalidate_by")
        if deadline < now:
            continue
        result.append(value)
    return sorted(result, key=lambda value: value["invariant_id"])[:limit]
