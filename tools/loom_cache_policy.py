#!/usr/bin/env python3
"""Content-bound cache classes with exact dependency-subtree invalidation."""

import hashlib
import json
from pathlib import Path


POLICY_PATH = Path(__file__).resolve().parent.parent / "contracts" / "cache-classes-v1.json"
SOURCE_FIELDS = {
    "runtime-generation", "host-adapter-generation", "project-state-generation",
    "request-generation", "domain-facts-generation", "vault-generation",
    "provider-semantics-generation",
}


class CachePolicyError(ValueError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def policy():
    try:
        value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CachePolicyError(f"cache policy is unavailable: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1 \
            or value.get("execution_authority") is not False \
            or not isinstance(value.get("classes"), dict):
        raise CachePolicyError("cache policy is invalid")
    return value


def _validate_sources(generations):
    if not isinstance(generations, dict) or set(generations) != SOURCE_FIELDS \
            or any(not isinstance(value, str) or not value or len(value) > 128
                   for value in generations.values()):
        raise CachePolicyError("cache source generations are invalid")
    return dict(generations)


def build_registry(generations):
    sources = _validate_sources(generations)
    classes = policy()["classes"]
    built = {}
    pending = dict(classes)
    while pending:
        progressed = False
        for name in sorted(tuple(pending)):
            dependencies = pending[name]
            if not isinstance(dependencies, list) or not dependencies \
                    or len(dependencies) != len(set(dependencies)):
                raise CachePolicyError(f"cache class {name} dependencies are invalid")
            if any(item not in sources and item not in classes for item in dependencies):
                raise CachePolicyError(f"cache class {name} has an unknown dependency")
            if any(item in classes and item not in built for item in dependencies):
                continue
            bound = {
                item: (sources[item] if item in sources else built[item]["generation"])
                for item in dependencies
            }
            built[name] = {"dependencies": bound, "generation": _digest(bound)}
            del pending[name]
            progressed = True
        if not progressed:
            raise CachePolicyError("cache dependency graph contains a cycle")
    body = {"schema_version": 1, "classes": built, "authorizes_execution": False}
    return {**body, "registry_digest": _digest(body)}


def validate_registry(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "classes", "authorizes_execution", "registry_digest"} \
            or value.get("schema_version") != 1 \
            or value.get("authorizes_execution") is not False \
            or not isinstance(value.get("classes"), dict) \
            or value.get("registry_digest") != _digest({
                key: value[key] for key in (
                    "schema_version", "classes", "authorizes_execution")
            }):
        raise CachePolicyError("cache registry is invalid")
    expected = set(policy()["classes"])
    if set(value["classes"]) != expected:
        raise CachePolicyError("cache registry classes are invalid")
    for item in value["classes"].values():
        if not isinstance(item, dict) or set(item) != {"dependencies", "generation"} \
                or not isinstance(item["dependencies"], dict) \
                or not item["dependencies"] \
                or item["generation"] != _digest(item["dependencies"]):
            raise CachePolicyError("cache class generation is invalid")
    return value


def invalidate(registry, changed_sources):
    validate_registry(registry)
    changed = set(changed_sources)
    if not changed or not changed <= SOURCE_FIELDS:
        raise CachePolicyError("changed cache sources are invalid")
    definitions = policy()["classes"]
    invalidated = set()
    while True:
        before = set(invalidated)
        for name, dependencies in definitions.items():
            if any(item in changed or item in invalidated for item in dependencies):
                invalidated.add(name)
        if before == invalidated:
            break
    return {
        "schema_version": 1,
        "changed_sources": sorted(changed),
        "invalidated_classes": sorted(invalidated),
        "retained_classes": sorted(set(definitions) - invalidated),
        "authorizes_execution": False,
    }
