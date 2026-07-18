#!/usr/bin/env python3
"""Generate capability status only from current evidence-graph predicates."""

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

import loom_reliability


STATUSES = {"supported", "experimental", "stale-proof", "unsupported", "unverified"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
MAX_BYTES = 4 * 1024 * 1024


class CapabilityRegistryError(RuntimeError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CapabilityRegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path):
    try:
        path = loom_reliability._absolute(
            path, "capability registry input", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise CapabilityRegistryError(str(exc)) from exc
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise CapabilityRegistryError("registry input is missing, redirected, or oversized")
    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CapabilityRegistryError(f"registry input is invalid: {exc}") from exc


def _declarations(value):
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2} \
            or not isinstance(value.get("version"), str) \
            or not isinstance(value.get("capabilities"), list) \
            or len(value["capabilities"]) > 512:
        raise CapabilityRegistryError("capability declarations are invalid")
    declarations, seen = [], set()
    for item in value["capabilities"]:
        required = {"id", "kind", "enforcement", "tests"}
        allowed = set(required)
        if value["schema_version"] == 2:
            allowed |= {"status", "evidence_ids", "limitations", "proof_binding"}
        if not isinstance(item, dict) or not required <= set(item) or not set(item) <= allowed \
                or not isinstance(item.get("id"), str) \
                or not ID_RE.fullmatch(item["id"]) or item["id"] in seen \
                or item.get("kind") not in {"mechanical", "advisory"} \
                or not isinstance(item.get("enforcement"), list) \
                or not isinstance(item.get("tests"), list) \
                or len(item["enforcement"]) > 64 or len(item["tests"]) > 64 \
                or len(item["enforcement"]) != len(set(item["enforcement"])) \
                or len(item["tests"]) != len(set(item["tests"])) \
                or any(not isinstance(path, str) or not path
                       for path in item["enforcement"] + item["tests"]):
            raise CapabilityRegistryError("capability declaration entry is invalid")
        seen.add(item["id"])
        declarations.append({key: item[key] for key in
                             ("id", "kind", "enforcement", "tests")})
    return value["version"], declarations


def _graph(value):
    if value is None:
        return None
    required = {"schema_version", "policy_id", "subject_digest", "evaluated_at",
                "active", "inactive", "predicates", "graph_sha256"}
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != 1 \
            or value.get("policy_id") != "loom-evidence-policy-v1" \
            or not isinstance(value.get("predicates"), dict) \
            or not isinstance(value.get("inactive"), list):
        raise CapabilityRegistryError("evidence graph result is invalid")
    return value


def generate(declarations, graph=None, *, root=None):
    version, items = _declarations(declarations)
    graph = _graph(graph)
    if root is not None:
        try:
            root = loom_reliability._absolute(
                root, "capability proof root", must_exist=True)
        except loom_reliability.ReliabilityError as exc:
            raise CapabilityRegistryError(str(exc)) from exc
    inactive_ids = {item.get("evidence_id") for item in graph["inactive"]} if graph else set()
    result = []
    for item in items:
        proof_files = []
        if root is not None:
            for role, paths in (("enforcement", item["enforcement"]),
                                ("test", item["tests"])):
                for relative in paths:
                    if "\\" in relative:
                        raise CapabilityRegistryError(
                            f"capability proof path is unsafe: {item['id']}: {relative}")
                    path = PurePosixPath(relative)
                    if path.is_absolute() or not path.parts \
                            or any(part in {"", ".", ".."} for part in path.parts):
                        raise CapabilityRegistryError(
                            f"capability proof path is unsafe: {item['id']}: {relative}")
                    try:
                        target = loom_reliability._absolute(
                            root.joinpath(*path.parts), "capability proof", must_exist=True)
                    except loom_reliability.ReliabilityError as exc:
                        raise CapabilityRegistryError(str(exc)) from exc
                    if not target.is_file() or not target.is_relative_to(root):
                        raise CapabilityRegistryError(
                            f"capability proof path is missing or unsafe: "
                            f"{item['id']}: {relative}")
                    raw = target.read_bytes()
                    proof_files.append({"role": role, "path": relative,
                                        "bytes": len(raw),
                                        "sha256": hashlib.sha256(raw).hexdigest()})
        predicate = f"capability:{item['id']}"
        active = sorted(graph["predicates"].get(predicate, [])) if graph else []
        stale = sorted(inactive_ids & set(
            evidence_id for row in (graph["inactive"] if graph else [])
            for evidence_id in [row.get("evidence_id")]
            if isinstance(evidence_id, str) and evidence_id.startswith(
                f"ev-cap-{item['id']}-")))
        if item["kind"] == "advisory":
            status = "unsupported"
            limitations = ["Human judgment is not machine-enforced."]
        elif active and root is not None:
            status = "supported"
            limitations = []
        elif active:
            status = "experimental"
            limitations = [
                "Evidence is current, but enforcement and test bytes were not bound during generation."]
        elif stale:
            status = "stale-proof"
            limitations = ["The last bound proof expired, was revoked, or lost a dependency."]
        else:
            status = "unverified"
            limitations = ["No current exact-subject evidence envelope is active."]
        result.append({**item, "status": status, "evidence_ids": active or stale,
                       "limitations": limitations,
                       "proof_binding": {
                           "subject_digest": graph["subject_digest"] if graph else None,
                           "evidence_graph_sha256": graph["graph_sha256"] if graph else None,
                           "files": proof_files,
                       }})
    return {
        "schema_version": 2, "version": version,
        "generated_by": "tools/loom_capability_registry.py",
        "evidence_policy": "loom-evidence-policy-v1",
        "subject_digest": graph["subject_digest"] if graph else None,
        "evaluated_at": graph["evaluated_at"] if graph else None,
        "capabilities": result,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("declarations")
    parser.add_argument("--graph")
    parser.add_argument("--root")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        declarations = _read(args.declarations)
        graph = _read(args.graph) if args.graph else None
        result = generate(declarations, graph, root=args.root)
    except CapabilityRegistryError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    try:
        output = loom_reliability._absolute(args.output, "capability registry output")
        loom_reliability.atomic_write_json(output, result)
    except loom_reliability.ReliabilityError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "generated", "output": str(output),
                      "capabilities": len(result["capabilities"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
