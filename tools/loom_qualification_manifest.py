#!/usr/bin/env python3
"""Derive and verify Loom's closed repeated-qualification dependency graph."""

import argparse
import ast
from collections import deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

import loom_reliability


class ManifestError(RuntimeError):
    pass


ROLES = {
    "mechanism-repeat", "shared-interface", "candidate-exact",
    "historical-compatibility",
}
BOUNDARY_FIELDS = {
    "schema_version", "python_entrypoints", "workflow_entrypoints", "roles",
    "declared_data_edges", "data_sets", "runtime_process_sources",
    "boundary_sha256",
}
BOUNDARY_BODY_FIELDS = BOUNDARY_FIELDS - {"boundary_sha256"}
DATA_EDGE_KINDS = {"declared-data", "candidate-projection"}
DEPENDENCY_KINDS = {
    "python-import", "process-invocation", "schema-ref", "declared-data",
    "candidate-projection", "workflow-call", "workflow-script",
    "external-action", "data-set-member",
}
BOUNDARY_DOMAIN = b"loom.release-qualification-boundary.v2\0"
MANIFEST_DOMAIN = b"loom.release-qualification-manifest.v2\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ACTION = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(.+)$")
WORKFLOW_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
WORKFLOW_ANCHOR = re.compile(r"(?:^|[\s:\-\[,])(?:&|\*)[A-Za-z_][A-Za-z0-9_-]*")
WORKFLOW_SCRIPT = re.compile(
    r"(?:^|[\s'\"])(?:python(?:[0-9.]*)?|py)(?:\.exe)?\s+"
    r"(?:-B\s+)?([A-Za-z0-9_./-]+\.py)(?=$|[\s'\"])",
    re.IGNORECASE | re.MULTILINE,
)
MAX_BOUNDARY_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_NODES = 4096


def _canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ManifestError("qualification graph value is not canonical") from exc


def _digest(domain, value):
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _safe_relative(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 \
            or "\\" in value or "\x00" in value:
        raise ManifestError("qualification dependency path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) \
            or path.as_posix() != value:
        raise ManifestError("qualification dependency path is unsafe")
    return path.as_posix()


def _sorted_unique_strings(value, label):
    if not isinstance(value, list) \
            or any(not isinstance(item, str) for item in value):
        raise ManifestError(f"qualification boundary {label} is invalid")
    result = [_safe_relative(item) for item in value]
    if result != sorted(set(result)):
        raise ManifestError(f"qualification boundary {label} is not canonical")
    return result


def seal_boundary(value):
    if not isinstance(value, dict) or set(value) != BOUNDARY_BODY_FIELDS \
            or value.get("schema_version") != 2:
        raise ManifestError("qualification boundary fields are invalid")
    python_entrypoints = _sorted_unique_strings(
        value.get("python_entrypoints"), "Python entrypoints")
    workflow_entrypoints = _sorted_unique_strings(
        value.get("workflow_entrypoints"), "workflow entrypoints")
    runtime_process_sources = _sorted_unique_strings(
        value.get("runtime_process_sources"), "runtime process sources")
    roles = value.get("roles")
    if not isinstance(roles, list):
        raise ManifestError("qualification boundary roles are invalid")
    normalized_roles = []
    for row in roles:
        if not isinstance(row, dict) or set(row) != {"path", "role"} \
                or row.get("role") not in ROLES:
            raise ManifestError("qualification boundary role is invalid")
        normalized_roles.append({
            "path": _safe_relative(row.get("path")), "role": row["role"],
        })
    if normalized_roles != sorted(
            normalized_roles, key=lambda row: row["path"]) \
            or len({row["path"] for row in normalized_roles}) != len(
                normalized_roles):
        raise ManifestError("qualification boundary roles are not canonical")
    edges = value.get("declared_data_edges")
    if not isinstance(edges, list):
        raise ManifestError("qualification boundary data edges are invalid")
    normalized_edges = []
    for row in edges:
        if not isinstance(row, dict) or set(row) != {
                "source", "target", "kind"} \
                or row.get("kind") not in DATA_EDGE_KINDS:
            raise ManifestError("qualification boundary data edge is invalid")
        normalized_edges.append({
            "source": _safe_relative(row.get("source")),
            "target": _safe_relative(row.get("target")),
            "kind": row["kind"],
        })
    if normalized_edges != sorted(
            normalized_edges,
            key=lambda row: (row["source"], row["kind"], row["target"])) \
            or len({(row["source"], row["kind"], row["target"])
                    for row in normalized_edges}) != len(normalized_edges):
        raise ManifestError(
            "qualification boundary data edges are not canonical")
    data_sets = value.get("data_sets")
    if not isinstance(data_sets, list):
        raise ManifestError("qualification boundary data sets are invalid")
    normalized_sets = []
    for row in data_sets:
        if not isinstance(row, dict) or set(row) != {"source", "pattern"}:
            raise ManifestError("qualification boundary data set is invalid")
        source = _safe_relative(row.get("source"))
        pattern = _safe_relative(row.get("pattern"))
        if "**" in pattern or not any(mark in pattern for mark in "*?["):
            raise ManifestError("qualification boundary data-set pattern is invalid")
        normalized_sets.append({"source": source, "pattern": pattern})
    if normalized_sets != sorted(
            normalized_sets, key=lambda row: (row["source"], row["pattern"])):
        raise ManifestError("qualification boundary data sets are not canonical")
    body = {
        "schema_version": 2,
        "python_entrypoints": python_entrypoints,
        "workflow_entrypoints": workflow_entrypoints,
        "roles": normalized_roles,
        "declared_data_edges": normalized_edges,
        "data_sets": normalized_sets,
        "runtime_process_sources": runtime_process_sources,
    }
    return {**body, "boundary_sha256": _digest(BOUNDARY_DOMAIN, body)}


def validate_boundary(value):
    if not isinstance(value, dict) or set(value) != BOUNDARY_FIELDS \
            or not isinstance(value.get("boundary_sha256"), str) \
            or HEX64.fullmatch(value["boundary_sha256"]) is None:
        raise ManifestError("qualification boundary is invalid")
    body = {key: item for key, item in value.items()
            if key != "boundary_sha256"}
    sealed = seal_boundary(body)
    if sealed != value:
        raise ManifestError("qualification boundary is stale or forged")
    return value


def _regular_path(root, relative):
    relative = _safe_relative(relative)
    path = root / PurePosixPath(relative)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ManifestError(
            f"qualification dependency is missing: {relative}") from exc
    if not resolved.is_relative_to(root) or path.is_symlink() \
            or loom_reliability._is_redirect(path) or not path.is_file():
        raise ManifestError(
            f"qualification dependency is redirected or non-regular: {relative}")
    current = path.parent
    while current != root:
        if current.is_symlink() or loom_reliability._is_redirect(current):
            raise ManifestError(
                f"qualification dependency parent is redirected: {relative}")
        current = current.parent
    return path


def _kind(relative):
    if relative.endswith(".py"):
        return "python"
    if relative.startswith(".github/workflows/") \
            and relative.endswith((".yml", ".yaml")):
        return "workflow"
    if relative.endswith(".schema.json"):
        return "schema"
    if relative.startswith("contracts/") and relative.endswith(".json"):
        return "contract"
    return "data"


def _local_module(root, source_relative, module, level=0):
    if not isinstance(module, str) or not module:
        return None
    if level:
        parent = PurePosixPath(source_relative).parent
        for _ in range(max(0, level - 1)):
            parent = parent.parent
        candidate = (parent / (module.replace(".", "/") + ".py")).as_posix()
        return candidate if (root / candidate).is_file() else None
    top = module.split(".")[0]
    candidates = [
        f"tools/{top}.py", f"{top}.py", f"{top}/__init__.py",
    ]
    for candidate in candidates:
        if (root / candidate).is_file():
            return candidate
    return None


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _string_constants(node):
    return [
        item.value for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    ]


def _process_dependencies(root, source_relative, tree, runtime_sources):
    dependencies = set()
    process_names = {
        "subprocess.run", "subprocess.Popen", "subprocess.call",
        "subprocess.check_call", "subprocess.check_output",
        "loom_operation_supervisor.run",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) not in process_names:
            continue
        command = None
        if node.args:
            command = node.args[0]
        for keyword in node.keywords:
            if keyword.arg == "command":
                command = keyword.value
        if command is None:
            continue
        strings = _string_constants(command)
        for token in strings:
            normalized = token.replace("\\", "/")
            if not normalized.endswith(".py"):
                continue
            if "/" not in normalized:
                candidates = [
                    f"tools/{normalized}",
                    (PurePosixPath(source_relative).parent / normalized).as_posix(),
                ]
            else:
                candidates = [normalized.lstrip("./")]
            target = next(
                (item for item in candidates if (root / item).is_file()), None)
            if target is None:
                raise ManifestError(
                    f"local process dependency is missing from {source_relative}")
            dependencies.add(("process-invocation", target))
        if any(
                isinstance(item, ast.Name) and item.id == "__file__"
                for item in ast.walk(command)):
            dependencies.add(("process-invocation", source_relative))
        direct = list(command.elts) if isinstance(command, (ast.List, ast.Tuple)) \
            else []
        for index, item in enumerate(direct[:-1]):
            if isinstance(item, ast.Constant) and item.value == "-m" \
                    and isinstance(direct[index + 1], ast.Constant) \
                    and isinstance(direct[index + 1].value, str):
                target = _local_module(
                    root, source_relative, direct[index + 1].value)
                if target:
                    dependencies.add(("process-invocation", target))
        python_selected = any(
            isinstance(item, ast.Attribute)
            and _call_name(item) in {"sys.executable"}
            for item in ast.walk(command))
        if python_selected and not strings \
                and source_relative not in runtime_sources:
            raise ManifestError(
                f"local process dependency is ambiguous in {source_relative}")
    return dependencies


def _python_dependencies(root, relative, path, runtime_sources):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise ManifestError(
            f"qualification Python dependency is unreadable: {relative}") from exc
    dependencies = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = _local_module(root, relative, alias.name)
                if target:
                    dependencies.add(("python-import", target))
        elif isinstance(node, ast.ImportFrom):
            target = _local_module(
                root, relative, node.module or "", node.level)
            if target:
                dependencies.add(("python-import", target))
        elif isinstance(node, ast.Call) and _call_name(node.func) in {
                "__import__", "importlib.import_module"}:
            if not node.args or not isinstance(node.args[0], ast.Constant) \
                    or not isinstance(node.args[0].value, str):
                raise ManifestError(
                    f"dynamic import is ambiguous in {relative}")
            target = _local_module(root, relative, node.args[0].value)
            if target:
                dependencies.add(("python-import", target))
    dependencies.update(_process_dependencies(
        root, relative, tree, runtime_sources))
    return dependencies


def _schema_dependencies(root, relative, path):
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ManifestError(
            f"qualification JSON dependency is unreadable: {relative}") from exc
    dependencies = set()
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            reference = item.get("$ref")
            if isinstance(reference, str) and not reference.startswith("#"):
                target_text = reference.split("#", 1)[0]
                target = (PurePosixPath(relative).parent / target_text).as_posix()
                target = _safe_relative(target)
                if not (root / target).is_file():
                    raise ManifestError(
                        f"schema reference is missing from {relative}")
                dependencies.add(("schema-ref", target))
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return dependencies


def _workflow_dependencies(root, relative, path):
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ManifestError(
            f"qualification workflow is unreadable: {relative}") from exc
    if WORKFLOW_ANCHOR.search(text):
        raise ManifestError(
            f"qualification workflow uses unsupported YAML aliases: {relative}")
    dependencies = set()
    for used in WORKFLOW_USES.findall(text):
        if used.startswith("./"):
            target = _safe_relative(used[2:])
            if not (root / target).is_file():
                raise ManifestError(
                    f"local workflow dependency is missing from {relative}")
            dependencies.add(("workflow-call", target))
            continue
        matched = ACTION.fullmatch(used)
        if matched is None or HEX40.fullmatch(matched.group(2)) is None:
            raise ManifestError(
                f"qualification workflow action is not full-SHA pinned: {relative}")
        dependencies.add(("external-action", used))
    for script in WORKFLOW_SCRIPT.findall(text):
        target = _safe_relative(script.lstrip("./"))
        if not (root / target).is_file():
            raise ManifestError(
                f"workflow script dependency is missing from {relative}")
        dependencies.add(("workflow-script", target))
    return dependencies


def _dependencies(root, relative, path, runtime_sources):
    kind = _kind(relative)
    if kind == "python":
        return _python_dependencies(root, relative, path, runtime_sources)
    if kind == "workflow":
        return _workflow_dependencies(root, relative, path)
    if kind in {"schema", "contract"}:
        return _schema_dependencies(root, relative, path)
    return set()


def derive(root, boundary):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ManifestError("qualification repository root is invalid")
    boundary = validate_boundary(boundary)
    roles = {row["path"]: row["role"] for row in boundary["roles"]}
    declared = {}
    for row in boundary["declared_data_edges"]:
        declared.setdefault(row["source"], set()).add(
            (row["kind"], row["target"]))
    for row in boundary["data_sets"]:
        matches = []
        try:
            candidates = sorted(root.glob(row["pattern"]))
        except (OSError, ValueError) as exc:
            raise ManifestError("qualification data-set traversal failed") from exc
        for path in candidates:
            if len(matches) >= MAX_NODES:
                raise ManifestError("qualification data set is oversized")
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            _regular_path(root, relative)
            matches.append(relative)
        if not matches:
            raise ManifestError("qualification data set is empty")
        for target in matches:
            declared.setdefault(row["source"], set()).add(
                ("data-set-member", target))
    entrypoints = sorted(
        boundary["python_entrypoints"] + boundary["workflow_entrypoints"])
    pending = deque(entrypoints)
    reached = set()
    nodes = {}
    runtime_sources = set(boundary["runtime_process_sources"])
    while pending:
        relative = pending.popleft()
        if relative in reached:
            continue
        if len(reached) >= MAX_NODES:
            raise ManifestError("qualification dependency graph is oversized")
        path = _regular_path(root, relative)
        role = roles.get(relative)
        if role is None:
            raise ManifestError(
                f"qualification dependency is unclassified: {relative}")
        dependencies = _dependencies(
            root, relative, path, runtime_sources) | declared.get(relative, set())
        normalized = []
        for dependency_kind, target in sorted(
                dependencies, key=lambda item: (item[0], item[1])):
            if dependency_kind not in DEPENDENCY_KINDS:
                raise ManifestError("qualification dependency kind is invalid")
            if dependency_kind == "external-action":
                normalized.append({"kind": dependency_kind, "target": target})
                continue
            target = _safe_relative(target)
            target_role = roles.get(target)
            if target_role is None:
                raise ManifestError(
                    f"qualification dependency is unclassified: {target}")
            if target_role == "candidate-exact":
                if dependency_kind != "candidate-projection":
                    raise ManifestError(
                        "candidate implementation crossed the qualification boundary")
                normalized.append({
                    "kind": dependency_kind, "target": "candidate:" + target,
                })
                continue
            _regular_path(root, target)
            normalized.append({"kind": dependency_kind, "target": target})
            if target not in reached:
                pending.append(target)
        nodes[relative] = {
            "path": relative, "role": role, "kind": _kind(relative),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "dependencies": normalized,
        }
        reached.add(relative)
    allowed_unreached = {
        row["path"] for row in boundary["roles"]
        if row["role"] == "candidate-exact"
        and any(edge["target"] == row["path"]
                and edge["kind"] == "candidate-projection"
                for edge in boundary["declared_data_edges"])
    }
    stale_roles = set(roles) - reached - allowed_unreached
    if stale_roles:
        raise ManifestError(
            "qualification boundary contains unreachable classifications")
    body = {
        "schema_version": 2,
        "boundary_sha256": boundary["boundary_sha256"],
        "entrypoints": entrypoints,
        "nodes": [nodes[path] for path in sorted(nodes)],
    }
    return {**body, "manifest_sha256": _digest(MANIFEST_DOMAIN, body)}


def validate_manifest(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "boundary_sha256", "entrypoints", "nodes",
            "manifest_sha256"} \
            or value.get("schema_version") != 2 \
            or HEX64.fullmatch(str(value.get("boundary_sha256", ""))) is None \
            or HEX64.fullmatch(str(value.get("manifest_sha256", ""))) is None:
        raise ManifestError("qualification manifest fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "manifest_sha256"}
    if value["manifest_sha256"] != _digest(MANIFEST_DOMAIN, body):
        raise ManifestError("qualification manifest digest is invalid")
    entries = value.get("entrypoints")
    if not isinstance(entries, list) or entries != sorted(set(entries)) \
            or any(_safe_relative(item) != item for item in entries):
        raise ManifestError("qualification manifest entrypoints are invalid")
    nodes = value.get("nodes")
    if not isinstance(nodes, list) or not nodes or len(nodes) > MAX_NODES:
        raise ManifestError("qualification manifest nodes are invalid")
    paths = []
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {
                "path", "role", "kind", "sha256", "dependencies"} \
                or node.get("role") not in ROLES \
                or node.get("kind") not in {
                    "python", "workflow", "schema", "contract", "data"} \
                or HEX64.fullmatch(str(node.get("sha256", ""))) is None \
                or not isinstance(node.get("dependencies"), list):
            raise ManifestError("qualification manifest node is invalid")
        path = _safe_relative(node.get("path"))
        paths.append(path)
        dependencies = node["dependencies"]
        if dependencies != sorted(
                dependencies, key=lambda row: (row.get("kind"), row.get("target"))):
            raise ManifestError("qualification manifest dependencies are not canonical")
        for edge in dependencies:
            if not isinstance(edge, dict) or set(edge) != {"kind", "target"} \
                    or edge.get("kind") not in DEPENDENCY_KINDS \
                    or not isinstance(edge.get("target"), str):
                raise ManifestError("qualification manifest dependency is invalid")
    if paths != sorted(set(paths)) or not set(entries).issubset(paths):
        raise ManifestError("qualification manifest node inventory is invalid")
    return value


def verify(root, boundary, manifest):
    validate_manifest(manifest)
    current = derive(root, boundary)
    if current != manifest:
        raise ManifestError("qualification manifest is stale")
    return manifest


def explain(manifest, target):
    manifest = validate_manifest(manifest)
    target = _safe_relative(target)
    nodes = {row["path"]: row for row in manifest["nodes"]}
    if target not in nodes:
        raise ManifestError("qualification explanation target is absent")
    pending = deque((entry, [entry]) for entry in manifest["entrypoints"])
    visited = set()
    while pending:
        current, chain = pending.popleft()
        if current == target:
            return chain
        if current in visited:
            continue
        visited.add(current)
        for edge in nodes[current]["dependencies"]:
            dependency = edge["target"]
            if dependency in nodes and dependency not in visited:
                pending.append((dependency, [*chain, dependency]))
    raise ManifestError("qualification explanation chain is absent")


def _load(path, max_bytes):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or not 1 <= path.stat().st_size <= max_bytes:
        raise ManifestError("qualification JSON transport is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ManifestError("qualification JSON is invalid") from exc


def _write(path, value):
    loom_reliability.atomic_write_json(Path(path), value)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Derive or verify the closed qualification dependency graph.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    derive_parser = subparsers.add_parser("derive")
    derive_parser.add_argument("--root", required=True)
    derive_parser.add_argument("--boundary", required=True)
    derive_parser.add_argument("--output", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", required=True)
    verify_parser.add_argument("--boundary", required=True)
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--explain")
    args = parser.parse_args(argv)
    try:
        boundary = validate_boundary(_load(args.boundary, MAX_BOUNDARY_BYTES))
        if args.command == "derive":
            manifest = derive(args.root, boundary)
            _write(args.output, manifest)
            result = {
                "status": "derived", "manifest_sha256": manifest[
                    "manifest_sha256"], "nodes": len(manifest["nodes"]),
            }
        else:
            manifest = verify(
                args.root, boundary, _load(args.manifest, MAX_MANIFEST_BYTES))
            result = {
                "status": "verified", "manifest_sha256": manifest[
                    "manifest_sha256"], "nodes": len(manifest["nodes"]),
            }
            if args.explain:
                result["chain"] = explain(manifest, args.explain)
        print(json.dumps(result, sort_keys=True))
        return 0
    except ManifestError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
