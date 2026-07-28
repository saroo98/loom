#!/usr/bin/env python3
"""Compile persisted-entity projections into one fail-closed parity report."""

import argparse
import ast
import hashlib
import json
from pathlib import Path

import loom_reliability
import loom_truth


ROOT = Path(__file__).resolve().parents[1]
ENTITIES = {
    "owner-message": {
        "schema": "schemas/owner-message.schema.json",
        "schema_required": ("$defs", "current", "allOf", 1, "required"),
        "schema_version": ("$defs", "current", "allOf", 1, "properties",
                           "schema_version", "const"),
        "module": "tools/loom_message.py",
        "validator": ("function-set", "_validate_v5", "fields"),
        "writer": ("function-dict", "build", "value"),
        "writer_extras": (),
        "readable_versions": [1, 2, 3, 4, 5],
        "reader": "validate",
        "compatibility_tests": (
            "tools/test_owner_message.py",
            "tools/test_loom_session.py",
        ),
        "documentation": "docs/simple-adaptive-experience.md",
    },
    "session-receipt": {
        "schema": "schemas/session-receipt.schema.json",
        "schema_required": ("required",),
        "schema_current_extras": ("block_reason", "terminal_authority"),
        "schema_version": ("properties", "schema_version", "enum"),
        "module": "tools/loom_session.py",
        "validator": ("function-set", "_receipt_from_data", "fields"),
        "writer": ("module-dict", "receipt_data"),
        "writer_extras": ("receipt_hash",),
        "readable_versions": [1, 2],
        "reader": "_receipt_from_data",
        "compatibility_tests": ("tools/test_loom_session.py",),
        "documentation": "docs/architecture.md",
    },
    "orchestration-action": {
        "schema": "schemas/orchestration-action.schema.json",
        "schema_required": ("required",),
        "schema_version": ("properties", "schema_version", "const"),
        "module": "tools/loom_orchestrator.py",
        "validator": ("module-set", "ACTION_FIELDS"),
        "writer": ("module-dict", "action"),
        "writer_extras": ("action_hash",),
        "readable_versions": [6, 7, 8, 9, 10],
        "reader": "_validate_action",
        "compatibility_tests": ("tools/test_production_orchestrator.py",),
        "documentation": "docs/architecture.md",
    },
    "recovery-receipt": {
        "schema": "schemas/recovery-receipt.schema.json",
        "schema_required": ("$defs", "v3", "required"),
        "schema_version": ("$defs", "v3", "properties", "schema_version", "const"),
        "module": "tools/loom_orchestrator.py",
        "validator": ("schema-validator", "_validate_recovery_receipt_v3"),
        "writer": ("function-dict", "_recovery_receipt", "body"),
        "writer_extras": ("receipt_hash",),
        "readable_versions": [1, 2, 3],
        "reader": "_validate_recovery_receipt",
        "compatibility_tests": (
            "tools/test_recovery_contract_schemas.py",
            "tools/test_control_plane_recovery.py",
        ),
        "documentation": "docs/architecture.md",
    },
    "activation-set": {
        "schema": "schemas/activation-set.schema.json",
        "schema_required": ("required",),
        "schema_version": ("properties", "schema_version", "const"),
        "module": "tools/loom_activation.py",
        "validator": ("function-set", "_validate_receipt", "fields"),
        "writer": ("function-dict", "create", "value"),
        "writer_extras": ("receipt_sha256",),
        "readable_versions": [1],
        "reader": "_validate_receipt",
        "compatibility_tests": ("tools/test_activation_sets_phase3.py",),
        "documentation": "docs/architecture.md",
    },
    "execution-chain": {
        "schema": "schemas/execution-chain.schema.json",
        "schema_required": ("required",),
        "schema_version": ("properties", "schema_version", "const"),
        "module": "tools/loom_execution_chain.py",
        "validator": ("function-set", "_validate", "required"),
        "writer": ("function-dict", "create", "value"),
        "writer_extras": (),
        "readable_versions": [1],
        "reader": "_validate",
        "compatibility_tests": ("tools/test_execution_chain_phase3.py",),
        "documentation": "docs/architecture.md",
    },
}


class ParityError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _at(value, path):
    for item in path:
        value = value[item]
    return value


def _literal_string_set(node):
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        values = [ast.literal_eval(item) for item in node.elts]
        if all(isinstance(item, str) for item in values):
            return set(values)
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError):
        return None
    return set(value) if isinstance(value, (set, list, tuple)) \
        and all(isinstance(item, str) for item in value) else None


def _module_assignments(tree):
    values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 \
                or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        direct = _literal_string_set(node.value)
        if direct is not None:
            values[name] = direct
            continue
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.BitOr):
            left = values.get(node.value.left.id) if isinstance(
                node.value.left, ast.Name) else _literal_string_set(node.value.left)
            right = values.get(node.value.right.id) if isinstance(
                node.value.right, ast.Name) else _literal_string_set(node.value.right)
            if left is not None and right is not None:
                values[name] = left | right
    return values


def _module_integer_assignments(tree):
    values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 \
                or not isinstance(node.targets[0], ast.Name):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
        if type(value) is int:
            values[node.targets[0].id] = value
    return values


def _integer_values(node, constants):
    values = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and type(item.value) is int:
            values.add(item.value)
        elif isinstance(item, ast.Name) and item.id in constants:
            values.add(constants[item.id])
    return values


def _reader_versions(tree, function):
    """Recover the closed version set that a reader actually branches on."""
    constants = _module_integer_assignments(tree)
    node = _function(tree, function)
    versions = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Compare) \
                and "schema_version" in ast.dump(item, include_attributes=False):
            versions.update(_integer_values(item, constants))
    if not versions:
        raise ParityError(
            f"semantic reader {function} has no closed schema-version contract")
    return versions


def _semantic_hash(path):
    suffix = path.suffix.casefold()
    if suffix == ".json":
        return _digest(json.loads(path.read_text(encoding="utf-8")))
    if suffix == ".py":
        tree = ast.parse(path.read_text(encoding="utf-8"))
        payload = ast.dump(tree, annotate_fields=True, include_attributes=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    payload = " ".join(path.read_text(encoding="utf-8").split())
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _function(tree, name):
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1:
        raise ParityError(f"semantic function {name} is missing or ambiguous")
    return matches[0]


def _local_set(tree, function, variable):
    node = _function(tree, function)
    values = {}
    for item in ast.walk(node):
        if not isinstance(item, ast.Assign) or len(item.targets) != 1 \
                or not isinstance(item.targets[0], ast.Name):
            continue
        name = item.targets[0].id
        direct = _literal_string_set(item.value)
        if direct is not None:
            values[name] = direct
            continue
        if isinstance(item.value, ast.BinOp) and isinstance(item.value.op, ast.BitOr):
            left = values.get(item.value.left.id) if isinstance(
                item.value.left, ast.Name) else _literal_string_set(item.value.left)
            right = values.get(item.value.right.id) if isinstance(
                item.value.right, ast.Name) else _literal_string_set(item.value.right)
            if left is not None and right is not None:
                values[name] = left | right
    if variable not in values:
        raise ParityError(
            f"semantic set {function}.{variable} is not statically closed")
    return values[variable]


def _local_dict_keys(tree, function, variable):
    node = _function(tree, function)
    candidates = []
    for item in ast.walk(node):
        if isinstance(item, ast.Assign) and len(item.targets) == 1 \
                and isinstance(item.targets[0], ast.Name) \
                and item.targets[0].id == variable and isinstance(item.value, ast.Dict):
            keys = []
            for key in item.value.keys:
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    raise ParityError(
                        f"semantic writer {function}.{variable} has dynamic fields")
                keys.append(key.value)
            candidates.append(set(keys))
    if len(candidates) != 1:
        raise ParityError(
            f"semantic writer {function}.{variable} is missing or ambiguous")
    return candidates[0]


def _module_dict_keys(tree, variable):
    candidates = []
    for item in ast.walk(tree):
        if isinstance(item, ast.Assign) and len(item.targets) == 1 \
                and isinstance(item.targets[0], ast.Name) \
                and item.targets[0].id == variable and isinstance(item.value, ast.Dict):
            keys = []
            for key in item.value.keys:
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    raise ParityError(
                        f"semantic writer {variable} has dynamic fields")
                keys.append(key.value)
            candidates.append(set(keys))
    if len(candidates) != 1:
        raise ParityError(f"semantic writer {variable} is missing or ambiguous")
    return candidates[0]


def _projection_fields(tree, projection):
    kind, *arguments = projection
    if kind == "module-set":
        values = _module_assignments(tree)
        if arguments[0] not in values:
            raise ParityError(f"semantic module set {arguments[0]} is missing")
        return values[arguments[0]]
    if kind == "function-set":
        return _local_set(tree, *arguments)
    if kind == "function-dict":
        return _local_dict_keys(tree, *arguments)
    if kind == "module-dict":
        return _module_dict_keys(tree, *arguments)
    if kind == "schema-validator":
        function = _function(tree, arguments[0])
        calls = [
            item for item in ast.walk(function)
            if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute)
            and item.func.attr == "validate_schema"
        ]
        if len(calls) != 1:
            raise ParityError(
                f"schema validator {arguments[0]} is missing or ambiguous")
        return None
    raise ParityError(f"unknown semantic projection kind: {kind}")


def compile_report(root=ROOT):
    root = Path(root).resolve()
    rows = []
    source_hashes = {}
    for name, contract in ENTITIES.items():
        schema_path = root / contract["schema"]
        module_path = root / contract["module"]
        documentation_path = root / contract["documentation"]
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        required = set(_at(schema, contract["schema_required"]))
        required.update(contract.get("schema_current_extras", ()))
        validator = _projection_fields(tree, contract["validator"])
        writer = _projection_fields(tree, contract["writer"])
        writer.update(contract.get("writer_extras", ()))
        if validator is not None and validator != required:
            raise ParityError(
                f"{name} validator drift: missing={sorted(required-validator)} "
                f"extra={sorted(validator-required)}")
        if writer != required:
            raise ParityError(
                f"{name} writer drift: missing={sorted(required-writer)} "
                f"extra={sorted(writer-required)}")
        schema_version = _at(schema, contract["schema_version"])
        current = max(schema_version) if isinstance(schema_version, list) else schema_version
        if current != max(contract["readable_versions"]):
            raise ParityError(f"{name} current/readable version drift")
        reader_versions = _reader_versions(tree, contract["reader"])
        expected_versions = set(contract["readable_versions"])
        if reader_versions != expected_versions:
            raise ParityError(
                f"{name} reader drift: missing={sorted(expected_versions-reader_versions)} "
                f"extra={sorted(reader_versions-expected_versions)}")
        documentation = documentation_path.read_text(encoding="utf-8").lower()
        if name.replace("-", " ") not in documentation \
                and name.replace("-", "_") not in documentation \
                and name not in documentation:
            raise ParityError(f"{name} documentation projection is missing")
        compatibility_paths = [
            root / relative for relative in contract["compatibility_tests"]]
        for path in (schema_path, module_path, documentation_path,
                     *compatibility_paths):
            relative = path.relative_to(root).as_posix()
            source_hashes[relative] = _semantic_hash(path)
        rows.append({
            "entity": name,
            "current_version": current,
            "readable_versions": contract["readable_versions"],
            "reader": contract["reader"],
            "compatibility_tests": list(contract["compatibility_tests"]),
            "future_version_policy": "preserve-in-quarantine-never-activate",
            "required_fields": sorted(required),
            "schema": contract["schema"],
            "validator": contract["validator"][-1],
            "writer": contract["writer"][-2],
            "documentation": contract["documentation"],
        })
    body = {
        "schema_version": 1,
        "status": "passed",
        "entities": rows,
        "source_hashes": dict(sorted(source_hashes.items())),
    }
    body["report_sha256"] = _digest(body)
    return body


def classify_version(entity, version):
    if entity not in ENTITIES or type(version) is not int or version < 1:
        return "invalid"
    readable = ENTITIES[entity]["readable_versions"]
    if version == max(readable):
        return "active"
    if version in readable:
        return "legacy-readable"
    if version > max(readable):
        return "future-quarantine"
    return "invalid"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--output", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    report = compile_report(root)
    output = Path(args.output).resolve()
    registry_path = root / "contracts" / "truth-authorities-v1.json"
    if registry_path.is_file() \
            and output == (root / "docs" / "generated-semantic-parity.json"):
        try:
            registry = loom_truth.validate_registry(json.loads(
                registry_path.read_text(encoding="utf-8")))
        except (
                OSError, UnicodeError, json.JSONDecodeError,
                loom_truth.TruthError) as exc:
            raise ParityError(
                f"truth authority registry is unavailable: {exc}") from exc
        declarations = [
            item for item in registry["generated_outputs"]
            if item["path"] == "docs/generated-semantic-parity.json"
            and item["generator"] == "tools/loom_semantic_parity.py"]
        if len(declarations) != 1:
            raise ParityError(
                "semantic parity projection lacks one registered generator")
    if args.check:
        try:
            existing = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ParityError(f"semantic parity report is unavailable: {exc}") from exc
        if existing != report:
            old_hashes = existing.get("source_hashes", {}) \
                if isinstance(existing, dict) else {}
            changed = sorted(
                path for path in set(old_hashes) | set(report["source_hashes"])
                if old_hashes.get(path) != report["source_hashes"].get(path))
            raise ParityError(
                "semantic parity report is stale; changed="
                + (",".join(changed[:12]) if changed else "entity-projection"))
    else:
        loom_reliability.atomic_write_json(output, report)
    print(json.dumps({
        "status": report["status"],
        "entities": len(report["entities"]),
        "report_sha256": report["report_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
