#!/usr/bin/env python3
"""Derive and verify the closed candidate-exact release product interface."""

import argparse
import ast
import hashlib
import json
from pathlib import Path

import loom_reliability


class ProductInterfaceError(RuntimeError):
    pass


FIELDS = {
    "schema_version", "vault_schema_min", "vault_schema_max",
}
DIGEST_DOMAIN = b"loom.release-product-interface.v1\0"
MAX_BYTES = 64 * 1024


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def seal(value):
    if not isinstance(value, dict) or set(value) != FIELDS \
            or value.get("schema_version") != 1 \
            or type(value.get("vault_schema_min")) is not int \
            or type(value.get("vault_schema_max")) is not int \
            or value["vault_schema_min"] != 1 \
            or value["vault_schema_max"] < value["vault_schema_min"] \
            or value["vault_schema_max"] > 1024:
        raise ProductInterfaceError("release product interface fields are invalid")
    body = {
        "schema_version": 1,
        "vault_schema_min": value["vault_schema_min"],
        "vault_schema_max": value["vault_schema_max"],
    }
    return {
        **body,
        "interface_sha256": hashlib.sha256(
            DIGEST_DOMAIN + _canonical(body)).hexdigest(),
    }


def validate(value):
    if not isinstance(value, dict) or "interface_sha256" not in value:
        raise ProductInterfaceError("release product interface digest is missing")
    body = {key: item for key, item in value.items()
            if key != "interface_sha256"}
    expected = seal(body)
    if value != expected:
        raise ProductInterfaceError("release product interface digest is invalid")
    return value


def _root(value):
    try:
        root = loom_reliability._absolute(
            value, "release product interface root", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise ProductInterfaceError(str(exc)) from exc
    if not root.is_dir():
        raise ProductInterfaceError("release product interface root is invalid")
    return root


def _vault_schema_version(root):
    source = root / "tools" / "loom_vault.py"
    try:
        if not source.is_file() or source.is_symlink() \
                or source.stat().st_size > 4 * 1024 * 1024:
            raise ProductInterfaceError("vault schema authority is unsafe")
        tree = ast.parse(source.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise ProductInterfaceError("vault schema authority is invalid") from exc
    values = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 \
                or not isinstance(node.targets[0], ast.Name) \
                or node.targets[0].id != "VAULT_SCHEMA_VERSION":
            continue
        if not isinstance(node.value, ast.Constant) \
                or type(node.value.value) is not int:
            raise ProductInterfaceError("vault schema authority is not literal")
        values.append(node.value.value)
    if len(values) != 1 or not 1 <= values[0] <= 1024:
        raise ProductInterfaceError("vault schema authority is ambiguous")
    return values[0]


def derive(root):
    root = _root(root)
    return seal({
        "schema_version": 1,
        "vault_schema_min": 1,
        "vault_schema_max": _vault_schema_version(root),
    })


def _read(path):
    try:
        path = Path(path)
        if not path.is_file() or path.is_symlink() \
                or path.stat().st_size > MAX_BYTES:
            raise ProductInterfaceError("release product interface is unsafe")
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProductInterfaceError("release product interface is invalid") from exc


def load(root, *, path=None):
    root = _root(root)
    path = root / "contracts" / "release-product-interface-v1.json" \
        if path is None else Path(path)
    observed = validate(_read(path))
    if observed != derive(root):
        raise ProductInterfaceError("release product interface is stale")
    return observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--output")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        root = _root(args.root)
        output = Path(args.output) if args.output else (
            root / "contracts" / "release-product-interface-v1.json")
        value = derive(root)
        if args.check:
            load(root, path=output)
            status = "current"
        else:
            output = loom_reliability._absolute(
                output, "release product interface output")
            loom_reliability.atomic_write_json(output, value)
            status = "generated"
    except (
            ProductInterfaceError, loom_reliability.ReliabilityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": status,
        "interface_sha256": value["interface_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
