#!/usr/bin/env python3
"""Reject new sensitive-operation bypasses in designated Loom modules."""

import argparse
import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SensitivePolicyError(RuntimeError):
    pass


def _call_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Visitor(ast.NodeVisitor):
    def __init__(self, module, forbidden):
        self.module = module
        self.forbidden = forbidden
        self.functions = []
        self.calls = []

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        name = _call_name(node.func)
        if name in self.forbidden:
            self.calls.append({
                "module": self.module,
                "function": ".".join(self.functions) if self.functions else "<module>",
                "call": name,
                "line": node.lineno,
            })
        self.generic_visit(node)


def inspect(root=ROOT, policy_path=None):
    root = Path(root).resolve()
    path = Path(policy_path or root / "contracts" / "sensitive-operation-policy-v1.json")
    policy = json.loads(path.read_text(encoding="utf-8"))
    if set(policy) != {
            "schema_version", "designated_modules", "forbidden_calls",
            "exceptions", "authorities"} or policy["schema_version"] != 1:
        raise SensitivePolicyError("sensitive-operation policy is invalid")
    exception_keys = {
        (item["module"], item["function"], item["call"])
        for item in policy["exceptions"]
        if set(item) == {"module", "function", "call", "reason"}
        and isinstance(item["reason"], str) and item["reason"].strip()
    }
    if len(exception_keys) != len(policy["exceptions"]):
        raise SensitivePolicyError("sensitive-operation exceptions are invalid")
    findings = []
    observed_exceptions = set()
    source_hashes = {}
    for relative in policy["designated_modules"]:
        module = root / relative
        source = module.read_text(encoding="utf-8")
        source_hashes[relative] = hashlib.sha256(source.encode("utf-8")).hexdigest()
        visitor = _Visitor(relative, set(policy["forbidden_calls"]))
        visitor.visit(ast.parse(source))
        for call in visitor.calls:
            key = (call["module"], call["function"], call["call"])
            if key in exception_keys:
                observed_exceptions.add(key)
            else:
                findings.append(call)
    stale = sorted(exception_keys - observed_exceptions)
    if findings or stale:
        raise SensitivePolicyError(
            "sensitive-operation bypass policy failed: "
            + json.dumps({"findings": findings, "stale_exceptions": stale},
                         sort_keys=True))
    body = {
        "schema_version": 1,
        "status": "passed",
        "designated_modules": list(policy["designated_modules"]),
        "observed_exceptions": [
            {"module": item[0], "function": item[1], "call": item[2]}
            for item in sorted(observed_exceptions)
        ],
        "source_hashes": dict(sorted(source_hashes.items())),
        "authorities": policy["authorities"],
    }
    body["report_sha256"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("utf-8")).hexdigest()
    return body


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--policy")
    args = parser.parse_args(argv)
    report = inspect(args.root, args.policy)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
