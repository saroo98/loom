#!/usr/bin/env python3
"""Generate and verify Loom's complete maintenance CLI contract inventory."""

import argparse
import ast
import json
import os
import subprocess
import sys
import tempfile
import hashlib
import re
from pathlib import Path


class ContractError(RuntimeError):
    pass


WRITE_CLASS = {
    "loom_adaptation_eval": "explicit-destination", "loom_docs": "explicit-destination",
    "loom_gate": "explicit-destination", "loom_install": "runtime-state",
    "loom_kickoff": "explicit-destination", "loom_launcher": "runtime-state",
    "loom_lifecycle": "explicit-destination", "loom_memory": "owner-state",
    "loom_orchestrator": "owner-state", "loom_plugin_package": "explicit-destination",
    "loom_preferences": "owner-state", "loom_release": "explicit-destination",
    "loom_survey": "explicit-destination", "loom_test": "explicit-destination",
}
RUNTIME = {"loom_launcher", "loom_orchestrator"}
TEXT_OUTPUT = {"loom_lint"}
MIXED_OUTPUT = {"loom_launcher"}


def _entrypoints(root):
    tools = root / "tools"
    result = []
    for path in sorted(tools.glob("loom_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise ContractError(f"{path.name} cannot be inventoried: {exc}") from exc
        executable = any(
            isinstance(node, ast.If)
            and any(isinstance(item, ast.Name) and item.id == "__name__"
                    for item in ast.walk(node.test))
            for node in tree.body)
        if executable and path.name != "loom_cli_contract.py":
            result.append(path)
    return result


def _parser_options(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) \
                or node.func.attr != "add_argument":
            continue
        flags = [item.value for item in node.args
                 if isinstance(item, ast.Constant) and isinstance(item.value, str)
                 and item.value.startswith("-")]
        if not flags:
            continue
        keywords = {item.arg: item.value for item in node.keywords if item.arg}
        action = keywords.get("action")
        action = action.value if isinstance(action, ast.Constant) else None
        expects_value = action not in {"store_true", "store_false", "help", "version"}
        nargs = keywords.get("nargs")
        nargs = nargs.value if isinstance(nargs, ast.Constant) else None
        requires_value = expects_value and nargs not in {"?", "*"}
        for flag in flags:
            result[flag] = {"expects_value": expects_value,
                            "requires_value": requires_value}
    result.setdefault("-h", {"expects_value": False, "requires_value": False})
    result.setdefault("--help", {"expects_value": False, "requires_value": False})
    return dict(sorted(result.items()))


def _subcommands(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    commands = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) \
                or node.func.attr != "add_parser" or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            commands.add(first.value)
    return sorted(commands)


def _tree_digest(root):
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append((path.relative_to(root).as_posix(), path.stat().st_size,
                            hashlib.sha256(path.read_bytes()).hexdigest()))
    return entries


def _runtime_help_options(root, path, subcommands):
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    outputs = []
    for suffix in [[], *[[command] for command in subcommands]]:
        probe = subprocess.run(
            [sys.executable, "-B", str(path), *suffix, "--help"],
            cwd=root / "tools", env=environment, capture_output=True,
            text=True, timeout=10, check=False)
        if probe.returncode != 0 or probe.stderr.strip():
            raise ContractError(f"{path.stem} help contract cannot be inventoried")
        outputs.append(probe.stdout)
    text = "\n".join(outputs)
    result = {}
    for flag, metavar in re.findall(
            r"(?<!\w)(--?[A-Za-z][A-Za-z0-9-]*)(?:[ =]+([A-Z][A-Z0-9_-]*))?", text):
        expects = bool(metavar)
        result[flag] = {"expects_value": expects, "requires_value": expects}
    return result


def inventory(root):
    root = Path(root).resolve()
    if not (root / "tools").is_dir():
        raise ContractError("repository tools directory is missing")
    tools = []
    for path in _entrypoints(root):
        name = path.stem
        writes = WRITE_CLASS.get(name, "none")
        subcommands = _subcommands(path)
        options = _parser_options(path)
        options.update({key: value for key, value in
                        _runtime_help_options(root, path, subcommands).items()
                        if key not in options})
        tools.append({
            "name": name,
            "path": path.relative_to(root).as_posix(),
            "surface": "runtime" if name in RUNTIME else "maintenance",
            "writes": writes,
            "idempotency": ("read-only" if writes == "none" else
                            "operation-id-guarded" if writes == "owner-state" else
                            "receipt-guarded"),
            "machine_output": ("text" if name in TEXT_OUTPUT else
                               "mixed" if name in MIXED_OUTPUT else "json"),
            "exit_codes": {"success": 0, "refused": [1, 2]},
            "options": dict(sorted(options.items())),
            "subcommands": subcommands,
        })
    return {"schema_version": 1, "tools": tools}


def verify(root):
    root = Path(root).resolve()
    value = inventory(root)
    receipts = []
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for item in value["tools"]:
        command = [sys.executable, "-B", str(root / item["path"]), "--help"]
        try:
            probe = subprocess.run(
                command, cwd=root / "tools", env=environment, capture_output=True,
                text=True, timeout=10, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ContractError(f"{item['name']} --help exceeded 10 seconds") from exc
        if probe.returncode != 0 or "usage:" not in probe.stdout.casefold() \
                or probe.stderr.strip():
            raise ContractError(
                f"{item['name']} --help violated its zero-exit stdout-only contract")
        help_outputs = [probe.stdout]
        for command_name in item["subcommands"]:
            subprobe = subprocess.run(
                [sys.executable, "-B", str(root / item["path"]), command_name, "--help"],
                cwd=root / "tools", env=environment, capture_output=True,
                text=True, timeout=10, check=False)
            if subprobe.returncode != 0 or "usage:" not in subprobe.stdout.casefold() \
                    or subprobe.stderr.strip():
                raise ContractError(f"{item['name']} {command_name} --help violated its contract")
            help_outputs.append(subprobe.stdout)
        advertised = set(re.findall(
            r"(?<!\w)(--?[a-zA-Z][a-zA-Z0-9-]*)", "\n".join(help_outputs)))
        contracted = set(item["options"])
        if advertised != contracted:
            raise ContractError(f"{item['name']} advertised options differ from its parser contract")
        with tempfile.TemporaryDirectory(prefix="loom-cli-contract-") as temporary:
            sandbox = Path(temporary)
            isolated = dict(environment, HOME=str(sandbox), USERPROFILE=str(sandbox),
                            LOOM_HOME=str(sandbox / ".loom"))
            before = _tree_digest(sandbox)
            invalid = subprocess.run(
                [sys.executable, "-B", str(root / item["path"]),
                 "--loom-contract-invalid-option"],
                cwd=sandbox, env=isolated, capture_output=True, text=True,
                timeout=10, check=False)
            if invalid.returncode != 2 or invalid.stdout.strip() or "usage:" not in \
                    invalid.stderr.casefold() or _tree_digest(sandbox) != before:
                raise ContractError(f"{item['name']} invalid-option refusal is not side-effect-free")
            value_flags = [flag for flag, contract in item["options"].items()
                           if flag.startswith("--") and contract["requires_value"]]
            missing_value_exit = None
            if value_flags:
                missing = subprocess.run(
                    [sys.executable, "-B", str(root / item["path"]), value_flags[0]],
                    cwd=sandbox, env=isolated, capture_output=True, text=True,
                    timeout=10, check=False)
                missing_value_exit = missing.returncode
                if missing.returncode != 2 or missing.stdout.strip() \
                        or "usage:" not in missing.stderr.casefold() \
                        or _tree_digest(sandbox) != before:
                    raise ContractError(
                        f"{item['name']} missing-value refusal is not side-effect-free")
        receipts.append({"name": item["name"], "help_exit": probe.returncode,
                         "invalid_exit": invalid.returncode,
                         "missing_value_exit": missing_value_exit,
                         "options": len(contracted),
                         "subcommands": len(item["subcommands"]),
                         "stdout_bytes": len(probe.stdout.encode("utf-8"))})
    return {"status": "verified", "tools": len(receipts), "receipts": receipts,
            "inventory": value}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = verify(args.root) if args.verify else inventory(args.root)
    except ContractError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).resolve().write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
