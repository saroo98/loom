#!/usr/bin/env python3
"""Closed test inventories and deterministic release-suite shard plans."""

import argparse
import json
import os
import re
import sys
import unittest
from pathlib import Path

import loom_subject_identity
import loom_reliability


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MODULE = re.compile(r"^test_[A-Za-z0-9_]+$")
SUBJECT_FIELDS = {
    "repository", "source_commit", "source_tree_sha256", "public_root_sha256",
    "public_manifest_sha256", "public_file_count",
}
ENVIRONMENT_FIELDS = {
    "requested_label", "image_os", "image_version", "os", "os_release",
    "os_version", "architecture", "python_implementation", "python_version",
    "workflow_path", "workflow_digest", "action_manifest_digest",
    "event_name", "run_id", "run_attempt",
}
DEFAULT_EXCLUSIVE_MODULES = (
    "test_loom_bootstrap_v11",
    "test_loom_crypto_v11",
    "test_loom_owner_v11",
    "test_loom_plugin_package_v11",
    "test_loom_release_sign_v11",
    "test_loom_transfer_v11",
    "test_recovery_contract_schemas",
    "test_loom_mutation",
)


class SuitePlanError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load(path, label):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or path.stat().st_size > 4 * 1024 * 1024:
        raise SuitePlanError(f"{label} is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SuitePlanError(f"{label} is invalid") from exc


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def digest(value):
    return __import__("hashlib").sha256(canonical(value)).hexdigest()


def _seal(value, field):
    if field in value:
        raise SuitePlanError(f"unsealed {field} fields are invalid")
    return {**value, field: digest(value)}


def _subject(value):
    if not isinstance(value, dict) or set(value) != SUBJECT_FIELDS \
            or value.get("repository") != loom_subject_identity.REPOSITORY \
            or HEX40.fullmatch(str(value.get("source_commit", ""))) is None \
            or any(HEX64.fullmatch(str(value.get(field, ""))) is None for field in (
                "source_tree_sha256", "public_root_sha256",
                "public_manifest_sha256")) \
            or type(value.get("public_file_count")) is not int \
            or not 1 <= value["public_file_count"] <= 8192:
        raise SuitePlanError("suite subject is invalid")
    return dict(value)


def _environment(value):
    if not isinstance(value, dict) or set(value) != ENVIRONMENT_FIELDS \
            or any(not isinstance(value.get(field), str) or not value[field]
                   or len(value[field]) > 128 for field in ENVIRONMENT_FIELDS) \
            or any(HEX64.fullmatch(value.get(field, "")) is None for field in (
                "workflow_digest", "action_manifest_digest")):
        raise SuitePlanError("suite environment is invalid")
    return dict(value)


def _flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _flatten(test)
        else:
            yield test


def seal_inventory(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "subject", "environment", "harness_sha256",
            "modules", "module_count", "test_count"} \
            or value.get("schema_version") != 1 \
            or HEX64.fullmatch(str(value.get("harness_sha256", ""))) is None \
            or not isinstance(value.get("modules"), list):
        raise SuitePlanError("suite inventory fields are invalid")
    subject = _subject(value["subject"])
    environment = _environment(value["environment"])
    normalized, seen_modules, seen_tests = [], set(), set()
    for row in value["modules"]:
        if not isinstance(row, dict) or set(row) != {"module", "tests"} \
                or MODULE.fullmatch(str(row.get("module", ""))) is None \
                or row["module"] in seen_modules \
                or not isinstance(row.get("tests"), list) or not row["tests"]:
            raise SuitePlanError("suite inventory module is invalid")
        tests = []
        for test_id in row["tests"]:
            if not isinstance(test_id, str) or not test_id.startswith(
                    row["module"] + ".") or test_id in seen_tests:
                raise SuitePlanError("suite inventory test is invalid")
            seen_tests.add(test_id)
            tests.append(test_id)
        seen_modules.add(row["module"])
        normalized.append({"module": row["module"], "tests": sorted(tests)})
    normalized.sort(key=lambda row: row["module"])
    if value.get("module_count") != len(normalized) \
            or value.get("test_count") != len(seen_tests):
        raise SuitePlanError("suite inventory counts are invalid")
    body = {
        "schema_version": 1, "subject": subject, "environment": environment,
        "harness_sha256": value["harness_sha256"], "modules": normalized,
        "module_count": len(normalized), "test_count": len(seen_tests),
    }
    return _seal(body, "inventory_sha256")


def inventory(test_root, *, subject, environment, harness_sha256):
    """Discover one exact environment's complete unittest inventory."""
    root = Path(test_root).resolve()
    if not root.is_dir():
        raise SuitePlanError("test root is invalid")
    before_modules = set(sys.modules)
    sys.path.insert(0, str(root))
    try:
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(root), pattern="test_*.py", top_level_dir=str(root))
        loaded = list(_flatten(suite))
        if any(test.__class__.__name__ == "_FailedTest" for test in loaded):
            raise SuitePlanError("test discovery failed")
        grouped = {}
        for test in loaded:
            test_id = test.id()
            module = test_id.split(".", 1)[0]
            if MODULE.fullmatch(module) is None:
                raise SuitePlanError("test discovery returned an unsafe module")
            grouped.setdefault(module, []).append(test_id)
        if not grouped:
            raise SuitePlanError("test discovery returned an empty inventory")
        return seal_inventory({
            "schema_version": 1,
            "subject": subject,
            "environment": environment,
            "harness_sha256": harness_sha256,
            "modules": [
                {"module": module, "tests": sorted(tests)}
                for module, tests in sorted(grouped.items())
            ],
            "module_count": len(grouped),
            "test_count": len(loaded),
        })
    except SuitePlanError:
        raise
    except BaseException as exc:
        raise SuitePlanError("test discovery failed") from exc
    finally:
        sys.path.remove(str(root))
        for name in set(sys.modules) - before_modules:
            module = sys.modules.get(name)
            filename = getattr(module, "__file__", None)
            if filename and Path(filename).resolve().is_relative_to(root):
                sys.modules.pop(name, None)


def seal_timing_profile(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "default_p75_microseconds", "module_microseconds"} \
            or value.get("schema_version") != 1 \
            or type(value.get("default_p75_microseconds")) is not int \
            or value["default_p75_microseconds"] <= 0 \
            or not isinstance(value.get("module_microseconds"), dict):
        raise SuitePlanError("timing profile fields are invalid")
    timings = {}
    for module, microseconds in value["module_microseconds"].items():
        if MODULE.fullmatch(str(module)) is None or type(microseconds) is not int \
                or microseconds <= 0:
            raise SuitePlanError("timing profile module is invalid")
        timings[module] = microseconds
    return _seal({
        "schema_version": 1,
        "default_p75_microseconds": value["default_p75_microseconds"],
        "module_microseconds": dict(sorted(timings.items())),
    }, "profile_sha256")


def seal_policy(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "authority_mode", "exclusive_modules"} \
            or value.get("schema_version") != 1 \
            or value.get("authority_mode") not in {"serial", "certificate"} \
            or not isinstance(value.get("exclusive_modules"), list):
        raise SuitePlanError("suite policy fields are invalid")
    modules = value["exclusive_modules"]
    if len(modules) != len(set(modules)) or any(
            MODULE.fullmatch(str(module)) is None for module in modules):
        raise SuitePlanError("suite policy exclusive modules are invalid")
    return _seal({
        "schema_version": 1, "authority_mode": value["authority_mode"],
        "exclusive_modules": sorted(modules),
    }, "policy_sha256")


def _validate_seal(value, field, sealer):
    if not isinstance(value, dict) or field not in value:
        raise SuitePlanError(f"sealed {field} is missing")
    body = {key: item for key, item in value.items() if key != field}
    expected = sealer(body)
    if expected != value:
        raise SuitePlanError(f"sealed {field} is invalid")
    return value


def plan(inventory_value, *, timing_profile, policy, logical_cpus=None):
    inventory_value = _validate_seal(
        inventory_value, "inventory_sha256", seal_inventory)
    timing_profile = _validate_seal(
        timing_profile, "profile_sha256", seal_timing_profile)
    policy = _validate_seal(policy, "policy_sha256", seal_policy)
    logical = os.cpu_count() if logical_cpus is None else logical_cpus
    if type(logical) is not int or logical < 1:
        logical = 1
    modules = [row["module"] for row in inventory_value["modules"]]
    budget = min(len(modules), max(1, logical - 1 if logical > 2 else 1))
    exclusive_set = set(policy["exclusive_modules"])
    exclusive = sorted(module for module in modules if module in exclusive_set)
    general = [module for module in modules if module not in exclusive_set]
    general_shard_count = 0
    if general:
        general_shard_count = max(1, budget - (1 if exclusive else 0))
        general_shard_count = min(general_shard_count, len(general))
    estimates = {
        module: timing_profile["module_microseconds"].get(
            module, timing_profile["default_p75_microseconds"])
        for module in modules
    }
    shards = []
    if exclusive:
        shards.append({
            "shard_id": "exclusive", "exclusive": True,
            "estimated_microseconds": sum(estimates[module] for module in exclusive),
            "modules": exclusive,
        })
    general_shards = [{
        "shard_id": f"general-{index:03d}", "exclusive": False,
        "estimated_microseconds": 0, "modules": [],
    } for index in range(general_shard_count)]
    for module in sorted(general, key=lambda item: (-estimates[item], item)):
        target = min(
            general_shards,
            key=lambda row: (row["estimated_microseconds"], row["shard_id"]))
        target["modules"].append(module)
        target["estimated_microseconds"] += estimates[module]
    shards.extend(general_shards)
    body = {
        "schema_version": 1,
        "inventory_sha256": inventory_value["inventory_sha256"],
        "policy_sha256": policy["policy_sha256"],
        "timing_profile_sha256": timing_profile["profile_sha256"],
        "logical_cpu_count": logical,
        "max_parallel_workers": budget,
        "shards": shards,
    }
    return _seal(body, "plan_sha256")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-profile")
    validate.add_argument("path")
    inventory_parser = commands.add_parser("inventory")
    inventory_parser.add_argument("test_root")
    inventory_parser.add_argument("--subject", required=True)
    inventory_parser.add_argument("--environment", required=True)
    inventory_parser.add_argument("--harness-sha256", required=True)
    inventory_parser.add_argument("--output", required=True)
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("inventory")
    plan_parser.add_argument("--timing-profile", required=True)
    plan_parser.add_argument("--policy", required=True)
    plan_parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "validate-profile":
        value = _load(args.path, "timing profile")
        _validate_seal(value, "profile_sha256", seal_timing_profile)
        result = {"status": "valid", "profile_sha256": value["profile_sha256"]}
    elif args.command == "inventory":
        value = inventory(
            args.test_root,
            subject=_load(args.subject, "suite subject"),
            environment=_load(args.environment, "suite environment"),
            harness_sha256=args.harness_sha256)
        loom_reliability.atomic_write_json(Path(args.output).resolve(), value)
        result = {"status": "inventoried", "test_count": value["test_count"],
                  "inventory_sha256": value["inventory_sha256"]}
    else:
        value = plan(
            _load(args.inventory, "suite inventory"),
            timing_profile=_load(args.timing_profile, "timing profile"),
            policy=_load(args.policy, "suite policy"))
        loom_reliability.atomic_write_json(Path(args.output).resolve(), value)
        result = {"status": "planned", "shards": len(value["shards"]),
                  "plan_sha256": value["plan_sha256"]}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
