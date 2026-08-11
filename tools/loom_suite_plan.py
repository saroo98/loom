#!/usr/bin/env python3
"""Closed test inventories and deterministic release-suite shard plans."""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import loom_operation_supervisor
import loom_privacy
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
AUTHORITY_POLICY_FIELDS = {
    "schema_version", "authority_mode", "mechanism_schema",
    "candidate_schema", "release_schema",
}
AUTHORITY_POLICY_SCHEMA_IDENTIFIERS = {
    "mechanism_schema": "release-mechanism-qualification-v2",
    "candidate_schema": "release-candidate-admission-v2",
    "release_schema": "release-certificate-v2",
}
AUTHORITY_POLICY_DIGEST_DOMAIN = b"loom.release-authority-policy.v2\0"

SUITE_PLAN_ERROR_CODES = {
    "test discovery failed": "SUITE_INVENTORY_DISCOVERY_FAILED",
    "test discovery returned an unsafe module":
        "SUITE_INVENTORY_DISCOVERY_FAILED",
    "test discovery returned an empty inventory":
        "SUITE_INVENTORY_DISCOVERY_FAILED",
    "test root is invalid": "SUITE_INVENTORY_TEST_ROOT_INVALID",
    "test root contains a redirected entry": "SUITE_INVENTORY_REDIRECTED_ROOT",
    "protected discovery root is invalid":
        "SUITE_INVENTORY_PROTECTED_ROOT_INVALID",
    "test root is outside its discovery context":
        "SUITE_INVENTORY_CONTEXT_INVALID",
    "inventory discovery inputs are invalid": "SUITE_INVENTORY_INPUT_INVALID",
    "inventory runtime cleanup failed":
        "SUITE_INVENTORY_RUNTIME_CLEANUP_FAILED",
    "inventory privacy validation failed": "SUITE_INVENTORY_PRIVACY_FAILED",
    "inventory containment mutation detected": "SUITE_INVENTORY_MUTATION",
    "inventory containment failed": "SUITE_INVENTORY_CONTAINMENT_FAILED",
    "inventory discovery identity is invalid": "SUITE_INVENTORY_IDENTITY_INVALID",
    "inventory discovery cleanup failed": "SUITE_INVENTORY_CLEANUP_FAILED",
}
SUITE_PLAN_PUBLIC_ERROR_CODES = frozenset(SUITE_PLAN_ERROR_CODES.values())


class SuitePlanError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        code = SUITE_PLAN_ERROR_CODES.get(message)
        if code is not None:
            self.code = code


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


def _discover_inventory(test_root, *, subject, environment, harness_sha256):
    """Child-only unittest import and discovery implementation."""
    root = Path(test_root).resolve()
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


def _inventory_child(request_path, output_path):
    request = _load(request_path, "inventory request")
    if not isinstance(request, dict) or set(request) != {
            "test_root", "subject", "environment", "harness_sha256"}:
        raise SuitePlanError("inventory request fields are invalid")
    controller_root = Path(__file__).resolve().parent
    isolated_path = []
    for entry in sys.path:
        try:
            if Path(entry or os.curdir).resolve() == controller_root:
                continue
        except OSError:
            pass
        isolated_path.append(entry)
    sys.path[:] = isolated_path
    for name, module in list(sys.modules.items()):
        module_path = getattr(module, "__file__", None)
        if name == "__main__" or not isinstance(module_path, str):
            continue
        try:
            resolved = Path(module_path).resolve()
        except OSError:
            continue
        if resolved == controller_root or controller_root in resolved.parents:
            sys.modules.pop(name, None)
    value = _discover_inventory(
        request["test_root"], subject=request["subject"],
        environment=request["environment"],
        harness_sha256=request["harness_sha256"])
    loom_reliability.atomic_write_json(Path(output_path), value)


def _safe_discovery_source(test_root):
    try:
        root = loom_reliability._absolute(
            test_root, "test root", must_exist=True).resolve(strict=True)
        if not root.is_dir():
            raise SuitePlanError("test root is invalid")
        for entry in root.rglob("*"):
            if loom_reliability._is_redirect(entry):
                raise SuitePlanError("test root contains a redirected entry")
    except (OSError, loom_reliability.ReliabilityError) as exc:
        raise SuitePlanError("test root is invalid") from exc
    return root


def _minimal_protected_roots(values):
    roots = []
    for value in values:
        path = Path(value)
        try:
            path = path.resolve(strict=True)
        except OSError as exc:
            raise SuitePlanError("protected discovery root is invalid") from exc
        if path not in roots:
            roots.append(path)
    return [
        path for path in roots
        if not any(other != path and other in path.parents for other in roots)
    ]


def inventory(test_root, *, subject, environment, harness_sha256,
              timeout=300, protected_roots=(), context_root=None):
    """Discover one exact inventory in a supervised spawned interpreter."""
    root = _safe_discovery_source(test_root)
    if context_root is None and root.name == "tools" and all((
            (root.parent / "VERSION").is_file(),
            (root.parent / "contracts").is_dir(),
            (root.parent / "schemas").is_dir())):
        context_root = root.parent
    context = root if context_root is None \
        else _safe_discovery_source(context_root)
    if root != context and context not in root.parents:
        raise SuitePlanError("test root is outside its discovery context")
    relative_test_root = root.relative_to(context)
    subject = _subject(subject)
    environment = _environment(environment)
    if HEX64.fullmatch(str(harness_sha256)) is None \
            or type(timeout) not in {int, float} or not 0 < timeout <= 3600 \
            or not isinstance(protected_roots, (list, tuple)):
        raise SuitePlanError("inventory discovery inputs are invalid")
    discovery_root = Path(tempfile.mkdtemp(prefix="loom-si-")).resolve()
    runtime_root = None
    runtime_clean = discovery_clean = False
    inventory_value = None
    failure = None
    try:
        operation_root = discovery_root / "operation"
        operation_root.mkdir()
        candidate_context = operation_root / "candidate"
        shutil.copytree(context, candidate_context)
        candidate = candidate_context / relative_test_root
        request_path = discovery_root / "request.json"
        output_path = discovery_root / "inventory.json"
        loom_reliability.atomic_write_json(request_path, {
            "test_root": str(candidate), "subject": subject,
            "environment": environment, "harness_sha256": harness_sha256,
        })
        # Import lazily: the worker imports this module at startup.  Reusing its
        # environment factory keeps discovery and execution on one boundary.
        import loom_suite_worker
        child_environment, runtime_root = \
            loom_suite_worker._isolated_environment(
                discovery_root, "inventory")
        protected = _minimal_protected_roots([
            context, *protected_roots,
        ])
        try:
            operation, stdout, stderr = loom_operation_supervisor.run(
                operation_class="release-suite-inventory",
                command=[
                    sys.executable, "-B", str(Path(__file__).resolve()),
                    "_inventory-child", str(request_path), str(output_path),
                ],
                cwd=candidate, timeout=timeout,
                environment=child_environment,
                allowed_roots=[discovery_root],
                protected_roots=[operation_root, request_path, *protected],
                capabilities=["local-process", "descendant-containment"],
                capture_output=True)
        finally:
            if runtime_root is not None:
                try:
                    shutil.rmtree(runtime_root)
                    runtime_clean = not runtime_root.exists()
                except OSError:
                    runtime_clean = False
        if not runtime_clean:
            raise SuitePlanError("inventory runtime cleanup failed")
        try:
            if any(loom_privacy._isolated_secret_signature_match(stream)
                   is not None for stream in (stdout, stderr)):
                raise SuitePlanError("inventory privacy validation failed")
        except loom_privacy.PrivacyError as exc:
            raise SuitePlanError("inventory privacy validation failed") from exc
        expected_entries = {"operation", "request.json", "inventory.json"}
        observed_entries = {entry.name for entry in discovery_root.iterdir()}
        if observed_entries - expected_entries:
            raise SuitePlanError("inventory containment mutation detected")
        try:
            loom_operation_supervisor.require_passed(operation)
        except loom_operation_supervisor.SupervisorError as exc:
            message = ("test discovery failed"
                       if operation.get("primary_failure") == "nonzero-exit"
                       else "inventory containment failed")
            raise SuitePlanError(message) from exc
        inventory_value = _load(output_path, "suite inventory")
        inventory_value = _validate_seal(
            inventory_value, "inventory_sha256", seal_inventory)
        try:
            if loom_privacy._isolated_secret_signature_match(
                    canonical(inventory_value)) is not None:
                raise SuitePlanError("inventory privacy validation failed")
        except loom_privacy.PrivacyError as exc:
            raise SuitePlanError("inventory privacy validation failed") from exc
        if inventory_value["subject"] != subject \
                or inventory_value["environment"] != environment \
                or inventory_value["harness_sha256"] != harness_sha256:
            raise SuitePlanError("inventory discovery identity is invalid")
    except SuitePlanError as exc:
        failure = exc
    except (OSError, shutil.Error, loom_operation_supervisor.SupervisorError,
            loom_reliability.ReliabilityError) as exc:
        failure = SuitePlanError("inventory containment failed")
        failure.__cause__ = exc
    finally:
        try:
            shutil.rmtree(discovery_root)
            discovery_clean = not discovery_root.exists()
        except OSError:
            discovery_clean = False
    if not discovery_clean:
        raise SuitePlanError("inventory discovery cleanup failed")
    if failure is not None:
        raise failure
    return inventory_value


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


def seal_authority_policy(value):
    """Seal the v2 release-authority decision in its own digest domain."""
    if not isinstance(value, dict) or set(value) != AUTHORITY_POLICY_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("authority_mode") not in {"serial", "certificate"} \
            or any(value.get(field) != expected for field, expected in
                   AUTHORITY_POLICY_SCHEMA_IDENTIFIERS.items()):
        raise SuitePlanError("release authority policy fields are invalid")
    body = {
        "schema_version": 2,
        "authority_mode": value["authority_mode"],
        **AUTHORITY_POLICY_SCHEMA_IDENTIFIERS,
    }
    return {
        **body,
        "policy_sha256": hashlib.sha256(
            AUTHORITY_POLICY_DIGEST_DOMAIN + canonical(body)).hexdigest(),
    }


def validate_authority_policy(value):
    if not isinstance(value, dict) or "policy_sha256" not in value:
        raise SuitePlanError("release authority policy digest is missing")
    body = {key: item for key, item in value.items()
            if key != "policy_sha256"}
    try:
        expected = seal_authority_policy(body)
    except SuitePlanError as exc:
        raise SuitePlanError("release authority policy fields are invalid") from exc
    if value != expected:
        raise SuitePlanError("release authority policy digest is invalid")
    return value


def load_authority_policy(path):
    return validate_authority_policy(_load(path, "release authority policy"))


def load_candidate_policy(path):
    return _validate_seal(
        _load(path, "candidate shard policy"),
        "policy_sha256", seal_policy)


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
    # LPT determines membership and load only. Execute each shard in the same
    # canonical module order as the serial unittest discovery so process-global
    # fixtures cannot observe an arbitrary timing-profile order.
    for shard in general_shards:
        shard["modules"].sort()
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
    inventory_child = commands.add_parser("_inventory-child")
    inventory_child.add_argument("request")
    inventory_child.add_argument("output")
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("inventory")
    plan_parser.add_argument("--timing-profile", required=True)
    plan_parser.add_argument("--policy", required=True)
    plan_parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "_inventory-child":
        _inventory_child(args.request, args.output)
        return 0
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
