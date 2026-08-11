#!/usr/bin/env python3
"""Build and execute the fixed non-product mechanism qualification workload."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil

import loom_cut_manifest
import loom_qualification_manifest
import loom_reliability
import loom_suite_certificate_core
import loom_suite_harness
import loom_suite_plan
import loom_suite_worker


class WorkloadError(RuntimeError):
    pass


WORKLOAD_KIND = "mechanism-v2"
WORKLOAD_SOURCE_FILES = (
    "qualification/workload-v2/fixture_support.py",
    "qualification/workload-v2/test_qual_exclusive.py",
    "qualification/workload-v2/test_qual_general_a.py",
    "qualification/workload-v2/test_qual_general_b.py",
    "qualification/workload-v2/test_qual_serial.py",
)
POLICY_FIELDS = {
    "schema_version", "workload_kind", "source_files", "modules",
    "expected_tests", "exclusive_modules", "required_observations",
    "workload_source_sha256", "policy_sha256",
}
PROFILE_FIELDS = {
    "schema_version", "workload_kind", "default_p75_microseconds",
    "module_microseconds", "profile_sha256",
}
POLICY_DOMAIN = b"loom.release-qualification-workload-policy.v2\0"
PROFILE_DOMAIN = b"loom.release-qualification-timing-profile.v2\0"
SOURCE_DOMAIN = b"loom.release-qualification-workload-source.v2\0"
FIXTURE_DOMAIN = b"loom.release-qualification-fixture.v2\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_CONTRACT_BYTES = 1024 * 1024


def _canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkloadError("qualification workload value is not canonical") from exc


def _digest(domain, value):
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load_json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or not 1 <= path.stat().st_size <= MAX_CONTRACT_BYTES:
        raise WorkloadError("qualification workload contract is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise WorkloadError("qualification workload contract is invalid") from exc


def workload_source(root):
    root = Path(root).resolve()
    rows = []
    for relative in WORKLOAD_SOURCE_FILES:
        path = root / relative
        if not path.is_file() or path.is_symlink() \
                or loom_reliability._is_redirect(path):
            raise WorkloadError("qualification workload source is incomplete")
        raw = path.read_bytes()
        rows.append({
            "path": relative, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return {"files": rows, "sha256": _digest(SOURCE_DOMAIN, rows)}


def seal_policy(value):
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS - {
            "policy_sha256"} \
            or value.get("schema_version") != 2 \
            or value.get("workload_kind") != WORKLOAD_KIND \
            or value.get("source_files") != list(WORKLOAD_SOURCE_FILES) \
            or not isinstance(value.get("modules"), list) \
            or value["modules"] != sorted(set(value["modules"])) \
            or not value["modules"] \
            or any(re.fullmatch(r"test_qual_[A-Za-z0-9_]+", module) is None
                   for module in value["modules"]) \
            or not isinstance(value.get("expected_tests"), list) \
            or value["expected_tests"] != sorted(set(value["expected_tests"])) \
            or not value["expected_tests"] \
            or not isinstance(value.get("exclusive_modules"), list) \
            or value["exclusive_modules"] != sorted(set(
                value["exclusive_modules"])) \
            or not set(value["exclusive_modules"]).issubset(value["modules"]) \
            or value.get("required_observations") != 10 \
            or HEX64.fullmatch(str(value.get(
                "workload_source_sha256", ""))) is None:
        raise WorkloadError("qualification workload policy is invalid")
    body = dict(value)
    return {**body, "policy_sha256": _digest(POLICY_DOMAIN, body)}


def validate_policy(value, *, root=None):
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS:
        raise WorkloadError("qualification workload policy fields are invalid")
    body = {key: item for key, item in value.items() if key != "policy_sha256"}
    if seal_policy(body) != value:
        raise WorkloadError("qualification workload policy is stale or forged")
    if root is not None and value["workload_source_sha256"] != workload_source(
            root)["sha256"]:
        raise WorkloadError("qualification workload source digest is stale")
    return value


def load_policy(root):
    root = Path(root).resolve()
    return validate_policy(_load_json(
        root / "contracts" / "release-qualification-workload-policy-v2.json"),
        root=root)


def seal_timing_profile(value):
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS - {
            "profile_sha256"} \
            or value.get("schema_version") != 2 \
            or value.get("workload_kind") != WORKLOAD_KIND \
            or type(value.get("default_p75_microseconds")) is not int \
            or not 1 <= value["default_p75_microseconds"] <= 3_600_000_000 \
            or not isinstance(value.get("module_microseconds"), dict) \
            or list(value["module_microseconds"]) != sorted(
                value["module_microseconds"]) \
            or any(re.fullmatch(r"test_qual_[A-Za-z0-9_]+", module) is None
                   or type(duration) is not int
                   or not 1 <= duration <= 3_600_000_000
                   for module, duration in value["module_microseconds"].items()):
        raise WorkloadError("qualification timing profile is invalid")
    body = dict(value)
    return {**body, "profile_sha256": _digest(PROFILE_DOMAIN, body)}


def validate_timing_profile(value):
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
        raise WorkloadError("qualification timing profile fields are invalid")
    body = {key: item for key, item in value.items() if key != "profile_sha256"}
    if seal_timing_profile(body) != value:
        raise WorkloadError("qualification timing profile is stale or forged")
    return value


def load_timing_profile(root):
    return validate_timing_profile(_load_json(
        Path(root).resolve() / "contracts" /
        "release-qualification-timing-profile-v2.json"))


def _copy_regular(source, destination):
    if not source.is_file() or source.is_symlink() \
            or loom_reliability._is_redirect(source):
        raise WorkloadError("qualification fixture source is unsafe")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def build_fixture(destination, *, manifest, root=None, mechanism_root=None):
    root = Path(__file__).resolve().parents[1] if root is None \
        else Path(root).resolve()
    mechanism_root = root if mechanism_root is None \
        else Path(mechanism_root).resolve()
    destination = Path(destination).resolve()
    if destination.exists() or not destination.parent.is_dir():
        raise WorkloadError("qualification fixture destination is invalid")
    manifest = loom_qualification_manifest.validate_manifest(manifest)
    source_identity = workload_source(root)
    destination.mkdir()
    try:
        for node in manifest["nodes"]:
            source = mechanism_root / node["path"]
            if not source.is_file() or source.is_symlink() \
                    or loom_reliability._is_redirect(source):
                raise WorkloadError("qualification mechanism manifest is stale")
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != node["sha256"]:
                raise WorkloadError("qualification mechanism manifest is stale")
            if node["path"] in WORKLOAD_SOURCE_FILES:
                continue
            _copy_regular(source, destination / node["path"])
        for relative in WORKLOAD_SOURCE_FILES:
            _copy_regular(
                root / relative,
                destination / "tools" / PurePosixPath(relative).name)
        cut_manifest = loom_reliability.deterministic_manifest(destination)
        loom_reliability.atomic_write_json(
            destination / loom_cut_manifest.MANIFEST, cut_manifest)
        cut_manifest = loom_cut_manifest.verify(destination)
    except BaseException:
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise
    manifest_bytes = (destination / loom_cut_manifest.MANIFEST).read_bytes()
    body = {
        "schema_version": 2, "workload_kind": WORKLOAD_KIND,
        "mechanism_manifest_sha256": manifest["manifest_sha256"],
        "workload_source_sha256": source_identity["sha256"],
        "fixture_tree_sha256": cut_manifest["root_sha256"],
        "public_root_sha256": cut_manifest["root_sha256"],
        "public_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "public_file_count": len(cut_manifest["files"]) + 1,
    }
    return {**body, "fixture_sha256": _digest(FIXTURE_DOMAIN, body)}


def validate_serial_report(report, policy):
    policy = validate_policy(policy)
    if not isinstance(report, dict) \
            or report.get("mode") != "modules" \
            or report.get("selected_modules") != policy["modules"] \
            or report.get("successful") is not True \
            or report.get("failures") != 0 or report.get("errors") != 0 \
            or report.get("skipped") != 0 \
            or report.get("capability_complete") is not True \
            or report.get("within_budget") is not True:
        raise WorkloadError("qualification serial workload failed")
    test_ids = sorted(
        row.get("test") for row in report.get("timings", [])
        if isinstance(row, dict))
    if test_ids != policy["expected_tests"] \
            or len(test_ids) != len(set(test_ids)) \
            or any(row.get("status") != "passed"
                   for row in report.get("timings", [])):
        raise WorkloadError("qualification serial inventory is invalid")
    return report


def run_serial(fixture, policy):
    fixture = Path(fixture).resolve()
    policy = validate_policy(policy)
    report = loom_suite_harness.run_modules(
        policy["modules"], start_dir=fixture / "tools", verbosity=0)
    report["elapsed_microseconds"] = max(
        1, int(round(report.get("elapsed_seconds", 0) * 1_000_000)))
    return validate_serial_report(report, policy)


def _v1_policy(policy):
    return loom_suite_plan.seal_policy({
        "schema_version": 1, "authority_mode": "serial",
        "exclusive_modules": policy["exclusive_modules"],
    })


def _v1_profile(profile):
    return loom_suite_plan.seal_timing_profile({
        "schema_version": 1,
        "default_p75_microseconds": profile["default_p75_microseconds"],
        "module_microseconds": profile["module_microseconds"],
    })


def run_shadow(fixture, policy, timing_profile, output, *, environment,
               fixture_identity, logical_cpus, timeout,
               serial_report=None, source_commit=None):
    fixture = Path(fixture).resolve()
    output = Path(output).resolve()
    policy = validate_policy(policy)
    timing_profile = validate_timing_profile(timing_profile)
    if not isinstance(fixture_identity, dict) \
            or fixture_identity.get("workload_kind") != WORKLOAD_KIND \
            or fixture_identity.get("workload_source_sha256") != policy[
                "workload_source_sha256"] \
            or HEX64.fullmatch(str(fixture_identity.get(
                "mechanism_manifest_sha256", ""))) is None \
            or output.exists() or not output.parent.is_dir():
        raise WorkloadError("qualification shadow inputs are invalid")
    source_commit = fixture_identity["mechanism_manifest_sha256"][:40] \
        if source_commit is None else source_commit
    if HEX40.fullmatch(str(source_commit)) is None:
        raise WorkloadError("qualification source commit is invalid")
    cut_before = loom_cut_manifest.verify(fixture)
    harness_sha256 = hashlib.sha256(
        (fixture / "tools" / "loom_suite_harness.py").read_bytes()).hexdigest()
    subject = {
        "repository": "https://github.com/saroo98/loom",
        "source_commit": source_commit,
        "source_tree_sha256": fixture_identity["mechanism_manifest_sha256"],
        "public_root_sha256": fixture_identity["public_root_sha256"],
        "public_manifest_sha256": fixture_identity[
            "public_manifest_sha256"],
        "public_file_count": fixture_identity["public_file_count"],
    }
    inventory = loom_suite_plan.inventory(
        fixture / "tools", subject=subject, environment=environment,
        harness_sha256=harness_sha256, timeout=timeout,
        protected_roots=[fixture], context_root=fixture)
    observed_modules = [row["module"] for row in inventory["modules"]]
    observed_tests = sorted(
        test for row in inventory["modules"] for test in row["tests"])
    if observed_modules != policy["modules"] \
            or observed_tests != policy["expected_tests"]:
        raise WorkloadError("qualification workload inventory drifted")
    v1_policy = _v1_policy(policy)
    v1_profile = _v1_profile(timing_profile)
    plan = loom_suite_plan.plan(
        inventory, timing_profile=v1_profile, policy=v1_policy,
        logical_cpus=logical_cpus)
    output.mkdir()
    worker_root = output / "workers"
    worker_root.mkdir()
    receipts = loom_suite_worker.run_plan(
        fixture, inventory, plan, worker_root, timeout=timeout,
        protected_roots=[fixture])
    cell = loom_suite_certificate_core.compile_cell(
        inventory, plan, receipts, policy=v1_policy)
    serial_report = run_serial(fixture, policy) \
        if serial_report is None else validate_serial_report(
            serial_report, policy)
    comparison = loom_suite_certificate_core.compare_shadow(
        serial_report, cell)
    cut_after = loom_cut_manifest.verify(fixture)
    if cut_after != cut_before:
        raise WorkloadError("qualification fixture changed during execution")
    return {
        "schema_version": 2, "workload_kind": WORKLOAD_KIND,
        "workload_policy_sha256": policy["policy_sha256"],
        "timing_profile_sha256": timing_profile["profile_sha256"],
        "mechanism_manifest_sha256": fixture_identity[
            "mechanism_manifest_sha256"],
        "workload_source_sha256": fixture_identity[
            "workload_source_sha256"],
        "fixture_sha256": fixture_identity["fixture_sha256"],
        "serial_report": serial_report, "inventory": inventory,
        "plan": plan, "worker_receipts": receipts,
        "cell_certificate": cell, "comparison": comparison,
    }
