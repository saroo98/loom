#!/usr/bin/env python3
"""Compile and verify separated repeated-mechanism qualification evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import re

import loom_qualification_manifest
import loom_qualification_workload
import loom_suite_certificate_core
import loom_suite_plan
import loom_suite_worker


class QualificationV2Error(RuntimeError):
    pass


EVIDENCE_DOMAIN = "mechanism-qualification-v2"
OBSERVATION_DOMAIN = b"loom.release-qualification-observation.v2\0"
FAMILY_DOMAIN = b"loom.release-qualification-family.v2\0"
FAULT_DOMAIN = b"loom.release-qualification-fault.v2\0"
MECHANISM_DOMAIN = b"loom.release-mechanism-qualification.v2\0"
AUTHORITY_SEMANTICS_DOMAIN = b"loom.release-authority-semantics.v2\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PYTHON_VERSION = re.compile(r"^([0-9]+\.[0-9]+)\.[0-9]+(?:[-+].*)?$")
FAMILY_FIELDS = {
    "consumer", "requested_label", "image_os", "architecture",
    "python_implementation", "python_minor", "family_id",
}
CONTEXT_FIELDS = {
    "consumer", "qualification_workflow_path",
    "qualification_workflow_digest", "action_manifest_digest",
    "repository_source_tree_sha256",
}
SHADOW_FIELDS = {
    "schema_version", "workload_kind", "workload_policy_sha256",
    "timing_profile_sha256", "mechanism_manifest_sha256",
    "workload_source_sha256", "fixture_sha256", "serial_report",
    "inventory", "plan", "worker_receipts", "cell_certificate",
    "comparison",
}
SERIAL_FIELDS = {
    "schema_version", "mode", "selected_modules", "tests_run", "failures",
    "errors", "skipped", "elapsed_seconds", "elapsed_microseconds",
    "suppressed_stdout_chars", "max_seconds", "within_budget",
    "capability_complete", "status", "successful", "skip_receipts",
    "failure_diagnostics", "timings",
}
TIMING_FIELDS = {"test", "seconds", "status"}
COMPARISON_FIELDS = {
    "schema_version", "status", "subject_sha256", "environment_sha256",
    "serial_suite_sha256", "serial_outcomes_sha256",
    "sharded_outcomes_sha256", "cell_certificate_sha256",
    "serial_execution_microseconds", "sharded_execution_microseconds",
    "test_count", "comparison_sha256",
}
OBSERVATION_FIELDS = {
    "schema_version", "evidence_domain", "workload_kind", "consumer",
    "source_commit", "repository_source_tree_sha256",
    "mechanism_manifest_sha256", "boundary_sha256",
    "workload_policy_sha256", "workload_source_sha256",
    "timing_profile_sha256", "fixture_sha256", "family", "environment",
    "serial", "shadow", "comparison", "serial_microseconds",
    "sharded_microseconds", "paired_delta_microseconds", "test_count",
    "terminal_workers", "privacy_clean", "mutation_clean",
    "runtime_roots_clean", "observation_sha256",
}
FAMILY_RECORD_FIELDS = {
    "schema_version", "evidence_domain", *FAMILY_FIELDS,
    "mechanism_manifest_sha256", "boundary_sha256",
    "workload_policy_sha256", "workload_source_sha256",
    "timing_profile_sha256", "observation_count", "observations",
    "source_commits", "repository_source_tree_sha256s",
    "serial_microseconds", "sharded_microseconds", "paired_deltas",
    "serial_observed_median_microseconds",
    "serial_observed_max_microseconds",
    "sharded_observed_median_microseconds",
    "sharded_observed_max_microseconds",
    "all_observations_nonregressing", "family_sha256",
}
FAULT_CODES = (
    "candidate-mutation", "malformed-evidence", "missing-test",
    "privacy-leakage", "survivor-cleanup", "timeout",
    "unauthorized-skip", "unexpected-test", "wrong-subject",
)
FAULT_FIELDS = {
    "schema_version", "evidence_domain", "platform",
    "mechanism_manifest_sha256", "boundary_sha256",
    "workload_policy_sha256", "workload_source_sha256", "faults",
    "fault_receipt_sha256",
}
MECHANISM_FIELDS = {
    "schema_version", "status", "evidence_domain", "required_observations",
    "mechanism_manifest_sha256", "boundary_sha256",
    "workload_policy_sha256", "workload_source_sha256",
    "timing_profile_sha256", "authority_semantics_sha256", "families",
    "family_count", "fault_receipts", "all_families_nonregressing",
    "qualification_sha256",
}
LABELS = {
    "quality": ("ubuntu-latest", "macos-latest", "windows-latest"),
    "compatibility": ("ubuntu-24.04", "macos-15", "windows-2025"),
}
PYTHON_MINORS = ("3.10", "3.11", "3.12", "3.13", "3.14")
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024
MAX_MECHANISM_BYTES = 95_000_000


def _canonical(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise QualificationV2Error(
            "qualification evidence is not canonical") from exc


def _digest(domain, value):
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _load_json(path, max_bytes):
    path = Path(path)
    try:
        if not path.is_file() or path.is_symlink() \
                or not 1 <= path.stat().st_size <= max_bytes:
            raise QualificationV2Error(
                "qualification evidence transport is unsafe")
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if not 1 <= len(raw) <= max_bytes:
            raise QualificationV2Error(
                "qualification evidence transport is unsafe")
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except QualificationV2Error:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise QualificationV2Error(
            "qualification evidence transport is invalid") from exc


def _manifest(value):
    try:
        return loom_qualification_manifest.validate_manifest(value)
    except loom_qualification_manifest.ManifestError as exc:
        raise QualificationV2Error(
            "qualification mechanism manifest is invalid") from exc


def _workload(value):
    try:
        return loom_qualification_workload.validate_policy(value)
    except loom_qualification_workload.WorkloadError as exc:
        raise QualificationV2Error(
            "qualification workload policy is invalid") from exc


def _v1_policy(workload):
    return loom_suite_plan.seal_policy({
        "schema_version": 1, "authority_mode": "serial",
        "exclusive_modules": workload["exclusive_modules"],
    })


def _closed_serial(report, workload):
    if not isinstance(report, dict) or set(report) != SERIAL_FIELDS \
            or report.get("schema_version") != 1 \
            or report.get("max_seconds") is not None \
            or report.get("skip_receipts") != [] \
            or report.get("failure_diagnostics") != [] \
            or not isinstance(report.get("timings"), list) \
            or any(not isinstance(row, dict) or set(row) != TIMING_FIELDS
                   or not isinstance(row.get("test"), str)
                   or row.get("status") != "passed"
                   or not isinstance(row.get("seconds"), (int, float))
                   or isinstance(row.get("seconds"), bool)
                   or row["seconds"] < 0 for row in report["timings"]):
        raise QualificationV2Error(
            "qualification serial evidence fields are invalid")
    try:
        return loom_qualification_workload.validate_serial_report(
            report, workload)
    except loom_qualification_workload.WorkloadError as exc:
        raise QualificationV2Error(
            "qualification serial evidence is invalid") from exc


def _family(environment, consumer):
    if consumer not in LABELS or not isinstance(environment, dict):
        raise QualificationV2Error("qualification family is invalid")
    try:
        environment = loom_suite_plan._environment(environment)
    except loom_suite_plan.SuitePlanError as exc:
        raise QualificationV2Error("qualification environment is invalid") from exc
    matched = PYTHON_VERSION.fullmatch(environment["python_version"])
    if matched is None or environment["requested_label"] not in LABELS[consumer]:
        raise QualificationV2Error("qualification family is invalid")
    body = {
        "consumer": consumer,
        "requested_label": environment["requested_label"],
        "image_os": environment["image_os"],
        "architecture": environment["architecture"],
        "python_implementation": environment["python_implementation"],
        "python_minor": matched.group(1),
    }
    return {**body, "family_id": loom_suite_plan.digest(body)}


def family_identity(value):
    if not isinstance(value, dict):
        raise QualificationV2Error("qualification family identity is invalid")
    candidate = value.get("family") if isinstance(value.get("family"), dict) \
        else {key: value.get(key) for key in FAMILY_FIELDS}
    if set(candidate) != FAMILY_FIELDS \
            or candidate.get("consumer") not in LABELS \
            or candidate.get("requested_label") not in LABELS[
                candidate["consumer"]] \
            or candidate.get("python_minor") not in PYTHON_MINORS \
            or any(not isinstance(candidate.get(field), str)
                   for field in FAMILY_FIELDS) \
            or candidate["family_id"] != loom_suite_plan.digest({
                key: candidate[key] for key in FAMILY_FIELDS
                if key != "family_id"}):
        raise QualificationV2Error("qualification family identity is invalid")
    return dict(candidate)


def compile_observation(serial, shadow, comparison, *, manifest, workload,
                        context):
    manifest = _manifest(manifest)
    workload = _workload(workload)
    if not isinstance(context, dict) or set(context) != CONTEXT_FIELDS \
            or context.get("consumer") not in LABELS \
            or HEX64.fullmatch(str(context.get(
                "qualification_workflow_digest", ""))) is None \
            or HEX64.fullmatch(str(context.get(
                "action_manifest_digest", ""))) is None \
            or HEX64.fullmatch(str(context.get(
                "repository_source_tree_sha256", ""))) is None \
            or context.get("qualification_workflow_path") != \
            f".github/workflows/qualification-{context.get('consumer')}.yml":
        raise QualificationV2Error("qualification observation context is invalid")
    if not isinstance(shadow, dict) or set(shadow) != SHADOW_FIELDS \
            or shadow.get("schema_version") != 2 \
            or shadow.get("workload_kind") != \
            loom_qualification_workload.WORKLOAD_KIND \
            or shadow.get("mechanism_manifest_sha256") != manifest[
                "manifest_sha256"] \
            or shadow.get("workload_policy_sha256") != workload[
                "policy_sha256"] \
            or shadow.get("workload_source_sha256") != workload[
                "workload_source_sha256"] \
            or any(HEX64.fullmatch(str(shadow.get(field, ""))) is None
                   for field in ("timing_profile_sha256", "fixture_sha256")) \
            or serial != shadow.get("serial_report") \
            or comparison != shadow.get("comparison"):
        raise QualificationV2Error("qualification shadow evidence is invalid")
    try:
        serial = _closed_serial(serial, workload)
        inventory = loom_suite_plan._validate_seal(
            shadow["inventory"], "inventory_sha256",
            loom_suite_plan.seal_inventory)
        plan = shadow["plan"]
        receipts = shadow["worker_receipts"]
        cell = loom_suite_certificate_core.compile_cell(
            inventory, plan, receipts, policy=_v1_policy(workload))
        expected_comparison = loom_suite_certificate_core.compare_shadow(
            serial, cell)
    except (loom_qualification_workload.WorkloadError,
            loom_suite_plan.SuitePlanError,
            loom_suite_worker.SuiteWorkerError,
            loom_suite_certificate_core.CertificateError) as exc:
        raise QualificationV2Error(
            "qualification observation evidence is invalid") from exc
    if not isinstance(comparison, dict) \
            or set(comparison) != COMPARISON_FIELDS \
            or cell != shadow["cell_certificate"] \
            or expected_comparison != comparison \
            or comparison.get("status") != "matched":
        raise QualificationV2Error("qualification parity evidence is invalid")
    environment = inventory["environment"]
    if environment["event_name"] != "workflow_dispatch" \
            or environment["workflow_path"] != context[
                "qualification_workflow_path"] \
            or environment["workflow_digest"] != context[
                "qualification_workflow_digest"] \
            or environment["action_manifest_digest"] != context[
                "action_manifest_digest"]:
        raise QualificationV2Error("qualification workflow identity is invalid")
    subject = inventory["subject"]
    if subject["source_tree_sha256"] != manifest["manifest_sha256"] \
            or HEX40.fullmatch(subject["source_commit"]) is None:
        raise QualificationV2Error("qualification mechanism subject is invalid")
    observed_tests = sorted(row["test"] for row in cell["outcomes"])
    if observed_tests != workload["expected_tests"] \
            or cell["test_count"] != len(workload["expected_tests"]):
        raise QualificationV2Error("qualification workload coverage is invalid")
    terminal = all(
        receipt.get("operation", {}).get("survivors_confirmed_zero") is True
        and receipt.get("operation", {}).get(
            "protected_roots_unchanged") is True
        and receipt.get("operation", {}).get("status") == "passed"
        for receipt in receipts)
    privacy = all(receipt.get("privacy_clean") is True for receipt in receipts)
    mutation = all(
        receipt.get("mutation_clean") is True
        and receipt.get("pre_manifest_sha256") == receipt.get(
            "post_manifest_sha256") for receipt in receipts)
    runtime = all(
        receipt.get("runtime_roots_clean") is True for receipt in receipts)
    if not all((terminal, privacy, mutation, runtime)):
        raise QualificationV2Error("qualification worker integrity is invalid")
    serial_microseconds = serial.get("elapsed_microseconds")
    sharded_microseconds = cell.get("execution_microseconds")
    if type(serial_microseconds) is not int or serial_microseconds <= 0 \
            or type(sharded_microseconds) is not int \
            or sharded_microseconds <= 0:
        raise QualificationV2Error("qualification timing evidence is invalid")
    family = _family(environment, context["consumer"])
    body = {
        "schema_version": 2, "evidence_domain": EVIDENCE_DOMAIN,
        "workload_kind": loom_qualification_workload.WORKLOAD_KIND,
        "consumer": context["consumer"],
        "source_commit": subject["source_commit"],
        "repository_source_tree_sha256": context[
            "repository_source_tree_sha256"],
        "mechanism_manifest_sha256": manifest["manifest_sha256"],
        "boundary_sha256": manifest["boundary_sha256"],
        "workload_policy_sha256": workload["policy_sha256"],
        "workload_source_sha256": workload["workload_source_sha256"],
        "timing_profile_sha256": shadow["timing_profile_sha256"],
        "fixture_sha256": shadow["fixture_sha256"],
        "family": family, "environment": environment,
        "serial": serial, "shadow": shadow, "comparison": comparison,
        "serial_microseconds": serial_microseconds,
        "sharded_microseconds": sharded_microseconds,
        "paired_delta_microseconds": sharded_microseconds - serial_microseconds,
        "test_count": len(observed_tests), "terminal_workers": terminal,
        "privacy_clean": privacy, "mutation_clean": mutation,
        "runtime_roots_clean": runtime,
    }
    return {**body, "observation_sha256": _digest(OBSERVATION_DOMAIN, body)}


def verify_observation(value, *, manifest, workload):
    if not isinstance(value, dict) or set(value) != OBSERVATION_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("evidence_domain") != EVIDENCE_DOMAIN:
        raise QualificationV2Error("qualification observation fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "observation_sha256"}
    if HEX64.fullmatch(str(value.get("observation_sha256", ""))) is None \
            or value["observation_sha256"] != _digest(
                OBSERVATION_DOMAIN, body):
        raise QualificationV2Error("qualification observation digest is invalid")
    environment = value.get("environment")
    if not isinstance(environment, dict):
        raise QualificationV2Error("qualification observation environment is invalid")
    context = {
        "consumer": value["consumer"],
        "qualification_workflow_path": environment.get("workflow_path"),
        "qualification_workflow_digest": environment.get("workflow_digest"),
        "action_manifest_digest": environment.get("action_manifest_digest"),
        "repository_source_tree_sha256": value[
            "repository_source_tree_sha256"],
    }
    expected = compile_observation(
        value["serial"], value["shadow"], value["comparison"],
        manifest=manifest, workload=workload, context=context)
    if expected != value:
        raise QualificationV2Error("qualification observation is inconsistent")
    return value


def load_observation(path, *, manifest, workload):
    return verify_observation(
        _load_json(path, MAX_OBSERVATION_BYTES), manifest=manifest,
        workload=workload)


def _median(values):
    ordered = sorted(values)
    if len(ordered) != 10:
        raise QualificationV2Error("qualification median requires ten observations")
    return (ordered[4] + ordered[5]) // 2


def compile_family(observations, *, manifest, workload):
    manifest = _manifest(manifest)
    workload = _workload(workload)
    if not isinstance(observations, list) or len(observations) != 10:
        raise QualificationV2Error(
            "qualification family requires exactly ten observations")
    observations = [verify_observation(
        value, manifest=manifest, workload=workload) for value in observations]
    identities = [family_identity(value) for value in observations]
    if any(identity != identities[0] for identity in identities[1:]):
        raise QualificationV2Error("qualification family identities differ")
    unique_runs = {
        (row["environment"]["workflow_path"], row["environment"]["run_id"],
         row["environment"]["run_attempt"]) for row in observations
    }
    if len(unique_runs) != 10 \
            or len({row["observation_sha256"] for row in observations}) != 10 \
            or any(row["mechanism_manifest_sha256"] != manifest[
                "manifest_sha256"] for row in observations) \
            or any(row["workload_policy_sha256"] != workload[
                "policy_sha256"] for row in observations) \
            or len({row["timing_profile_sha256"] for row in observations}) != 1:
        raise QualificationV2Error("qualification family evidence is mixed")
    observations = sorted(
        observations, key=lambda row: row["observation_sha256"])
    serial = sorted(row["serial_microseconds"] for row in observations)
    sharded = sorted(row["sharded_microseconds"] for row in observations)
    deltas = [{
        "observation_sha256": row["observation_sha256"],
        "delta_microseconds": row["paired_delta_microseconds"],
    } for row in observations]
    identity = identities[0]
    body = {
        "schema_version": 2, "evidence_domain": EVIDENCE_DOMAIN,
        **identity,
        "mechanism_manifest_sha256": manifest["manifest_sha256"],
        "boundary_sha256": manifest["boundary_sha256"],
        "workload_policy_sha256": workload["policy_sha256"],
        "workload_source_sha256": workload["workload_source_sha256"],
        "timing_profile_sha256": observations[0]["timing_profile_sha256"],
        "observation_count": 10, "observations": observations,
        "source_commits": sorted({row["source_commit"] for row in observations}),
        "repository_source_tree_sha256s": sorted({
            row["repository_source_tree_sha256"] for row in observations}),
        "serial_microseconds": serial, "sharded_microseconds": sharded,
        "paired_deltas": deltas,
        "serial_observed_median_microseconds": _median(serial),
        "serial_observed_max_microseconds": max(serial),
        "sharded_observed_median_microseconds": _median(sharded),
        "sharded_observed_max_microseconds": max(sharded),
        "all_observations_nonregressing": all(
            row["delta_microseconds"] <= 0 for row in deltas),
    }
    return {**body, "family_sha256": _digest(FAMILY_DOMAIN, body)}


def verify_family(value, *, manifest, workload):
    if not isinstance(value, dict) or set(value) != FAMILY_RECORD_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("evidence_domain") != EVIDENCE_DOMAIN:
        raise QualificationV2Error("qualification family fields are invalid")
    body = {key: item for key, item in value.items() if key != "family_sha256"}
    if value.get("family_sha256") != _digest(FAMILY_DOMAIN, body):
        raise QualificationV2Error("qualification family digest is invalid")
    expected = compile_family(
        value.get("observations"), manifest=manifest, workload=workload)
    if expected != value:
        raise QualificationV2Error("qualification family is inconsistent")
    return value


def compile_fault_receipt(platform, results, *, manifest, workload):
    manifest = _manifest(manifest)
    workload = _workload(workload)
    if platform not in {"linux", "macos", "windows"} \
            or not isinstance(results, dict) \
            or set(results) != set(FAULT_CODES) \
            or any(value is not True for value in results.values()):
        raise QualificationV2Error("qualification fault evidence is incomplete")
    body = {
        "schema_version": 2, "evidence_domain": EVIDENCE_DOMAIN,
        "platform": platform,
        "mechanism_manifest_sha256": manifest["manifest_sha256"],
        "boundary_sha256": manifest["boundary_sha256"],
        "workload_policy_sha256": workload["policy_sha256"],
        "workload_source_sha256": workload["workload_source_sha256"],
        "faults": [{"code": code, "passed": True} for code in FAULT_CODES],
    }
    return {**body, "fault_receipt_sha256": _digest(FAULT_DOMAIN, body)}


def verify_fault_receipt(value, *, manifest, workload):
    if not isinstance(value, dict) or set(value) != FAULT_FIELDS:
        raise QualificationV2Error("qualification fault receipt fields are invalid")
    results = {
        row.get("code"): row.get("passed")
        for row in value.get("faults", []) if isinstance(row, dict)
    }
    expected = compile_fault_receipt(
        value.get("platform"), results, manifest=manifest, workload=workload)
    if expected != value:
        raise QualificationV2Error("qualification fault receipt is invalid")
    return value


def _authority_semantics(policy):
    try:
        policy = loom_suite_plan.validate_authority_policy(policy)
    except loom_suite_plan.SuitePlanError as exc:
        raise QualificationV2Error("release authority policy is invalid") from exc
    body = {
        key: value for key, value in policy.items()
        if key not in {"authority_mode", "policy_sha256"}
    }
    return _digest(AUTHORITY_SEMANTICS_DOMAIN, body)


def _topology(families):
    observed = {}
    for family in families:
        identity = family_identity(family)
        key = (identity["consumer"], identity["requested_label"],
               identity["python_minor"])
        if key in observed:
            raise QualificationV2Error("qualification family topology is duplicated")
        observed[key] = identity
    expected = {
        (consumer, label, python)
        for consumer, labels in LABELS.items()
        for label in labels for python in PYTHON_MINORS
    }
    if set(observed) != expected:
        raise QualificationV2Error("qualification family topology is incomplete")
    return observed


def compile_mechanism(families, fault_receipts, *, policy, manifest, workload):
    manifest = _manifest(manifest)
    workload = _workload(workload)
    if not isinstance(families, list) or not isinstance(fault_receipts, list):
        raise QualificationV2Error("mechanism qualification inputs are invalid")
    families = [verify_family(
        value, manifest=manifest, workload=workload) for value in families]
    _topology(families)
    if len(families) != 30 \
            or len({row["family_id"] for row in families}) != 30:
        raise QualificationV2Error("mechanism qualification families are invalid")
    fault_receipts = [verify_fault_receipt(
        value, manifest=manifest, workload=workload)
        for value in fault_receipts]
    if {row["platform"] for row in fault_receipts} != {
            "linux", "macos", "windows"} or len(fault_receipts) != 3:
        raise QualificationV2Error("mechanism fault coverage is incomplete")
    families = sorted(families, key=lambda row: row["family_id"])
    fault_receipts = sorted(
        fault_receipts, key=lambda row: row["platform"])
    all_nonregressing = all(
        row["all_observations_nonregressing"]
        and row["sharded_observed_median_microseconds"] <=
        row["serial_observed_median_microseconds"]
        and row["sharded_observed_max_microseconds"] <=
        row["serial_observed_max_microseconds"] for row in families)
    if not all_nonregressing:
        raise QualificationV2Error("mechanism qualification performance regressed")
    body = {
        "schema_version": 2, "status": "qualified",
        "evidence_domain": EVIDENCE_DOMAIN,
        "required_observations": workload["required_observations"],
        "mechanism_manifest_sha256": manifest["manifest_sha256"],
        "boundary_sha256": manifest["boundary_sha256"],
        "workload_policy_sha256": workload["policy_sha256"],
        "workload_source_sha256": workload["workload_source_sha256"],
        "timing_profile_sha256": families[0]["timing_profile_sha256"],
        "authority_semantics_sha256": _authority_semantics(policy),
        "families": families, "family_count": len(families),
        "fault_receipts": fault_receipts,
        "all_families_nonregressing": all_nonregressing,
    }
    return {**body, "qualification_sha256": _digest(MECHANISM_DOMAIN, body)}


def verify_mechanism(value, *, policy, manifest, workload, current_families):
    if not isinstance(value, dict) or set(value) != MECHANISM_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("status") != "qualified" \
            or value.get("evidence_domain") != EVIDENCE_DOMAIN:
        raise QualificationV2Error("mechanism qualification fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "qualification_sha256"}
    if value.get("qualification_sha256") != _digest(MECHANISM_DOMAIN, body):
        raise QualificationV2Error("mechanism qualification digest is invalid")
    expected = compile_mechanism(
        value.get("families"), value.get("fault_receipts"), policy=policy,
        manifest=manifest, workload=workload)
    if expected != value:
        raise QualificationV2Error("mechanism qualification is inconsistent")
    if not isinstance(current_families, list):
        raise QualificationV2Error("current qualification families are invalid")
    current = sorted(
        (family_identity(row) for row in current_families),
        key=lambda row: row["family_id"])
    recorded = sorted(
        (family_identity(row) for row in value["families"]),
        key=lambda row: row["family_id"])
    if current != recorded:
        raise QualificationV2Error("qualified runner family set is stale")
    return value


def load_mechanism(path, *, policy, manifest, workload, current_families):
    return verify_mechanism(
        _load_json(path, MAX_MECHANISM_BYTES), policy=policy,
        manifest=manifest, workload=workload,
        current_families=current_families)


def _repository_inputs(root):
    root = Path(root).resolve()
    boundary = loom_qualification_manifest.validate_boundary(_load_json(
        root / "contracts" / "release-qualification-boundary-v2.json",
        loom_qualification_manifest.MAX_BOUNDARY_BYTES))
    manifest = loom_qualification_manifest.verify(
        root, boundary, _load_json(
            root / "contracts" / "release-qualification-manifest-v2.json",
            loom_qualification_manifest.MAX_MANIFEST_BYTES))
    workload = loom_qualification_workload.load_policy(root)
    return root, manifest, workload


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify separated release-mechanism qualification evidence.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    observation_parser = subparsers.add_parser("verify-observation")
    observation_parser.add_argument("--root", required=True)
    observation_parser.add_argument("--observation", required=True)
    mechanism_parser = subparsers.add_parser("verify-mechanism")
    mechanism_parser.add_argument("--root", required=True)
    mechanism_parser.add_argument("--qualification", required=True)
    mechanism_parser.add_argument("--current-families", required=True)
    mechanism_parser.add_argument("--policy", required=True)
    args = parser.parse_args(argv)
    try:
        root, manifest, workload = _repository_inputs(args.root)
        if args.command == "verify-observation":
            value = load_observation(
                args.observation, manifest=manifest, workload=workload)
            result = {
                "status": "verified",
                "observation_sha256": value["observation_sha256"],
            }
        else:
            policy = loom_suite_plan.load_authority_policy(args.policy)
            current_families = _load_json(
                args.current_families, MAX_OBSERVATION_BYTES)
            value = load_mechanism(
                args.qualification, policy=policy, manifest=manifest,
                workload=workload, current_families=current_families)
            result = {
                "status": "verified",
                "qualification_sha256": value["qualification_sha256"],
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except (QualificationV2Error, loom_qualification_manifest.ManifestError,
            loom_qualification_workload.WorkloadError,
            loom_suite_plan.SuitePlanError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)},
                         sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
