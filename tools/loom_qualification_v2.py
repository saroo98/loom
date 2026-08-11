#!/usr/bin/env python3
"""Compile and verify separated repeated-mechanism qualification evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import re

import loom_qualification_manifest
import loom_qualification_workload
import loom_exact_cut_receipt
import loom_suite_certificate_core
import loom_suite_plan
import loom_suite_worker
import loom_subject_identity


class QualificationV2Error(RuntimeError):
    pass


EVIDENCE_DOMAIN = "mechanism-qualification-v2"
OBSERVATION_DOMAIN = b"loom.release-qualification-observation.v2\0"
FAMILY_DOMAIN = b"loom.release-qualification-family.v2\0"
FAULT_DOMAIN = b"loom.release-qualification-fault.v2\0"
MECHANISM_DOMAIN = b"loom.release-mechanism-qualification.v2\0"
CANDIDATE_DOMAIN = b"loom.release-candidate-admission.v2\0"
EQUIVALENCE_DOMAIN = b"loom.release-candidate-equivalence.v2\0"
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
NATIVE_PLATFORMS = (
    "linux-arm64", "linux-x64", "macos-arm64", "macos-x64",
    "windows-arm64", "windows-x64",
)
NATIVE_RECEIPT_FIELDS = {
    "schema_version", "platform", "source_commit", "binary_sha256",
    "rebuild_sha256", "source_sha256", "cargo_lock_sha256", "sbom_sha256",
    "provenance_sha256", "environment_sha256", "workflow_digest",
    "action_manifest_digest", "receipt_sha256",
}
NATIVE_EVIDENCE_FIELDS = {"receipt", "environment", "provenance"}
NATIVE_PROVENANCE_FIELDS = {
    "schema_version", "repository", "commit", "platform",
    "binary_sha256", "source_sha256", "cargo_lock_sha256",
    "independent_build", "builder",
}
NATIVE_LABELS = {
    "linux-arm64": ("ubuntu-24.04-arm", "linux", "arm64"),
    "linux-x64": ("ubuntu-24.04", "linux", "x64"),
    "macos-arm64": ("macos-15", "macos", "arm64"),
    "macos-x64": ("macos-15-intel", "macos", "x64"),
    "windows-arm64": ("windows-11-arm", "windows", "arm64"),
    "windows-x64": ("windows-2025", "windows", "x64"),
}
CANDIDATE_BUNDLE_FIELDS = {
    "schema_version", "consumer", "exact_cut_receipts",
    "matrix_certificate", "clean_room",
}
CLEAN_ROOM_BUNDLE_FIELDS = {"receipt", "suite"}
CLEAN_ROOM_RECEIPT_FIELDS = {
    "schema_version", "evidence_class", "status", "subject_sha256",
    "returncode", "stdout_sha256", "stderr_sha256", "disposable_home",
    "maintainer_state_loaded", "network_isolation_proven", "rust_toolchain",
    "operation_receipt_sha256", "containment_provider", "verification_mode",
    "suite_certificate_sha256", "suite_evidence_sha256", "limitations",
    "receipt_sha256",
}
CANDIDATE_FIELDS = {
    "schema_version", "status", "evidence_domain", "authority_mode",
    "authority_policy_sha256", "mechanism_manifest_sha256",
    "boundary_sha256", "mechanism_qualification_sha256", "source_commit",
    "repository_source_tree_sha256", "public_root_sha256",
    "public_manifest_sha256", "public_file_count", "test_inventory_sha256",
    "test_count", "cell_count", "harness_sha256", "candidate_policy_sha256",
    "candidate_timing_profile_sha256", "quality", "compatibility",
    "matrix_certificates", "cell_comparisons", "clean_room_receipt_sha256",
    "native_evidence", "native_subjects", "candidate_admission_sha256",
}
EQUIVALENCE_CONTEXT_FIELDS = {
    "repository", "workflow_path", "workflow_digest",
    "action_manifest_digest", "event_name", "run_id", "run_attempt",
}
EQUIVALENCE_FIELDS = {
    "schema_version", "status", "evidence_domain", "repository",
    "reviewed_commit", "merge_commit", "merge_base",
    "reviewed_git_tree_oid", "merge_git_tree_oid", "reviewed_tree_sha256",
    "merge_tree_sha256", "canonical_source_tree_sha256",
    "source_entry_count", "source_modes_sha256",
    "generated_evidence_sha256", "public_root_sha256",
    "public_manifest_sha256", "public_file_count",
    "candidate_admission_sha256", "test_inventory_sha256", "test_count",
    "harness_sha256", "candidate_policy_sha256",
    "candidate_timing_profile_sha256", "native_source_sha256",
    "cargo_lock_sha256", "context", "equivalence_sha256",
}
GENERATED_EQUIVALENCE_PATHS = (
    "docs/capabilities.json", "docs/generated-evidence.json",
)
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024
MAX_MECHANISM_BYTES = 95_000_000
MAX_CANDIDATE_BYTES = 64 * 1024 * 1024
MAX_EQUIVALENCE_BYTES = 4 * 1024 * 1024


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


def _candidate_environment(environment):
    if not isinstance(environment, dict):
        raise QualificationV2Error("candidate environment is invalid")
    projection = {
        key: environment.get(key) for key in loom_suite_plan.ENVIRONMENT_FIELDS
    }
    try:
        projection = loom_suite_plan._environment(projection)
    except loom_suite_plan.SuitePlanError as exc:
        raise QualificationV2Error("candidate environment is invalid") from exc
    if environment.get("evidence_class") != "ci-reproduced" \
            or environment.get("environment_sha256") != loom_suite_plan.digest({
                key: item for key, item in environment.items()
                if key != "environment_sha256"}) \
            or environment.get("event_name") not in {
                "pull_request", "push", "workflow_dispatch"}:
        raise QualificationV2Error("candidate environment is untrusted")
    return projection


def _clean_room(value, *, receipt_by_environment, cells, policy):
    if not isinstance(value, dict) or set(value) != CLEAN_ROOM_BUNDLE_FIELDS:
        raise QualificationV2Error("candidate clean-room evidence is invalid")
    receipt = value.get("receipt")
    suite = value.get("suite")
    if not isinstance(receipt, dict) \
            or set(receipt) != CLEAN_ROOM_RECEIPT_FIELDS:
        raise QualificationV2Error("candidate clean-room receipt is invalid")
    body = {key: item for key, item in receipt.items()
            if key != "receipt_sha256"}
    home = receipt.get("disposable_home")
    rust = receipt.get("rust_toolchain")
    if receipt.get("schema_version") != 1 \
            or receipt.get("evidence_class") != "mechanical-local" \
            or receipt.get("status") != "passed" \
            or receipt.get("returncode") != 0 \
            or receipt.get("maintainer_state_loaded") is not False \
            or type(receipt.get("network_isolation_proven")) is not bool \
            or any(HEX64.fullmatch(str(receipt.get(field, ""))) is None
                   for field in ("subject_sha256", "stdout_sha256",
                                 "stderr_sha256",
                                 "operation_receipt_sha256",
                                 "receipt_sha256")) \
            or receipt["receipt_sha256"] != loom_suite_plan.digest(body) \
            or not isinstance(receipt.get("containment_provider"), str) \
            or not receipt["containment_provider"] \
            or not isinstance(receipt.get("limitations"), list) \
            or not receipt["limitations"] \
            or any(not isinstance(item, str) or not item
                   for item in receipt["limitations"]) \
            or not isinstance(home, dict) or set(home) != {
                "file_count", "bytes", "tree_sha256", "path_sample"} \
            or type(home.get("file_count")) is not int \
            or home["file_count"] < 0 \
            or type(home.get("bytes")) is not int or home["bytes"] < 0 \
            or HEX64.fullmatch(str(home.get("tree_sha256", ""))) is None \
            or not isinstance(home.get("path_sample"), list) \
            or len(home["path_sample"]) > 32 \
            or any(not isinstance(item, str) or not item or ".." in item
                   or item.startswith(("/", "\\")) or ":" in item
                   for item in home["path_sample"]) \
            or not isinstance(rust, dict) or set(rust) != {
                "rustc_sha256", "cargo_sha256", "rustc_version_sha256",
                "cargo_version_sha256", "locked_dependencies_vendored",
                "dependency_provisioning_network_blocked"} \
            or any(HEX64.fullmatch(str(rust.get(field, ""))) is None
                   for field in ("rustc_sha256", "cargo_sha256",
                                 "rustc_version_sha256",
                                 "cargo_version_sha256")) \
            or rust.get("locked_dependencies_vendored") is not True \
            or type(rust.get(
                "dependency_provisioning_network_blocked")) is not bool:
        raise QualificationV2Error("candidate clean-room receipt is invalid")
    matching = [
        cell for cell in cells
        if cell["environment"]["requested_label"] == "ubuntu-24.04"
        and cell["environment"]["python_version"].startswith("3.11.")
    ]
    if len(matching) != 1:
        raise QualificationV2Error("candidate clean-room cell is ambiguous")
    cell = matching[0]
    exact_receipt = receipt_by_environment.get(cell["environment_sha256"])
    if exact_receipt is None or suite != exact_receipt["suite"]:
        raise QualificationV2Error("candidate clean-room suite is stale")
    mode = receipt.get("verification_mode")
    if mode == "serial-evidence":
        if receipt.get("suite_certificate_sha256") is not None \
                or receipt.get("suite_evidence_sha256") != \
                loom_suite_plan.digest(suite):
            raise QualificationV2Error(
                "candidate clean-room serial binding is invalid")
    elif mode == "certificate":
        if policy["authority_mode"] != "certificate" \
                or receipt.get("suite_evidence_sha256") is not None \
                or receipt.get("suite_certificate_sha256") != cell[
                    "cell_certificate_sha256"]:
            raise QualificationV2Error(
                "candidate clean-room certificate binding is invalid")
    else:
        raise QualificationV2Error("candidate clean-room mode is invalid")
    return {"receipt": receipt, "suite": suite}


def _candidate_matrix(value, *, consumer, policy):
    if not isinstance(value, dict) or set(value) != CANDIDATE_BUNDLE_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("consumer") != consumer:
        raise QualificationV2Error(f"{consumer} candidate bundle is invalid")
    try:
        matrix = loom_suite_certificate_core.verify_matrix(
            value.get("matrix_certificate"))
    except loom_suite_certificate_core.CertificateError as exc:
        raise QualificationV2Error(
            f"{consumer} candidate matrix is invalid") from exc
    if matrix.get("consumer") != consumer or matrix.get("cell_count") != 15:
        raise QualificationV2Error(
            f"{consumer} candidate matrix coverage is incomplete")
    try:
        loom_suite_certificate_core._require_release_topology(
            matrix["cells"], consumer)
    except loom_suite_certificate_core.CertificateError as exc:
        raise QualificationV2Error(
            f"{consumer} candidate topology is invalid") from exc
    receipts = value.get("exact_cut_receipts")
    if not isinstance(receipts, list) or len(receipts) != 15:
        raise QualificationV2Error(
            f"{consumer} exact-cut coverage is incomplete")
    cells = {row["environment_sha256"]: row for row in matrix["cells"]}
    receipt_by_environment = {}
    comparisons = []
    for receipt in receipts:
        try:
            receipt = loom_exact_cut_receipt.verify_receipt(
                receipt, require_static=False)
        except ValueError as exc:
            raise QualificationV2Error(
                f"{consumer} exact-cut receipt is invalid") from exc
        environment = _candidate_environment(receipt["environment"])
        environment_sha256 = loom_suite_plan.digest(environment)
        cell = cells.get(environment_sha256)
        if cell is None or environment_sha256 in receipt_by_environment \
                or not isinstance(receipt.get("operation_id"), str) \
                or not receipt["operation_id"] \
                or str(receipt.get("platform", "")).casefold() != str(
                    environment["os"]).casefold() \
                or str(receipt.get("architecture", "")).casefold().replace(
                    "_", "") != str(environment["architecture"]).casefold(
                    ).replace("_", "") \
                or receipt.get("python") != environment["python_version"] \
                or environment["workflow_path"] != \
                f".github/workflows/{consumer}.yml" \
                or receipt["source_commit"] != matrix["subject"][
                    "source_commit"] \
                or receipt["verified_root_sha256"] != matrix["subject"][
                    "public_root_sha256"] \
                or receipt["public_manifest_sha256"] != matrix["subject"][
                    "public_manifest_sha256"] \
                or receipt["public_file_count"] != matrix["subject"][
                    "public_file_count"]:
            raise QualificationV2Error(
                f"{consumer} exact-cut subject is invalid")
        try:
            comparison = loom_suite_certificate_core.compare_shadow(
                receipt["suite"], cell)
        except loom_suite_certificate_core.CertificateError as exc:
            raise QualificationV2Error(
                f"{consumer} serial-shadow parity is invalid") from exc
        if comparison.get("status") != "matched":
            raise QualificationV2Error(
                f"{consumer} serial-shadow parity did not match")
        receipt_by_environment[environment_sha256] = receipt
        comparisons.append({
            "environment_sha256": environment_sha256,
            "comparison_sha256": comparison["comparison_sha256"],
        })
    if set(receipt_by_environment) != set(cells):
        raise QualificationV2Error(
            f"{consumer} exact-cut coverage is incomplete")
    if consumer == "quality":
        if value.get("clean_room") is not None:
            raise QualificationV2Error(
                "quality candidate bundle contains clean-room evidence")
        clean_room = None
    else:
        clean_room = _clean_room(
            value.get("clean_room"),
            receipt_by_environment=receipt_by_environment,
            cells=matrix["cells"], policy=policy)
    normalized = {
        "schema_version": 2, "consumer": consumer,
        "exact_cut_receipts": sorted(
            receipt_by_environment.values(), key=lambda row:
            loom_suite_plan.digest(_candidate_environment(row["environment"]))),
        "matrix_certificate": matrix, "clean_room": clean_room,
    }
    return normalized, sorted(
        comparisons, key=lambda row: row["environment_sha256"])


def _native_evidence(values, source_commit):
    if not isinstance(values, list) or len(values) != len(NATIVE_PLATFORMS):
        raise QualificationV2Error("candidate native evidence is incomplete")
    normalized = []
    for value in values:
        if not isinstance(value, dict) or set(value) != NATIVE_EVIDENCE_FIELDS:
            raise QualificationV2Error("candidate native receipt is invalid")
        receipt = value.get("receipt")
        environment = value.get("environment")
        provenance = value.get("provenance")
        if not isinstance(receipt, dict) \
                or set(receipt) != NATIVE_RECEIPT_FIELDS \
                or not isinstance(environment, dict) \
                or set(environment) != loom_exact_cut_receipt.ENVIRONMENT_FIELDS \
                or not isinstance(provenance, dict) \
                or set(provenance) != NATIVE_PROVENANCE_FIELDS:
            raise QualificationV2Error("candidate native receipt is invalid")
        body = {key: item for key, item in receipt.items()
                if key != "receipt_sha256"}
        platform = receipt.get("platform")
        expected = NATIVE_LABELS.get(platform)
        architecture = str(environment.get("architecture", "")).casefold() \
            .replace("_", "").replace("-", "")
        architecture = (
            "x64" if architecture in {"amd64", "x64", "x8664"}
            else "arm64" if architecture in {"arm64", "aarch64"}
            else architecture)
        environment_body = {
            key: item for key, item in environment.items()
            if key != "environment_sha256"
        }
        builder = provenance.get("builder")
        provenance_bytes = _canonical(provenance) + b"\n"
        if receipt.get("schema_version") != 2 \
                or platform not in NATIVE_PLATFORMS \
                or receipt.get("source_commit") != source_commit \
                or receipt.get("binary_sha256") != receipt.get(
                    "rebuild_sha256") \
                or any(HEX64.fullmatch(str(receipt.get(field, ""))) is None
                       for field in NATIVE_RECEIPT_FIELDS - {
                           "schema_version", "platform", "source_commit"}) \
                or receipt.get("receipt_sha256") != \
                loom_suite_plan.digest(body) \
                or expected is None \
                or environment.get("evidence_class") != "ci-reproduced" \
                or environment.get("requested_label") != expected[0] \
                or str(environment.get("os", "")).casefold() != expected[1] \
                or architecture != expected[2] \
                or environment.get("workflow_path") != \
                ".github/workflows/build-helper.yml" \
                or environment.get("event_name") not in {
                    "pull_request", "push", "workflow_dispatch"} \
                or environment.get("environment_sha256") != \
                loom_suite_plan.digest(environment_body) \
                or receipt.get("environment_sha256") != environment.get(
                    "environment_sha256") \
                or receipt.get("workflow_digest") != environment.get(
                    "workflow_digest") \
                or receipt.get("action_manifest_digest") != environment.get(
                    "action_manifest_digest") \
                or provenance.get("schema_version") != 1 \
                or provenance.get("repository") != \
                "https://github.com/saroo98/loom" \
                or provenance.get("commit") != source_commit \
                or provenance.get("platform") != platform \
                or provenance.get("binary_sha256") != receipt.get(
                    "binary_sha256") \
                or provenance.get("source_sha256") != receipt.get(
                    "source_sha256") \
                or provenance.get("cargo_lock_sha256") != receipt.get(
                    "cargo_lock_sha256") \
                or provenance.get("independent_build") is not True \
                or not isinstance(builder, dict) or set(builder) != {
                    "id", "run_id"} \
                or builder.get("id") != "github-actions-native-helper" \
                or builder.get("run_id") != environment.get("run_id") \
                or receipt.get("provenance_sha256") != hashlib.sha256(
                    provenance_bytes).hexdigest():
            raise QualificationV2Error("candidate native receipt is invalid")
        normalized.append({
            "receipt": dict(receipt), "environment": dict(environment),
            "provenance": dict(provenance),
        })
    normalized.sort(key=lambda row: row["receipt"]["platform"])
    receipts = [row["receipt"] for row in normalized]
    if [row["platform"] for row in receipts] != list(NATIVE_PLATFORMS) \
            or any(len({row[field] for row in receipts}) != 1
                   for field in ("source_sha256", "cargo_lock_sha256",
                                 "workflow_digest",
                                 "action_manifest_digest")):
        raise QualificationV2Error("candidate native subjects are inconsistent")
    subjects = [{
        "platform": row["platform"],
        "binary_sha256": row["binary_sha256"],
        "sbom_sha256": row["sbom_sha256"],
        "provenance_sha256": row["provenance_sha256"],
        "receipt_sha256": row["receipt_sha256"],
    } for row in receipts]
    return normalized, subjects


def compile_candidate(quality, compatibility, native, *, mechanism, policy,
                      manifest, workload=None):
    manifest = _manifest(manifest)
    try:
        policy = loom_suite_plan.validate_authority_policy(policy)
    except loom_suite_plan.SuitePlanError as exc:
        raise QualificationV2Error("candidate authority policy is invalid") from exc
    quality, quality_comparisons = _candidate_matrix(
        quality, consumer="quality", policy=policy)
    compatibility, compatibility_comparisons = _candidate_matrix(
        compatibility, consumer="compatibility", policy=policy)
    matrices = [quality["matrix_certificate"],
                compatibility["matrix_certificate"]]
    subjects = [row["subject"] for row in matrices]
    if subjects[0] != subjects[1] \
            or subjects[0].get("repository") != \
            "https://github.com/saroo98/loom":
        raise QualificationV2Error("candidate matrix subjects differ")
    subject = subjects[0]
    inventories = [
        [outcome["test"] for outcome in matrix["cells"][0]["outcomes"]]
        for matrix in matrices
    ]
    if inventories[0] != inventories[1] or not inventories[0]:
        raise QualificationV2Error("candidate test inventories differ")
    cells = [cell for matrix in matrices for cell in matrix["cells"]]
    if len({cell["harness_sha256"] for cell in cells}) != 1 \
            or len({cell["policy_sha256"] for cell in cells}) != 1 \
            or len({cell["timing_profile_sha256"] for cell in cells}) != 1:
        raise QualificationV2Error("candidate suite inputs differ")
    native, native_subjects = _native_evidence(
        native, subject["source_commit"])
    current_families = [
        _family(cell["environment"], matrix["consumer"])
        for matrix in matrices for cell in matrix["cells"]
    ]
    if policy["authority_mode"] == "serial":
        if mechanism is not None:
            raise QualificationV2Error(
                "serial candidate must not claim certificate qualification")
        qualification_sha256 = None
    else:
        if workload is None:
            raise QualificationV2Error(
                "certificate candidate lacks qualification workload")
        mechanism = verify_mechanism(
            mechanism, policy=policy, manifest=manifest,
            workload=workload, current_families=current_families)
        qualification_sha256 = mechanism["qualification_sha256"]
    comparisons = sorted(
        quality_comparisons + compatibility_comparisons,
        key=lambda row: row["environment_sha256"])
    body = {
        "schema_version": 2, "status": "admitted",
        "evidence_domain": "candidate-admission-v2",
        "authority_mode": policy["authority_mode"],
        "authority_policy_sha256": policy["policy_sha256"],
        "mechanism_manifest_sha256": manifest["manifest_sha256"],
        "boundary_sha256": manifest["boundary_sha256"],
        "mechanism_qualification_sha256": qualification_sha256,
        "source_commit": subject["source_commit"],
        "repository_source_tree_sha256": subject["source_tree_sha256"],
        "public_root_sha256": subject["public_root_sha256"],
        "public_manifest_sha256": subject["public_manifest_sha256"],
        "public_file_count": subject["public_file_count"],
        "test_inventory_sha256": loom_suite_plan.digest(inventories[0]),
        "test_count": len(inventories[0]), "cell_count": len(cells),
        "harness_sha256": cells[0]["harness_sha256"],
        "candidate_policy_sha256": cells[0]["policy_sha256"],
        "candidate_timing_profile_sha256": cells[0][
            "timing_profile_sha256"],
        "quality": quality, "compatibility": compatibility,
        "matrix_certificates": [{
            "consumer": matrix["consumer"],
            "matrix_certificate_sha256": matrix[
                "matrix_certificate_sha256"],
        } for matrix in matrices],
        "cell_comparisons": comparisons,
        "clean_room_receipt_sha256": compatibility["clean_room"][
            "receipt"]["receipt_sha256"],
        "native_evidence": native, "native_subjects": native_subjects,
    }
    return {**body, "candidate_admission_sha256": _digest(
        CANDIDATE_DOMAIN, body)}


def verify_candidate(value, *, expected_commit, expected_tree,
                     expected_public_root, mechanism, policy, manifest,
                     workload=None):
    if not isinstance(value, dict) or set(value) != CANDIDATE_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("status") != "admitted" \
            or value.get("evidence_domain") != "candidate-admission-v2":
        raise QualificationV2Error("candidate admission fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "candidate_admission_sha256"}
    if value.get("candidate_admission_sha256") != _digest(
            CANDIDATE_DOMAIN, body) \
            or value.get("source_commit") != expected_commit \
            or value.get("repository_source_tree_sha256") != expected_tree \
            or value.get("public_root_sha256") != expected_public_root:
        raise QualificationV2Error("candidate admission identity is invalid")
    expected = compile_candidate(
        value.get("quality"), value.get("compatibility"),
        value.get("native_evidence"), mechanism=mechanism, policy=policy,
        manifest=manifest, workload=workload)
    if expected != value:
        raise QualificationV2Error("candidate admission is inconsistent")
    return value


def load_candidate(path, *, expected_commit, expected_tree,
                   expected_public_root, mechanism, policy, manifest,
                   workload=None):
    return verify_candidate(
        _load_json(path, MAX_CANDIDATE_BYTES),
        expected_commit=expected_commit, expected_tree=expected_tree,
        expected_public_root=expected_public_root, mechanism=mechanism,
        policy=policy, manifest=manifest, workload=workload)


def _candidate_seal(value):
    if not isinstance(value, dict) or set(value) != CANDIDATE_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("status") != "admitted" \
            or value.get("evidence_domain") != "candidate-admission-v2":
        raise QualificationV2Error("candidate admission fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "candidate_admission_sha256"}
    if value.get("candidate_admission_sha256") != _digest(
            CANDIDATE_DOMAIN, body):
        raise QualificationV2Error("candidate admission digest is invalid")
    return value


def _equivalence_context(value):
    if not isinstance(value, dict) or set(value) != EQUIVALENCE_CONTEXT_FIELDS \
            or value.get("repository") != \
            "https://github.com/saroo98/loom" \
            or value.get("workflow_path") != \
            ".github/workflows/candidate-equivalence.yml" \
            or value.get("event_name") != "push" \
            or any(HEX64.fullmatch(str(value.get(field, ""))) is None
                   for field in ("workflow_digest",
                                 "action_manifest_digest")) \
            or not isinstance(value.get("run_id"), str) \
            or not value["run_id"] \
            or not isinstance(value.get("run_attempt"), str) \
            or not value["run_attempt"]:
        raise QualificationV2Error(
            "candidate equivalence workflow identity is invalid")
    return dict(value)


def _git_value(repository, *arguments):
    try:
        value = loom_subject_identity._run_git(repository, *arguments).strip()
    except loom_subject_identity.SubjectIdentityError as exc:
        raise QualificationV2Error("candidate equivalence Git identity failed") \
            from exc
    if HEX40.fullmatch(value) is None:
        raise QualificationV2Error("candidate equivalence Git identity is invalid")
    return value


def compile_equivalence(admission, *, reviewed_commit, merge_commit,
                        repository, context):
    admission = _candidate_seal(admission)
    repository = Path(repository).resolve()
    context = _equivalence_context(context)
    if not repository.is_dir() \
            or HEX40.fullmatch(str(reviewed_commit)) is None \
            or HEX40.fullmatch(str(merge_commit)) is None \
            or reviewed_commit == merge_commit \
            or admission.get("source_commit") != reviewed_commit \
            or admission.get("quality", {}).get(
                "matrix_certificate", {}).get("subject", {}).get(
                    "repository") != context["repository"]:
        raise QualificationV2Error("candidate equivalence input is invalid")
    reviewed_tree_oid = _git_value(
        repository, "rev-parse", f"{reviewed_commit}^{{tree}}")
    merge_tree_oid = _git_value(
        repository, "rev-parse", f"{merge_commit}^{{tree}}")
    merge_base = _git_value(
        repository, "merge-base", reviewed_commit, merge_commit)
    try:
        parent_row = loom_subject_identity._run_git(
            repository, "rev-list", "--parents", "-n", "1",
            merge_commit).strip().split()
    except loom_subject_identity.SubjectIdentityError as exc:
        raise QualificationV2Error(
            "candidate equivalence merge parents are unavailable") from exc
    try:
        reviewed_tree = loom_subject_identity.git_tree_inventory(
            repository, reviewed_commit)
        merge_tree = loom_subject_identity.git_tree_inventory(
            repository, merge_commit)
    except loom_subject_identity.SubjectIdentityError as exc:
        raise QualificationV2Error(
            "candidate equivalence tree inventory failed") from exc
    if len(parent_row) != 3 or parent_row[0] != merge_commit \
            or reviewed_commit not in parent_row[1:] \
            or any(HEX40.fullmatch(item) is None for item in parent_row) \
            or merge_base != reviewed_commit \
            or reviewed_tree_oid != merge_tree_oid \
            or reviewed_tree["entries"] != merge_tree["entries"] \
            or reviewed_tree["tree_sha256"] != admission.get(
                "repository_source_tree_sha256"):
        raise QualificationV2Error(
            "candidate commits do not contain identical reviewed bytes")
    entries = reviewed_tree["entries"]
    by_path = {row["path"]: row for row in entries}
    if any(path not in by_path for path in GENERATED_EQUIVALENCE_PATHS):
        raise QualificationV2Error(
            "candidate generated evidence is missing from the committed tree")
    generated = [by_path[path] for path in GENERATED_EQUIVALENCE_PATHS]
    native = admission.get("native_evidence")
    if not isinstance(native, list) or len(native) != len(NATIVE_PLATFORMS):
        raise QualificationV2Error("candidate native evidence is invalid")
    body = {
        "schema_version": 2, "status": "equivalent",
        "evidence_domain": "candidate-equivalence-v2",
        "repository": context["repository"],
        "reviewed_commit": reviewed_commit, "merge_commit": merge_commit,
        "merge_base": merge_base,
        "reviewed_git_tree_oid": reviewed_tree_oid,
        "merge_git_tree_oid": merge_tree_oid,
        "reviewed_tree_sha256": reviewed_tree["tree_sha256"],
        "merge_tree_sha256": merge_tree["tree_sha256"],
        "canonical_source_tree_sha256": loom_subject_identity.digest({
            "schema_version": 1, "entries": entries}),
        "source_entry_count": len(entries),
        "source_modes_sha256": loom_subject_identity.digest([{
            "path": row["path"], "mode": row["mode"]} for row in entries]),
        "generated_evidence_sha256": loom_subject_identity.digest(generated),
        "public_root_sha256": admission["public_root_sha256"],
        "public_manifest_sha256": admission["public_manifest_sha256"],
        "public_file_count": admission["public_file_count"],
        "candidate_admission_sha256": admission[
            "candidate_admission_sha256"],
        "test_inventory_sha256": admission["test_inventory_sha256"],
        "test_count": admission["test_count"],
        "harness_sha256": admission["harness_sha256"],
        "candidate_policy_sha256": admission["candidate_policy_sha256"],
        "candidate_timing_profile_sha256": admission[
            "candidate_timing_profile_sha256"],
        "native_source_sha256": native[0]["receipt"]["source_sha256"],
        "cargo_lock_sha256": native[0]["receipt"]["cargo_lock_sha256"],
        "context": context,
    }
    return {**body, "equivalence_sha256": _digest(
        EQUIVALENCE_DOMAIN, body)}


def verify_equivalence(value, *, admission, expected_commit, repository):
    if not isinstance(value, dict) or set(value) != EQUIVALENCE_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("status") != "equivalent" \
            or value.get("evidence_domain") != "candidate-equivalence-v2" \
            or value.get("merge_commit") != expected_commit:
        raise QualificationV2Error("candidate equivalence fields are invalid")
    body = {key: item for key, item in value.items()
            if key != "equivalence_sha256"}
    if value.get("equivalence_sha256") != _digest(
            EQUIVALENCE_DOMAIN, body):
        raise QualificationV2Error("candidate equivalence digest is invalid")
    expected = compile_equivalence(
        admission, reviewed_commit=value.get("reviewed_commit"),
        merge_commit=expected_commit, repository=repository,
        context=value.get("context"))
    if expected != value:
        raise QualificationV2Error("candidate equivalence is inconsistent")
    return value


def load_equivalence(path, *, admission, expected_commit, repository):
    return verify_equivalence(
        _load_json(path, MAX_EQUIVALENCE_BYTES), admission=admission,
        expected_commit=expected_commit, repository=repository)


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
