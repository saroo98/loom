#!/usr/bin/env python3
"""Reproducible public builder and evidence-gated Loom release certification."""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import loom_privacy
import loom_reliability
import loom_adaptation_eval
import loom_docs
import loom_install
import loom_improvement
import loom_performance


ROOT_FILES = {
    "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE", "PRIVACY.md",
    "README.md", "START-HERE.md", "VERSION",
}
ROOT_DIRECTORIES = {".github", "docs", "loom", "schemas", "skill", "templates", "tools"}
MANIFEST = "BUILD-MANIFEST.json"
LOCAL_CHECKS = (
    "suite", "adaptation", "privacy", "failure_injection",
    "reproducible_build", "installer_cycle", "performance_contracts", "docs",
    "twenty_project_bound",
)
EXTERNAL_CHECKS = (
    "cross-platform-ci", "unfamiliar-user-usability", "independent-hostile-review",
    "production-performance", "production-memory-replay",
)
EXTERNAL_EVIDENCE_FIELDS = {
    "schema_version", "check_id", "status", "evidence_id", "subject",
    "issued_at", "expires_at", "issuer", "payload", "payload_sha256",
    "attestation",
}
SUBJECT_FIELDS = {"repository", "commit_sha", "root_sha256"}
ISSUER_FIELDS = {"id", "kind", "independent"}
ATTESTATION_FIELDS = {"algorithm", "key_id", "signature"}
TRUST_POLICY_FIELDS = {"schema_version", "subject", "issuers"}
TRUSTED_ISSUER_FIELDS = {
    "id", "kind", "key_id", "algorithm", "modulus_hex", "exponent",
    "checks", "independent",
}
LOCAL_EVIDENCE_FIELDS = {
    "schema_version", "status", "verification_id", "subject", "verified_at",
    "expires_at", "local_checks", "evidence", "evidence_sha256",
}
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
PRODUCTION_PERFORMANCE_FIELDS = {
    "provider_attested", "receipt_bundle_sha256", "measurement_bundle_sha256",
    "sample_count", "workload_count", "workloads", "successful_samples",
    "regression_status",
}
PERFORMANCE_WORKLOAD_FIELDS = {
    "id", "tier", "sample_count", "p50_total_tokens", "p95_total_tokens",
    "worst_total_tokens", "token_budget", "p95_wall_ms", "worst_wall_ms",
    "wall_budget_ms",
}
PRODUCTION_REPLAY_FIELDS = {
    "provider_attested", "session_bundle_sha256", "replay_bundle_sha256",
    "production_session_count", "pair_count", "simulation_count", "exact_domain",
    "improvement_reproduced", "regression_guard_passed", "claims",
}
REPLAY_CLAIM_FIELDS = {
    "metric", "domain", "scope", "longitudinal_sample_count", "replay_pair_count",
    "longitudinal_status", "replay_status", "regression_alarm",
}
CROSS_PLATFORM_CI_FIELDS = {
    "run_id", "run_url", "total_jobs", "passed_jobs", "conclusion", "jobs",
}
CI_JOB_FIELDS = {"id", "os", "python", "conclusion", "url"}
REQUIRED_CI_OSES = {"ubuntu-latest", "macos-latest", "windows-latest"}
REQUIRED_CI_PYTHONS = {"3.10", "3.11", "3.12", "3.13"}
USABILITY_FIELDS = {
    "study_id", "study_bundle_sha256", "public_build_sha256",
    "participant_count", "unfamiliar_participant_count",
    "clean_environment_count", "fresh_install_count",
    "real_request_completion_count", "completed_without_maintainer_count",
    "coaching_event_count", "install_receipt_bundle_sha256",
    "request_receipt_bundle_sha256",
}
HOSTILE_REVIEW_FIELDS = {
    "report_sha256", "review_bundle_sha256", "reproduced_build_sha256",
    "critical_findings", "high_findings", "scope_complete",
    "reviewer_independent",
}


class ReleaseError(RuntimeError):
    pass


def _eligible(relative):
    if relative.as_posix() == MANIFEST:
        return False
    if len(relative.parts) == 1:
        return relative.name in ROOT_FILES
    return relative.parts[0] in ROOT_DIRECTORIES \
        and "__pycache__" not in relative.parts \
        and relative.suffix.lower() not in {".pyc", ".pyo"}


def build_public(source, destination, *, forbidden_tokens):
    try:
        source = loom_reliability._absolute(
            source, "release source", must_exist=True)
        destination = loom_reliability._absolute(destination, "release destination")
    except loom_reliability.ReliabilityError as exc:
        raise ReleaseError(str(exc)) from exc
    if not source.is_dir() or destination.exists():
        raise ReleaseError("release source must be a directory and destination must not exist")
    if destination == source or destination.is_relative_to(source) \
            or source.is_relative_to(destination):
        raise ReleaseError("release source and destination must be separate trees")
    if not forbidden_tokens:
        raise ReleaseError("release build requires real private/owner firewall tokens")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".loom-public-", dir=destination.parent))
    try:
        copied = []
        for path in loom_reliability._regular_files(source):
            relative = path.relative_to(source)
            if not _eligible(relative):
                continue
            output = staging / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, output)
            copied.append(relative.as_posix())
        missing = sorted(item for item in ROOT_FILES if item not in copied)
        if missing:
            raise ReleaseError("release source lacks required public roots: " + ", ".join(missing))
        payload_manifest = loom_reliability.deterministic_manifest(staging)
        loom_reliability.atomic_write_json(staging / MANIFEST, payload_manifest)
        firewall = loom_privacy.scan_publication(
            staging, forbidden_tokens=forbidden_tokens, require_owner_tokens=True)
        if not firewall["clean"]:
            raise ReleaseError("release firewall rejected the public build")
        os.replace(staging, destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {"status": "built", "destination": str(destination),
            "root_sha256": payload_manifest["root_sha256"],
            "files": payload_manifest["files"], "firewall": firewall}


def _canonical_hash(value):
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _evidence_time(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _valid_subject(subject):
    return isinstance(subject, dict) and set(subject) == SUBJECT_FIELDS \
        and isinstance(subject.get("repository"), str) \
        and subject["repository"].startswith("https://github.com/") \
        and re.fullmatch(r"[0-9a-f]{40}", str(subject.get("commit_sha", ""))) \
        and re.fullmatch(r"[0-9a-f]{64}", str(subject.get("root_sha256", "")))


def _validated_local_evidence(value, *, now=None):
    if not isinstance(value, dict) or set(value) != LOCAL_EVIDENCE_FIELDS \
            or value.get("schema_version") != 1 or value.get("status") != "passed" \
            or not _valid_subject(value.get("subject")) \
            or not isinstance(value.get("evidence"), dict):
        return None
    try:
        if str(uuid.UUID(value["verification_id"])) != value["verification_id"]:
            return None
    except (ValueError, TypeError, AttributeError):
        return None
    issued = _evidence_time(value.get("verified_at"))
    expires = _evidence_time(value.get("expires_at"))
    instant = now or dt.datetime.now(dt.timezone.utc)
    if issued is None or expires is None or not issued <= instant <= expires:
        return None
    checks = value.get("local_checks")
    if not isinstance(checks, dict) or set(checks) != set(LOCAL_CHECKS) \
            or not all(type(item) is bool for item in checks.values()):
        return None
    body = {key: item for key, item in value.items() if key != "evidence_sha256"}
    if value.get("evidence_sha256") != _canonical_hash(body):
        return None
    return checks, value["subject"]


def seal_local_evidence(*, subject, local_checks, evidence, now=None):
    if not _valid_subject(subject) or not isinstance(local_checks, dict) \
            or set(local_checks) != set(LOCAL_CHECKS) \
            or not all(type(item) is bool for item in local_checks.values()) \
            or not isinstance(evidence, dict):
        raise ReleaseError("local release evidence inputs are invalid")
    instant = now or dt.datetime.now(dt.timezone.utc)
    if instant.tzinfo is None:
        raise ReleaseError("local release evidence time must be timezone-aware")
    instant = instant.astimezone(dt.timezone.utc).replace(microsecond=0)
    expires = instant + dt.timedelta(hours=48)
    value = {
        "schema_version": 1,
        "status": "passed" if all(local_checks.values()) else "failed",
        "verification_id": str(uuid.uuid4()),
        "subject": dict(subject),
        "verified_at": instant.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "local_checks": dict(local_checks),
        "evidence": json.loads(json.dumps(evidence)),
    }
    value["evidence_sha256"] = _canonical_hash(value)
    return value


def _trusted_issuer(check_id, evidence, trust_policy):
    if not isinstance(trust_policy, dict) or set(trust_policy) != TRUST_POLICY_FIELDS \
            or trust_policy.get("schema_version") != 1 \
            or trust_policy.get("subject") != evidence.get("subject") \
            or not isinstance(trust_policy.get("issuers"), list):
        return None
    issuer = evidence["issuer"]
    attestation = evidence["attestation"]
    matches = [item for item in trust_policy["issuers"]
               if isinstance(item, dict)
               and item.get("id") == issuer["id"]
               and item.get("key_id") == attestation["key_id"]]
    if len(matches) != 1:
        return None
    trusted = matches[0]
    if set(trusted) != TRUSTED_ISSUER_FIELDS \
            or trusted.get("kind") != issuer["kind"] \
            or trusted.get("independent") is not True \
            or trusted.get("algorithm") != "rsa-pkcs1v15-sha256" \
            or not isinstance(trusted.get("checks"), list) \
            or check_id not in trusted["checks"] \
            or len(trusted["checks"]) != len(set(trusted["checks"])) \
            or any(item not in EXTERNAL_CHECKS for item in trusted["checks"]):
        return None
    try:
        modulus = int(trusted["modulus_hex"], 16)
        exponent = trusted["exponent"]
    except (TypeError, ValueError):
        return None
    if not isinstance(trusted.get("modulus_hex"), str) \
            or not re.fullmatch(r"[0-9a-f]{512,1024}", trusted["modulus_hex"]) \
            or type(exponent) is not int or exponent < 3 or exponent % 2 == 0 \
            or modulus.bit_length() < 2048:
        return None
    return modulus, exponent


def _signature_valid(evidence, trusted_key):
    modulus, exponent = trusted_key
    try:
        signature = base64.b64decode(
            evidence["attestation"]["signature"], validate=True)
    except (ValueError, TypeError):
        return False
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    body = {key: value for key, value in evidence.items() if key != "attestation"}
    body["attestation"] = {
        "algorithm": evidence["attestation"]["algorithm"],
        "key_id": evidence["attestation"]["key_id"],
    }
    digest_info = SHA256_DIGEST_INFO + hashlib.sha256(_canonical_bytes(body)).digest()
    padding = b"\xff" * (size - len(digest_info) - 3)
    if len(padding) < 8:
        return False
    expected = b"\x00\x01" + padding + b"\x00" + digest_info
    recovered = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        size, "big")
    return hmac.compare_digest(recovered, expected)


def _sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _nonnegative_integer(value):
    return type(value) is int and value >= 0


def _production_performance_passed(payload):
    if set(payload) != PRODUCTION_PERFORMANCE_FIELDS \
            or payload.get("provider_attested") is not True \
            or not _sha256(payload.get("receipt_bundle_sha256")) \
            or not _sha256(payload.get("measurement_bundle_sha256")) \
            or type(payload.get("sample_count")) is not int \
            or payload["sample_count"] < 20 \
            or payload.get("successful_samples") != payload["sample_count"] \
            or type(payload.get("workload_count")) is not int \
            or payload["workload_count"] < 4 \
            or payload.get("regression_status") != "passed" \
            or not isinstance(payload.get("workloads"), list) \
            or len(payload["workloads"]) != payload["workload_count"]:
        return False
    identifiers = set()
    tiers = set()
    measured_samples = 0
    for workload in payload["workloads"]:
        if not isinstance(workload, dict) or set(workload) != PERFORMANCE_WORKLOAD_FIELDS:
            return False
        identifier = workload.get("id")
        tier = workload.get("tier")
        if not isinstance(identifier, str) \
                or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", identifier) is None \
                or identifier in identifiers or tier not in {"S", "M", "L", "XL"} \
                or tier in tiers or type(workload.get("sample_count")) is not int \
                or workload["sample_count"] < 5:
            return False
        token_values = [workload.get(field) for field in (
            "p50_total_tokens", "p95_total_tokens", "worst_total_tokens",
            "token_budget")]
        wall_values = [workload.get(field) for field in (
            "p95_wall_ms", "worst_wall_ms", "wall_budget_ms")]
        if not all(_nonnegative_integer(value) for value in token_values + wall_values) \
                or token_values[3] == 0 or wall_values[2] == 0 \
                or not token_values[0] <= token_values[1] <= token_values[2] \
                <= token_values[3] \
                or not wall_values[0] <= wall_values[1] <= wall_values[2]:
            return False
        identifiers.add(identifier)
        tiers.add(tier)
        measured_samples += workload["sample_count"]
    return tiers == {"S", "M", "L", "XL"} \
        and measured_samples == payload["sample_count"]


def _production_replay_passed(payload):
    if set(payload) != PRODUCTION_REPLAY_FIELDS \
            or payload.get("provider_attested") is not True \
            or not _sha256(payload.get("session_bundle_sha256")) \
            or not _sha256(payload.get("replay_bundle_sha256")) \
            or type(payload.get("production_session_count")) is not int \
            or type(payload.get("pair_count")) is not int \
            or payload["pair_count"] < 16 \
            or payload["production_session_count"] < payload["pair_count"] * 2 \
            or payload.get("simulation_count") != 0 \
            or payload.get("exact_domain") is not True \
            or payload.get("improvement_reproduced") is not True \
            or payload.get("regression_guard_passed") is not True \
            or not isinstance(payload.get("claims"), list) \
            or not 2 <= len(payload["claims"]) <= 32:
        return False
    scopes = set()
    pair_total = 0
    claim_keys = set()
    for claim in payload["claims"]:
        if not isinstance(claim, dict) or set(claim) != REPLAY_CLAIM_FIELDS \
                or claim.get("metric") not in loom_improvement.METRICS \
                or not isinstance(claim.get("domain"), str) \
                or loom_improvement.ID_RE.fullmatch(claim["domain"]) is None \
                or claim.get("scope") not in {"general-calibration", "exact-domain"} \
                or (claim["scope"] == "general-calibration") != \
                (claim["domain"] == "general") \
                or type(claim.get("longitudinal_sample_count")) is not int \
                or claim["longitudinal_sample_count"] < \
                loom_improvement.MIN_LONGITUDINAL_SAMPLES \
                or type(claim.get("replay_pair_count")) is not int \
                or claim["replay_pair_count"] < loom_improvement.MIN_REPLAY_PAIRS \
                or claim.get("longitudinal_status") != "improved" \
                or claim.get("replay_status") != "improved" \
                or claim.get("regression_alarm") is not False:
            return False
        key = (claim["metric"], claim["domain"])
        if key in claim_keys:
            return False
        claim_keys.add(key)
        scopes.add(claim["scope"])
        pair_total += claim["replay_pair_count"]
    return scopes == {"general-calibration", "exact-domain"} \
        and pair_total == payload["pair_count"]


def _cross_platform_ci_passed(payload, subject):
    if set(payload) != CROSS_PLATFORM_CI_FIELDS \
            or type(payload.get("run_id")) is not int or payload["run_id"] <= 0 \
            or payload.get("total_jobs") != 12 \
            or payload.get("passed_jobs") != 12 \
            or payload.get("conclusion") != "success" \
            or not isinstance(payload.get("jobs"), list) \
            or len(payload["jobs"]) != 12:
        return False
    run_url = f"{subject['repository']}/actions/runs/{payload['run_id']}"
    if payload.get("run_url") != run_url:
        return False
    combinations = set()
    identifiers = set()
    urls = set()
    for job in payload["jobs"]:
        if not isinstance(job, dict) or set(job) != CI_JOB_FIELDS \
                or type(job.get("id")) is not int or job["id"] <= 0 \
                or job.get("os") not in REQUIRED_CI_OSES \
                or job.get("python") not in REQUIRED_CI_PYTHONS \
                or job.get("conclusion") != "success" \
                or job.get("url") != f"{run_url}/job/{job.get('id')}" \
                or job["id"] in identifiers or job["url"] in urls:
            return False
        identifiers.add(job["id"])
        urls.add(job["url"])
        combinations.add((job["os"], job["python"]))
    expected = {(os_name, python) for os_name in REQUIRED_CI_OSES
                for python in REQUIRED_CI_PYTHONS}
    return combinations == expected


def _unfamiliar_user_usability_passed(payload, subject):
    if set(payload) != USABILITY_FIELDS \
            or not isinstance(payload.get("study_id"), str) \
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
                            payload["study_id"]) is None \
            or payload.get("public_build_sha256") != subject["root_sha256"]:
        return False
    hashes = [payload.get(field) for field in (
        "study_bundle_sha256", "install_receipt_bundle_sha256",
        "request_receipt_bundle_sha256")]
    if not all(_sha256(value) for value in hashes) or len(set(hashes)) != len(hashes):
        return False
    count = payload.get("participant_count")
    if type(count) is not int or count < 1:
        return False
    complete_counts = (
        "unfamiliar_participant_count", "clean_environment_count",
        "fresh_install_count", "real_request_completion_count",
        "completed_without_maintainer_count",
    )
    return all(payload.get(field) == count for field in complete_counts) \
        and payload.get("coaching_event_count") == 0


def _independent_hostile_review_passed(payload, subject):
    if set(payload) != HOSTILE_REVIEW_FIELDS \
            or payload.get("reproduced_build_sha256") != subject["root_sha256"] \
            or payload.get("scope_complete") is not True \
            or payload.get("reviewer_independent") is not True \
            or payload.get("critical_findings") != 0 \
            or payload.get("high_findings") != 0:
        return False
    report_hash = payload.get("report_sha256")
    bundle_hash = payload.get("review_bundle_sha256")
    return _sha256(report_hash) and _sha256(bundle_hash) \
        and report_hash != bundle_hash


def _external_passed(check_id, evidence, *, trust_policy=None, now=None):
    if not isinstance(evidence, dict) or set(evidence) != EXTERNAL_EVIDENCE_FIELDS \
            or evidence.get("schema_version") != 1 \
            or evidence.get("check_id") != check_id \
            or evidence.get("status") != "passed":
        return False
    try:
        if str(uuid.UUID(evidence["evidence_id"])) != evidence["evidence_id"]:
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    subject = evidence.get("subject")
    if not _valid_subject(subject):
        return False
    issued = _evidence_time(evidence.get("issued_at"))
    expires = _evidence_time(evidence.get("expires_at"))
    instant = now or dt.datetime.now(dt.timezone.utc)
    if issued is None or expires is None or not issued <= instant <= expires:
        return False
    issuer = evidence.get("issuer")
    if not isinstance(issuer, dict) or set(issuer) != ISSUER_FIELDS \
            or not isinstance(issuer.get("id"), str) or not issuer["id"].strip() \
            or issuer.get("kind") not in {
                "github-actions", "independent-participant", "independent-reviewer",
                "independent-benchmark"} \
            or issuer.get("independent") is not True:
        return False
    payload = evidence.get("payload")
    if not isinstance(payload, dict) \
            or evidence.get("payload_sha256") != _canonical_hash(payload):
        return False
    attestation = evidence.get("attestation")
    if not isinstance(attestation, dict) or set(attestation) != ATTESTATION_FIELDS \
            or attestation.get("algorithm") != "rsa-pkcs1v15-sha256" \
            or not all(isinstance(attestation.get(field), str)
                       and attestation[field].strip()
                       for field in ("key_id", "signature")):
        return False
    trusted_key = _trusted_issuer(check_id, evidence, trust_policy)
    if trusted_key is None or not _signature_valid(evidence, trusted_key):
        return False
    if check_id == "unfamiliar-user-usability":
        return _unfamiliar_user_usability_passed(payload, subject)
    if check_id == "independent-hostile-review":
        return _independent_hostile_review_passed(payload, subject)
    if check_id == "production-performance":
        return _production_performance_passed(payload)
    if check_id == "production-memory-replay":
        return _production_replay_passed(payload)
    return _cross_platform_ci_passed(payload, subject)


def certification_report(*, local_checks, external_evidence, trust_policy=None, now=None):
    if not isinstance(local_checks, dict) or not isinstance(external_evidence, dict):
        raise ReleaseError("release evidence must be structured mappings")
    local_validation = _validated_local_evidence(local_checks, now=now)
    validated_checks = local_validation[0] if local_validation else {}
    local_subject = local_validation[1] if local_validation else None
    checks = []
    for check_id in LOCAL_CHECKS:
        passed = validated_checks.get(check_id) is True
        checks.append({"id": check_id, "status": "passed" if passed else "failed"})
    unverified = ([] if local_validation else [
        {"id": "local-verification", "status": "failed"}])
    seen_evidence_ids = set()
    for check_id in EXTERNAL_CHECKS:
        evidence = external_evidence.get(check_id)
        passed = _external_passed(
            check_id, evidence, trust_policy=trust_policy, now=now)
        if passed and evidence.get("subject") != local_subject:
            passed = False
        evidence_id = evidence.get("evidence_id") if isinstance(evidence, dict) else None
        if passed and evidence_id in seen_evidence_ids:
            passed = False
        if passed:
            seen_evidence_ids.add(evidence_id)
        status = "passed" if passed else ("failed" if evidence else "unverified")
        checks.append({"id": check_id, "status": status})
        if not passed:
            unverified.append({"id": check_id, "status": status})
    passed_count = sum(item["status"] == "passed" for item in checks)
    certified = passed_count == len(checks)
    return {
        "schema_version": 1,
        "status": "certified" if certified else "blocked",
        "score": 100 if certified else int(100 * passed_count / len(checks)),
        "checks": checks,
        "unverified": unverified,
        "claim_100_allowed": certified,
        "limitations": ([] if certified else [
            "No 100 score or production certification until every external proof is supplied."]),
    }


def _suite(root):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-p", "test_*.py"],
        cwd=root / "tools", capture_output=True, text=True, timeout=900, check=False,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return {"passed": result.returncode == 0, "returncode": result.returncode,
            "output": (result.stdout + result.stderr)[-4000:]}


def _performance_contracts():
    policy = loom_performance.evaluate_benchmarks()
    observed = loom_performance.run_observed_benchmarks()
    scenarios = observed.get("scenarios", {})
    passed = policy.get("passed") is True \
        and set(scenarios) == {
            "cold_start", "warm_session", "project_switch", "resume", "year_long"} \
        and scenarios["cold_start"].get("disk_reads") == 2 \
        and scenarios["warm_session"].get("disk_reads") == 0 \
        and scenarios["warm_session"].get("cache_hits") == 2 \
        and scenarios["project_switch"].get("disk_reads") == 1 \
        and scenarios["resume"].get("disk_reads") == 1 \
        and scenarios["year_long"].get("capsule_chars", 513) <= 512 \
        and observed.get("tiny_task", {}).get("measurement_kind") == \
        "synthetic-policy-fixture"
    return {"passed": passed, "policy": policy, "observed": observed,
            "certifies_production_usage": False}


def sanitize_suite_evidence(suite, *, root, home):
    value = dict(suite)
    value["output"] = loom_privacy.minimize_evidence(
        value.get("output", ""), roots=(root, home), max_chars=4000)
    return value


def _git_release_identity(root):
    def run(*arguments):
        result = subprocess.run(
            ["git", "-C", str(root), *arguments], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30, check=False)
        if result.returncode != 0:
            raise ReleaseError(
                "release verification requires a readable Git identity: "
                + (result.stderr.strip() or result.stdout.strip() or "git failed"))
        return result.stdout.strip()

    commit = run("rev-parse", "--verify", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("release verification requires an immutable commit SHA")
    dirty = run("status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise ReleaseError("release verification requires a clean committed worktree")
    remote = run("remote", "get-url", "origin")
    ssh = re.fullmatch(r"git@github\.com:([^/]+)/(.+?)(?:\.git)?", remote)
    https = re.fullmatch(r"https://github\.com/([^/]+)/(.+?)(?:\.git)?/?", remote)
    match = ssh or https
    if match is None:
        raise ReleaseError("release verification requires a canonical GitHub origin")
    repository = f"https://github.com/{match.group(1)}/{match.group(2)}"
    return {"repository": repository, "commit_sha": commit}


def verify_local(root, *, forbidden_tokens):
    try:
        root = loom_reliability._absolute(root, "release root", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise ReleaseError(str(exc)) from exc
    if not forbidden_tokens:
        raise ReleaseError("local verification requires real private/owner tokens")
    identity_before = _git_release_identity(root)
    suite = sanitize_suite_evidence(_suite(root), root=root, home=Path.home())
    performance_contracts = _performance_contracts()
    docs = loom_docs.audit_docs(root)
    offline = loom_privacy.audit_offline_modules(root / "tools")
    with tempfile.TemporaryDirectory(prefix="loom-release-proof-") as temporary:
        workspace = Path(temporary)
        adaptation = loom_adaptation_eval.run_suite(workspace / "adaptation")
        first = build_public(root, workspace / "public-one",
                             forbidden_tokens=forbidden_tokens)
        second = build_public(root, workspace / "public-two",
                              forbidden_tokens=forbidden_tokens)
        reproducible = first["root_sha256"] == second["root_sha256"]
        installed = loom_install.install(workspace / "public-one", workspace / "installed")
        checked = loom_install.check(workspace / "installed")
        removed = loom_install.uninstall(
            workspace / "installed", confirmation=installed["install_id"])
        installer_cycle = checked["status"] == "installed" \
            and removed["status"] == "uninstalled" and removed["target_removed"]
        privacy = first["firewall"]
    scenario = next((item for item in adaptation["scenarios"]
                     if item["id"] == "twenty-project-year"), None)
    local = {
        "suite": suite["passed"],
        "adaptation": adaptation["status"] == "passed",
        "privacy": privacy["clean"] and offline["offline"],
        "failure_injection": suite["passed"],
        "reproducible_build": reproducible,
        "installer_cycle": installer_cycle,
        "performance_contracts": performance_contracts["passed"],
        "docs": docs["status"] == "passed",
        "twenty_project_bound": bool(scenario and scenario["passed"]),
    }
    identity_after = _git_release_identity(root)
    if identity_after != identity_before:
        raise ReleaseError("release source identity changed during local verification")
    subject = {**identity_after, "root_sha256": first["root_sha256"]}
    evidence = {
        "suite": suite,
        "adaptation_scenarios": adaptation["scenario_count"],
        "privacy": privacy,
        "offline": offline,
        "docs": docs,
        "build_hashes": [first["root_sha256"], second["root_sha256"]],
        "installer": {"files_verified": checked["files_verified"],
                      "target_removed": removed["target_removed"]},
        "performance_contracts": performance_contracts,
        "twenty_project_measurements": (
            scenario["measurements"] if scenario else None),
    }
    return seal_local_evidence(
        subject=subject, local_checks=local, evidence=evidence)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("source")
    build.add_argument("destination")
    build.add_argument("--forbid", action="append", default=[])
    certify = sub.add_parser("certify")
    certify.add_argument("--local-checks", required=True)
    certify.add_argument("--external-evidence", required=True)
    certify.add_argument("--trust-policy", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("root")
    verify.add_argument("--forbid", action="append", default=[])
    verify.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_public(
                args.source, args.destination, forbidden_tokens=args.forbid)
        elif args.command == "certify":
            local = json.loads(Path(args.local_checks).read_text(encoding="utf-8"))
            external = json.loads(Path(args.external_evidence).read_text(encoding="utf-8"))
            trust_policy = json.loads(Path(args.trust_policy).read_text(encoding="utf-8"))
            result = certification_report(
                local_checks=local, external_evidence=external,
                trust_policy=trust_policy)
        else:
            result = verify_local(args.root, forbidden_tokens=args.forbid)
            if args.output:
                loom_reliability.atomic_write_json(Path(args.output).resolve(), result)
    except (ReleaseError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in {"built", "certified", "passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
