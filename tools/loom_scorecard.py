#!/usr/bin/env python3
"""Generate evidence-bound Loom scorecards and fair competitive comparisons."""

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import loom_adaptation_eval
import loom_adapter_conformance
import loom_benchmark
import loom_docs
import loom_domain_benchmark
import loom_mutation
import loom_privacy
import loom_release
import loom_test
import loom_version


DEFAULT_RUBRIC = Path(__file__).resolve().parents[1] / "contracts" / "score-rubric-v2.json"
LEGACY_EVIDENCE_CLASSES = {
    "mechanical-local", "matrix-reproduced", "real-host", "provider-attested",
    "longitudinal-local", "independent-external", "public-adoption", "claimed-only",
}
CURRENT_EVIDENCE_CLASSES = {
    "mechanical-local", "ci-reproduced", "real-host", "provider-native",
    "host-observed", "longitudinal-local", "independently-witnessed",
    "independent-external", "public-adoption", "claimed-only",
}
EVIDENCE_CLASSES = LEGACY_EVIDENCE_CLASSES | CURRENT_EVIDENCE_CLASSES
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z0-9-]{1,96}$")
TRUST_CRITICAL_CATEGORIES = {
    "tool-correctness", "lifecycle-enforcement", "owner-learning",
    "memory-isolation-bounds", "robustness-safety", "privacy-sovereignty",
    "testing-release-engineering", "observability-claim-honesty",
}


class ScoreError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ScoreError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read_json(path, maximum):
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise ScoreError(f"evidence input is missing, redirected, or oversized: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScoreError(f"evidence input is invalid: {path.name}: {exc}") from exc


def _time(value, label):
    if not isinstance(value, str):
        raise ScoreError(f"{label} is not a timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScoreError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ScoreError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _now_text(now=None):
    value = now or dt.datetime.now(dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_rubric(path=DEFAULT_RUBRIC):
    path = Path(path).resolve()
    value = _read_json(path, MAX_SNAPSHOT_BYTES)
    if isinstance(value, dict) and value.get("schema_version") == 2:
        fields = {"schema_version", "rubric_id", "title", "base_rubric",
                  "evidence_classes", "class_renames"}
        if set(value) != fields or value.get("rubric_id") != "loom-cross-cutting-v2" \
                or value.get("base_rubric") != "score-rubric-v1.json" \
                or set(value.get("evidence_classes", [])) != CURRENT_EVIDENCE_CLASSES \
                or value.get("evidence_classes") != list(dict.fromkeys(
                    value.get("evidence_classes", []))) \
                or value.get("class_renames") != {
                    "matrix-reproduced": "ci-reproduced",
                    "provider-attested": "provider-native"}:
            raise ScoreError("score rubric v2 descriptor is invalid")
        base_path = (path.parent / value["base_rubric"]).resolve()
        if base_path.parent != path.parent or base_path.is_symlink():
            raise ScoreError("score rubric v2 base escapes the contract directory")
        base = load_rubric(base_path)
        translated = []
        for category in base["categories"]:
            requirements = []
            for requirement in category["requirements"]:
                requirements.append({**requirement, "allowed_evidence_classes": [
                    value["class_renames"].get(item, item)
                    for item in requirement["allowed_evidence_classes"]]})
            translated.append({**category, "requirements": requirements})
        value = {"schema_version": 1, "rubric_id": value["rubric_id"],
                 "title": value["title"],
                 "evidence_classes": value["evidence_classes"],
                 "categories": translated}
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "rubric_id", "title", "evidence_classes", "categories"} \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("rubric_id"), str) \
            or not isinstance(value.get("title"), str) \
            or value.get("evidence_classes") != list(dict.fromkeys(
                value.get("evidence_classes", []))) \
            or frozenset(value.get("evidence_classes", [])) not in {
                frozenset(LEGACY_EVIDENCE_CLASSES), frozenset(CURRENT_EVIDENCE_CLASSES)} \
            or not isinstance(value.get("categories"), list) \
            or not 1 <= len(value["categories"]) <= 32:
        raise ScoreError("score rubric shape is invalid")
    categories = set()
    requirements = set()
    weight = 0
    for category in value["categories"]:
        if not isinstance(category, dict) or set(category) != {
                "id", "label", "weight", "requirements"} \
                or not isinstance(category["id"], str) or category["id"] in categories \
                or not isinstance(category["label"], str) \
                or type(category["weight"]) is not int \
                or not 1 <= category["weight"] <= 100 \
                or not isinstance(category["requirements"], list) \
                or not 1 <= len(category["requirements"]) <= 16:
            raise ScoreError("score rubric category is invalid")
        categories.add(category["id"])
        weight += category["weight"]
        points = 0
        for requirement in category["requirements"]:
            if not isinstance(requirement, dict) or set(requirement) != {
                    "id", "points", "allowed_evidence_classes"} \
                    or not isinstance(requirement["id"], str) \
                    or requirement["id"] in requirements \
                    or type(requirement["points"]) is not int \
                    or not 1 <= requirement["points"] <= 100 \
                    or not isinstance(requirement["allowed_evidence_classes"], list) \
                    or not requirement["allowed_evidence_classes"] \
                    or len(requirement["allowed_evidence_classes"]) != len(set(
                        requirement["allowed_evidence_classes"])) \
                    or not set(requirement["allowed_evidence_classes"]) <= set(
                        value["evidence_classes"]):
                raise ScoreError("score rubric requirement is invalid")
            requirements.add(requirement["id"])
            points += requirement["points"]
        if points != 100:
            raise ScoreError(f"category points do not total 100: {category['id']}")
    if weight != 100:
        raise ScoreError("score rubric weights do not total 100")
    return value


def source_subject(root):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ScoreError("score subject is not a directory")
    files = []
    try:
        for path in loom_release._eligible_files(root):
            raw = path.read_bytes()
            files.append({"path": path.relative_to(root).as_posix(), "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest()})
    except (OSError, loom_release.ReleaseError) as exc:
        raise ScoreError(f"score subject inventory failed: {exc}") from exc
    tree_sha256 = _digest(sorted(files, key=lambda item: item["path"]))
    commit = None
    repository = "local:loom"
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=10, check=False)
        if result.returncode == 0 and len(result.stdout.strip()) == 40:
            commit = result.stdout.strip().lower()
        remote = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"], cwd=root,
            capture_output=True, text=True, timeout=10, check=False)
        if remote.returncode == 0 and remote.stdout.strip():
            repository = remote.stdout.strip()[:256]
    except (OSError, subprocess.SubprocessError):
        pass
    kind = "public-cut" if (root / loom_release.MANIFEST).is_file() else "source-tree"
    if kind == "public-cut":
        try:
            tree_sha256 = loom_release._verify_cut_manifest(root)["root_sha256"]
            plugin = json.loads((root / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"), object_pairs_hook=_strict_object)
            if isinstance(plugin.get("repository"), str):
                repository = plugin["repository"][:256]
        except (OSError, UnicodeError, json.JSONDecodeError, loom_release.ReleaseError) as exc:
            raise ScoreError(f"public-cut subject verification failed: {exc}") from exc
    return {"kind": kind, "repository": repository,
            "commit_sha": commit, "tree_sha256": tree_sha256}


def _record_body(record):
    return {key: value for key, value in record.items()
            if key not in {"evidence_id", "digest", "attestation"}}


def _make_record(subject, requirement_id, status, artifact_id, artifacts,
                 *, tool, locator, observed_at, evidence_class="mechanical-local",
                 expires_at=None):
    artifact = artifacts[artifact_id]
    record = {
        "schema_version": 1,
        "coverage_id": f"{requirement_id}:{tool}:{locator}",
        "subject": subject,
        "evidence_class": evidence_class,
        "status": status,
        "requirement_id": requirement_id,
        "source": {"tool": tool, "locator": locator, "artifact_id": artifact_id,
                   "artifact_sha256": _digest(artifact)},
        "observed_at": observed_at,
        "expires_at": expires_at,
        "attestation": None,
    }
    record["digest"] = _digest(_record_body(record))
    record["evidence_id"] = "ev-" + record["digest"][:32]
    return record


def _score_trusted_key(record, trust_policy, rubric):
    if not isinstance(trust_policy, dict) or set(trust_policy) != {
            "schema_version", "rubric_id", "subject", "issuers"} \
            or trust_policy.get("schema_version") != 1 \
            or trust_policy.get("rubric_id") != rubric["rubric_id"] \
            or trust_policy.get("subject") != record["subject"] \
            or not isinstance(trust_policy.get("issuers"), list) \
            or not 1 <= len(trust_policy["issuers"]) <= 32:
        return None
    attestation = record.get("attestation")
    if not isinstance(attestation, dict) or set(attestation) != {
            "algorithm", "key_id", "signature"} \
            or attestation.get("algorithm") != "rsa-pkcs1v15-sha256":
        return None
    matches = [item for item in trust_policy["issuers"]
               if isinstance(item, dict) and item.get("key_id") == attestation["key_id"]]
    if len(matches) != 1:
        return None
    issuer = matches[0]
    if set(issuer) != {"id", "key_id", "algorithm", "modulus_hex", "exponent",
                       "independent", "evidence_classes", "requirements"} \
            or issuer.get("algorithm") != "rsa-pkcs1v15-sha256" \
            or issuer.get("independent") is not True \
            or not isinstance(issuer.get("evidence_classes"), list) \
            or record["evidence_class"] not in issuer["evidence_classes"] \
            or len(issuer["evidence_classes"]) != len(set(issuer["evidence_classes"])) \
            or not isinstance(issuer.get("requirements"), list) \
            or record["requirement_id"] not in issuer["requirements"] \
            or len(issuer["requirements"]) != len(set(issuer["requirements"])):
        return None
    try:
        modulus = int(issuer["modulus_hex"], 16)
        exponent = issuer["exponent"]
    except (TypeError, ValueError):
        return None
    if not isinstance(issuer.get("modulus_hex"), str) \
            or not re.fullmatch(r"[0-9a-f]{512,1024}", issuer["modulus_hex"]) \
            or type(exponent) is not int or exponent < 3 or exponent % 2 == 0 \
            or modulus.bit_length() < 2048:
        return None
    return modulus, exponent


def validate_evidence(bundle, rubric, *, as_of=None, trust_policy=None):
    if not isinstance(bundle, dict) or set(bundle) != {
            "schema_version", "subject", "generated_at", "artifacts", "records"} \
            or bundle.get("schema_version") != 1 \
            or not isinstance(bundle.get("subject"), dict) \
            or not isinstance(bundle.get("artifacts"), dict) \
            or not isinstance(bundle.get("records"), list) \
            or len(bundle["artifacts"]) > 32 or len(bundle["records"]) > 256:
        raise ScoreError("score evidence bundle shape is invalid")
    subject = bundle["subject"]
    if set(subject) != {"kind", "repository", "commit_sha", "tree_sha256"} \
            or subject["kind"] not in {"source-tree", "public-cut", "competitor-revision"} \
            or not isinstance(subject["repository"], str) \
            or subject["commit_sha"] is not None and (
                not isinstance(subject["commit_sha"], str)
                or not COMMIT_RE.fullmatch(subject["commit_sha"])) \
            or not isinstance(subject["tree_sha256"], str) \
            or not SHA_RE.fullmatch(subject["tree_sha256"]):
        raise ScoreError("score evidence subject is invalid")
    generated = _time(bundle["generated_at"], "evidence generated_at")
    evaluated = as_of or dt.datetime.now(dt.timezone.utc)
    if generated > evaluated + dt.timedelta(minutes=5):
        raise ScoreError("score evidence is from the future")
    if len(_canonical(bundle)) > MAX_EVIDENCE_BYTES:
        raise ScoreError("score evidence bundle exceeds its byte bound")
    requirement_map = {
        requirement["id"]: requirement
        for category in rubric["categories"] for requirement in category["requirements"]}
    seen_ids = set()
    seen_coverage = set()
    seen_requirements = {}
    for artifact_id, artifact in bundle["artifacts"].items():
        if not isinstance(artifact_id, str) or not ID_RE.fullmatch(artifact_id) \
                or not isinstance(artifact, dict) or len(artifact) > 64:
            raise ScoreError("score evidence artifact is invalid")
    for record in bundle["records"]:
        if not isinstance(record, dict) or set(record) != {
                "schema_version", "evidence_id", "coverage_id", "subject",
                "evidence_class", "status", "requirement_id", "source",
                "observed_at", "expires_at", "attestation", "digest"} \
                or record.get("schema_version") != 1 \
                or record.get("subject") != subject \
                or record.get("evidence_class") not in set(rubric["evidence_classes"]) \
                or record.get("status") not in {"passed", "failed", "unverified"} \
                or record.get("requirement_id") not in requirement_map \
                or record.get("digest") != _digest(_record_body(record)) \
                or record.get("evidence_id") != "ev-" + record["digest"][:32]:
            raise ScoreError("score evidence record is invalid or tampered")
        source = record["source"]
        if not isinstance(source, dict) or set(source) != {
                "tool", "locator", "artifact_id", "artifact_sha256"} \
                or source["artifact_id"] not in bundle["artifacts"] \
                or source["artifact_sha256"] != _digest(
                    bundle["artifacts"][source["artifact_id"]]):
            raise ScoreError("score evidence artifact binding is invalid")
        observed = _time(record["observed_at"], "evidence observed_at")
        if observed > evaluated + dt.timedelta(minutes=5):
            raise ScoreError("score evidence record is from the future")
        if record["expires_at"] is not None \
                and _time(record["expires_at"], "evidence expires_at") <= evaluated:
            raise ScoreError("provided score evidence is stale")
        requirement = requirement_map[record["requirement_id"]]
        if record["evidence_class"] != "claimed-only" \
                and record["evidence_class"] not in requirement["allowed_evidence_classes"]:
            raise ScoreError("score evidence class cannot satisfy its requirement")
        if record["evidence_class"] in {"mechanical-local", "claimed-only"}:
            if record["attestation"] is not None:
                raise ScoreError("local or claimed-only evidence cannot carry external authority")
        else:
            trusted = _score_trusted_key(record, trust_policy, rubric)
            if trusted is None or not loom_release._signature_valid(record, trusted):
                raise ScoreError("non-local score evidence lacks trusted independent authority")
        if record["evidence_id"] in seen_ids or record["coverage_id"] in seen_coverage:
            raise ScoreError("duplicate score evidence identity or coverage")
        if record["requirement_id"] in seen_requirements:
            raise ScoreError("a requirement has contradictory or duplicate evidence")
        seen_ids.add(record["evidence_id"])
        seen_coverage.add(record["coverage_id"])
        seen_requirements[record["requirement_id"]] = record
    return seen_requirements


def score(rubric, bundle, *, as_of=None, trust_policy=None):
    evaluated = as_of or dt.datetime.now(dt.timezone.utc)
    records = validate_evidence(
        bundle, rubric, as_of=evaluated, trust_policy=trust_policy)
    categories = []
    overall = 0.0
    for category in rubric["categories"]:
        awarded = []
        withheld = []
        raw = 0
        for requirement in category["requirements"]:
            record = records.get(requirement["id"])
            if record and record["status"] == "passed" \
                    and record["evidence_class"] != "claimed-only":
                raw += requirement["points"]
                awarded.append(requirement["id"])
            else:
                withheld.append(requirement["id"])
        weighted = round(category["weight"] * raw / 100, 2)
        overall += weighted
        categories.append({
            "id": category["id"], "label": category["label"],
            "weight": category["weight"], "raw_score": raw,
            "weighted_score": weighted,
            "awarded_requirements": awarded,
            "withheld_requirements": withheld,
        })
    body = {
        "schema_version": 1, "rubric_id": rubric["rubric_id"],
        "subject": bundle["subject"], "evaluated_at": _now_text(evaluated),
        "status": "certified" if not any(
            item["withheld_requirements"] for item in categories) else "local-evidence",
        "overall_score": round(overall, 2), "evidence_records": len(bundle["records"]),
        "categories": categories,
    }
    return {**body, "scorecard_sha256": _digest(body)}


def validate_scorecard(value, rubric):
    required = {"schema_version", "rubric_id", "subject", "evaluated_at", "status",
                "overall_score", "evidence_records", "categories", "scorecard_sha256"}
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != 1 \
            or value.get("rubric_id") != rubric["rubric_id"] \
            or value.get("status") not in {"local-evidence", "certified"} \
            or type(value.get("overall_score")) not in {int, float} \
            or not 0 <= value["overall_score"] <= 100 \
            or type(value.get("evidence_records")) is not int \
            or not 0 <= value["evidence_records"] <= 256 \
            or not isinstance(value.get("categories"), list) \
            or value["scorecard_sha256"] != _digest({
                key: item for key, item in value.items() if key != "scorecard_sha256"}):
        raise ScoreError("scorecard is invalid, tampered, or uses another rubric")
    expected = {item["id"]: item for item in rubric["categories"]}
    observed = set()
    weighted = 0.0
    for item in value["categories"]:
        if not isinstance(item, dict) or set(item) != {
                "id", "label", "weight", "raw_score", "weighted_score",
                "awarded_requirements", "withheld_requirements"} \
                or item.get("id") not in expected or item["id"] in observed \
                or item["label"] != expected[item["id"]]["label"] \
                or item["weight"] != expected[item["id"]]["weight"] \
                or type(item["raw_score"]) not in {int, float} \
                or not 0 <= item["raw_score"] <= 100 \
                or item["weighted_score"] != round(
                    item["weight"] * item["raw_score"] / 100, 2):
            raise ScoreError("scorecard category is invalid")
        expected_requirements = {
            requirement["id"] for requirement in expected[item["id"]]["requirements"]}
        awarded = item["awarded_requirements"]
        withheld = item["withheld_requirements"]
        if not isinstance(awarded, list) or not isinstance(withheld, list) \
                or set(awarded) & set(withheld) \
                or set(awarded) | set(withheld) != expected_requirements:
            raise ScoreError("scorecard requirement accounting is invalid")
        observed.add(item["id"])
        weighted += item["weighted_score"]
    if observed != set(expected) or round(weighted, 2) != value["overall_score"]:
        raise ScoreError("scorecard arithmetic or coverage is invalid")
    return value


def regression(rubric, baseline, current):
    validate_scorecard(baseline, rubric)
    validate_scorecard(current, rubric)
    baseline_rows = {item["id"]: item for item in baseline["categories"]}
    current_rows = {item["id"]: item for item in current["categories"]}
    decreases = []
    for category_id in baseline_rows:
        prior = baseline_rows[category_id]["raw_score"]
        observed = current_rows[category_id]["raw_score"]
        if observed < prior:
            decreases.append({
                "category_id": category_id, "baseline": prior, "current": observed,
                "delta": round(observed - prior, 2),
                "trust_critical": category_id in TRUST_CRITICAL_CATEGORIES,
            })
    blocking = [item for item in decreases if item["trust_critical"]]
    body = {
        "schema_version": 1, "rubric_id": rubric["rubric_id"],
        "baseline_subject": baseline["subject"], "current_subject": current["subject"],
        "status": "blocked" if blocking else "passed",
        "decreases": decreases, "blocking_decreases": blocking,
    }
    return {**body, "regression_sha256": _digest(body)}


def _suite_modules(report):
    result = {}
    for item in report.get("timings", []):
        module = item.get("test", "").split(".", 1)[0]
        if module:
            result[module] = result.get(module, True) and item.get("status") == "passed"
    return result


def _suite_tests(report):
    return {item.get("test"): item.get("status")
            for item in report.get("timings", []) if item.get("test")}


def _complete_suite_correctness(report):
    return report.get("mode") == "full" \
        and report.get("failures") == 0 and report.get("errors") == 0 \
        and report.get("within_budget") is True


def _artifact_summaries(*, suite, fast, docs, privacy, mutation, adapter,
                        domain, performance, adaptation, version, publication):
    performance_failures = sum(item.get("failure_count", 1)
                               for item in performance.get("results", []))
    return {
        "suite": {key: suite.get(key) for key in (
            "mode", "tests_run", "failures", "errors", "skipped", "successful",
            "capability_complete", "elapsed_seconds", "within_budget")}
        | {"modules": _suite_modules(suite)},
        "fast-gate": {key: fast.get(key) for key in (
            "tests_run", "failures", "errors", "skipped", "successful",
            "within_budget", "elapsed_seconds", "max_seconds")},
        "docs": docs,
        "privacy": privacy,
        "mutation": {key: mutation.get(key) for key in (
            "status", "mutants", "killed", "score", "minimum_score")},
        "adapter": adapter,
        "domain": {key: domain.get(key) for key in (
            "policy_version", "case_count", "passed", "failures",
            "critical_high_unsafe_authorizations", "material_boundary_misses",
            "macro_precision", "macro_recall")},
        "performance": {"measurement_kind": performance.get("measurement_kind"),
                        "iterations": performance.get("iterations"),
                        "failure_count": performance_failures,
                        "workloads": [item.get("workload_id")
                                      for item in performance.get("results", [])],
                        "receipt_sha256": performance.get("receipt_sha256")},
        "adaptation": {"scenario_count": adaptation.get("scenario_count"),
                       "passed": all(item.get("passed")
                                     for item in adaptation.get("scenarios", [])),
                       "scenario_ids": [item.get("id")
                                        for item in adaptation.get("scenarios", [])]},
        "version": version,
        "publication": publication,
    }


def collect_local(root, *, suite_mode="full", now=None,
                  suite_report=None, publication_report=None):
    root = Path(root).resolve()
    before = source_subject(root)
    observed = _now_text(now)
    expires = _now_text((now or dt.datetime.now(dt.timezone.utc)) + dt.timedelta(days=30))
    suite = suite_report or loom_test.run(suite_mode, verbosity=0)
    fast = loom_test.run("fast", max_seconds=30, verbosity=0)
    docs = loom_docs.audit_docs(root)
    privacy = loom_privacy.audit_offline_modules(root / "tools")
    mutation = loom_mutation.run(root, minimum_score=100, timeout=120)
    adapter = loom_adapter_conformance.run(root)
    domain = loom_domain_benchmark.run(root / "benchmarks" / "domain-intelligence" / "corpus.json")
    performance = loom_benchmark.run(
        root / "benchmarks" / "performance" / "corpus.json",
        iterations=1, warmups=0)
    with tempfile.TemporaryDirectory(prefix="loom-score-adaptation-") as temporary:
        adaptation = loom_adaptation_eval.run_suite(Path(temporary))
    version = loom_version.verify(root)
    if publication_report is None:
        with tempfile.TemporaryDirectory(prefix="loom-score-cut-") as temporary:
            cut = Path(temporary) / "cut"
            build = loom_release.build_public(
                root, cut, forbidden_tokens=[], source_classification="public-release")
            verified_manifest = loom_release._verify_cut_manifest(cut)
            post_scan = loom_privacy.scan_publication(
                cut, forbidden_tokens=[], require_owner_tokens=False)
            publication = {
                "status": build["status"], "root_sha256": build["root_sha256"],
                "clean": build["firewall"]["clean"],
                "files_scanned": build["firewall"]["files_scanned"],
                "protection_claimed": build["owner_token_policy"]["protection_claimed"],
                "manifest_verified": verified_manifest["root_sha256"] == build["root_sha256"],
                "post_scan_clean": post_scan["clean"],
            }
    else:
        publication = publication_report
    after = source_subject(root)
    if before != after:
        raise ScoreError("score subject changed while local evidence was collected")
    artifacts = _artifact_summaries(
        suite=suite, fast=fast, docs=docs, privacy=privacy, mutation=mutation,
        adapter=adapter, domain=domain, performance=performance,
        adaptation=adaptation, version=version, publication=publication)
    modules = artifacts["suite"]["modules"]
    tests = _suite_tests(suite)

    def module(*names):
        return all(modules.get(name) is True for name in names)

    def test(*names):
        return all(tests.get(name) == "passed" for name in names)

    checks = {
        "architecture-boundaries": (docs["status"] == "passed" and module(
            "test_loom_v11_contracts", "test_documentation_coherence"), "suite"),
        "single-runtime-state-authority": (version["status"] == "coherent"
            and adapter["status"] == "passed", "adapter"),
        "closed-cli-contracts": (module("test_tool_contracts"), "suite"),
        "fail-closed-tool-behavior": (mutation["status"] == "passed", "mutation"),
        "epistemic-artifact-discipline": (module("test_loom_lint"), "suite"),
        "plan-integrity-enforcement": (module(
            "test_loom_lint", "test_production_orchestrator"), "suite"),
        "causal-plan-before-build": (module("test_loom_gate"), "suite"),
        "gates-work-orders-verification": (module(
            "test_loom_gate", "test_production_orchestrator"), "suite"),
        "known-domain-routing": (test(
            "test_domain_universality.DomainUniversalityTests."
            "test_composite_domain_loads_only_matching_adapters",
            "test_domain_universality.DomainUniversalityTests."
            "test_unknown_domain_blocks_for_invariant_discovery_without_generic_defaults"),
            "suite"),
        "unknown-domain-authority-gate": (domain["passed"] and module(
            "test_domain_evidence", "test_domain_benchmark"), "domain"),
        "complete-token-accounting": (module("test_token_accounting_v3"), "suite"),
        "bounded-tier-s-context": (module("test_tier_s_fast_path"), "suite"),
        "bounded-fast-gate": (fast["successful"] and fast["within_budget"], "fast-gate"),
        "local-performance-corpus": (artifacts["performance"]["failure_count"] == 0,
                                     "performance"),
        "one-command-surface": (docs["status"] == "passed", "docs"),
        "intent-routing-without-command-sprawl": (docs["status"] == "passed"
            and module("test_production_orchestrator"), "docs"),
        "scoped-learning-admission": (module("test_owner_learning_phase2"), "suite"),
        "effect-attribution-forgetting": (module(
            "test_owner_learning_phase2", "test_improvement_proof"), "suite"),
        "encrypted-owner-vault": (module(
            "test_loom_vault_v11", "test_loom_crypto_v11"), "suite"),
        "project-domain-isolation": (artifacts["adaptation"]["passed"], "adaptation"),
        "bounded-merge-forgetting": (module(
            "test_loom_merge_v11", "test_loom_transfer_v11"), "suite"),
        "bounded-adapter-protocol": (adapter["status"] == "passed"
            and adapter["protocol_version"] == 2, "adapter"),
        "transactional-shared-adapters": (adapter["status"] == "passed"
            and module("test_loom_plugin_adapters_v11"), "adapter"),
        "complete-world-freshness": (test(
            "test_loom_runtime.WorldFingerprintTests."
            "test_real_prepare_loader_binds_every_world_input",
            "test_loom_runtime.InvalidWorldStateTests."
            "test_drift_routes_to_internal_selective_regate_then_execution"), "suite"),
        "failure-injection-mutation": (mutation["status"] == "passed"
            and module("test_reliability_excellence"), "mutation"),
        "all-file-publication-firewall": (publication["clean"] and test(
            "test_privacy_excellence.PrivacyExcellenceTests."
            "test_firewall_scans_binary_content_and_every_filename",
            "test_privacy_excellence.PrivacyExcellenceTests."
            "test_firewall_rejects_common_provider_and_high_entropy_credentials"),
            "publication"),
        "offline-no-telemetry-runtime": (privacy["offline"]
            and not privacy["findings"], "privacy"),
        "sovereign-cut-verification": (publication["status"] == "built"
            and publication["manifest_verified"] and publication["post_scan_clean"],
            "publication"),
        "complete-local-suite": (_complete_suite_correctness(suite), "suite"),
        "trust-critical-mutation-gate": (mutation["status"] == "passed"
            and mutation["score"] == 100, "mutation"),
        "coherent-documentation": (docs["status"] == "passed", "docs"),
        "honest-install-limitations": (docs["status"] == "passed"
            and module("test_documentation_coherence"), "docs"),
        "capability-truth-registry": (docs["status"] == "passed"
            and adapter["evidence_status"] == "simulated-conformant", "adapter"),
        "content-bound-usage-receipts": (module(
            "test_token_accounting_v3", "test_performance_end_to_end"), "suite"),
        "public-installable-artifact": (publication["status"] == "built"
            and module("test_loom_plugin_package_v11"), "publication"),
    }
    records = []
    for requirement_id, (passed, artifact_id) in checks.items():
        records.append(_make_record(
            before, requirement_id, "passed" if passed else "unverified",
            artifact_id, artifacts, tool=f"loom-{artifact_id}",
            locator=requirement_id, observed_at=observed, expires_at=expires))
    return {"schema_version": 1, "subject": before, "generated_at": observed,
            "artifacts": artifacts, "records": records}


def collect_release(root, *, now=None):
    root = Path(root).resolve()
    if not (root / loom_release.MANIFEST).is_file():
        raise ScoreError("release evidence requires an exported public cut")
    verification = loom_release.verify_cut(root, forbidden_tokens=[])
    observed = verification["suite"]
    suite = {
        "schema_version": 1, "mode": "full",
        "tests_run": observed["tests_run"],
        "failures": 0 if observed["passed"] else 1,
        "errors": 0, "skipped": len(observed["skip_receipts"]),
        "elapsed_seconds": observed["elapsed_seconds"], "max_seconds": 900,
        "within_budget": observed["passed"],
        "capability_complete": observed["capability_complete"],
        "status": ("passed" if observed["capability_complete"]
                   else "passed-with-capability-skips"),
        "successful": observed["passed"] and observed["capability_complete"],
        "skip_receipts": observed["skip_receipts"], "timings": observed["timings"],
    }
    publication = {
        "status": "built", "root_sha256": verification["root_sha256"],
        "clean": verification["firewall"]["clean"],
        "files_scanned": verification["firewall"]["files_scanned"],
        "protection_claimed": False, "manifest_verified": True,
        "post_scan_clean": verification["firewall"]["clean"],
        "exact_cut_suite_passed": observed["passed"],
    }
    return collect_local(
        root, suite_mode="full", now=now,
        suite_report=suite, publication_report=publication)


def _validate_snapshot(snapshot, rubric, evaluated):
    required = {"schema_version", "project_id", "project_name", "canonical_repository",
                "revision", "accessed_at", "expires_at", "rubric_id", "categories"}
    if not isinstance(snapshot, dict) or set(snapshot) != required \
            or snapshot.get("schema_version") != 1 \
            or snapshot.get("rubric_id") != rubric["rubric_id"] \
            or not isinstance(snapshot.get("project_id"), str) \
            or not ID_RE.fullmatch(snapshot["project_id"]) \
            or not isinstance(snapshot.get("project_name"), str) \
            or not 1 <= len(snapshot["project_name"]) <= 96 \
            or not isinstance(snapshot.get("canonical_repository"), str) \
            or not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/?",
                                snapshot["canonical_repository"]) \
            or not isinstance(snapshot.get("revision"), str) \
            or not COMMIT_RE.fullmatch(snapshot["revision"]) \
            or not isinstance(snapshot.get("categories"), list) \
            or not 1 <= len(snapshot["categories"]) <= 32:
        raise ScoreError("competitive snapshot is invalid, stale, or uses another rubric")
    accessed = _time(snapshot["accessed_at"], "snapshot accessed_at")
    expires = _time(snapshot["expires_at"], "snapshot expires_at")
    if accessed > evaluated + dt.timedelta(minutes=5) or expires <= evaluated \
            or expires <= accessed or expires - accessed > dt.timedelta(days=45):
        raise ScoreError("competitive snapshot is invalid, stale, or uses another rubric")
    expected = {item["id"] for item in rubric["categories"]}
    observed = set()
    for item in snapshot["categories"]:
        if not isinstance(item, dict) or set(item) != {
                "category_id", "applicability", "score", "status", "sources", "rationale"} \
                or item["category_id"] not in expected \
                or item["category_id"] in observed \
                or item["applicability"] not in {"applicable", "not-applicable"} \
                or item["status"] not in {"verified", "unverified", "not-applicable"} \
                or not isinstance(item["sources"], list) \
                or len(item["sources"]) > 12 \
                or len(item["sources"]) != len(set(item["sources"])) \
                or any(not isinstance(source, str) or not source.startswith("https://")
                       for source in item["sources"]) \
                or not isinstance(item["rationale"], str) \
                or not 1 <= len(item["rationale"]) <= 1000:
            raise ScoreError("competitive snapshot category is invalid")
        if item["status"] == "verified" and (
                type(item["score"]) not in {int, float}
                or not 0 <= item["score"] <= 100 or not item["sources"]):
            raise ScoreError("verified competitive score lacks a score or source")
        if item["status"] == "unverified" and item["score"] is not None:
            raise ScoreError("unverified competitive category cannot carry a score")
        if item["applicability"] == "not-applicable" and (
                item["status"] != "not-applicable" or item["score"] is not None):
            raise ScoreError("not-applicable competitive category is contradictory")
        observed.add(item["category_id"])
    if observed != expected:
        raise ScoreError("competitive snapshot does not cover the complete rubric")
    return snapshot


def compare(rubric, snapshots, *, as_of=None):
    evaluated = as_of or dt.datetime.now(dt.timezone.utc)
    weights = {item["id"]: item["weight"] for item in rubric["categories"]}
    projects = []
    seen = set()
    for snapshot in snapshots:
        snapshot = _validate_snapshot(snapshot, rubric, evaluated)
        if snapshot["project_id"] in seen:
            raise ScoreError("competitive comparison repeats a project")
        seen.add(snapshot["project_id"])
        applicable = 0
        known = 0
        points = 0.0
        unknown = []
        for item in snapshot["categories"]:
            weight = weights[item["category_id"]]
            if item["applicability"] == "not-applicable":
                continue
            applicable += weight
            if item["status"] == "verified":
                known += weight
                points += weight * item["score"] / 100
            else:
                unknown.append(item["category_id"])
        if not applicable:
            raise ScoreError("competitive snapshot has no applicable categories")
        lower = round(points * 100 / applicable, 2)
        upper = round((points + applicable - known) * 100 / applicable, 2)
        known_score = round(points * 100 / known, 2) if known else None
        projects.append({
            "project_id": snapshot["project_id"], "project_name": snapshot["project_name"],
            "known_score": known_score, "lower_bound": lower, "upper_bound": upper,
            "evidence_coverage": round(known * 100 / applicable, 2),
            "unverified_categories": sorted(unknown),
        })
    body = {"schema_version": 1, "rubric_id": rubric["rubric_id"],
            "evaluated_at": _now_text(evaluated), "projects": projects}
    return {**body, "comparison_sha256": _digest(body)}


def _write(path, value):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-rubric")
    validate.add_argument("--rubric", default=str(DEFAULT_RUBRIC))
    collect = sub.add_parser("collect-local")
    collect.add_argument("root")
    collect.add_argument("--rubric", default=str(DEFAULT_RUBRIC))
    collect.add_argument("--suite", choices=("fast", "full"), default="full")
    collect.add_argument("--output", required=True)
    release = sub.add_parser("collect-release")
    release.add_argument("root")
    release.add_argument("--rubric", default=str(DEFAULT_RUBRIC))
    release.add_argument("--output", required=True)
    scoring = sub.add_parser("score")
    scoring.add_argument("--rubric", default=str(DEFAULT_RUBRIC))
    scoring.add_argument("--evidence", required=True)
    scoring.add_argument("--as-of")
    scoring.add_argument("--trust-policy")
    scoring.add_argument("--output", required=True)
    comparison = sub.add_parser("compare")
    comparison.add_argument("--rubric", default=str(DEFAULT_RUBRIC))
    comparison.add_argument("--snapshot", action="append", required=True)
    comparison.add_argument("--as-of")
    comparison.add_argument("--output", required=True)
    regress = sub.add_parser("regression")
    regress.add_argument("--rubric", default=str(DEFAULT_RUBRIC))
    regress.add_argument("--baseline", required=True)
    regress.add_argument("--current", required=True)
    regress.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        rubric = load_rubric(args.rubric)
        if args.command == "validate-rubric":
            result = {"status": "valid", "rubric_id": rubric["rubric_id"],
                      "categories": len(rubric["categories"]),
                      "weight": sum(item["weight"] for item in rubric["categories"])}
        elif args.command in {"collect-local", "collect-release"}:
            root = Path(args.root).resolve()
            output = Path(args.output).resolve()
            try:
                output.relative_to(root)
            except ValueError:
                pass
            else:
                raise ScoreError("score evidence output must stay outside its subject tree")
            result = (collect_local(root, suite_mode=args.suite)
                      if args.command == "collect-local" else collect_release(root))
            _write(output, result)
            printed = {"status": "collected", "output": str(output),
                       "subject": result["subject"], "records": len(result["records"]),
                       "artifacts": len(result["artifacts"])}
        elif args.command == "score":
            evidence = _read_json(args.evidence, MAX_EVIDENCE_BYTES)
            as_of = _time(args.as_of, "as_of") if args.as_of else None
            trust_policy = (_read_json(args.trust_policy, MAX_SNAPSHOT_BYTES)
                            if args.trust_policy else None)
            result = score(rubric, evidence, as_of=as_of, trust_policy=trust_policy)
            _write(args.output, result)
        elif args.command == "compare":
            as_of = _time(args.as_of, "as_of") if args.as_of else None
            snapshots = [_read_json(path, MAX_SNAPSHOT_BYTES) for path in args.snapshot]
            result = compare(rubric, snapshots, as_of=as_of)
            _write(args.output, result)
        else:
            baseline = _read_json(args.baseline, MAX_EVIDENCE_BYTES)
            current = _read_json(args.current, MAX_EVIDENCE_BYTES)
            result = regression(rubric, baseline, current)
            _write(args.output, result)
    except (ScoreError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(locals().get("printed", result), indent=2, sort_keys=True))
    return 1 if args.command == "regression" and result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
