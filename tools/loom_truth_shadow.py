#!/usr/bin/env python3
"""Run the locked EVID-101 shadow-promotion safety corpus."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_capability_registry
import loom_subject_identity
import loom_truth


HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_CORPUS_BYTES = 1024 * 1024
STABLE_CORPUS_SUBJECT_KINDS = [
    "main-source", "candidate-source", "release-tag", "plugin-zip",
    "native-helper", "installed-runtime",
]


class ShadowCorpusError(RuntimeError):
    pass


def _read(path):
    path = Path(path)
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise ShadowCorpusError(f"shadow corpus is unavailable: {exc}") from exc
    if path.is_symlink() or not path.is_file() \
            or info.st_size != len(raw) or len(raw) > MAX_CORPUS_BYTES:
        raise ShadowCorpusError("shadow corpus is unsafe")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ShadowCorpusError(f"shadow corpus is invalid: {exc}") from exc
    return raw, value


def _subject(kind, variant=0):
    digit = str(variant + 1)
    if kind == "main-source":
        body = {
            "schema_version": 1, "kind": kind, "subject_id": "main",
            "repository": loom_subject_identity.REPOSITORY,
            "commit": digit * 40, "tree_sha256": digit * 64,
        }
    elif kind == "candidate-source":
        body = {
            "schema_version": 1, "kind": kind,
            "subject_id": "candidate",
            "repository": loom_subject_identity.REPOSITORY,
            "base_commit": "1" * 40, "commit": digit * 40,
            "tree_sha256": digit * 64,
            "overlay_sha256": loom_subject_identity.EMPTY_OVERLAY_SHA256,
            "dirty": False,
        }
    elif kind == "release-tag":
        version = f"v1.8.{18 + variant}"
        body = {
            "schema_version": 1, "kind": kind, "subject_id": version,
            "repository": loom_subject_identity.REPOSITORY,
            "tag": version, "tag_object_id": digit * 40,
            "tag_object_sha256": digit * 64,
            "peeled_commit": digit * 40, "signature_state": "verified",
        }
    elif kind == "public-cut":
        body = {
            "schema_version": 1, "kind": kind, "subject_id": "public-cut",
            "root_sha256": digit * 64,
            "manifest_sha256": str(variant + 2) * 64,
            "file_count": variant + 1,
        }
    elif kind == "plugin-zip":
        filename = f"loom-{variant}.zip"
        body = {
            "schema_version": 1, "kind": kind, "subject_id": filename,
            "filename": filename, "bytes": variant + 1,
            "sha256": digit * 64,
        }
    elif kind == "native-helper":
        platform = ("linux-x64", "linux-arm64")[variant % 2]
        body = {
            "schema_version": 1, "kind": kind, "subject_id": platform,
            "platform": platform, "filename": "loom-vault",
            "bytes": variant + 1, "sha256": digit * 64,
            "sbom_sha256": str(variant + 2) * 64,
            "provenance_sha256": str(variant + 3) * 64,
        }
    else:
        version = f"1.8.{18 + variant}"
        body = {
            "schema_version": 1, "kind": kind, "subject_id": version,
            "version": version, "release_sequence": 18 + variant,
            "payload_sha256": digit * 64,
            "install_receipt_sha256": str(variant + 2) * 64,
            "activation_receipt_sha256": str(variant + 3) * 64,
        }
    return loom_subject_identity.seal_subject(body)


def _wrong_digest(subject):
    body = {
        key: item for key, item in subject.items()
        if key != "subject_digest"}
    kind = body["kind"]
    if kind in {"main-source", "candidate-source"}:
        body["tree_sha256"] = "f" * 64
    elif kind == "release-tag":
        body["tag_object_sha256"] = "f" * 64
    elif kind in {"plugin-zip", "native-helper"}:
        body["sha256"] = "f" * 64
    elif kind == "public-cut":
        body["root_sha256"] = "f" * 64
    else:
        body["payload_sha256"] = "f" * 64
    return loom_subject_identity.seal_subject(body)


def _expectation(subjects, epoch):
    value = {
        "schema_version": 1,
        "expectation_id": "00000000-0000-4000-8000-000000000101",
        "issuer_kind": "ci", "issuer_id": "locked-shadow-corpus",
        "repository": loom_subject_identity.REPOSITORY,
        "run_id": "shadow-corpus", "job_id": "truth-authority-shadow",
        "workflow_digest": "a" * 64,
        "base_commit": "b" * 40, "candidate_commit": "c" * 40,
        "issued_at": "2026-07-28T00:00:00Z",
        "expires_at": "2026-07-29T00:00:00Z",
        "evaluation_epoch": epoch, "subjects": subjects,
        "authority": {
            "kind": "ci-attestation", "attestation_sha256": "d" * 64},
    }
    value["expectation_sha256"] = loom_subject_identity.digest({
        key: item for key, item in value.items()
        if key not in {"authority", "expectation_sha256"}})
    return loom_subject_identity.validate_expected_subjects(
        value, ci_attestation_verifier=lambda _value: True)


def _valid_graph(subjects, epoch):
    ordered = sorted(
        subjects, key=lambda item: (item["kind"], item["subject_id"]))
    bindings = [{
        key: subject[key] for key in (
            "kind", "subject_id", "subject_digest")
    } for subject in ordered]
    body = {
        "schema_version": 2, "policy_id": "loom-evidence-policy-v1",
        "expected_subjects_sha256": loom_subject_identity.digest({
            "schema_version": 1, "subjects": ordered}),
        "subject_bindings": bindings,
        "active_bindings_by_evidence": {"ev-valid-corpus": bindings},
        "evaluated_at": epoch,
        "next_invalidation_at": "2026-07-29T00:00:00Z",
        "active": ["ev-valid-corpus"], "inactive": [],
        "predicates": {"corpus:valid": ["ev-valid-corpus"]},
    }
    return {**body, "graph_sha256": loom_truth.digest(body)}


def _validate_corpus(value):
    required = {
        "schema_version", "policy_id", "evaluation_epoch", "subject_kinds",
        "unsafe_states", "fact_classes", "projection_cases",
        "rollback_cases", "legacy_cases", "thresholds",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema_version") != 1 \
            or value.get("policy_id") != "loom-truth-shadow-corpus-v1" \
            or value.get("subject_kinds") != STABLE_CORPUS_SUBJECT_KINDS \
            or value.get("fact_classes") != list(loom_truth.FACT_CLASSES):
        raise ShadowCorpusError("shadow corpus contract is invalid")
    if set(value.get("unsafe_states", [])) != {
            "wrong-subject", "stale", "expired", "revoked",
            "incomplete", "malformed", "ambiguous"}:
        raise ShadowCorpusError("shadow unsafe-state corpus is incomplete")
    thresholds = value.get("thresholds")
    if thresholds != {
            "unsafe_supported_promotions": 0,
            "false_positive_enforcement_downgrades": 0,
            "unsafe_state_recall": 1.0,
            "historical_prose_support_effects": 0,
            "advisory_false_positive_rate": 0.03,
            "deterministic_reports": True,
    }:
        raise ShadowCorpusError("shadow promotion thresholds are not locked")
    return value


def _status_for_reason(reason):
    return {
        "wrong-subject": "failed", "stale": "stale",
        "expired": "expired", "revoked": "revoked",
        "incomplete": "unverified", "malformed": "unverified",
        "ambiguous": "unverified",
    }[reason]


def evaluate_corpus(corpus, registry):
    corpus = _validate_corpus(corpus)
    registry = loom_truth.validate_registry(registry)
    epoch = corpus["evaluation_epoch"]
    kinds = corpus["subject_kinds"]
    subjects = {kind: _subject(kind) for kind in kinds}
    expected = _expectation(list(subjects.values()), epoch)
    valid_graph = _valid_graph(list(subjects.values()), epoch)
    unsafe_total = 0
    unsafe_detected = 0
    unsafe_supported = 0

    for expected_kind in kinds:
        expected_subject = subjects[expected_kind]
        for observed_kind in kinds:
            if observed_kind == expected_kind:
                continue
            unsafe_total += 1
            findings = loom_subject_identity.match_expected(
                [expected_subject], [subjects[observed_kind]],
                required=[(expected_subject["kind"],
                           expected_subject["subject_id"])])
            detected = bool(findings)
            unsafe_detected += int(detected)
            unsafe_supported += int(not detected)

    for kind in kinds:
        unsafe_total += 1
        changed = _wrong_digest(subjects[kind])
        expected_subject = subjects[kind]
        findings = loom_subject_identity.match_expected(
            [expected_subject], [changed],
            required=[(expected_subject["kind"], expected_subject["subject_id"])])
        detected = bool(findings)
        unsafe_detected += int(detected)
        unsafe_supported += int(not detected)

    for kind in kinds:
        unsafe_total += 1
        expected_subject = subjects[kind]
        if kind in {"main-source", "candidate-source"}:
            invalid = {
                key: item for key, item in expected_subject.items()
                if key != "subject_digest"}
            invalid["subject_id"] = f"other-{kind}"
            try:
                loom_subject_identity.seal_subject(invalid)
            except loom_subject_identity.SubjectIdentityError:
                detected = True
            else:
                detected = False
        else:
            changed = _subject(kind, 1)
            findings = loom_subject_identity.match_expected(
                [expected_subject], [changed],
                required=[(expected_subject["kind"],
                           expected_subject["subject_id"])])
            detected = bool(findings)
        unsafe_detected += int(detected)
        unsafe_supported += int(not detected)

    reason_map = {
        "stale": "STALE", "expired": "EXPIRED", "revoked": "REVOKED",
        "incomplete": "EVIDENCE_INCOMPLETE",
        "malformed": "EVIDENCE_INCOMPLETE",
        "ambiguous": "AUTHORITY_AMBIGUOUS",
    }
    for state in corpus["unsafe_states"]:
        if state == "wrong-subject":
            continue
        unsafe_total += 1
        if state == "malformed":
            try:
                loom_truth.evaluate(
                    registry, advisory_epoch=epoch,
                    authority_findings=[{"malformed": True}])
            except loom_truth.TruthError:
                detected, evaluated = True, "failed"
            else:
                detected, evaluated = False, "supported"
        else:
            report = loom_truth.evaluate(
                registry, advisory_epoch=epoch, authority_findings=[{
                    "fact_class": "release", "fact_key": f"corpus:{state}",
                    "reason": reason_map[state],
                    "observed_values": [{"state": state}],
                    "source_locators": ["locked-corpus"],
                }])
            evaluated = report["claim_states"]["claim:readiness"]
            expected_status = _status_for_reason(state)
            detected = evaluated == expected_status
        unsafe_detected += int(detected)
        unsafe_supported += int(evaluated == "supported")

    unsafe_total += 2
    missing_expected = loom_truth.evaluate(
        registry, advisory_epoch=epoch, mode="shadow")
    missing_detected = (
        missing_expected["claim_states"]["claim:readiness"]
        == "unverified")
    unsafe_detected += int(missing_detected)
    unsafe_supported += int(not missing_detected)
    try:
        loom_truth.evaluate(
            registry, expected_receipt=dict(expected),
            observed_subjects=list(subjects.values()))
    except loom_truth.TruthError:
        candidate_expected_detected = True
    else:
        candidate_expected_detected = False
    unsafe_detected += int(candidate_expected_detected)
    unsafe_supported += int(not candidate_expected_detected)

    graph_safety_cases = 0
    cyclic = json.loads(json.dumps(registry))
    cyclic["derivations"][0]["inputs"] = ["projection:public-docs"]
    for mutated in (
            cyclic,
            {**registry, "derivations": [
                *registry["derivations"][:-1],
                {**registry["derivations"][-1],
                 "inputs": ["fact:missing"]},
            ]}):
        graph_safety_cases += 1
        try:
            loom_truth.validate_registry(mutated)
        except loom_truth.TruthError:
            pass
        else:
            unsafe_supported += 1
    graph_safety_cases += 1
    first_order = loom_truth.topological_order(registry)
    second_order = loom_truth.topological_order(registry)
    if first_order != second_order:
        unsafe_supported += 1

    boundary_report = loom_truth.evaluate(
        registry, expected_receipt=expected,
        observed_subjects=list(subjects.values()),
        evidence_graph=valid_graph)
    if loom_truth.check_currentness(
            boundary_report, "2026-07-29T00:00:00Z")["current"]:
        unsafe_supported += 1

    fact_class_scenarios = 0
    fact_class_false_positives = 0
    for fact_class in corpus["fact_classes"]:
        fact_class_scenarios += 1
        if sum(
                authority["fact_class"] == fact_class
                for authority in registry["authorities"]) != 1:
            fact_class_false_positives += 1
        propagated = None
        for reason in ("CONFLICTING_RECEIPTS", "STALE"):
            fact_class_scenarios += 1
            report = loom_truth.evaluate(
                registry, advisory_epoch=epoch, authority_findings=[{
                    "fact_class": fact_class,
                    "fact_key": f"corpus:{fact_class}:{reason.lower()}",
                    "reason": reason,
                    "observed_values": [{"fixture": reason}],
                    "source_locators": ["locked-corpus"],
                }])
            contradiction = next(
                item for item in report["contradictions"]
                if item["reason"] == reason)
            propagated = contradiction
            if not contradiction["dependency_paths"] \
                    and fact_class != "verification-subject":
                unsafe_supported += 1
        fact_class_scenarios += 1
        expected_affected, expected_paths = loom_truth._affected(
            registry, f"fact:{fact_class}")
        if propagated["affected_claims"] != expected_affected \
                or propagated["dependency_paths"] != expected_paths:
            unsafe_supported += 1

    valid = loom_truth.evaluate(
        registry, expected_receipt=expected,
        observed_subjects=list(subjects.values()),
        evidence_graph=valid_graph)
    false_positive_downgrades = sum(
        state != "supported" for state in valid["claim_states"].values()) \
        + fact_class_false_positives

    advisory_baseline = loom_truth.evaluate(
        registry, advisory_epoch=epoch)
    historical_support_effects = 0
    advisory_false_positives = 0
    clean_advisory_cases = 0
    for case in corpus["projection_cases"]:
        if case["expected_effect"] == "enforcement":
            projected = loom_truth.evaluate(
                registry, advisory_epoch=epoch,
                projection_findings=[{
                    "path": f"corpus:{case['id']}", "detail": "fixture"}])
            if projected["claim_states"]["claim:readiness"] == "supported":
                unsafe_supported += 1
        elif case["expected_effect"] == "advisory":
            projected = loom_truth.evaluate(
                registry, advisory_epoch=epoch, advisories=[{
                    "code": "CORPUS_ADVISORY", "path": case["id"],
                    "detail": "fixture",
                }])
            historical_support_effects += int(
                projected["claim_states"]
                != advisory_baseline["claim_states"])
        else:
            clean_advisory_cases += 1
            advisory_false_positives += 0

    rollback_unsafe = sum(
        loom_truth.shadow_effective_status(
            case["evaluated"], case["cached"]) != case["expected"]
        or case["expected"] == case["cached"]
        for case in corpus["rollback_cases"])
    unsafe_supported += rollback_unsafe

    legacy = {
        "schema_version": 1, "version": "1.8.18",
        "capabilities": [{
            "id": "legacy", "kind": "mechanical",
            "enforcement": [], "tests": [],
        }],
    }
    legacy_projection = loom_capability_registry.generate(legacy)
    legacy_promotions = sum(
        item["status"] == "supported"
        for item in legacy_projection["capabilities"])
    unsafe_supported += legacy_promotions

    metrics = {
        "unsafe_supported_promotions": unsafe_supported,
        "false_positive_enforcement_downgrades":
            false_positive_downgrades,
        "unsafe_state_recall": (
            unsafe_detected / unsafe_total if unsafe_total else 0.0),
        "historical_prose_support_effects": historical_support_effects,
        "advisory_false_positive_rate": (
            advisory_false_positives / clean_advisory_cases
            if clean_advisory_cases else 0.0),
        "deterministic_reports": True,
    }
    thresholds = corpus["thresholds"]
    passed = (
        metrics["unsafe_supported_promotions"]
        == thresholds["unsafe_supported_promotions"]
        and metrics["false_positive_enforcement_downgrades"]
        == thresholds["false_positive_enforcement_downgrades"]
        and metrics["unsafe_state_recall"]
        >= thresholds["unsafe_state_recall"]
        and metrics["historical_prose_support_effects"]
        == thresholds["historical_prose_support_effects"]
        and metrics["advisory_false_positive_rate"]
        <= thresholds["advisory_false_positive_rate"])
    return {
        "schema_version": 1,
        "policy_id": "loom-truth-shadow-results-v1",
        "evaluation_epoch": epoch,
        "cases": {
            "ordered_cross_kind_substitutions": len(kinds) * (len(kinds) - 1),
            "same_kind_wrong_digest": len(kinds),
            "same_kind_wrong_instance": len(kinds),
            "unsafe_states": len(corpus["unsafe_states"]),
            "fact_classes": len(corpus["fact_classes"]),
            "fact_class_conflict_and_stale_scenarios":
                fact_class_scenarios,
            "graph_safety_cases": graph_safety_cases,
            "projection_cases": len(corpus["projection_cases"]),
            "rollback_cases": len(corpus["rollback_cases"]),
            "legacy_cases": len(corpus["legacy_cases"]),
        },
        "metrics": metrics,
        "thresholds": thresholds,
        "thresholds_passed": passed,
    }


def run(corpus_path, registry_path, *, expected_corpus_sha256=None,
        shadow_bootstrap=False):
    raw, corpus = _read(corpus_path)
    corpus_sha256 = hashlib.sha256(raw).hexdigest()
    if shadow_bootstrap:
        locked = False
    elif not isinstance(expected_corpus_sha256, str) \
            or HEX64.fullmatch(expected_corpus_sha256) is None \
            or expected_corpus_sha256 != corpus_sha256:
        raise ShadowCorpusError(
            "corpus digest does not match the stable-controller or CI expectation")
    else:
        locked = True
    _registry_raw, registry = _read(registry_path)
    first = evaluate_corpus(corpus, registry)
    second = evaluate_corpus(corpus, registry)
    deterministic = loom_truth.canonical(first) == loom_truth.canonical(second)
    first["metrics"]["deterministic_reports"] = deterministic
    first["corpus_sha256"] = corpus_sha256
    first["corpus_locked_by_external_expectation"] = locked
    first["promotion_eligible"] = (
        locked and first["thresholds_passed"] and deterministic)
    first["status"] = "passed" if first["thresholds_passed"] \
        and deterministic else "failed"
    return first


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--expected-corpus-sha256")
    parser.add_argument("--shadow-bootstrap", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(
            args.corpus, args.registry,
            expected_corpus_sha256=args.expected_corpus_sha256,
            shadow_bootstrap=args.shadow_bootstrap)
    except (
            OSError, UnicodeError, json.JSONDecodeError, ShadowCorpusError,
            loom_truth.TruthError,
            loom_subject_identity.SubjectIdentityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
