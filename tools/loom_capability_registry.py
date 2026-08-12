#!/usr/bin/env python3
"""Generate capability projection from declarations and current typed evidence."""

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

import loom_reliability
import loom_product_interface
import loom_suite_harness
import loom_subject_identity


STATUSES = {"supported", "experimental", "stale-proof", "unsupported", "unverified"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
MAX_BYTES = 4 * 1024 * 1024
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class CapabilityRegistryError(RuntimeError):
    pass


def _check_suite_diagnostic_projection(root):
    """Keep candidate public diagnostics synchronized outside the harness."""
    policy = loom_suite_harness.load_diagnostic_policy(root)
    import loom_lifecycle
    import loom_suite_plan
    import v11_test_support
    expected = {
        "BOOTSTRAP_CONCURRENT_CHILD_FAILED",
        "BOOTSTRAP_CONCURRENT_LAUNCHER_REWRITE",
        "BOOTSTRAP_CONCURRENT_OUTPUT_INVALID",
        "BOOTSTRAP_CONCURRENT_RUNTIME_INVALID",
        "BOOTSTRAP_CONCURRENT_STAGING_SURVIVOR",
        "BOOTSTRAP_INSTALLED_PROBE_TIMEOUT",
        "BOOTSTRAP_SIGNED_ACTIVATION_TIMEOUT",
        "HOST_UNVERIFIED",
        *loom_suite_plan.SUITE_PLAN_PUBLIC_ERROR_CODES,
        *loom_lifecycle.LIFECYCLE_VERIFICATION_PUBLIC_ERROR_CODES,
        *v11_test_support.NATIVE_HELPER_PUBLIC_ERROR_CODES,
    }
    if policy["public_error_codes"] != sorted(expected):
        raise CapabilityRegistryError(
            "release suite diagnostic projection is stale")
    return policy


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CapabilityRegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path):
    try:
        path = loom_reliability._absolute(
            path, "capability registry input", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise CapabilityRegistryError(str(exc)) from exc
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise CapabilityRegistryError("registry input is missing, redirected, or oversized")
    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CapabilityRegistryError(f"registry input is invalid: {exc}") from exc


def _root_version(root):
    try:
        root_path = loom_reliability._absolute(root, "capability registry root",
                                               must_exist=True)
        version_path = loom_reliability._absolute(
            root_path / "VERSION", "capability registry VERSION", must_exist=True)
        value = version_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError, loom_reliability.ReliabilityError) as exc:
        raise CapabilityRegistryError(f"VERSION authority is unavailable: {exc}") from exc
    if not version_path.is_file() or not SEMVER_RE.fullmatch(value):
        raise CapabilityRegistryError("VERSION authority is invalid")
    return value


def _declarations(value):
    authoritative = isinstance(value, dict) \
        and value.get("schema_version") == 1 \
        and value.get("policy_id") == "loom-capability-declarations-v1"
    legacy = isinstance(value, dict) and value.get("schema_version") in {1, 2} \
        and isinstance(value.get("version"), str)
    if not (authoritative or legacy) \
            or not isinstance(value.get("capabilities"), list) \
            or len(value["capabilities"]) > 512:
        raise CapabilityRegistryError("capability declarations are invalid")
    declarations, seen = [], set()
    for item in value["capabilities"]:
        required = {"id", "kind", "enforcement", "tests"}
        allowed = set(required)
        if authoritative:
            required |= {
                "required_predicates", "required_subject_kinds", "limitations"}
            allowed = set(required)
        elif value["schema_version"] == 2:
            allowed |= {"status", "evidence_ids", "limitations", "proof_binding"}
        if not isinstance(item, dict) or not required <= set(item) or not set(item) <= allowed \
                or not isinstance(item.get("id"), str) \
                or not ID_RE.fullmatch(item["id"]) or item["id"] in seen \
                or item.get("kind") not in {"mechanical", "advisory"} \
                or not isinstance(item.get("enforcement"), list) \
                or not isinstance(item.get("tests"), list) \
                or len(item["enforcement"]) > 64 or len(item["tests"]) > 64 \
                or len(item["enforcement"]) != len(set(item["enforcement"])) \
                or len(item["tests"]) != len(set(item["tests"])) \
                or any(not isinstance(path, str) or not path
                       for path in item["enforcement"] + item["tests"]) \
                or authoritative and (
                    not isinstance(item["required_predicates"], list)
                    or not item["required_predicates"]
                    or len(item["required_predicates"])
                    != len(set(item["required_predicates"]))
                    or any(not isinstance(predicate, str) or not predicate
                           for predicate in item["required_predicates"])
                    or not isinstance(item["required_subject_kinds"], list)
                    or len(item["required_subject_kinds"])
                    != len(set(item["required_subject_kinds"]))
                    or any(kind not in loom_subject_identity.SUBJECT_KINDS
                           for kind in item["required_subject_kinds"])
                    or not isinstance(item["limitations"], list)
                    or any(not isinstance(limitation, str) or not limitation
                           for limitation in item["limitations"])):
            raise CapabilityRegistryError("capability declaration entry is invalid")
        seen.add(item["id"])
        declaration = {key: item[key] for key in
                       ("id", "kind", "enforcement", "tests")}
        declaration.update({
            "required_predicates": list(item["required_predicates"])
            if authoritative else [f"capability:{item['id']}"],
            "required_subject_kinds": list(item["required_subject_kinds"])
            if authoritative and item["kind"] == "mechanical" else [],
            "limitations": list(item["limitations"]) if authoritative else [],
        })
        declarations.append(declaration)
    return value.get("version"), declarations, authoritative


def _graph(value):
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2} \
            or value.get("policy_id") != "loom-evidence-policy-v1" \
            or not isinstance(value.get("predicates"), dict) \
            or not isinstance(value.get("inactive"), list):
        raise CapabilityRegistryError("evidence graph result is invalid")
    required = {
        "schema_version", "policy_id", "subject_digest", "evaluated_at",
        "active", "inactive", "predicates", "graph_sha256",
    } if value["schema_version"] == 1 else {
        "schema_version", "policy_id", "expected_subjects_sha256",
        "subject_bindings", "active_bindings_by_evidence",
        "evaluated_at", "next_invalidation_at",
        "active", "inactive", "predicates", "graph_sha256",
    }
    if set(value) != required:
        raise CapabilityRegistryError("evidence graph result fields are invalid")
    if value.get("graph_sha256") != _digest({
            key: item for key, item in value.items()
            if key != "graph_sha256"}):
        raise CapabilityRegistryError("evidence graph result digest is invalid")
    return value


def generate(
        declarations, graph=None, *, root=None,
        trusted_expected_subjects_sha256=None):
    version, items, authoritative = _declarations(declarations)
    graph = _graph(graph)
    if root is not None:
        try:
            root = loom_reliability._absolute(
                root, "capability proof root", must_exist=True)
        except loom_reliability.ReliabilityError as exc:
            raise CapabilityRegistryError(str(exc)) from exc
        root_version = _root_version(root)
        if authoritative:
            version = root_version
        elif version != root_version:
            version = root_version
    if authoritative and root is None:
        raise CapabilityRegistryError(
            "authoritative capability declarations require the VERSION authority")
    inactive_ids = {item.get("evidence_id") for item in graph["inactive"]} if graph else set()
    trusted_graph = graph is not None and graph["schema_version"] == 2 \
        and graph["expected_subjects_sha256"] \
        == trusted_expected_subjects_sha256
    subject_bindings = []
    if trusted_graph:
        subject_bindings = sorted({
            (binding["kind"], binding["subject_id"], binding["subject_digest"]):
            binding
            for bindings in graph["active_bindings_by_evidence"].values()
            for binding in bindings
        }.values(), key=lambda binding: (
            binding["kind"], binding["subject_id"],
            binding["subject_digest"]))
    result = []
    for item in items:
        proof_files = []
        if root is not None:
            for role, paths in (("enforcement", item["enforcement"]),
                                ("test", item["tests"])):
                for relative in paths:
                    if "\\" in relative:
                        raise CapabilityRegistryError(
                            f"capability proof path is unsafe: {item['id']}: {relative}")
                    path = PurePosixPath(relative)
                    if path.is_absolute() or not path.parts \
                            or any(part in {"", ".", ".."} for part in path.parts):
                        raise CapabilityRegistryError(
                            f"capability proof path is unsafe: {item['id']}: {relative}")
                    try:
                        target = loom_reliability._absolute(
                            root.joinpath(*path.parts), "capability proof", must_exist=True)
                    except loom_reliability.ReliabilityError as exc:
                        raise CapabilityRegistryError(str(exc)) from exc
                    if not target.is_file() or not target.is_relative_to(root):
                        raise CapabilityRegistryError(
                            f"capability proof path is missing or unsafe: "
                            f"{item['id']}: {relative}")
                    raw = target.read_bytes()
                    proof_files.append({"role": role, "path": relative,
                                        "bytes": len(raw),
                                        "sha256": hashlib.sha256(raw).hexdigest()})
        active_by_predicate = {
            predicate: sorted(graph["predicates"].get(predicate, []))
            for predicate in item["required_predicates"]} if graph else {}
        all_active = trusted_graph and bool(active_by_predicate) and all(
            active_by_predicate[predicate] for predicate in active_by_predicate)
        active = sorted({
            evidence_id
            for evidence_ids in active_by_predicate.values()
            for evidence_id in evidence_ids})
        relevant_bindings = []
        if trusted_graph:
            relevant_bindings = sorted({
                (binding["kind"], binding["subject_id"], binding["subject_digest"]):
                binding
                for evidence_id in active
                for binding in graph["active_bindings_by_evidence"].get(
                    evidence_id, [])
            }.values(), key=lambda binding: (
                binding["kind"], binding["subject_id"],
                binding["subject_digest"]))
        subject_kinds = {binding["kind"] for binding in relevant_bindings}
        stale = sorted(inactive_ids & set(
            evidence_id for row in (graph["inactive"] if graph else [])
            for evidence_id in [row.get("evidence_id")]
            if isinstance(evidence_id, str) and evidence_id.startswith(
                f"ev-cap-{item['id']}-")))
        if item["kind"] == "advisory":
            status = "unsupported"
            limitations = item["limitations"] or [
                "Human judgment is not machine-enforced."]
        elif all_active and root is not None \
                and set(item["required_subject_kinds"]) <= subject_kinds:
            status = "supported"
            limitations = item["limitations"]
        elif all_active:
            status = "unverified"
            limitations = item["limitations"] + [
                "Evidence is incomplete until code bytes and every required typed "
                "subject are bound."]
        elif stale:
            status = "stale-proof"
            limitations = item["limitations"] + [
                "The last bound proof expired, was revoked, became stale, or lost a dependency."]
        else:
            status = "unverified"
            limitations = item["limitations"] + [
                "No current exact-subject typed evidence envelope is active."]
        public_declaration = {key: item[key] for key in
                              ("id", "kind", "enforcement", "tests",
                               "required_predicates", "required_subject_kinds")}
        result.append({**public_declaration, "status": status,
                       "evidence_ids": active or stale,
                       "limitations": limitations,
                       "proof_binding": {
                           "subject_bindings": relevant_bindings,
                           "evidence_graph_sha256": graph["graph_sha256"] if graph else None,
                           "files": proof_files,
                       }})
    return {
        "schema_version": 3, "version": version,
        "generated_by": "tools/loom_capability_registry.py",
        "evidence_policy": "loom-evidence-policy-v1",
        "declarations_policy": "loom-capability-declarations-v1"
        if authoritative else "legacy-read-only",
        "subject_bindings": subject_bindings,
        "expected_subjects_sha256": (
            graph.get("expected_subjects_sha256") if trusted_graph else None),
        "evaluated_at": graph["evaluated_at"] if graph else None,
        "next_invalidation_at": (
            graph.get("next_invalidation_at") if trusted_graph else None),
        "capabilities": result,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--graph")
    parser.add_argument("--expected-subjects")
    parser.add_argument("--trusted-ci-attestation")
    parser.add_argument("--trusted-run-id")
    parser.add_argument("--output")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--now")
    args = parser.parse_args(argv)
    try:
        root = loom_reliability._absolute(
            args.root, "capability registry root", must_exist=True)
        declarations_path = root / "contracts" / "capability-declarations-v1.json"
        declarations = _read(declarations_path)
        loom_product_interface.load(root)
        _check_suite_diagnostic_projection(root)
        graph = _read(args.graph) if args.graph else None
        trusted_expected_digest = None
        if args.expected_subjects:
            expected_receipt = loom_subject_identity.validate_expected_subjects(
                _read(args.expected_subjects),
                ci_attestation_verifier=lambda candidate: (
                    candidate["issuer_kind"] == "ci"
                    and candidate["run_id"] == args.trusted_run_id
                    and candidate["authority"]["attestation_sha256"]
                    == args.trusted_ci_attestation))
            trusted_expected_digest = loom_subject_identity.digest({
                "schema_version": 1,
                "subjects": sorted(
                    expected_receipt["subjects"],
                    key=lambda item: (item["kind"], item["subject_id"])),
            })
        result = generate(
            declarations, graph, root=root,
            trusted_expected_subjects_sha256=trusted_expected_digest)
        output = loom_reliability._absolute(
            args.output if args.output else root / "docs" / "capabilities.json",
            "capability registry output")
        if args.check:
            if result["next_invalidation_at"] is not None:
                if args.now is None:
                    raise CapabilityRegistryError(
                        "trusted current time is required for capability expiry")
                try:
                    current = dt.datetime.fromisoformat(
                        args.now.replace("Z", "+00:00"))
                    boundary = dt.datetime.fromisoformat(
                        result["next_invalidation_at"].replace("Z", "+00:00"))
                except (AttributeError, ValueError) as exc:
                    raise CapabilityRegistryError(
                        "capability expiry time is invalid") from exc
                if current.tzinfo is None or boundary.tzinfo is None \
                        or current >= boundary:
                    raise CapabilityRegistryError(
                        "capability evidence crossed its invalidation boundary")
            if _read(output) != result:
                raise CapabilityRegistryError(
                    "generated capability projection is stale")
        else:
            loom_reliability.atomic_write_json(output, result)
    except (
            CapabilityRegistryError, loom_reliability.ReliabilityError,
            loom_product_interface.ProductInterfaceError,
            loom_subject_identity.SubjectIdentityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "current" if args.check else "generated",
                      "output": str(output),
                      "capabilities": len(result["capabilities"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
