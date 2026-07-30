#!/usr/bin/env python3
"""Evaluate closed truth authorities and emit deterministic contradiction reports."""

import argparse
import datetime as dt
import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath

import loom_reliability
import loom_subject_identity


POLICY_ID = "loom-truth-authority-v1"
FACT_CLASSES = (
    "version", "inventory", "schema-protocol", "capability",
    "release", "platform-host", "generated-freshness", "verification-subject",
)
EVALUATORS = {
    "identity", "evidence-predicate", "capability-status",
    "readiness-status", "projection-freshness",
}
REPAIR = {
    "WRONG_SUBJECT": "replace-or-revoke-evidence",
    "EXPIRED": "replace-or-revoke-evidence",
    "REVOKED": "replace-or-revoke-evidence",
    "STALE": "repair-governing-source",
    "EVIDENCE_INCOMPLETE": "downgrade-claim",
    "AUTHORITY_AMBIGUOUS": "register-unique-authority",
    "CONFLICTING_RECEIPTS": "repair-governing-source",
    "EXPECTED_SUBJECT_UNAVAILABLE": "downgrade-claim",
    "PROJECTION_STALE": "repair-projection-materializer",
}
STATUS = {
    "WRONG_SUBJECT": "failed",
    "EXPIRED": "expired",
    "REVOKED": "revoked",
    "STALE": "stale",
    "EVIDENCE_INCOMPLETE": "unverified",
    "AUTHORITY_AMBIGUOUS": "unverified",
    "CONFLICTING_RECEIPTS": "failed",
    "EXPECTED_SUBJECT_UNAVAILABLE": "unverified",
    "PROJECTION_STALE": "stale",
}
INACTIVE_REASON = {
    "wrong-subject": "WRONG_SUBJECT",
    "expected-subject-unavailable": "EXPECTED_SUBJECT_UNAVAILABLE",
    "expired": "EXPIRED",
    "revoked": "REVOKED",
    "stale": "STALE",
    "verification-failed": "EVIDENCE_INCOMPLETE",
    "evidence-incomplete": "EVIDENCE_INCOMPLETE",
    "authority-ambiguous": "AUTHORITY_AMBIGUOUS",
    "conflicting-receipts": "CONFLICTING_RECEIPTS",
    "dependency-inactive": "EVIDENCE_INCOMPLETE",
}
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPENDENCY_PATHS = 4096
NODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
TRUTH_STATUSES = {
    "supported", "unsupported", "unverified", "stale",
    "expired", "revoked", "failed",
}


class TruthError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TruthError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path, label):
    path = Path(path)
    try:
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_size > MAX_BYTES:
            raise TruthError(f"{label} is missing, redirected, or oversized")
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TruthError(f"{label} is invalid: {exc}") from exc


def _safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise TruthError("truth registry path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TruthError("truth registry path is unsafe")
    return path.as_posix()


def validate_registry(value):
    fields = {
        "schema_version", "policy_id", "fact_classes", "authorities",
        "derivations", "generated_outputs", "structured_projections", "budgets",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or value.get("policy_id") != POLICY_ID \
            or value.get("fact_classes") != list(FACT_CLASSES):
        raise TruthError("truth authority registry fields are invalid")
    authorities, authority_ids = value.get("authorities"), set()
    if not isinstance(authorities, list) or not 8 <= len(authorities) <= 256:
        raise TruthError("truth authority registry is incomplete")
    for authority in authorities:
        required = {"id", "fact_class", "locator", "reader", "subject_kinds"}
        if not isinstance(authority, dict) or set(authority) != required \
                or not isinstance(authority["id"], str) \
                or not NODE.fullmatch(authority["id"]) \
                or authority["id"] in authority_ids \
                or authority["fact_class"] not in FACT_CLASSES \
                or authority["reader"] not in {
                    "semver-file", "git-tree", "json-contract",
                    "typed-subject-set", "generated-manifest"} \
                or not isinstance(authority["locator"], str) \
                or not authority["locator"] \
                or not isinstance(authority["subject_kinds"], list) \
                or len(authority["subject_kinds"]) \
                != len(set(authority["subject_kinds"])) \
                or any(kind not in loom_subject_identity.SUBJECT_KINDS
                       for kind in authority["subject_kinds"]):
            raise TruthError("truth authority declaration is invalid")
        authority_ids.add(authority["id"])
    for fact_class in FACT_CLASSES:
        if sum(item["fact_class"] == fact_class for item in authorities) != 1:
            raise TruthError(
                f"fact class {fact_class} lacks one unique governing authority")
    generated, generated_paths = value.get("generated_outputs"), set()
    if not isinstance(generated, list) or len(generated) > 256:
        raise TruthError("generated output inventory is invalid")
    for item in generated:
        if not isinstance(item, dict) or set(item) != {
                "path", "generator", "inputs"} \
                or _safe_path(item["path"]) in generated_paths \
                or not isinstance(item["generator"], str) \
                or not re.fullmatch(r"tools/loom_[a-z0-9_]+\.py", item["generator"]) \
                or not isinstance(item["inputs"], list) or not item["inputs"]:
            raise TruthError("generated output declaration is invalid")
        generated_paths.add(item["path"])
    expected_budgets = {
        "git_entries": loom_subject_identity.MAX_GIT_ENTRIES,
        "git_blob_bytes": loom_subject_identity.MAX_GIT_BLOB_BYTES,
        "git_total_bytes": loom_subject_identity.MAX_GIT_TOTAL_BYTES,
        "overlay_entries": loom_subject_identity.MAX_OVERLAY_ENTRIES,
        "overlay_total_bytes": loom_subject_identity.MAX_OVERLAY_TOTAL_BYTES,
        "generated_outputs": loom_subject_identity.MAX_GENERATED_OUTPUTS,
        "generated_file_bytes":
            loom_subject_identity.MAX_GENERATED_FILE_BYTES,
        "generated_total_bytes":
            loom_subject_identity.MAX_GENERATED_TOTAL_BYTES,
    }
    if value.get("budgets") != expected_budgets:
        raise TruthError(
            "truth authority budgets differ from the hard evaluator bounds")
    projections, projection_ids = value.get("structured_projections"), set()
    if not isinstance(projections, list) or len(projections) > 128:
        raise TruthError("structured projection registry is invalid")
    for item in projections:
        if not isinstance(item, dict) or set(item) != {
                "id", "path", "selector_kind", "selector", "authority_id"} \
                or item["id"] in projection_ids \
                or item["authority_id"] not in authority_ids \
                or item["selector_kind"] not in {
                    "json-pointer", "html-data-attribute",
                    "markdown-marker", "full-file"} \
                or item["selector_kind"] == "json-pointer" \
                and not item["selector"].startswith("/") \
                or item["selector_kind"] == "html-data-attribute" \
                and not item["selector"].startswith("data-loom-") \
                or item["selector_kind"] == "markdown-marker" \
                and NODE.fullmatch(item["selector"]) is None \
                or item["selector_kind"] == "full-file" \
                and item["path"] not in generated_paths:
            raise TruthError("structured projection declaration is invalid")
        _safe_path(item["path"])
        projection_ids.add(item["id"])
    topological_order(value)
    return value


def topological_order(registry):
    derivations = registry.get("derivations")
    if not isinstance(derivations, list) or len(derivations) > 1024:
        raise TruthError("truth derivation registry is invalid")
    rows, indegree, downstream = {}, {}, defaultdict(set)
    for item in derivations:
        if not isinstance(item, dict) or set(item) != {
                "id", "inputs", "evaluator"} \
                or not isinstance(item["id"], str) \
                or not NODE.fullmatch(item["id"]) or item["id"] in rows \
                or item["evaluator"] not in EVALUATORS \
                or not isinstance(item["inputs"], list) \
                or len(item["inputs"]) > 64 \
                or len(item["inputs"]) != len(set(item["inputs"])):
            raise TruthError("truth derivation is invalid")
        rows[item["id"]] = item
        indegree[item["id"]] = len(item["inputs"])
    for item in rows.values():
        for dependency in item["inputs"]:
            if dependency not in rows:
                raise TruthError(
                    f"truth derivation dependency is missing: {dependency}")
            downstream[dependency].add(item["id"])
    ready = sorted(node for node, count in indegree.items() if count == 0)
    ordered = []
    while ready:
        node = ready.pop(0)
        ordered.append(node)
        for dependent in sorted(downstream[node]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if len(ordered) != len(rows):
        raise TruthError("truth derivation graph contains a cycle")
    return ordered


def _reverse_edges(registry):
    result = defaultdict(set)
    for item in registry["derivations"]:
        for dependency in item["inputs"]:
            result[dependency].add(item["id"])
    return result


def _affected(registry, origin):
    reverse = _reverse_edges(registry)
    queue, paths, visited = deque([(origin, [origin])]), [], set()
    while queue:
        node, path = queue.popleft()
        if (node, tuple(path)) in visited:
            continue
        visited.add((node, tuple(path)))
        if len(visited) > MAX_DEPENDENCY_PATHS:
            raise TruthError("truth affected-claim propagation exceeds its bound")
        for dependent in sorted(reverse[node]):
            child = path + [dependent]
            if dependent.startswith(("claim:", "projection:")):
                paths.append(child)
                if len(paths) > MAX_DEPENDENCY_PATHS:
                    raise TruthError(
                        "truth dependency path report exceeds its bound")
            queue.append((dependent, child))
    affected = sorted({path[-1] for path in paths})
    return affected, sorted(paths)


def _authority(registry, fact_class):
    return next(item for item in registry["authorities"]
                if item["fact_class"] == fact_class)


def _contradiction(
        registry, *, fact_class, fact_key, reason, expected_subjects=(),
        observed_subjects=(), observed_values=(), source_locators=(),
        evaluated_at, next_invalidation_at=None):
    authority = _authority(registry, fact_class)
    origin = f"fact:{fact_class}"
    affected, paths = _affected(registry, origin)
    identity = {
        "fact_class": fact_class, "fact_key": fact_key,
        "governing_source_id": authority["id"], "reason": reason,
        "expected_subject_digests": sorted(
            item["subject_digest"] for item in expected_subjects),
        "observed_subject_digests": sorted(
            item["subject_digest"] for item in observed_subjects),
        "observed_value_digests": sorted(digest(item) for item in observed_values),
    }
    return {
        "id": digest(identity), "fact_class": fact_class, "fact_key": fact_key,
        "reason": reason,
        "disposition": "block" if reason in {
            "WRONG_SUBJECT", "EXPIRED", "REVOKED", "CONFLICTING_RECEIPTS"} else
            "downgrade",
        "governing_source_id": authority["id"],
        "authority_sha256": digest(authority),
        "expected_subjects": sorted(
            expected_subjects,
            key=lambda item: (item["kind"], item["subject_id"])),
        "observed_subjects": sorted(
            observed_subjects,
            key=lambda item: (item["kind"], item["subject_id"])),
        "observed_values": sorted(
            observed_values, key=lambda item: canonical(item)),
        "source_locators": sorted(set(source_locators)),
        "affected_claims": affected, "dependency_paths": paths,
        "smallest_repair": REPAIR[reason],
        "evaluated_at": evaluated_at,
        "next_invalidation_at": next_invalidation_at,
    }


def _subject_fact(kind):
    if kind in {"main-source", "candidate-source"}:
        return "inventory"
    if kind in {"release-tag", "plugin-zip"}:
        return "release"
    return "platform-host"


def _normalize_time(value):
    return loom_subject_identity._instant(
        value, "evaluation epoch").isoformat().replace("+00:00", "Z")


def evaluate(
        registry, *, expected_receipt=None, observed_subjects=(),
        evidence_graph=None, authority_findings=(), projection_findings=(),
        advisories=(),
        mode="shadow", advisory_epoch=None):
    registry = validate_registry(registry)
    if mode not in {"shadow", "enforced"}:
        raise TruthError("truth evaluation mode is invalid")
    expected = []
    expected_digest = None
    next_invalidation = None
    if expected_receipt is not None:
        if not isinstance(
                expected_receipt,
                loom_subject_identity.VerifiedExpectedSubjects):
            raise TruthError(
                "expected subjects were not verified by a stable controller or CI")
        expected = expected_receipt["subjects"]
        expected_digest = expected_receipt["expectation_sha256"]
        evaluated_at = _normalize_time(expected_receipt["evaluation_epoch"])
        next_invalidation = _normalize_time(expected_receipt["expires_at"])
    else:
        if mode != "shadow" or advisory_epoch is None:
            raise TruthError(
                "shadow evaluation without verified expectations needs an explicit "
                "advisory epoch")
        evaluated_at = _normalize_time(advisory_epoch)
    expected_map = loom_subject_identity.subject_map(list(expected))
    observed_map = loom_subject_identity.subject_map(list(observed_subjects))
    contradictions = []
    if expected_receipt is None:
        contradictions.append(_contradiction(
            registry, fact_class="verification-subject",
            fact_key="expected-subject-set",
            reason="EXPECTED_SUBJECT_UNAVAILABLE",
            observed_subjects=list(observed_map.values()),
            source_locators=["stable-controller-or-ci"],
            evaluated_at=evaluated_at))
    else:
        for key, expected_subject in sorted(expected_map.items()):
            observed = observed_map.get(key)
            if observed is None or observed["subject_digest"] \
                    != expected_subject["subject_digest"]:
                contradictions.append(_contradiction(
                    registry, fact_class=_subject_fact(key[0]),
                    fact_key=f"{key[0]}:{key[1]}", reason="WRONG_SUBJECT",
                    expected_subjects=[expected_subject],
                    observed_subjects=[observed] if observed else [],
                    source_locators=[_authority(
                        registry, _subject_fact(key[0]))["locator"]],
                    evaluated_at=evaluated_at,
                    next_invalidation_at=next_invalidation))
    if evidence_graph is not None:
        if not isinstance(evidence_graph, dict) \
                or evidence_graph.get("schema_version") != 2 \
                or evidence_graph.get("policy_id") \
                != "loom-evidence-policy-v1" \
                or not isinstance(evidence_graph.get("inactive"), list) \
                or not isinstance(evidence_graph.get("active"), list) \
                or evidence_graph.get("graph_sha256") != digest({
                    key: item for key, item in evidence_graph.items()
                    if key != "graph_sha256"}):
            raise TruthError("evidence graph result is invalid")
        if expected_receipt is not None:
            expected_subject_digest = loom_subject_identity.digest({
                "schema_version": 1,
                "subjects": sorted(
                    expected_receipt["subjects"],
                    key=lambda item: (item["kind"], item["subject_id"])),
            })
            if evidence_graph.get("expected_subjects_sha256") \
                    != expected_subject_digest \
                    or evidence_graph.get("evaluated_at") != evaluated_at:
                raise TruthError(
                    "evidence graph does not bind the trusted expectation")
        graph_next = evidence_graph.get("next_invalidation_at")
        if isinstance(graph_next, str):
            normalized = _normalize_time(graph_next)
            if next_invalidation is None or normalized < next_invalidation:
                next_invalidation = normalized
        for item in evidence_graph["inactive"]:
            reason = INACTIVE_REASON.get(item.get("reason"))
            if reason is None:
                continue
            bindings = item.get("subject_bindings", [])
            kinds = {binding.get("kind") for binding in bindings
                     if isinstance(binding, dict)}
            fact_class = "platform-host" if kinds & {
                "native-helper", "installed-runtime"} else \
                "release" if kinds & {"release-tag", "plugin-zip"} else \
                "verification-subject"
            contradictions.append(_contradiction(
                registry, fact_class=fact_class,
                fact_key=item.get("evidence_id", "unknown-evidence"),
                reason=reason,
                observed_values=[{"inactive_reason": item.get("reason")}],
                source_locators=["evidence-graph"],
                evaluated_at=evaluated_at,
                next_invalidation_at=next_invalidation))
        if expected_receipt is not None and not evidence_graph["active"] \
                and not evidence_graph["inactive"]:
            contradictions.append(_contradiction(
                registry, fact_class="verification-subject",
                fact_key="evidence-graph", reason="EVIDENCE_INCOMPLETE",
                observed_values=[{"detail": "no evaluated evidence"}],
                source_locators=["evidence-graph"],
                evaluated_at=evaluated_at,
                next_invalidation_at=next_invalidation))
    elif expected_receipt is not None:
        contradictions.append(_contradiction(
            registry, fact_class="verification-subject",
            fact_key="evidence-graph", reason="EVIDENCE_INCOMPLETE",
            observed_values=[{"detail": "evidence graph unavailable"}],
            source_locators=["evidence-graph"],
            evaluated_at=evaluated_at,
            next_invalidation_at=next_invalidation))
    for finding in authority_findings:
        fields = {
            "fact_class", "fact_key", "reason", "observed_values",
            "source_locators",
        }
        if not isinstance(finding, dict) or set(finding) != fields \
                or finding["fact_class"] not in FACT_CLASSES \
                or finding["reason"] not in {
                    "EVIDENCE_INCOMPLETE", "AUTHORITY_AMBIGUOUS",
                    "CONFLICTING_RECEIPTS", "STALE", "EXPIRED", "REVOKED",
                } \
                or not isinstance(finding["fact_key"], str) \
                or not finding["fact_key"] \
                or not isinstance(finding["observed_values"], list) \
                or not isinstance(finding["source_locators"], list):
            raise TruthError("authority finding is invalid")
        contradictions.append(_contradiction(
            registry, fact_class=finding["fact_class"],
            fact_key=finding["fact_key"], reason=finding["reason"],
            observed_values=finding["observed_values"],
            source_locators=finding["source_locators"],
            evaluated_at=evaluated_at,
            next_invalidation_at=next_invalidation))
    for finding in projection_findings:
        if not isinstance(finding, dict) or set(finding) != {
                "path", "detail"}:
            raise TruthError("projection finding is invalid")
        contradictions.append(_contradiction(
            registry, fact_class="generated-freshness",
            fact_key=finding["path"], reason="PROJECTION_STALE",
            observed_values=[{"detail": finding["detail"]}],
            source_locators=[finding["path"]],
            evaluated_at=evaluated_at,
            next_invalidation_at=next_invalidation))
    contradictions = sorted(
        {item["id"]: item for item in contradictions}.values(),
        key=lambda item: (
            item["fact_class"], item["fact_key"], item["reason"], item["id"]))
    claim_states = {
        item["id"]: "supported" for item in registry["derivations"]
        if item["id"].startswith("claim:")
    }
    for contradiction in contradictions:
        state = STATUS[contradiction["reason"]]
        for claim in contradiction["affected_claims"]:
            if not claim.startswith("claim:"):
                continue
            current = claim_states.get(claim, "supported")
            order = {
                "supported": 0, "unsupported": 1, "unverified": 2,
                "stale": 3, "expired": 4, "revoked": 5, "failed": 6,
            }
            if order[state] > order[current]:
                claim_states[claim] = state
    normalized_advisories = []
    for item in advisories:
        if not isinstance(item, dict) or set(item) != {"code", "path", "detail"}:
            raise TruthError("truth advisory is invalid")
        normalized_advisories.append(dict(item))
    body = {
        "schema_version": 1, "policy_id": POLICY_ID, "mode": mode,
        "evaluated_at": evaluated_at,
        "next_invalidation_at": next_invalidation,
        "authority_registry_sha256": digest(registry),
        "expected_subjects_sha256": expected_digest,
        "contradictions": contradictions,
        "advisories": sorted(
            normalized_advisories,
            key=lambda item: (item["path"], item["code"], item["detail"])),
        "claim_states": dict(sorted(claim_states.items())),
    }
    return {**body, "report_sha256": digest(body)}


def check_currentness(report, now):
    if not isinstance(report, dict) or report.get("report_sha256") != digest({
            key: item for key, item in report.items() if key != "report_sha256"}):
        raise TruthError("truth report digest is invalid")
    boundary = report.get("next_invalidation_at")
    if boundary is None:
        return {"status": "unbounded", "current": True}
    current = loom_subject_identity._instant(now, "now")
    limit = loom_subject_identity._instant(boundary, "next_invalidation_at")
    return {"status": "current" if current < limit else "expired",
            "current": current < limit, "next_invalidation_at": boundary}


def shadow_effective_status(evaluated_status, cached_status=None):
    """Never restore a cached support state over a current unsafe evaluation."""
    if evaluated_status not in TRUTH_STATUSES \
            or cached_status is not None and cached_status not in TRUTH_STATUSES:
        raise TruthError("truth status is invalid")
    return evaluated_status


def enforcement_outcome(report):
    if not isinstance(report, dict) or report.get("mode") not in {
            "shadow", "enforced"} \
            or not isinstance(report.get("contradictions"), list):
        raise TruthError("truth enforcement report is invalid")
    unsafe = any(item.get("disposition") == "block"
                 for item in report["contradictions"])
    policy_failure = report["mode"] == "enforced" \
        and bool(report["contradictions"])
    return "failed" if unsafe or policy_failure else "passed"


def render_markdown(report):
    lines = [
        "# Loom truth contradictions", "",
        f"Mode: **{report['mode']}**",
        f"Evaluated at: `{report['evaluated_at']}`",
        f"Next invalidation: `{report['next_invalidation_at'] or 'none'}`", "",
        "Unsafe evidence is downgraded in every mode. Shadow mode changes only "
        "whether non-safety contradictions fail CI.", "",
        "| Fact | Reason | Governing source | Affected claims | Repair |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report["contradictions"]:
        affected = ", ".join(item["affected_claims"]) or "none"
        lines.append(
            f"| `{item['fact_key']}` | {item['reason']} | "
            f"`{item['governing_source_id']}` | {affected} | "
            f"`{item['smallest_repair']}` |")
    if not report["contradictions"]:
        lines.append("| none | none | none | none | none |")
    lines.extend(["", "## Advisory prose", ""])
    if report["advisories"]:
        lines.extend(
            f"- `{item['path']}`: {item['detail']} (`{item['code']}`)"
            for item in report["advisories"])
    else:
        lines.append("- none")
    lines.extend(["", f"Report digest: `{report['report_sha256']}`", ""])
    return "\n".join(lines)


def _projection_findings(root):
    findings = []
    try:
        import loom_semantic_parity
    except ImportError:
        return [{
            "path": "docs/generated-semantic-parity.json",
            "detail": "registered semantic parity projection is unavailable",
        }]
    try:
        expected = loom_semantic_parity.compile_report(root)
        observed = read_json(
            Path(root) / "docs" / "generated-semantic-parity.json",
            "semantic parity projection")
        if observed != expected:
            findings.append({
                "path": "docs/generated-semantic-parity.json",
                "detail": "registered semantic parity projection is stale",
            })
    except (TruthError, loom_semantic_parity.ParityError):
        findings.append({
            "path": "docs/generated-semantic-parity.json",
            "detail": "registered semantic parity projection is unavailable",
        })
    return findings


def _advisory_prose(root):
    findings = []
    probes = {
        "README.md": re.compile(
            r"(?:published release|current candidate).{0,40}v?[0-9]+\.[0-9]+\.[0-9]+",
            re.I),
    }
    for relative, pattern in probes.items():
        path = Path(root) / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if pattern.search(text):
            findings.append({
                "code": "UNREGISTERED_VERSION_PROSE",
                "path": relative,
                "detail": "Version prose is advisory because this location is not "
                          "a registered structured projection.",
            })
    return findings


def _load_subjects(path):
    if path is None:
        return []
    value = read_json(path, "observed subject set")
    subjects = value.get("subjects") if isinstance(value, dict) else None
    loom_subject_identity.subject_map(subjects)
    return subjects


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--registry")
    parser.add_argument("--expected")
    parser.add_argument("--observed")
    parser.add_argument("--graph")
    parser.add_argument("--mode", choices=("shadow", "enforced"), default="shadow")
    parser.add_argument("--advisory-epoch")
    parser.add_argument("--trusted-ci-attestation")
    parser.add_argument("--trusted-run-id")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--now")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    registry_path = Path(args.registry) if args.registry else \
        root / "contracts" / "truth-authorities-v1.json"
    output = root / "docs" / "truth-contradictions.json"
    try:
        registry = validate_registry(read_json(registry_path, "truth registry"))
        if args.check:
            report = read_json(output, "truth report")
            expected_receipt = None
            if report.get("expected_subjects_sha256") is not None:
                if not args.expected:
                    raise TruthError(
                        "verified expectation is required to recompute this report")
                expected_receipt = loom_subject_identity.validate_expected_subjects(
                    read_json(args.expected, "expected subject set"),
                    ci_attestation_verifier=lambda value: (
                        value["issuer_kind"] == "ci"
                        and value["run_id"] == args.trusted_run_id
                        and value["authority"]["attestation_sha256"]
                        == args.trusted_ci_attestation))
            recomputed = evaluate(
                registry, expected_receipt=expected_receipt,
                observed_subjects=_load_subjects(args.observed),
                evidence_graph=(
                    read_json(args.graph, "evidence graph")
                    if args.graph else None),
                projection_findings=_projection_findings(root),
                advisories=_advisory_prose(root),
                mode=report.get("mode"),
                advisory_epoch=(
                    report.get("evaluated_at")
                    if expected_receipt is None else None))
            if recomputed != report:
                raise TruthError(
                    "truth contradiction report is stale at its stored epoch")
            if report.get("next_invalidation_at") is not None \
                    and args.now is None:
                raise TruthError(
                    "trusted current time is required for a live expiry check")
            status = check_currentness(report, args.now) if args.now else {
                "status": "content-current", "current": True}
            if not status["current"]:
                raise TruthError("truth contradiction report crossed its invalidation boundary")
        else:
            expected = None
            if args.expected:
                expected = read_json(args.expected, "expected subject set")
                trusted_attestation = args.trusted_ci_attestation
                trusted_run = args.trusted_run_id
                expected = loom_subject_identity.validate_expected_subjects(
                    expected,
                    ci_attestation_verifier=lambda value: (
                        value["issuer_kind"] == "ci"
                        and value["run_id"] == trusted_run
                        and value["authority"]["attestation_sha256"]
                        == trusted_attestation))
            graph = read_json(args.graph, "evidence graph") if args.graph else None
            report = evaluate(
                registry, expected_receipt=expected,
                observed_subjects=_load_subjects(args.observed),
                evidence_graph=graph,
                projection_findings=_projection_findings(root),
                advisories=_advisory_prose(root),
                mode=args.mode, advisory_epoch=args.advisory_epoch)
            loom_reliability.atomic_write_json(output, report)
            status = {"status": "generated", "current": True}
    except (
            OSError, UnicodeError, json.JSONDecodeError, TruthError,
            loom_subject_identity.SubjectIdentityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": status["status"],
        "contradictions": len(report["contradictions"]),
        "advisories": len(report["advisories"]),
        "report_sha256": report["report_sha256"],
    }, sort_keys=True))
    return 1 if enforcement_outcome(report) == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
