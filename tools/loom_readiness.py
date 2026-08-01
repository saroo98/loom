#!/usr/bin/env python3
"""Generate release and host truth surfaces from closed contracts and exact receipts."""

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import loom_host_registry
import loom_reliability
import loom_subject_identity


STATUSES = {"supported", "experimental", "failed", "skipped", "expired", "stale",
            "unverified", "unsupported", "not_applicable", "revoked"}
SUPPORT_STATUSES = {"supported", "experimental", "stale", "unsupported",
                    "not_applicable"}
SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_RECEIPTS = 2048
GRAPH_FIELDS = {
    "schema_version", "policy_id", "expected_subjects_sha256",
    "subject_bindings", "active_bindings_by_evidence", "evaluated_at",
    "next_invalidation_at", "active", "inactive", "predicates",
    "graph_sha256",
}
INACTIVE_STATUS = {
    "wrong-subject": ("failed", "WRONG_SUBJECT"),
    "expired": ("expired", "EXPIRED"),
    "revoked": ("revoked", "REVOKED"),
    "stale": ("stale", "STALE"),
    "expected-subject-unavailable": (
        "unverified", "EXPECTED_SUBJECT_UNAVAILABLE"),
    "verification-failed": ("unverified", "EVIDENCE_INCOMPLETE"),
    "dependency-inactive": ("unverified", "EVIDENCE_INCOMPLETE"),
}
STATUS_ORDER = {
    "supported": 0, "not_applicable": 0, "experimental": 1,
    "unsupported": 2, "unverified": 3, "stale": 4, "expired": 5,
    "revoked": 6, "failed": 7, "skipped": 1,
}


class ReadinessError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _time(value, label):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ReadinessError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ReadinessError(f"{label} lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _stamp(value):
    return _time(value, "evaluation epoch").replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def _public_binding(value):
    required = {"kind", "subject_id", "subject_digest"}
    if not isinstance(value, dict) or set(value) != required \
            or value.get("kind") not in loom_subject_identity.SUBJECT_KINDS \
            or not isinstance(value.get("subject_id"), str) \
            or not value["subject_id"] \
            or SHA.fullmatch(str(value.get("subject_digest", ""))) is None:
        raise ReadinessError("readiness subject binding is invalid")
    return {key: value[key] for key in ("kind", "subject_id", "subject_digest")}


def _receipts(value, subject, *, evaluation_epoch):
    """Read legacy aggregate receipts for inspection without promoting them."""
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) != {"schema_version", "receipts"} \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("receipts"), list) \
            or len(value["receipts"]) > MAX_RECEIPTS:
        raise ReadinessError("readiness evidence bundle is invalid")
    result, consumption = {}, {}
    required = {"receipt_id", "claim_id", "status", "release_subject", "valid_until",
                "evidence_class", "artifact_sha256", "runner", "consumption_limit"}
    for row in value["receipts"]:
        if not isinstance(row, dict) or set(row) != required \
                or not isinstance(row.get("receipt_id"), str) or not row["receipt_id"] \
                or row["receipt_id"] in consumption \
                or not isinstance(row.get("claim_id"), str) or not row["claim_id"] \
                or row.get("status") not in STATUSES \
                or row.get("release_subject") != subject \
                or row.get("evidence_class") not in {
                    "mechanical-local", "host-observed", "ci-reproduced",
                    "real-host", "provider-native", "independently-witnessed",
                    "independent-external"} \
                or not isinstance(row.get("runner"), str) \
                or not row["runner"].strip() \
                or not SHA.fullmatch(str(row.get("artifact_sha256", ""))) \
                or type(row.get("consumption_limit")) is not int \
                or not 1 <= row["consumption_limit"] <= 16:
            raise ReadinessError("readiness evidence receipt is invalid or wrong-subject")
        if row["valid_until"] is not None:
            valid_until = _time(row["valid_until"], "legacy receipt expiry")
            if evaluation_epoch >= valid_until:
                row = {**row, "status": "expired"}
        consumption[row["receipt_id"]] = 1
        result.setdefault(row["claim_id"], []).append(row)
    for rows in result.values():
        for row in rows:
            if consumption[row["receipt_id"]] > row["consumption_limit"]:
                raise ReadinessError("readiness evidence was over-consumed")
    return result


def _legacy_claim(claim_id, default, summary, receipts, *, required=True,
                  support_status="supported"):
    rows = receipts.get(claim_id, [])
    if rows:
        statuses = {row["status"] for row in rows}
        if len(statuses) != 1:
            status = "failed"
            reasons = ["CONFLICTING_EXACT_RECEIPTS"]
        else:
            status = statuses.pop()
            reasons = [] if status == "supported" else [f"EVIDENCE_{status.upper()}"]
        if status == "supported":
            status = "unverified"
            reasons = ["LEGACY_SUBJECT_UNTYPED"]
        receipt_ids = sorted(row["receipt_id"] for row in rows)
        subject = rows[0]["release_subject"]
        valid_until = min((row["valid_until"] for row in rows
                           if row["valid_until"] is not None), default=None)
    else:
        status, receipt_ids, subject, valid_until = default, [], None, None
        reasons = (
            [] if default in {"supported", "not_applicable"} else
            ["GOVERNING_SOURCE_STALE"] if default == "stale" else
            ["GOVERNING_SOURCE_UNSUPPORTED"] if default == "unsupported" else
            ["QUALIFYING_RECEIPT_MISSING"])
    return {"id": claim_id, "status": status,
            "support_status": support_status, "evidence_status": status,
            "required": required,
            "reason_codes": reasons, "receipt_ids": receipt_ids,
            "subject_bindings": [], "legacy_release_subject": subject,
            "valid_until": valid_until,
            "public_summary": summary}


def _graph(value, trusted_expected_subjects_sha256):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != GRAPH_FIELDS \
            or value.get("schema_version") != 2 \
            or value.get("policy_id") != "loom-evidence-policy-v1" \
            or value.get("graph_sha256") != hashlib.sha256(_canonical({
                key: item for key, item in value.items()
                if key != "graph_sha256"})).hexdigest() \
            or not SHA.fullmatch(str(
                value.get("expected_subjects_sha256", ""))) \
            or value["expected_subjects_sha256"] \
            != trusted_expected_subjects_sha256 \
            or not isinstance(value.get("predicates"), dict) \
            or not isinstance(value.get("active"), list) \
            or not isinstance(value.get("inactive"), list) \
            or not isinstance(value.get("active_bindings_by_evidence"), dict):
        raise ReadinessError(
            "typed evidence graph is invalid or lacks a trusted expectation binding")
    active = set(value["active"])
    if set(value["active_bindings_by_evidence"]) != active:
        raise ReadinessError("typed active evidence binding inventory is incomplete")
    for evidence_id, bindings in value["active_bindings_by_evidence"].items():
        if not isinstance(evidence_id, str) or not evidence_id \
                or not isinstance(bindings, list) or not bindings:
            raise ReadinessError("typed active evidence binding is incomplete")
        for binding in bindings:
            _public_binding(binding)
    for predicate, evidence_ids in value["predicates"].items():
        if not isinstance(predicate, str) or not predicate \
                or not isinstance(evidence_ids, list) \
                or not set(evidence_ids) <= active:
            raise ReadinessError("typed readiness predicate index is invalid")
    for item in value["inactive"]:
        if not isinstance(item, dict) or set(item) != {
                "evidence_id", "reason", "predicate_type",
                "subject_bindings"} \
                or item.get("reason") not in INACTIVE_STATUS \
                or not isinstance(item.get("subject_bindings"), list):
            raise ReadinessError("typed inactive evidence is invalid")
        for binding in item["subject_bindings"]:
            _public_binding(binding)
    _time(value["evaluated_at"], "typed graph evaluation epoch")
    if value["next_invalidation_at"] is not None:
        _time(value["next_invalidation_at"], "typed graph invalidation boundary")
    return value


def _typed_claim(claim_id, summary, graph, required_kinds, *, required=True,
                 support_status="supported"):
    active = sorted(graph["predicates"].get(claim_id, [])) if graph else []
    inactive = [
        item for item in graph["inactive"]
        if item["predicate_type"] == claim_id] if graph else []
    bindings = sorted({
        (binding["kind"], binding["subject_id"], binding["subject_digest"]):
        _public_binding(binding)
        for evidence_id in active
        for binding in graph["active_bindings_by_evidence"][evidence_id]
    }.values(), key=lambda item: (
        item["kind"], item["subject_id"], item["subject_digest"]))
    kinds = {item["kind"] for item in bindings}
    if active and set(required_kinds) <= kinds:
        status, reasons = "supported", []
    elif active:
        status, reasons = "unverified", ["EVIDENCE_INCOMPLETE"]
    elif inactive:
        states = [INACTIVE_STATUS[item["reason"]] for item in inactive]
        status, reason = max(states, key=lambda item: STATUS_ORDER[item[0]])
        reasons = [reason]
    else:
        status, reasons = "unverified", ["QUALIFYING_RECEIPT_MISSING"]
    return {
        "id": claim_id, "status": status,
        "support_status": support_status, "evidence_status": status,
        "required": required,
        "reason_codes": reasons, "receipt_ids": active or sorted(
            item["evidence_id"] for item in inactive),
        "subject_bindings": bindings, "legacy_release_subject": None,
        "valid_until": graph["next_invalidation_at"] if graph and active else None,
        "public_summary": summary,
    }


def _truth_clamp(claim, truth_report):
    if truth_report is None:
        return claim
    state = truth_report["claim_states"].get("claim:readiness", "supported")
    if STATUS_ORDER[state] <= STATUS_ORDER[claim["status"]]:
        return claim
    return {
        **claim, "status": state, "evidence_status": state,
        "reason_codes": sorted(set(
            claim["reason_codes"] + ["TRUTH_CONTRADICTION"])),
    }


def _validate_truth(report, *, evaluation_epoch, expected_subjects_sha256):
    if report is None:
        return None
    if not isinstance(report, dict) \
            or report.get("report_sha256") != hashlib.sha256(_canonical({
                key: item for key, item in report.items()
                if key != "report_sha256"})).hexdigest() \
            or report.get("evaluated_at") != evaluation_epoch \
            or report.get("expected_subjects_sha256") \
            != expected_subjects_sha256 \
            or not isinstance(report.get("claim_states"), dict):
        raise ReadinessError("truth report does not bind this readiness evaluation")
    return report


def generate(*, version, release_subject=None, evidence=None,
             evaluation_epoch=None, trusted_expected_subjects_sha256=None,
             truth_report=None, report_kind="source-tree",
             release_subject_sha256=None):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) \
            or release_subject is not None and not SHA.fullmatch(str(release_subject)) \
            or report_kind not in {"source-tree", "release"} \
            or report_kind == "source-tree" and release_subject_sha256 is not None \
            or report_kind == "release" and not SHA.fullmatch(
                str(release_subject_sha256 or "")):
        raise ReadinessError("readiness release identity is invalid")
    epoch = _stamp(
        evaluation_epoch or loom_host_registry.REVIEWED_AT + "T00:00:00Z")
    graph = None
    legacy_receipts = {}
    if evidence is not None and isinstance(evidence, dict) \
            and evidence.get("schema_version") == 2:
        if not SHA.fullmatch(str(trusted_expected_subjects_sha256 or "")):
            raise ReadinessError(
                "typed readiness requires a stable-controller or CI expectation digest")
        graph = _graph(evidence, trusted_expected_subjects_sha256)
        if graph["evaluated_at"] != epoch:
            raise ReadinessError(
                "readiness epoch differs from typed evidence evaluation")
    elif evidence is not None:
        if release_subject is None:
            raise ReadinessError("legacy readiness evidence lacks its aggregate subject")
        legacy_receipts = _receipts(
            evidence, release_subject, evaluation_epoch=_time(epoch, "evaluation epoch"))
    truth_report = _validate_truth(
        truth_report, evaluation_epoch=epoch,
        expected_subjects_sha256=(
            graph["expected_subjects_sha256"] if graph else None))
    claims = []
    for host_id, host in loom_host_registry.HOSTS.items():
        for surface in host["surfaces"]:
            claim_id = f"host.{host_id}.{surface}"
            summary = (
                "Host contract is known; support requires current exact "
                "candidate, runtime, and helper receipts.")
            if host["contract_status"] == "stale":
                default = "stale"
                support_status = "stale"
            elif host["evidence_status"] == "unsupported":
                default = "unsupported"
                support_status = "unsupported"
            elif host["evidence_status"] == "experimental":
                default = "unverified"
                support_status = "experimental"
            else:
                default = "unverified"
                support_status = "supported"
            claim = _typed_claim(
                claim_id, summary, graph,
                ("candidate-source", "installed-runtime", "native-helper"),
                support_status=support_status) \
                if graph else _legacy_claim(
                    claim_id, default, summary, legacy_receipts,
                    support_status=support_status)
            claims.append(_truth_clamp(claim, truth_report))
    for platform_id in ("windows-x64", "windows-arm64", "macos-x64", "macos-arm64",
                        "linux-x64", "linux-arm64"):
        claim_id = f"platform.{platform_id}"
        summary = "Native platform support requires a current exact-helper receipt."
        claim = _typed_claim(
            claim_id, summary, graph, ("native-helper",),
            support_status="supported") \
            if graph else _legacy_claim(
                claim_id, "unverified", summary, legacy_receipts,
                support_status="supported")
        claims.append(_truth_clamp(claim, truth_report))
    for claim_id, summary in (
            ("release.exact-cut", "Exact public bytes passed their embedded suite and firewall."),
            ("release.privacy", "Every delivered byte passed the all-file privacy firewall."),
            ("release.reproducibility", "Independent builders reproduced the required artifacts."),
            ("release.sbom", "SBOMs reconcile with the final helper binaries."),
            ("release.provenance", "Portable provenance binds the immutable release subject."),
            ("release.rollback", "Runtime, state, rollback, and uninstall drills passed."),
            ("release.threshold-authority", "Independent release authorities met the threshold."),
            ("external.hostile-audit", "An independent hostile audit accepted the exact release.")):
        required_kinds = (
            "main-source", "candidate-source", "release-tag",
            "plugin-zip", "native-helper",
        )
        claim = _typed_claim(
            claim_id, summary, graph, required_kinds,
            support_status="supported") \
            if graph else _legacy_claim(
                claim_id, "unverified", summary, legacy_receipts,
                support_status="supported")
        claims.append(_truth_clamp(claim, truth_report))
    counts = {status: sum(item["status"] == status for item in claims)
              for status in sorted(STATUSES)}
    support_counts = {
        status: sum(item["support_status"] == status for item in claims)
        for status in sorted(SUPPORT_STATUSES)}
    blockers = [item["id"] for item in claims
                if item["required"] and item["status"] not in {"supported", "not_applicable"}]
    host_contract_raw = loom_host_registry.CONTRACT_PATH.read_bytes()
    evidence_raw = _canonical(evidence) if evidence is not None else b"null"
    truth_raw = _canonical(truth_report) if truth_report is not None else b"null"
    registry_digest = hashlib.sha256(
        host_contract_raw + b"\0" + evidence_raw + b"\0" + truth_raw).hexdigest()
    subject_bindings = sorted({
        (binding["kind"], binding["subject_id"], binding["subject_digest"]):
        binding
        for claim in claims for binding in claim["subject_bindings"]
    }.values(), key=lambda item: (
        item["kind"], item["subject_id"], item["subject_digest"]))
    next_invalidation = graph["next_invalidation_at"] if graph else min(
        (claim["valid_until"] for claim in claims
         if claim["valid_until"] is not None), default=None)
    return {"schema_version": 3, "report_kind": report_kind,
            "version": version,
            "release_subject_sha256": release_subject_sha256,
            "evaluated_at": epoch, "next_invalidation_at": next_invalidation,
            "expected_subjects_sha256": (
                graph["expected_subjects_sha256"] if graph else None),
            "subject_bindings": subject_bindings,
            "legacy_release_subject": release_subject,
            "registry_sha256": registry_digest,
            "overall": "ready" if not blockers else "not-ready",
            "claims": sorted(claims, key=lambda item: item["id"]),
            "counts": counts, "support_counts": support_counts,
            "promotion_blockers": blockers}


def render_markdown(value):
    title = ("Loom release readiness" if value.get("report_kind") == "release"
             else "Loom source-tree readiness")
    lines = [f"# {title}", "", f"Version: `{value['version']}`",
             f"Overall: **{value['overall'].upper()}**", "",
             f"Evaluated at: `{value['evaluated_at']}`",
             f"Next invalidation: `{value['next_invalidation_at'] or 'none'}`", "",
             "This page is generated from versioned host contracts and exact evidence receipts. ",
             "Missing evidence remains unverified; it is never converted into a pass.", "",
             "| Claim | Support | Evidence | Receipts |",
             "| --- | --- | --- | --- |"]
    for item in value["claims"]:
        evidence = ", ".join(item["receipt_ids"]) if item["receipt_ids"] else "none"
        lines.append(
            f"| `{item['id']}` | {item['support_status']} | "
            f"{item['evidence_status']} | {evidence} |")
    lines.extend(["", f"Registry digest: `{value['registry_sha256']}`", ""])
    return "\n".join(lines)


def render_host(host_id):
    host = loom_host_registry.HOSTS[host_id]
    roots = "\n".join(f"- `{item}`" for item in host["global_roots"])
    projects = "\n".join(f"- `{item}`" for item in host["project_roots"]) or "- none declared"
    sources = "\n".join(f"- {item}" for item in host["sources"])
    assurance = ""
    if host_id == "codex":
        assurance = (
            "## Canonical route\n\n"
            "For a marketplace installation, the enabled plugin's skill and local stdio MCP "
            "server are canonical. The global roots above are direct-source fallback routes, "
            "not additional routes to retain beside the plugin. During an approved plugin "
            "migration, Loom removes only an exact receipt-owned user MCP registration and "
            "moves only an exact receipt-owned direct skill into a private rollback archive. "
            "An unowned, changed, or ambiguous duplicate blocks migration instead of being "
            "overwritten or deleted.\n\n"
            "## Assurance modes\n\n"
            "- **Standard:** the plugin-provided local MCP server bootstraps and delegates to the "
            "stable launcher. It needs no lifecycle-hook trust and makes no hook-enforcement "
            "claim.\n"
            "- **Verified:** after one explicit approval, receipt-owned user hooks add exact "
            "prompt sealing, bounded session continuity, structured-write scope checks, freshness "
            "observations, compaction continuity, and subagent/stop observations. Codex hook "
            "coverage is a guardrail, not a sandbox; unsupported or unobserved tool paths remain "
            "outside the claim.\n\n"
        )
    return (f"# {host_id} integration\n\n"
            f"Contract status: **{host['contract_status']}**<br>\n"
            f"Evidence status: **{host['evidence_status']}**<br>\n"
            f"Proof expiry: **{host['proof_ttl_days']} days**\n\n"
            "## Global routes\n\n" + roots + "\n\n"
            "## Project routes that can conflict\n\n" + projects + "\n\n"
            f"Precedence policy: `{host['precedence']}`. Duplicate Loom routes block execution.\n\n"
            + assurance + "## Sources\n\n" + sources + "\n")


def write_outputs(root, value):
    root = Path(root).resolve()
    loom_reliability.atomic_write_json(root / "docs" / "release-readiness.json", value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--evidence")
    parser.add_argument("--release-subject")
    parser.add_argument("--evaluation-epoch")
    parser.add_argument("--expected-subjects")
    parser.add_argument("--trusted-ci-attestation")
    parser.add_argument("--trusted-run-id")
    parser.add_argument("--truth-report")
    parser.add_argument("--now")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    try:
        evidence = (json.loads(Path(args.evidence).read_text(encoding="utf-8"))
                    if args.evidence else None)
        trusted_expected_digest = None
        if args.expected_subjects:
            expected_receipt = loom_subject_identity.validate_expected_subjects(
                json.loads(Path(args.expected_subjects).read_text(
                    encoding="utf-8")),
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
        truth_path = Path(args.truth_report) if args.truth_report else \
            root / "docs" / "truth-contradictions.json"
        truth_report = (
            json.loads(truth_path.read_text(encoding="utf-8"))
            if truth_path.is_file() else None)
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
        value = generate(version=version, release_subject=args.release_subject,
                         evidence=evidence,
                         evaluation_epoch=(
                             args.evaluation_epoch
                             or truth_report and truth_report["evaluated_at"]),
                         trusted_expected_subjects_sha256=(
                             trusted_expected_digest),
                         truth_report=truth_report)
        if args.check:
            if value["next_invalidation_at"] is not None:
                if args.now is None:
                    raise ReadinessError(
                        "trusted current time is required for readiness expiry")
                if _time(args.now, "trusted current time") >= _time(
                        value["next_invalidation_at"],
                        "readiness invalidation boundary"):
                    raise ReadinessError(
                        "readiness evidence crossed its invalidation boundary")
            expected = json.loads((root / "docs" / "release-readiness.json").read_text(
                encoding="utf-8"))
            if expected != value:
                raise ReadinessError("generated readiness data is stale")
        else:
            write_outputs(root, value)
    except (
            OSError, UnicodeError, json.JSONDecodeError, ReadinessError,
            loom_subject_identity.SubjectIdentityError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "current" if args.check else "generated",
                      "overall": value["overall"],
                      "claims": len(value["claims"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
