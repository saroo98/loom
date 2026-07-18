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


STATUSES = {"supported", "experimental", "failed", "skipped", "expired", "stale",
            "unverified", "unsupported", "not_applicable", "revoked"}
SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_RECEIPTS = 2048


class ReadinessError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _receipts(value, subject):
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
                or not SHA.fullmatch(str(row.get("artifact_sha256", ""))) \
                or type(row.get("consumption_limit")) is not int \
                or not 1 <= row["consumption_limit"] <= 16:
            raise ReadinessError("readiness evidence receipt is invalid or wrong-subject")
        consumption[row["receipt_id"]] = 1
        result.setdefault(row["claim_id"], []).append(row)
    for rows in result.values():
        for row in rows:
            if consumption[row["receipt_id"]] > row["consumption_limit"]:
                raise ReadinessError("readiness evidence was over-consumed")
    return result


def _claim(claim_id, default, summary, receipts, *, required=True):
    rows = receipts.get(claim_id, [])
    if rows:
        statuses = {row["status"] for row in rows}
        if len(statuses) != 1:
            status = "failed"
            reasons = ["CONFLICTING_EXACT_RECEIPTS"]
        else:
            status = statuses.pop()
            reasons = [] if status == "supported" else [f"EVIDENCE_{status.upper()}"]
        receipt_ids = sorted(row["receipt_id"] for row in rows)
        subject = rows[0]["release_subject"]
        valid_until = min((row["valid_until"] for row in rows
                           if row["valid_until"] is not None), default=None)
    else:
        status, receipt_ids, subject, valid_until = default, [], None, None
        reasons = [] if default in {"supported", "not_applicable"} \
            else ["QUALIFYING_RECEIPT_MISSING"]
    return {"id": claim_id, "status": status, "required": required,
            "reason_codes": reasons, "receipt_ids": receipt_ids,
            "release_subject": subject, "valid_until": valid_until,
            "public_summary": summary}


def generate(*, version, release_subject=None, evidence=None):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) \
            or release_subject is not None and not SHA.fullmatch(str(release_subject)):
        raise ReadinessError("readiness release identity is invalid")
    receipts = _receipts(evidence, release_subject) if release_subject else {}
    claims = []
    for host_id, host in loom_host_registry.HOSTS.items():
        for surface in host["surfaces"]:
            claim_id = f"host.{host_id}.{surface}"
            if host["contract_status"] == "stale":
                default = "stale"
            elif host["evidence_status"] == "unsupported":
                default = "unsupported"
            elif host["evidence_status"] == "real-host-verified":
                default = "supported"
            else:
                default = "experimental"
            claims.append(_claim(
                claim_id, default,
                "Host contract is known; support requires a current exact-host invocation receipt.",
                receipts))
    for platform_id in ("windows-x64", "windows-arm64", "macos-x64", "macos-arm64",
                        "linux-x64", "linux-arm64"):
        claims.append(_claim(
            f"platform.{platform_id}", "unverified",
            "Native platform support requires a current exact-artifact receipt.", receipts))
    for claim_id, summary in (
            ("release.exact-cut", "Exact public bytes passed their embedded suite and firewall."),
            ("release.privacy", "Every delivered byte passed the all-file privacy firewall."),
            ("release.reproducibility", "Independent builders reproduced the required artifacts."),
            ("release.sbom", "SBOMs reconcile with the final helper binaries."),
            ("release.provenance", "Portable provenance binds the immutable release subject."),
            ("release.rollback", "Runtime, state, rollback, and uninstall drills passed."),
            ("release.threshold-authority", "Independent release authorities met the threshold."),
            ("external.hostile-audit", "An independent hostile audit accepted the exact release.")):
        claims.append(_claim(claim_id, "unverified", summary, receipts))
    counts = {status: sum(item["status"] == status for item in claims)
              for status in sorted(STATUSES)}
    blockers = [item["id"] for item in claims
                if item["required"] and item["status"] not in {"supported", "not_applicable"}]
    host_contract_raw = loom_host_registry.CONTRACT_PATH.read_bytes()
    evidence_raw = _canonical(evidence) if evidence is not None else b"null"
    registry_digest = hashlib.sha256(host_contract_raw + b"\0" + evidence_raw).hexdigest()
    reviewed = loom_host_registry.REVIEWED_AT + "T00:00:00Z"
    return {"schema_version": 1, "version": version,
            "release_subject": release_subject, "generated_at": reviewed,
            "registry_sha256": registry_digest,
            "overall": "ready" if not blockers else "not-ready",
            "claims": sorted(claims, key=lambda item: item["id"]),
            "counts": counts, "promotion_blockers": blockers}


def render_markdown(value):
    lines = ["# Loom release readiness", "", f"Version: `{value['version']}`",
             f"Overall: **{value['overall'].upper()}**", "",
             "This page is generated from versioned host contracts and exact evidence receipts. ",
             "Missing evidence remains unverified; it is never converted into a pass.", "",
             "| Claim | Status | Evidence |", "| --- | --- | --- |"]
    for item in value["claims"]:
        evidence = ", ".join(item["receipt_ids"]) if item["receipt_ids"] else "none"
        lines.append(f"| `{item['id']}` | {item['status']} | {evidence} |")
    lines.extend(["", f"Registry digest: `{value['registry_sha256']}`", ""])
    return "\n".join(lines)


def render_host(host_id):
    host = loom_host_registry.HOSTS[host_id]
    roots = "\n".join(f"- `{item}`" for item in host["global_roots"])
    projects = "\n".join(f"- `{item}`" for item in host["project_roots"]) or "- none declared"
    sources = "\n".join(f"- {item}" for item in host["sources"])
    return (f"# {host_id} integration\n\n"
            f"Contract status: **{host['contract_status']}**  \n"
            f"Evidence status: **{host['evidence_status']}**  \n"
            f"Proof expiry: **{host['proof_ttl_days']} days**\n\n"
            "## Global routes\n\n" + roots + "\n\n"
            "## Project routes that can conflict\n\n" + projects + "\n\n"
            f"Precedence policy: `{host['precedence']}`. Duplicate Loom routes block execution.\n\n"
            "## Sources\n\n" + sources + "\n")


def write_outputs(root, value):
    root = Path(root).resolve()
    loom_reliability.atomic_write_json(root / "docs" / "release-readiness.json", value)
    loom_reliability.atomic_write_text(
        root / "docs" / "release-readiness.md", render_markdown(value))
    hosts = root / "docs" / "hosts"
    hosts.mkdir(parents=True, exist_ok=True)
    for host_id in loom_host_registry.HOSTS:
        loom_reliability.atomic_write_text(hosts / f"{host_id}.md", render_host(host_id))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--evidence")
    parser.add_argument("--release-subject")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    try:
        evidence = (json.loads(Path(args.evidence).read_text(encoding="utf-8"))
                    if args.evidence else None)
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
        value = generate(version=version, release_subject=args.release_subject,
                         evidence=evidence)
        if args.check:
            expected = json.loads((root / "docs" / "release-readiness.json").read_text(
                encoding="utf-8"))
            if expected != value or (root / "docs" / "release-readiness.md").read_text(
                    encoding="utf-8") != render_markdown(value):
                raise ReadinessError("generated readiness documentation is stale")
            for host_id in loom_host_registry.HOSTS:
                if (root / "docs" / "hosts" / f"{host_id}.md").read_text(
                        encoding="utf-8") != render_host(host_id):
                    raise ReadinessError("generated host documentation is stale")
        else:
            write_outputs(root, value)
    except (OSError, UnicodeError, json.JSONDecodeError, ReadinessError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "current" if args.check else "generated",
                      "overall": value["overall"],
                      "claims": len(value["claims"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
