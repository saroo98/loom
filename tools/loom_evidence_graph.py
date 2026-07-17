#!/usr/bin/env python3
"""Validate bounded evidence envelopes and propagate expiry and revocation."""

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


MAX_BYTES = 8 * 1024 * 1024
MAX_ENVELOPES = 4096
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^ev-[a-z0-9._-]{1,96}$")
PREDICATE_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
EVIDENCE_CLASSES = {
    "mechanical-local", "ci-reproduced", "real-host", "provider-native",
    "host-observed", "longitudinal-local", "independently-witnessed",
    "independent-external", "public-adoption",
}
ENVELOPE_FIELDS = {
    "schema_version", "evidence_id", "subject_digest", "predicate_type",
    "producer", "evidence_class", "environment", "issued_at", "expires_at",
    "payload_sha256", "limitations", "signer", "verifier", "depends_on",
    "revoked", "envelope_sha256",
}


class EvidenceGraphError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceGraphError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _time(value, label):
    if not isinstance(value, str):
        raise EvidenceGraphError(f"{label} is not a timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceGraphError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise EvidenceGraphError(f"{label} lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _read(path):
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise EvidenceGraphError("evidence bundle is missing, redirected, or oversized")
    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceGraphError(f"evidence bundle is invalid: {exc}") from exc


def seal_envelope(value):
    body = {key: item for key, item in value.items() if key != "envelope_sha256"}
    return {**body, "envelope_sha256": digest(body)}


def _validate_envelope(value, subject_digest):
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("evidence_id"), str) \
            or not ID_RE.fullmatch(value["evidence_id"]) \
            or value.get("subject_digest") != subject_digest \
            or not isinstance(value.get("predicate_type"), str) \
            or not PREDICATE_RE.fullmatch(value["predicate_type"]) \
            or value.get("evidence_class") not in EVIDENCE_CLASSES \
            or not isinstance(value.get("environment"), dict) \
            or len(value["environment"]) > 32 \
            or not isinstance(value.get("payload_sha256"), str) \
            or not SHA_RE.fullmatch(value["payload_sha256"]) \
            or not isinstance(value.get("limitations"), list) \
            or len(value["limitations"]) > 32 \
            or any(not isinstance(item, str) or not item or len(item) > 512
                   for item in value["limitations"]) \
            or not isinstance(value.get("depends_on"), list) \
            or len(value["depends_on"]) > 64 \
            or len(value["depends_on"]) != len(set(value["depends_on"])) \
            or any(not isinstance(item, str) or not ID_RE.fullmatch(item)
                   for item in value["depends_on"]) \
            or type(value.get("revoked")) is not bool:
        raise EvidenceGraphError("evidence envelope fields are invalid")
    producer = value.get("producer")
    if not isinstance(producer, dict) or set(producer) != {"id", "version", "digest"} \
            or not all(isinstance(producer[key], str) and producer[key]
                       for key in ("id", "version", "digest")) \
            or not SHA_RE.fullmatch(producer["digest"]):
        raise EvidenceGraphError("evidence producer is invalid")
    signer = value.get("signer")
    if not isinstance(signer, dict) or set(signer) != {
            "authority", "key_id", "algorithm", "signature"} \
            or not isinstance(signer["authority"], str) or not signer["authority"] \
            or signer["algorithm"] not in {
                "none", "rsa-pkcs1v15-sha256", "ed25519", "sigstore-bundle"} \
            or (signer["algorithm"] == "none" and (
                signer["key_id"] is not None or signer["signature"] is not None)) \
            or (signer["algorithm"] != "none" and (
                not isinstance(signer["key_id"], str) or not signer["key_id"]
                or not isinstance(signer["signature"], str) or not signer["signature"])):
        raise EvidenceGraphError("evidence signer is invalid")
    if value["evidence_class"] not in {"mechanical-local", "host-observed"} \
            and signer["algorithm"] == "none":
        raise EvidenceGraphError("non-local evidence lacks a signed authority")
    verifier = value.get("verifier")
    if not isinstance(verifier, dict) or set(verifier) != {
            "id", "verified_at", "status"} \
            or not isinstance(verifier["id"], str) or not verifier["id"] \
            or verifier["status"] not in {"passed", "failed", "unverified"}:
        raise EvidenceGraphError("evidence verifier is invalid")
    issued = _time(value["issued_at"], "issued_at")
    verified = _time(verifier["verified_at"], "verified_at")
    expires = _time(value["expires_at"], "expires_at") \
        if value["expires_at"] is not None else None
    if verified < issued or expires is not None and expires <= issued:
        raise EvidenceGraphError("evidence time ordering is invalid")
    if value["envelope_sha256"] != digest({
            key: item for key, item in value.items() if key != "envelope_sha256"}):
        raise EvidenceGraphError("evidence envelope digest mismatch")


def evaluate(bundle, *, as_of=None):
    if not isinstance(bundle, dict) or set(bundle) != {
            "schema_version", "policy_id", "subject_digest", "envelopes"} \
            or bundle.get("schema_version") != 1 \
            or bundle.get("policy_id") != "loom-evidence-policy-v1" \
            or not isinstance(bundle.get("subject_digest"), str) \
            or not SHA_RE.fullmatch(bundle["subject_digest"]) \
            or not isinstance(bundle.get("envelopes"), list) \
            or len(bundle["envelopes"]) > MAX_ENVELOPES:
        raise EvidenceGraphError("evidence graph bundle is invalid")
    by_id = {}
    for envelope in bundle["envelopes"]:
        _validate_envelope(envelope, bundle["subject_digest"])
        if envelope["evidence_id"] in by_id:
            raise EvidenceGraphError("duplicate evidence identity")
        by_id[envelope["evidence_id"]] = envelope
    for envelope in by_id.values():
        if not set(envelope["depends_on"]) <= set(by_id):
            raise EvidenceGraphError("evidence dependency is missing")
    visiting, visited = set(), set()
    def visit(evidence_id):
        if evidence_id in visiting:
            raise EvidenceGraphError("evidence graph contains a cycle")
        if evidence_id in visited:
            return
        visiting.add(evidence_id)
        for dependency in by_id[evidence_id]["depends_on"]:
            visit(dependency)
        visiting.remove(evidence_id); visited.add(evidence_id)
    for evidence_id in sorted(by_id):
        visit(evidence_id)
    evaluated = (as_of or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    states = {}
    def state(evidence_id):
        if evidence_id in states:
            return states[evidence_id]
        envelope = by_id[evidence_id]
        reason = None
        if envelope["revoked"]:
            reason = "revoked"
        elif envelope["expires_at"] is not None \
                and _time(envelope["expires_at"], "expires_at") <= evaluated:
            reason = "expired"
        elif envelope["verifier"]["status"] != "passed":
            reason = "verification-failed"
        elif any(state(dependency) is not None
                 for dependency in envelope["depends_on"]):
            reason = "dependency-inactive"
        states[evidence_id] = reason
        return reason
    for evidence_id in sorted(by_id):
        state(evidence_id)
    active = sorted(evidence_id for evidence_id, reason in states.items() if reason is None)
    predicates = {}
    for evidence_id in active:
        predicates.setdefault(by_id[evidence_id]["predicate_type"], []).append(evidence_id)
    body = {
        "schema_version": 1, "policy_id": bundle["policy_id"],
        "subject_digest": bundle["subject_digest"],
        "evaluated_at": evaluated.isoformat().replace("+00:00", "Z"),
        "active": active,
        "inactive": [{"evidence_id": evidence_id, "reason": states[evidence_id]}
                     for evidence_id in sorted(by_id) if states[evidence_id] is not None],
        "predicates": {key: sorted(value) for key, value in sorted(predicates.items())},
    }
    return {**body, "graph_sha256": digest(body)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle")
    parser.add_argument("--as-of")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        as_of = _time(args.as_of, "as_of") if args.as_of else None
        result = evaluate(_read(args.bundle), as_of=as_of)
    except EvidenceGraphError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
