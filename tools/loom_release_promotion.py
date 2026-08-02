#!/usr/bin/env python3
"""Verify draft or public release bytes without building, uploading, or rewriting."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_reliability


class PromotionError(RuntimeError):
    pass


_GATE_FIELDS = {
    "signed_tag_verified", "passport_verified", "matrix_certificate_verified",
    "native_evidence_verified", "rollback_verified", "attestation_verified",
    "expected_sha256", "release_asset_sha256",
}
MAX_GATE_BYTES = 64 * 1024


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_gate(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() \
            or not 0 < path.stat().st_size <= MAX_GATE_BYTES:
        raise PromotionError("promotion gate is unsafe")
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PromotionError("promotion gate is unreadable") from exc


def _digest(value):
    if isinstance(value, str) and value.startswith("sha256:"):
        value = value[7:]
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PromotionError("release digest is invalid")
    return value


def _verify(asset, gate, status):
    if not isinstance(gate, dict) or set(gate) != _GATE_FIELDS:
        raise PromotionError("promotion gate is incomplete or contains unknown fields")
    for name in sorted(_GATE_FIELDS - {"expected_sha256", "release_asset_sha256"}):
        if gate[name] is not True:
            raise PromotionError(name.replace("_verified", "").replace("_", " ") +
                                 " verification failed")
    expected = _digest(gate["expected_sha256"])
    api_digest = _digest(gate["release_asset_sha256"])
    path = Path(asset).resolve()
    if not path.is_file() or path.is_symlink():
        raise PromotionError("downloaded release asset is unsafe")
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected or api_digest != expected:
        raise PromotionError("downloaded, expected, and release API bytes disagree")
    normalized_gate = dict(gate)
    normalized_gate["expected_sha256"] = expected
    normalized_gate["release_asset_sha256"] = api_digest
    body = {"schema_version": 1, "status": status, "asset_sha256": observed,
            "asset_bytes": path.stat().st_size, "gate": normalized_gate}
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def verify_draft(asset, gate):
    return _verify(asset, gate, "verified-draft")


def verify_public(asset, gate, *, installed_subject_sha256=None,
                  represented_installed_subjects=()):
    result = _verify(asset, gate, "verified-public")
    installed = (_digest(installed_subject_sha256)
                 if installed_subject_sha256 is not None else result["asset_sha256"])
    represented = sorted({_digest(value) for value in represented_installed_subjects})
    body = {key: value for key, value in result.items() if key != "receipt_sha256"}
    body.update({"installed_subject_sha256": installed,
                 "represented_installed_subjects": represented,
                 "behavior_rerun_required": installed != result["asset_sha256"]
                 and installed not in represented})
    return {**body, "receipt_sha256": hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-draft", "verify-public"))
    parser.add_argument("asset")
    parser.add_argument("--gate", required=True)
    parser.add_argument("--installed-subject")
    parser.add_argument("--represented-installed-subject", action="append", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        gate = _load_gate(args.gate)
        result = (verify_draft(args.asset, gate) if args.command == "verify-draft"
                  else verify_public(args.asset, gate,
                                     installed_subject_sha256=args.installed_subject,
                                     represented_installed_subjects=(
                                         args.represented_installed_subject)))
        output = Path(args.output).resolve()
        if output.exists():
            raise PromotionError("promotion receipt output already exists")
        loom_reliability.atomic_write_json(output, result)
    except (PromotionError, loom_reliability.ReliabilityError, OSError,
            UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": result["status"],
                      "receipt_sha256": result["receipt_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
