#!/usr/bin/env python3
"""Closed, bounded, privacy-safe reasons for Loom terminal blocks."""

import hashlib
import json
import re
from pathlib import PurePosixPath


SCHEMA_VERSION = 1
MAX_TEXT = 240
MAX_FINDINGS = 8
CODE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
FINDING_RE = re.compile(r"^[A-Z][A-Z0-9._-]{0,63}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
CATEGORIES = {
    "authority", "configuration", "domain", "handler", "intent",
    "lifecycle", "memory", "project", "recovery", "unknown",
}
LIFECYCLE_STATES = {
    "current", "invalid", "missing", "not-applicable", "stale", "unknown",
}
OWNERSHIP = {
    "loom-owned", "not-applicable", "owner-modified", "unknown", "unowned",
}
PRISTINE_PROOF = {"failed", "not-applicable", "proved", "unknown"}
RECOVERY = {"not-applicable", "owner-decision", "safe", "unsafe", "unknown"}

_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/]|\\\\|/(?:home|users|private|tmp|var/tmp)(?:/|\b))")
_SECRET_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)"
    r"\s*(?:=|:|is\b|was\b)\s*[^\s,;]{4,}|"
    r"\b(?:ghp|github_pat|sk|xox[baprs])[_-][A-Za-z0-9_-]{12,}|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b)")


class BlockReasonError(ValueError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value, label):
    if not isinstance(value, str):
        raise BlockReasonError(f"{label} is invalid")
    normalized = " ".join(value.split()).strip()
    if not normalized or len(normalized) > MAX_TEXT:
        raise BlockReasonError(f"{label} is invalid")
    if _ABSOLUTE_PATH_RE.search(normalized) or _SECRET_RE.search(normalized):
        raise BlockReasonError(f"{label} contains private or secret-bearing content")
    return normalized


def safe_text(value, fallback):
    """Return bounded safe diagnostic text without echoing rejected input."""
    try:
        return _text(value, "diagnostic text")
    except BlockReasonError:
        return _text(fallback, "diagnostic fallback")


def _safe_path(value):
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 240 \
            or "\\" in value or ":" in value or any(ord(char) < 32 for char in value):
        raise BlockReasonError("safe_path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) \
            or path.as_posix() != value:
        raise BlockReasonError("safe_path is invalid")
    return value


def validate(value):
    fields = {
        "schema_version", "code", "category", "expected", "observed",
        "safe_path", "lifecycle_state", "finding_codes", "finding_count",
        "ownership", "pristine_proof", "changes_made", "automatic_recovery",
        "next_action", "implementation_authorized", "requires_new_action",
        "reason_hash",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or not isinstance(value.get("code"), str) \
            or not CODE_RE.fullmatch(value["code"]) \
            or value.get("category") not in CATEGORIES \
            or value.get("lifecycle_state") not in LIFECYCLE_STATES \
            or value.get("ownership") not in OWNERSHIP \
            or value.get("pristine_proof") not in PRISTINE_PROOF \
            or value.get("automatic_recovery") not in RECOVERY \
            or type(value.get("changes_made")) is not bool \
            or value.get("implementation_authorized") is not False \
            or value.get("requires_new_action") is not True:
        raise BlockReasonError("block reason fields are invalid")
    _text(value["expected"], "expected")
    _text(value["observed"], "observed")
    _text(value["next_action"], "next_action")
    _safe_path(value["safe_path"])
    codes = value.get("finding_codes")
    count = value.get("finding_count")
    if not isinstance(codes, list) or len(codes) > MAX_FINDINGS \
            or len(codes) != len(set(codes)) \
            or not all(isinstance(item, str) and FINDING_RE.fullmatch(item)
                       for item in codes) \
            or type(count) is not int or not 0 <= count <= 4096 \
            or count < len(codes):
        raise BlockReasonError("block reason findings are invalid")
    body = {key: value[key] for key in fields - {"reason_hash"}}
    if not isinstance(value.get("reason_hash"), str) \
            or not DIGEST_RE.fullmatch(value["reason_hash"]) \
            or value["reason_hash"] != _digest(body):
        raise BlockReasonError("block reason digest is invalid")
    return value


def build(*, code, category, expected, observed, safe_path=None,
          lifecycle_state="not-applicable", finding_codes=(), finding_count=None,
          ownership="not-applicable", pristine_proof="not-applicable",
          changes_made=False, automatic_recovery="not-applicable", next_action):
    codes = list(dict.fromkeys(str(item).upper() for item in finding_codes))[:MAX_FINDINGS]
    body = {
        "schema_version": SCHEMA_VERSION,
        "code": str(code).casefold().replace("_", "-")[:128],
        "category": category,
        "expected": _text(expected, "expected"),
        "observed": _text(observed, "observed"),
        "safe_path": _safe_path(safe_path),
        "lifecycle_state": lifecycle_state,
        "finding_codes": codes,
        "finding_count": len(codes) if finding_count is None else finding_count,
        "ownership": ownership,
        "pristine_proof": pristine_proof,
        "changes_made": changes_made,
        "automatic_recovery": automatic_recovery,
        "next_action": _text(next_action, "next_action"),
        "implementation_authorized": False,
        "requires_new_action": True,
    }
    return validate({**body, "reason_hash": _digest(body)})


def generic(code, recommendation, *, category="unknown"):
    normalized_code = str(code).casefold().replace("_", "-")[:128]
    observed = safe_text(
        recommendation,
        "Loom could not establish a trustworthy authority state for this request.")
    finding = re.sub(r"[^A-Z0-9._-]", "-", str(code).upper())[:64].strip("-")
    if not finding or not FINDING_RE.fullmatch(finding):
        finding = "BLOCKED"
    return build(
        code=normalized_code, category=category,
        expected="One unambiguous, current, and safely authorized Loom action.",
        observed=observed,
        finding_codes=[finding], finding_count=1,
        ownership="not-applicable", pristine_proof="not-applicable",
        automatic_recovery="owner-decision",
        next_action="Resolve the reported condition, then start a fresh Loom request.")
