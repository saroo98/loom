#!/usr/bin/env python3
"""Closed authority receipts for Loom developing or verifying Loom."""

import datetime as dt
import base64
import hashlib
import json
import re
import uuid


ROLES = {
    "owner", "stable_controller", "candidate_runtime", "candidate_self_test",
    "external_verifier", "release_authority",
}
ACTIONS = {"plan", "authorize", "repair", "self-test", "verify", "certify", "sign"}
ACTION_ROLE = {
    "plan": "stable_controller",
    "authorize": "stable_controller",
    "repair": "stable_controller",
    "self-test": "candidate_self_test",
    "verify": "external_verifier",
    "certify": "external_verifier",
    "sign": "release_authority",
}
SAFE_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class SelfHostingError(ValueError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _instant(value, label):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise SelfHostingError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise SelfHostingError(f"{label} must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc)


def _receipt_hash(value):
    return _hash({
        key: item for key, item in value.items()
        if key not in {"receipt_hash", "authority"}
    })


def _signed_payload(value):
    return _canonical({
        key: item for key, item in value.items()
        if key not in {"receipt_hash", "authority"}
    })


def create(*, controller_subject, candidate_subject, candidate_source_digest,
           dirty_diff_digest, candidate_build_digest, roles, allowed_actions,
           issued_at, expires_at, historical_work=False,
           causal_scope="implementation", external_verification_digest=None,
           authority_key_id, authority_public_key, signer):
    body = {
        "schema_version": 1,
        "receipt_id": str(uuid.uuid4()),
        "controller_subject": controller_subject,
        "candidate_subject": candidate_subject,
        "candidate_source_digest": candidate_source_digest,
        "dirty_diff_digest": dirty_diff_digest,
        "candidate_build_digest": candidate_build_digest,
        "roles": dict(roles),
        "allowed_actions": sorted(set(allowed_actions)),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "historical_work": historical_work,
        "causal_scope": causal_scope,
        "external_verification_digest": external_verification_digest,
    }
    body["receipt_hash"] = _receipt_hash(body)
    if not callable(signer):
        raise SelfHostingError("self-hosting receipt signer is unavailable")
    signature = signer(_signed_payload(body))
    body["authority"] = {
        "algorithm": "ed25519",
        "key_id": authority_key_id,
        "public_key": authority_public_key,
        "signature": signature,
    }
    return validate(body)


def validate(value, *, now=None):
    fields = {
        "schema_version", "receipt_id", "controller_subject", "candidate_subject",
        "candidate_source_digest", "dirty_diff_digest", "candidate_build_digest",
        "roles", "allowed_actions", "issued_at", "expires_at", "historical_work",
        "causal_scope", "external_verification_digest", "receipt_hash",
        "authority",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("receipt_id"), str) \
            or value.get("receipt_hash") != _receipt_hash(value) \
            or value.get("controller_subject") == value.get("candidate_subject"):
        raise SelfHostingError("self-hosting receipt fields are invalid")
    try:
        if str(uuid.UUID(value["receipt_id"])) != value["receipt_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise SelfHostingError("self-hosting receipt identity is invalid") from exc
    for field in (
            "controller_subject", "candidate_subject", "candidate_source_digest",
            "dirty_diff_digest", "candidate_build_digest", "receipt_hash"):
        if not isinstance(value.get(field), str) or DIGEST.fullmatch(value[field]) is None:
            raise SelfHostingError(f"{field} is invalid")
    external = value.get("external_verification_digest")
    if external is not None and (
            not isinstance(external, str) or DIGEST.fullmatch(external) is None):
        raise SelfHostingError("external verification digest is invalid")
    authority = value.get("authority")
    if not isinstance(authority, dict) or set(authority) != {
            "algorithm", "key_id", "public_key", "signature"} \
            or authority.get("algorithm") != "ed25519" \
            or not isinstance(authority.get("key_id"), str) \
            or KEY_ID.fullmatch(authority["key_id"]) is None:
        raise SelfHostingError("self-hosting authority envelope is invalid")
    try:
        if len(base64.b64decode(authority["public_key"], validate=True)) != 32 \
                or len(base64.b64decode(authority["signature"], validate=True)) != 64:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise SelfHostingError("self-hosting authority signature is invalid") from exc
    roles = value.get("roles")
    if not isinstance(roles, dict) or set(roles) != ROLES \
            or any(not isinstance(actor, str) or SAFE_ACTOR.fullmatch(actor) is None
                   for actor in roles.values()):
        raise SelfHostingError("self-hosting roles are invalid")
    candidate_actors = {roles["candidate_runtime"], roles["candidate_self_test"]}
    if roles["stable_controller"] in candidate_actors \
            or roles["external_verifier"] in candidate_actors \
            or roles["release_authority"] in candidate_actors \
            or roles["external_verifier"] == roles["stable_controller"]:
        raise SelfHostingError("self-hosting authority roles collapse")
    actions = value.get("allowed_actions")
    if not isinstance(actions, list) or actions != sorted(set(actions)) \
            or not actions or any(action not in ACTIONS for action in actions):
        raise SelfHostingError("self-hosting actions are invalid")
    if type(value.get("historical_work")) is not bool \
            or value.get("causal_scope") not in {"implementation", "verification-only"} \
            or (value["historical_work"]
                != (value["causal_scope"] == "verification-only")):
        raise SelfHostingError("self-hosting causal scope is invalid")
    issued = _instant(value.get("issued_at"), "issued_at")
    expires = _instant(value.get("expires_at"), "expires_at")
    if expires <= issued or expires - issued > dt.timedelta(days=30):
        raise SelfHostingError("self-hosting receipt lifetime is invalid")
    check = _instant(now, "now") if now is not None else None
    if check is not None and not issued <= check <= expires:
        raise SelfHostingError("self-hosting receipt is stale")
    return value


def authorize(value, *, action, actor, candidate_subject, now,
              trusted_controller_keys, signature_verifier):
    validate(value, now=now)
    authority = value["authority"]
    if not isinstance(trusted_controller_keys, dict) \
            or trusted_controller_keys.get(authority["key_id"]) \
            != authority["public_key"] \
            or not callable(signature_verifier):
        raise SelfHostingError("self-hosting stable-controller trust is unavailable")
    try:
        valid_signature = signature_verifier(
            _signed_payload(value), authority["signature"], authority["public_key"])
    except Exception as exc:
        raise SelfHostingError(
            "self-hosting stable-controller signature could not be verified") from exc
    if valid_signature is not True:
        raise SelfHostingError("self-hosting stable-controller signature is invalid")
    if action not in ACTIONS or action not in value["allowed_actions"]:
        raise SelfHostingError("self-hosting action is not authorized")
    if candidate_subject != value["candidate_subject"]:
        raise SelfHostingError("self-hosting candidate subject changed")
    required_role = ACTION_ROLE[action]
    if actor != value["roles"][required_role]:
        raise SelfHostingError("self-hosting actor substituted the required role")
    if actor == value["roles"]["candidate_runtime"] and action != "self-test":
        raise SelfHostingError("candidate runtime cannot authorize its own change")
    if value["causal_scope"] == "verification-only" and action in {
            "plan", "authorize", "repair"}:
        raise SelfHostingError("verification-only work cannot receive implementation causality")
    if action == "sign" and value["external_verification_digest"] is None:
        raise SelfHostingError("release signing requires external verification of this subject")
    return {
        "action": action,
        "role": required_role,
        "candidate_subject": candidate_subject,
        "independent": action in {"verify", "certify"},
        "causal_scope": value["causal_scope"],
        "receipt_id": value["receipt_id"],
    }
