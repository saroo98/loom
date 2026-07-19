#!/usr/bin/env python3
"""Sealed authority state for terminal Loom session receipts."""

import hashlib
import json
import re

import loom_block_reason


SCHEMA_VERSION = 1
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
STATES = {"closed", "terminal-block"}


class TerminalAuthorityError(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")).hexdigest()


def build(*, status, operation_id, block_reason=None):
    if status not in {"completed", "blocked"} \
            or not isinstance(operation_id, str) or not DIGEST_RE.fullmatch(operation_id):
        raise TerminalAuthorityError("terminal authority inputs are invalid")
    if status == "blocked":
        loom_block_reason.validate(block_reason)
        body = {
            "schema_version": SCHEMA_VERSION,
            "state": "terminal-block",
            "blocked_operation_id": operation_id,
            "implementation_authorized": False,
            "requires_new_action": True,
            "allowed_next": "diagnose-resolve-and-reinvoke",
            "reason_hash": block_reason["reason_hash"],
        }
    else:
        if block_reason is not None:
            raise TerminalAuthorityError("completed session cannot carry a block reason")
        body = {
            "schema_version": SCHEMA_VERSION,
            "state": "closed",
            "blocked_operation_id": None,
            "implementation_authorized": None,
            "requires_new_action": False,
            "allowed_next": "normal",
            "reason_hash": None,
        }
    return {**body, "authority_hash": _digest(body)}


def validate(value):
    fields = {
        "schema_version", "state", "blocked_operation_id",
        "implementation_authorized", "requires_new_action", "allowed_next",
        "reason_hash", "authority_hash",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("state") not in STATES \
            or not isinstance(value.get("authority_hash"), str) \
            or not DIGEST_RE.fullmatch(value["authority_hash"]):
        raise TerminalAuthorityError("terminal authority fields are invalid")
    body = {key: value[key] for key in fields - {"authority_hash"}}
    if value["authority_hash"] != _digest(body):
        raise TerminalAuthorityError("terminal authority digest is invalid")
    if value["state"] == "terminal-block":
        if not isinstance(value["blocked_operation_id"], str) \
                or not DIGEST_RE.fullmatch(value["blocked_operation_id"]) \
                or value["implementation_authorized"] is not False \
                or value["requires_new_action"] is not True \
                or value["allowed_next"] != "diagnose-resolve-and-reinvoke" \
                or not isinstance(value["reason_hash"], str) \
                or not DIGEST_RE.fullmatch(value["reason_hash"]):
            raise TerminalAuthorityError("terminal block authority is invalid")
    elif value["blocked_operation_id"] is not None \
            or value["implementation_authorized"] is not None \
            or value["requires_new_action"] is not False \
            or value["allowed_next"] != "normal" \
            or value["reason_hash"] is not None:
        raise TerminalAuthorityError("closed terminal authority is invalid")
    return value
