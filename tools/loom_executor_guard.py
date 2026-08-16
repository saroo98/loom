#!/usr/bin/env python3
"""Owner-private host-operation ledger and cancellation freeze authority."""

import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path

import loom_operation_supervisor
import loom_reliability
import loom_windows_acl


MAX_GUARD_BYTES = 512 * 1024
MAX_OPERATIONS = 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_REASON = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
KINDS = {"structured-write", "supervised-process"}


class GuardError(RuntimeError):
    pass


class GuardPending(GuardError):
    pass


class GuardFrozen(GuardError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _action_identity(action):
    if not isinstance(action, dict):
        raise GuardError("executor guard action identity is invalid")
    try:
        action_id = str(uuid.UUID(str(action.get("action_id"))))
    except (ValueError, TypeError, AttributeError) as exc:
        raise GuardError("executor guard action identity is invalid") from exc
    project_id = action.get("project_id")
    generation_id = action.get("generation_id")
    operation_id = action.get("operation_id")
    owner_home = action.get("owner_home")
    if action_id != action.get("action_id") \
            or not isinstance(project_id, str) \
            or re.fullmatch(r"p-[0-9a-f]{32}", project_id) is None \
            or not isinstance(generation_id, str) \
            or SAFE_GENERATION.fullmatch(generation_id) is None \
            or not isinstance(operation_id, str) \
            or HEX64.fullmatch(operation_id) is None \
            or not isinstance(owner_home, str) \
            or not Path(owner_home).is_absolute():
        raise GuardError("executor guard action identity is invalid")
    return {
        "action_id": action_id,
        "project_id": project_id,
        "generation_id": generation_id,
        "action_operation_id": operation_id,
        "owner_home": str(Path(owner_home).resolve()),
    }


def _guard_root(directory, action, *, create):
    identity = _action_identity(action)
    owner = Path(identity["owner_home"])
    directory = Path(directory).resolve()
    try:
        relative = directory.relative_to(owner)
    except ValueError as exc:
        raise GuardError("executor guard directory is outside owner authority") from exc
    try:
        if create:
            # The orchestration directory itself is an existing Loom authority
            # root.  It need not be owner-private (notably in the disposable
            # legacy adapter), so make the guard child private at creation
            # instead of attempting to retroactively prove every ancestor DACL.
            return loom_reliability.ensure_private_directory(
                directory, ["executor-guards"])
        root = directory / "executor-guards"
        if not os.path.lexists(root):
            return root
        root = loom_reliability._absolute(
            root, "executor guard root", must_exist=True)
        if os.name == "nt":
            loom_windows_acl.verify_private_directory(root)
        elif os.name == "posix":
            info = root.lstat()
            if not stat.S_ISDIR(info.st_mode) \
                    or stat.S_IMODE(info.st_mode) & 0o077:
                raise GuardError("executor guard storage is unsafe")
        else:
            raise GuardError("executor guard storage is unavailable")
        return root
    except GuardError:
        raise
    except (OSError, loom_reliability.ReliabilityError,
            loom_windows_acl.WindowsAclError) as exc:
        raise GuardError("executor guard storage is unsafe") from exc


def guard_path(directory, action):
    identity = _action_identity(action)
    return _guard_root(directory, action, create=False) / (
        identity["action_id"] + ".json")


def _event_identity(event):
    if not isinstance(event, dict):
        raise GuardError("host operation identity is invalid")
    values = {}
    for field in ("session_id", "turn_id", "tool_use_id", "tool_name"):
        item = event.get(field)
        if not isinstance(item, str) or not item or len(item) > 256:
            raise GuardError("host operation identity is invalid")
        values[field] = item
    try:
        input_raw = _canonical(event.get("tool_input", {}))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise GuardError("host operation input is invalid") from exc
    if len(input_raw) > 256 * 1024:
        raise GuardError("host operation input exceeds its bound")
    return {
        "host_session_sha256": hashlib.sha256(
            values["session_id"].encode("utf-8")).hexdigest(),
        "host_turn_sha256": hashlib.sha256(
            values["turn_id"].encode("utf-8")).hexdigest(),
        "operation_id": hashlib.sha256((
            values["session_id"] + "\0" + values["tool_use_id"]
        ).encode("utf-8")).hexdigest(),
        "tool_name": values["tool_name"],
        "input_sha256": hashlib.sha256(input_raw).hexdigest(),
    }


def _validate_operation(value):
    fields = {
        "operation_id", "host_turn_sha256", "tool_name", "input_sha256",
        "kind", "state", "supervisor_receipt",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or not all(HEX64.fullmatch(str(value.get(field, ""))) is not None
                       for field in (
                           "operation_id", "host_turn_sha256", "input_sha256")) \
            or not isinstance(value.get("tool_name"), str) \
            or not 1 <= len(value["tool_name"]) <= 256 \
            or value.get("kind") not in KINDS \
            or value.get("state") not in {"open", "closed"}:
        raise GuardError("executor guard operation is invalid")
    receipt = value["supervisor_receipt"]
    if value["kind"] == "structured-write" and receipt is not None:
        raise GuardError("structured host operation carries process evidence")
    if value["kind"] == "supervised-process" and value["state"] == "closed":
        _safe_supervisor_receipt(receipt)
    elif value["kind"] == "supervised-process" and receipt is not None:
        raise GuardError("open process operation carries terminal evidence")


def _validate(value, action):
    identity = _action_identity(action)
    fields = {
        "schema_version", "action_id", "project_id", "generation_id",
        "action_operation_id", "coverage_state", "host_session_sha256",
        "coverage_failure", "operations", "freeze", "guard_sha256",
    }
    unsigned = {
        key: item for key, item in value.items()
        if key != "guard_sha256"
    } if isinstance(value, dict) else {}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 \
            or any(value.get(key) != identity[key] for key in (
                "action_id", "project_id", "generation_id",
                "action_operation_id")) \
            or value.get("coverage_state") not in {"awaiting-host", "active"} \
            or (value.get("host_session_sha256") is not None
                and HEX64.fullmatch(str(value["host_session_sha256"])) is None) \
            or (value["coverage_state"] == "active") \
            != (value.get("host_session_sha256") is not None) \
            or type(value.get("coverage_failure")) is not bool \
            or not isinstance(value.get("operations"), list) \
            or len(value["operations"]) > MAX_OPERATIONS \
            or value.get("guard_sha256") != _hash(unsigned):
        raise GuardError("executor guard is invalid")
    seen = set()
    for operation in value["operations"]:
        _validate_operation(operation)
        if operation["operation_id"] in seen:
            raise GuardError("executor guard operation identity is duplicated")
        seen.add(operation["operation_id"])
    freeze_value = value["freeze"]
    if freeze_value is not None:
        if not isinstance(freeze_value, dict) or set(freeze_value) != {
                "reason_code", "operation_count", "freeze_sha256"} \
                or not isinstance(freeze_value.get("reason_code"), str) \
                or SAFE_REASON.fullmatch(freeze_value["reason_code"]) is None \
                or freeze_value.get("operation_count") != len(value["operations"]) \
                or freeze_value.get("freeze_sha256") != _hash({
                    key: item for key, item in freeze_value.items()
                    if key != "freeze_sha256"}):
            raise GuardError("executor guard freeze is invalid")
    return value


def _write(path, value, action):
    candidate = dict(value)
    candidate["guard_sha256"] = _hash({
        key: item for key, item in candidate.items()
        if key != "guard_sha256"})
    _validate(candidate, action)
    try:
        loom_reliability.atomic_write_json(path, candidate)
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard could not be persisted") from exc
    return json.loads(json.dumps(candidate))


def initialize(directory, action):
    identity = _action_identity(action)
    root = _guard_root(directory, action, create=True)
    path = root / (identity["action_id"] + ".json")
    if os.path.lexists(path):
        return read(directory, action)
    value = {
        "schema_version": 1,
        "action_id": identity["action_id"],
        "project_id": identity["project_id"],
        "generation_id": identity["generation_id"],
        "action_operation_id": identity["action_operation_id"],
        "coverage_state": "awaiting-host",
        "host_session_sha256": None,
        "coverage_failure": False,
        "operations": [],
        "freeze": None,
        "guard_sha256": "",
    }
    return _write(path, value, action)


def read(directory, action):
    path = guard_path(directory, action)
    try:
        if path.is_symlink() or not path.is_file() \
                or path.stat().st_size > MAX_GUARD_BYTES:
            raise GuardError("executor guard is unavailable or unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except GuardError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuardError("executor guard is unreadable") from exc
    return _validate(value, action)


def observe_post(
        directory, action, event, *, lifecycle_control=False,
        nonmutating=False, supervisor_receipt=None):
    value = read(directory, action)
    observed = _event_identity(event)
    if value["coverage_state"] == "awaiting-host":
        if not lifecycle_control or value["freeze"] is not None:
            value["coverage_failure"] = True
            return _write(guard_path(directory, action), value, action)
        value["coverage_state"] = "active"
        value["host_session_sha256"] = observed["host_session_sha256"]
        return _write(guard_path(directory, action), value, action)
    if observed["host_session_sha256"] != value["host_session_sha256"]:
        value["coverage_failure"] = True
        return _write(guard_path(directory, action), value, action)
    operation = next((
        item for item in value["operations"]
        if item["operation_id"] == observed["operation_id"]), None)
    if operation is None:
        if not lifecycle_control and not nonmutating:
            value["coverage_failure"] = True
        return _write(guard_path(directory, action), value, action)
    if operation["state"] != "open" \
            or operation["tool_name"] != observed["tool_name"] \
            or operation["input_sha256"] != observed["input_sha256"]:
        raise GuardError("host operation completion does not match its preflight")
    if operation["kind"] == "supervised-process":
        operation["supervisor_receipt"] = _safe_supervisor_receipt(
            supervisor_receipt)
    elif supervisor_receipt is not None:
        raise GuardError("structured host operation carries process evidence")
    operation["state"] = "closed"
    return _write(guard_path(directory, action), value, action)


def begin_operation(directory, action, event, *, operation_kind):
    if operation_kind not in KINDS:
        raise GuardError("host operation class is unsupported")
    value = read(directory, action)
    observed = _event_identity(event)
    if value["freeze"] is not None:
        raise GuardFrozen("executor mutation is frozen")
    if value["coverage_state"] != "active" \
            or value["coverage_failure"] \
            or observed["host_session_sha256"] != value["host_session_sha256"]:
        raise GuardPending("host operation coverage is not proven")
    existing = next((
        item for item in value["operations"]
        if item["operation_id"] == observed["operation_id"]), None)
    candidate = {
        "operation_id": observed["operation_id"],
        "host_turn_sha256": observed["host_turn_sha256"],
        "tool_name": observed["tool_name"],
        "input_sha256": observed["input_sha256"],
        "kind": operation_kind,
        "state": "open",
        "supervisor_receipt": None,
    }
    if existing is not None:
        if existing != candidate:
            raise GuardError("host operation identity was reused inconsistently")
        return value
    if len(value["operations"]) >= MAX_OPERATIONS:
        raise GuardPending("host operation ledger reached its bound")
    value["operations"].append(candidate)
    return _write(guard_path(directory, action), value, action)


def freeze(directory, action, *, reason_code):
    if not isinstance(reason_code, str) or SAFE_REASON.fullmatch(reason_code) is None:
        raise GuardError("executor freeze reason is invalid")
    try:
        value = read(directory, action)
    except GuardError:
        value = initialize(directory, action)
    if value["freeze"] is None:
        freeze_value = {
            "reason_code": reason_code,
            "operation_count": len(value["operations"]),
        }
        freeze_value["freeze_sha256"] = _hash(freeze_value)
        value["freeze"] = freeze_value
        return _write(guard_path(directory, action), value, action)
    if value["freeze"]["reason_code"] != reason_code:
        raise GuardError("executor is frozen for another exact operation")
    return value


def _safe_supervisor_receipt(receipt):
    try:
        verified = loom_operation_supervisor.verify_receipt(receipt)
    except loom_operation_supervisor.SupervisorError as exc:
        raise GuardError("supervised process evidence is invalid") from exc
    if verified["status"] != "passed" \
            or verified["primary_failure"] is not None \
            or verified["secondary_failures"] \
            or not verified["survivors_confirmed_zero"] \
            or not verified["protected_roots_unchanged"]:
        raise GuardError("supervised process did not terminate safely")
    return json.loads(json.dumps(verified))


def _evidence(value, action, *, project_world_sha256, terminal_state):
    if not isinstance(project_world_sha256, str) \
            or HEX64.fullmatch(project_world_sha256) is None \
            or terminal_state not in {"cancelled", "completed", "failed", "timed-out"}:
        raise GuardError("executor quiescence subject is invalid")
    if value["freeze"] is None \
            or value["coverage_state"] != "active" \
            or value["coverage_failure"]:
        raise GuardPending("executor host coverage is not closed")
    open_count = sum(
        item["state"] == "open" for item in value["operations"])
    if open_count:
        raise GuardPending("executor host operations remain open")
    for operation in value["operations"]:
        if operation["kind"] == "supervised-process":
            _safe_supervisor_receipt(operation["supervisor_receipt"])
    body = {
        "schema_version": 1,
        "case": "verified-host-terminal",
        "action_id": value["action_id"],
        "project_id": value["project_id"],
        "generation_id": value["generation_id"],
        "action_operation_id": value["action_operation_id"],
        "host_session_sha256": value["host_session_sha256"],
        "guard_sha256": value["guard_sha256"],
        "freeze_sha256": value["freeze"]["freeze_sha256"],
        "operation_count": len(value["operations"]),
        "open_operation_count": open_count,
        "supervisor_receipt_sha256s": [
            item["supervisor_receipt"]["receipt_sha256"]
            for item in value["operations"]
            if item["kind"] == "supervised-process"],
        "project_world_sha256": project_world_sha256,
        "terminal_state": terminal_state,
    }
    body["binding_sha256"] = _hash(body)
    return body


def seal_quiescence(
        directory, action, *, project_world_sha256, terminal_state):
    return _evidence(
        read(directory, action), action,
        project_world_sha256=project_world_sha256,
        terminal_state=terminal_state)


def validate_evidence(
        directory, action, evidence, *, project_world_sha256):
    if not isinstance(evidence, dict):
        raise GuardError("executor quiescence evidence is invalid")
    expected = _evidence(
        read(directory, action), action,
        project_world_sha256=project_world_sha256,
        terminal_state=evidence.get("terminal_state"))
    if evidence != expected:
        raise GuardError("executor quiescence evidence does not match its guard")
    return evidence
