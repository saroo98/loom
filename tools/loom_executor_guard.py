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
import loom_vault
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


class GuardMissing(GuardError):
    pass


class GuardFrozen(GuardError):
    pass


class GuardSecurity:
    """Carry canonical vault authority while preserving action-crypto tuple use."""

    def __init__(self, vault, crypto, owner_vault_id):
        try:
            canonical_owner = str(uuid.UUID(str(owner_vault_id)))
            if vault.identity()["owner_vault_id"] != canonical_owner \
                    or vault.crypto is not crypto:
                raise ValueError("vault authority mismatch")
        except (KeyError, TypeError, ValueError, AttributeError,
                loom_vault.VaultError) as exc:
            raise GuardError("executor guard vault authority is invalid") from exc
        self.vault = vault
        self.crypto = crypto
        self.owner_vault_id = canonical_owner

    def __iter__(self):
        yield self.crypto
        yield self.owner_vault_id


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
    try:
        owner_authority = loom_reliability._absolute(
            owner_home, "executor guard owner", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard owner authority is unsafe") from exc
    return {
        "action_id": action_id,
        "project_id": project_id,
        "generation_id": generation_id,
        "action_operation_id": operation_id,
        "owner_home": str(owner_authority),
    }


def _guard_root(directory, action, *, create):
    identity = _action_identity(action)
    try:
        owner = loom_reliability._absolute(
            identity["owner_home"], "executor guard owner", must_exist=True)
        directory = loom_reliability._absolute(
            directory, "executor guard directory", must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard root is unsafe") from exc
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


def _parent_identity(root):
    try:
        observed = loom_reliability.observe_root_identity(root)
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard parent identity is unsafe") from exc
    return {
        key: observed[key] for key in (
            "platform", "path_sha256", "kind", "device", "inode")
    }


def _validate_parent_identity(root, expected):
    if not isinstance(expected, dict) or set(expected) != {
            "platform", "path_sha256", "kind", "device", "inode"} \
            or expected.get("kind") != "directory" \
            or not isinstance(expected.get("platform"), str) \
            or HEX64.fullmatch(str(expected.get("path_sha256", ""))) is None \
            or any(type(expected.get(key)) is not int
                   for key in ("device", "inode")):
        raise GuardError("executor guard parent identity is invalid")
    if _parent_identity(root) != expected:
        raise GuardError("executor guard parent identity changed")


def _validate_leaf(path):
    try:
        if loom_reliability._is_redirect(path):
            raise GuardError("executor guard leaf is redirected")
        info = Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise GuardError("executor guard leaf is not a single-link regular file")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600:
            raise GuardError("executor guard leaf permissions are not private")
        if os.name == "nt":
            loom_windows_acl.verify_private_directory(Path(path).parent)
    except GuardError:
        raise
    except (OSError, loom_reliability.ReliabilityError,
            loom_windows_acl.WindowsAclError) as exc:
        raise GuardError("executor guard leaf is unsafe") from exc
    try:
        return loom_reliability.observe_root_identity(path)
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard leaf identity is unsafe") from exc


def _guard_body(value):
    return {
        key: item for key, item in value.items()
        if key not in {"guard_sha256", "guard_authentication"}
    }


def _authentication(security, action_id, guard_sha256):
    if security is None:
        return None
    try:
        crypto, owner_vault_id = security
        owner_vault_id = str(uuid.UUID(str(owner_vault_id)))
        tag = crypto.blind_index(
            "executor-guard-v2",
            f"{owner_vault_id}:{action_id}:{guard_sha256}")
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        raise GuardError("executor guard authentication is unavailable") from exc
    if HEX64.fullmatch(str(tag)) is None:
        raise GuardError("executor guard authentication is invalid")
    return {
        "mode": "owner-vault-blind-index-v1",
        "owner_vault_id": owner_vault_id,
        "tag": tag,
    }


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


def _validate(value, action, *, security=None, root=None):
    identity = _action_identity(action)
    fields = {
        "schema_version", "action_id", "project_id", "generation_id",
        "action_operation_id", "coverage_state", "host_session_sha256",
        "coverage_failure", "operations", "freeze", "storage_parent_identity",
        "guard_sha256", "guard_authentication",
    }
    unsigned = _guard_body(value) if isinstance(value, dict) else {}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 2 \
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
    expected_authentication = _authentication(
        security, identity["action_id"], value["guard_sha256"])
    if value.get("guard_authentication") != expected_authentication:
        raise GuardError("executor guard authentication does not match owner authority")
    if root is not None:
        _validate_parent_identity(root, value.get("storage_parent_identity"))
    seen = set()
    for operation in value["operations"]:
        _validate_operation(operation)
        if operation["operation_id"] in seen:
            raise GuardError("executor guard operation identity is duplicated")
        seen.add(operation["operation_id"])
    freeze_value = value["freeze"]
    if freeze_value is not None:
        legacy_fields = {"reason_code", "operation_count", "freeze_sha256"}
        exact_fields = {
            "operation_class", "reason_code", "subject_sha256",
            "operation_count", "freeze_sha256"}
        if not isinstance(freeze_value, dict) \
                or frozenset(freeze_value) not in {
                    frozenset(legacy_fields), frozenset(exact_fields)} \
                or not isinstance(freeze_value.get("reason_code"), str) \
                or SAFE_REASON.fullmatch(freeze_value["reason_code"]) is None \
                or ("operation_class" in freeze_value and (
                    not isinstance(freeze_value["operation_class"], str)
                    or SAFE_REASON.fullmatch(freeze_value["operation_class"]) is None
                    or HEX64.fullmatch(str(freeze_value.get("subject_sha256", ""))) is None)) \
                or freeze_value.get("operation_count") != len(value["operations"]) \
                or freeze_value.get("freeze_sha256") != _hash({
                    key: item for key, item in freeze_value.items()
                    if key != "freeze_sha256"}):
            raise GuardError("executor guard freeze is invalid")
    return value


def _canonical_security(security):
    return security if isinstance(security, GuardSecurity) else None


def _canonical_authentication(security, value, guard_sha256):
    previous = value.get("previous_head_sha256")
    return {
        "mode": "owner-vault-blind-index-v1",
        "owner_vault_id": security.owner_vault_id,
        "tag": security.crypto.blind_index(
            loom_vault.EXECUTOR_GUARD_HEAD_ENTITY_TYPE,
            ":".join((
                security.owner_vault_id, value["project_id"], value["action_id"],
                str(value["sequence"]), previous or "absent", guard_sha256))),
    }


def _finalize_canonical(value, security):
    candidate = json.loads(json.dumps(value))
    candidate.pop("guard_sha256", None)
    candidate.pop("guard_authentication", None)
    candidate["guard_sha256"] = _hash(candidate)
    candidate["guard_authentication"] = _canonical_authentication(
        security, candidate, candidate["guard_sha256"])
    return candidate


def _validate_canonical(value, action, *, security, root):
    identity = _action_identity(action)
    try:
        checked = loom_vault._validate_executor_guard_head(
            value, crypto=security.crypto,
            owner_vault_id=security.owner_vault_id,
            expected_project_id=identity["project_id"])
    except loom_vault.VaultError as exc:
        raise GuardError("canonical executor guard head is invalid") from exc
    if any(checked.get(field) != identity[field] for field in (
            "action_id", "project_id", "generation_id", "action_operation_id")):
        raise GuardError("canonical executor guard belongs to another action")
    _validate_parent_identity(root, checked.get("storage_parent_identity"))
    for operation in checked["operations"]:
        _validate_operation(operation)
    return checked


def _read_projection(path, action, *, security, root):
    try:
        before = _validate_leaf(path)
        if path.stat().st_size > MAX_GUARD_BYTES:
            raise GuardError("executor guard projection exceeds its bound")
        value = json.loads(path.read_text(encoding="utf-8"))
        loom_reliability.validate_root_identity(path, before)
    except GuardError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError,
            loom_reliability.ReliabilityError) as exc:
        raise GuardError("executor guard projection is unreadable") from exc
    return _validate_canonical(
        value, action, security=security, root=root)


def _write_projection(path, value, action, *, security):
    root = Path(path).parent
    candidate = _validate_canonical(
        value, action, security=security, root=root)
    try:
        parent_before = loom_reliability.observe_root_identity(root)
        _validate_parent_identity(root, candidate["storage_parent_identity"])
        if os.path.lexists(path):
            _validate_leaf(path)
        loom_reliability.atomic_write_json(path, candidate)
        if os.name == "posix":
            os.chmod(path, 0o600)
        loom_reliability._validate_directory_object_continuity(root, parent_before)
        _validate_leaf(path)
        observed = _read_projection(
            path, action, security=security, root=root)
    except GuardError:
        raise
    except (OSError, loom_reliability.ReliabilityError) as exc:
        raise GuardError("executor guard projection could not be persisted") from exc
    if observed != candidate:
        raise GuardError("executor guard projection durable reread does not match")
    return observed


def _canonical_head(security, project_id):
    try:
        return security.vault.read_executor_guard_head(project_id)
    except loom_vault.VaultError as exc:
        raise GuardError("canonical executor guard head is unavailable") from exc


def _require_quiescent_predecessor(head):
    freeze_value = head.get("freeze")
    if freeze_value is None or head.get("coverage_failure") \
            or any(operation.get("state") != "closed"
                   for operation in head.get("operations", [])):
        raise GuardError(
            "canonical executor guard predecessor is not exactly quiescent")


def _publish_canonical_projection(path, stored, action, security):
    observed = _write_projection(
        path, stored, action, security=security)
    current = _canonical_head(security, stored["project_id"])
    if current == stored:
        return observed
    if current is not None \
            and current.get("action_id") == stored["action_id"] \
            and current.get("sequence", 0) > stored["sequence"]:
        current = _validate_canonical(
            current, action, security=security, root=Path(path).parent)
        return _write_projection(
            path, current, action, security=security)
    raise GuardError("executor guard projection lost its canonical head before return")


def _read_canonical(directory, action, security):
    identity = _action_identity(action)
    root = _guard_root(directory, action, create=False)
    head = _canonical_head(security, identity["project_id"])
    path = root / (identity["action_id"] + ".json")
    if head is None:
        raise GuardMissing(
            "executor guard upgrade is required; no canonical vault head exists")
    if not root.exists():
        raise GuardError("canonical executor guard parent is unavailable")
    if head.get("action_id") != identity["action_id"]:
        if action.get("status") in {
                "completed", "failed", "expired", "cancelled", "superseded"} \
                and os.path.lexists(path):
            # A terminal action's authenticated projection is historical evidence,
            # never live mutation authority.  The current per-project vault head
            # may therefore belong to its successor without erasing auditability.
            return _read_projection(
                path, action, security=security, root=root)
        raise GuardError("canonical executor guard belongs to another action")
    head = _validate_canonical(
        head, action, security=security, root=root)
    if not os.path.lexists(path):
        return _write_projection(
            path, head, action, security=security)
    projection = _read_projection(
        path, action, security=security, root=root)
    if projection == head:
        return head
    if projection["sequence"] < head["sequence"]:
        return _write_projection(
            path, head, action, security=security)
    raise GuardError("executor guard projection is ahead, unrelated, or replayed")


def _commit_canonical(path, value, action, security):
    root = Path(path).parent
    current = _canonical_head(security, value["project_id"])
    if current is None:
        raise GuardMissing("canonical executor guard head is unavailable")
    current = _validate_canonical(
        current, action, security=security, root=root)
    if value.get("sequence") != current["sequence"] \
            or value.get("guard_sha256") != current["guard_sha256"] \
            or value.get("guard_authentication") != current["guard_authentication"]:
        raise GuardError("executor guard update is based on stale authority")
    candidate = json.loads(json.dumps(value))
    candidate["sequence"] = current["sequence"] + 1
    candidate["previous_head_sha256"] = current["guard_sha256"]
    candidate = _finalize_canonical(candidate, security)
    try:
        stored = security.vault.advance_executor_guard_head(
            candidate["project_id"],
            expected_predecessor_sha256=current["guard_sha256"],
            candidate=candidate)["head"]
    except loom_vault.VaultError as exc:
        raise GuardError("executor guard canonical CAS failed") from exc
    return _publish_canonical_projection(
        path, stored, action, security)


def _write(path, value, action, *, security=None):
    canonical = _canonical_security(security)
    if canonical is not None:
        return _commit_canonical(path, value, action, canonical)
    candidate = dict(value)
    root = Path(path).parent
    try:
        parent_before = loom_reliability.observe_root_identity(root)
        _validate_parent_identity(root, candidate.get("storage_parent_identity"))
        if os.path.lexists(path):
            _validate_leaf(path)
    except GuardError:
        raise
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard parent identity is unsafe") from exc
    candidate["guard_sha256"] = _hash(_guard_body(candidate))
    candidate["guard_authentication"] = _authentication(
        security, candidate["action_id"], candidate["guard_sha256"])
    _validate(candidate, action, security=security, root=root)
    try:
        loom_reliability.atomic_write_json(path, candidate)
        if os.name == "posix":
            os.chmod(path, 0o600)
        loom_reliability._validate_directory_object_continuity(
            root, parent_before)
        _validate_leaf(path)
    except loom_reliability.ReliabilityError as exc:
        raise GuardError("executor guard could not be persisted") from exc
    except OSError as exc:
        raise GuardError("executor guard could not be persisted") from exc
    return json.loads(json.dumps(candidate))


def initialize(directory, action, *, security=None):
    identity = _action_identity(action)
    root = _guard_root(directory, action, create=True)
    path = root / (identity["action_id"] + ".json")
    canonical = _canonical_security(security)
    if canonical is not None:
        current = _canonical_head(canonical, identity["project_id"])
        if current is None and os.path.lexists(path):
            _validate_leaf(path)
            raise GuardMissing(
                "executor guard upgrade is required; existing projection has no "
                "canonical vault head")
        if current is not None \
                and all(current.get(field) == identity[field] for field in (
                    "action_id", "project_id", "generation_id",
                    "action_operation_id")):
            return _read_canonical(directory, action, canonical)
        if current is not None:
            _require_quiescent_predecessor(current)
        value = {
            "schema_version": 3,
            "kind": "loom-executor-guard-head-v1",
            "owner_vault_id": canonical.owner_vault_id,
            "action_id": identity["action_id"],
            "project_id": identity["project_id"],
            "generation_id": identity["generation_id"],
            "action_operation_id": identity["action_operation_id"],
            "sequence": 1 if current is None else current["sequence"] + 1,
            "previous_head_sha256": (
                None if current is None else current["guard_sha256"]),
            "coverage_state": "awaiting-host",
            "host_session_sha256": None,
            "coverage_failure": False,
            "operations": [],
            "freeze": None,
            "storage_parent_identity": _parent_identity(root),
        }
        value = _finalize_canonical(value, canonical)
        try:
            stored = canonical.vault.advance_executor_guard_head(
                identity["project_id"],
                expected_predecessor_sha256=(
                    None if current is None else current["guard_sha256"]),
                candidate=value)["head"]
        except loom_vault.VaultError as exc:
            raise GuardError("executor guard initialization CAS failed") from exc
        return _publish_canonical_projection(
            path, stored, action, canonical)
    if os.path.lexists(path):
        return read(directory, action, security=security)
    value = {
        "schema_version": 2,
        "action_id": identity["action_id"],
        "project_id": identity["project_id"],
        "generation_id": identity["generation_id"],
        "action_operation_id": identity["action_operation_id"],
        "coverage_state": "awaiting-host",
        "host_session_sha256": None,
        "coverage_failure": False,
        "operations": [],
        "freeze": None,
        "storage_parent_identity": _parent_identity(root),
        "guard_sha256": "",
        "guard_authentication": None,
    }
    return _write(path, value, action, security=security)


def read(directory, action, *, security=None):
    canonical = _canonical_security(security)
    if canonical is not None:
        return _read_canonical(directory, action, canonical)
    path = guard_path(directory, action)
    if not os.path.lexists(path):
        raise GuardMissing("executor guard is unavailable")
    try:
        before = _validate_leaf(path)
        if path.stat().st_size > MAX_GUARD_BYTES:
            raise GuardError("executor guard is unavailable or unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        loom_reliability.validate_root_identity(path, before)
    except GuardError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError,
            loom_reliability.ReliabilityError) as exc:
        raise GuardError("executor guard is unreadable") from exc
    return _validate(
        value, action, security=security, root=path.parent)


def observe_post(
        directory, action, event, *, lifecycle_control=False,
        nonmutating=False, supervisor_receipt=None, security=None):
    value = read(directory, action, security=security)
    observed = _event_identity(event)
    if value["coverage_state"] == "awaiting-host":
        if lifecycle_control and value["freeze"] is None:
            value["coverage_state"] = "active"
            value["host_session_sha256"] = observed["host_session_sha256"]
            return _write(
                guard_path(directory, action), value, action,
                security=security)
        if lifecycle_control or nonmutating:
            return value
        else:
            value["coverage_failure"] = True
            return _write(
                guard_path(directory, action), value, action,
                security=security)
    operation = next((
        item for item in value["operations"]
        if item["operation_id"] == observed["operation_id"]), None)
    if operation is None:
        if lifecycle_control or nonmutating:
            return value
        value["coverage_failure"] = True
        return _write(
            guard_path(directory, action), value, action,
            security=security)
    if observed["host_session_sha256"] != value["host_session_sha256"]:
        raise GuardError("host operation completion changed its session identity")
    if operation["state"] != "open" \
            or operation["tool_name"] != observed["tool_name"] \
            or operation["host_turn_sha256"] != observed["host_turn_sha256"] \
            or operation["input_sha256"] != observed["input_sha256"]:
        raise GuardError("host operation completion does not match its preflight")
    if operation["kind"] == "supervised-process":
        operation["supervisor_receipt"] = _safe_supervisor_receipt(
            supervisor_receipt)
    elif supervisor_receipt is not None:
        raise GuardError("structured host operation carries process evidence")
    operation["state"] = "closed"
    return _write(
        guard_path(directory, action), value, action, security=security)


def begin_operation(
        directory, action, event, *, operation_kind, security=None):
    if operation_kind not in KINDS:
        raise GuardError("host operation class is unsupported")
    value = read(directory, action, security=security)
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
    return _write(
        guard_path(directory, action), value, action, security=security)


def freeze(
        directory, action, *, reason_code, operation_class=None,
        subject_sha256=None, security=None):
    if not isinstance(reason_code, str) or SAFE_REASON.fullmatch(reason_code) is None:
        raise GuardError("executor freeze reason is invalid")
    canonical = _canonical_security(security)
    if operation_class is None and canonical is None:
        operation_class = reason_code
    if subject_sha256 is None and canonical is None:
        subject_sha256 = _hash({
            "operation_class": operation_class,
            "action_identity": _action_identity(action),
        })
    if not isinstance(operation_class, str) \
            or SAFE_REASON.fullmatch(operation_class) is None \
            or not isinstance(subject_sha256, str) \
            or HEX64.fullmatch(subject_sha256) is None:
        raise GuardError("executor freeze operation identity is invalid")
    value = read(directory, action, security=security)
    if value["freeze"] is None:
        freeze_value = {
            "operation_class": operation_class,
            "reason_code": reason_code,
            "subject_sha256": subject_sha256,
            "operation_count": len(value["operations"]),
        }
        freeze_value["freeze_sha256"] = _hash(freeze_value)
        value["freeze"] = freeze_value
        return _write(
            guard_path(directory, action), value, action,
            security=security)
    expected = {
        "operation_class": operation_class,
        "reason_code": reason_code,
        "subject_sha256": subject_sha256,
    }
    if any(value["freeze"].get(key) != item for key, item in expected.items()):
        raise GuardError(
            "executor is frozen for another exact terminal operation; retry the "
            f"sealed {value['freeze'].get('operation_class', 'legacy')} operation")
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
    never_admitted = value["coverage_state"] == "awaiting-host" \
        and not value["operations"] \
        and value["host_session_sha256"] is None
    verified_terminal = value["coverage_state"] == "active"
    if value["freeze"] is None \
            or not (never_admitted or verified_terminal) \
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
        "case": (
            "host-never-admitted" if never_admitted
            else "verified-host-terminal"),
        "action_id": value["action_id"],
        "project_id": value["project_id"],
        "generation_id": value["generation_id"],
        "action_operation_id": value["action_operation_id"],
        "host_session_sha256": value["host_session_sha256"],
        "guard_sha256": value["guard_sha256"],
        "freeze_sha256": value["freeze"]["freeze_sha256"],
        "freeze_operation_class": value["freeze"].get("operation_class"),
        "freeze_reason_code": value["freeze"]["reason_code"],
        "freeze_subject_sha256": value["freeze"].get("subject_sha256"),
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
        directory, action, *, project_world_sha256, terminal_state,
        security=None):
    return _evidence(
        read(directory, action, security=security), action,
        project_world_sha256=project_world_sha256,
        terminal_state=terminal_state)


def validate_evidence(
        directory, action, evidence, *, project_world_sha256,
        security=None):
    if not isinstance(evidence, dict):
        raise GuardError("executor quiescence evidence is invalid")
    expected = _evidence(
        read(directory, action, security=security), action,
        project_world_sha256=project_world_sha256,
        terminal_state=evidence.get("terminal_state"))
    if evidence != expected:
        raise GuardError("executor quiescence evidence does not match its guard")
    return evidence
