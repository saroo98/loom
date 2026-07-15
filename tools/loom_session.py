#!/usr/bin/env python3
"""Automatic, local session controller behind Loom's one-command surface."""

import datetime as dt
import hashlib
import json
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import loom_runtime
import loom_memory
import loom_learning
import loom_preferences
import loom_planning
import loom_performance
import loom_transparency
import loom_improvement


SCHEMA_VERSION = 1
JOURNAL_FILE = "session-journal.json"
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 4096
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RECEIPT_STATUSES = {"completed", "blocked", "interrupted"}
EVENT_KINDS = {
    "session-opened", "session-interrupted", "session-reconciled",
    "session-receipt-sealed",
}

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class SessionError(ValueError):
    pass


class SessionBlocked(SessionError):
    def __init__(self, code, message):
        self.code = str(code)
        self.message = str(message)
        super().__init__(f"{self.code}: {self.message}")


class SessionInterrupted(SessionError):
    def __init__(self, code, message):
        self.code = str(code)
        self.message = str(message)
        super().__init__(f"{self.code}: {self.message}")


class _SessionFileLock:
    """Process-crash-safe exclusive lock for one project's session journal."""

    def __init__(self, path, timeout=30.0):
        self.path = Path(path)
        self.timeout = timeout
        self.stream = None

    def __enter__(self):
        _ensure_private_directory(self.path.parent)
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise SessionBlocked("SESSION_PATH_UNSAFE", "session lock is not a regular file")
        try:
            descriptor = os.open(
                self.path, os.O_RDWR | os.O_CREAT,
                stat.S_IRUSR | stat.S_IWUSR)
            self.stream = os.fdopen(descriptor, "r+b", buffering=0)
            if os.fstat(descriptor).st_size == 0:
                self.stream.write(b"0")
                self.stream.flush()
                os.fsync(descriptor)
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    self.stream.seek(0)
                    if os.name == "nt":
                        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                    else:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise SessionBlocked(
                            "SESSION_BUSY", "timed out waiting for the session lock") from exc
                    time.sleep(0.05)
        except SessionBlocked:
            self._close()
            raise
        except OSError as exc:
            self._close()
            raise SessionBlocked(
                "SESSION_LOCK_FAILED", f"cannot acquire session lock: {exc}") from exc

    def _close(self):
        if self.stream is not None:
            try:
                self.stream.close()
            finally:
                self.stream = None

    def __exit__(self, _type, _value, _traceback):
        if self.stream is not None:
            descriptor = self.stream.fileno()
            try:
                self.stream.seek(0)
                if os.name == "nt":
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                self._close()


def _canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _sha(value):
    if not isinstance(value, bytes):
        value = _canonical_json(value)
    return hashlib.sha256(value).hexdigest()


def _format_time(value):
    return loom_runtime._format_time(value)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, MappingProxyType):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _ensure_private_directory(path):
    path = Path(path)
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise SessionBlocked("SESSION_PATH_UNSAFE", "session path traverses a link")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise SessionBlocked("SESSION_PATH_UNSAFE", "session root is not a directory")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except OSError as exc:
        raise SessionBlocked(
            "SESSION_PATH_UNSAFE", f"cannot make session root private: {exc}") from exc


def _atomic_json(path, value):
    path = Path(path)
    _ensure_private_directory(path.parent)
    payload = _canonical_json(value) + b"\n"
    if len(payload) > MAX_JOURNAL_BYTES:
        raise SessionBlocked("SESSION_CAPACITY", "session journal exceeds its byte bound")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = None
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise SessionBlocked(
            "SESSION_WRITE_FAILED", f"cannot commit session journal: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _event(kind, session_id, operation_id, instant, payload, previous_hash):
    value = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "kind": kind,
        "session_id": session_id,
        "operation_id": operation_id,
        "recorded_at": _format_time(instant),
        "payload": payload,
        "previous_hash": previous_hash,
    }
    value["event_hash"] = _sha(value)
    return value


def _new_journal(instance_id, project_id):
    return {
        "schema_version": SCHEMA_VERSION,
        "instance_id": instance_id,
        "project_id": project_id,
        "events": [],
    }


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SessionBlocked(
                "SESSION_CORRUPT", f"session journal duplicates key {key!r}")
        value[key] = item
    return value


def _load_journal(path, instance_id, project_id):
    path = Path(path)
    if not path.exists():
        return _new_journal(instance_id, project_id)
    if path.is_symlink() or not path.is_file():
        raise SessionBlocked("SESSION_PATH_UNSAFE", "session journal is not a regular file")
    try:
        if path.stat().st_size > MAX_JOURNAL_BYTES:
            raise SessionBlocked("SESSION_CAPACITY", "session journal exceeds its byte bound")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except SessionBlocked:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SessionBlocked("SESSION_CORRUPT", f"cannot read session journal: {exc}") \
            from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "instance_id", "project_id", "events"}:
        raise SessionBlocked("SESSION_CORRUPT", "session journal fields are invalid")
    if value["schema_version"] != SCHEMA_VERSION \
            or value["instance_id"] != instance_id \
            or value["project_id"] != project_id \
            or not isinstance(value["events"], list) \
            or len(value["events"]) > MAX_EVENTS:
        raise SessionBlocked("SESSION_CORRUPT", "session journal identity is invalid")
    previous = None
    for index, event in enumerate(value["events"]):
        fields = {
            "schema_version", "event_id", "kind", "session_id", "operation_id",
            "recorded_at", "payload", "previous_hash", "event_hash",
        }
        if not isinstance(event, dict) or set(event) != fields:
            raise SessionBlocked(
                "SESSION_CORRUPT", f"session event {index} fields are invalid")
        claimed = event["event_hash"]
        body = dict(event)
        body.pop("event_hash")
        try:
            uuid.UUID(event["event_id"])
            uuid.UUID(event["session_id"])
            loom_runtime._parse_time(event["recorded_at"])
        except (ValueError, TypeError, AttributeError, loom_runtime.RuntimeBlocked) as exc:
            raise SessionBlocked(
                "SESSION_CORRUPT", f"session event {index} identity is invalid") from exc
        if event["schema_version"] != SCHEMA_VERSION \
                or event["kind"] not in EVENT_KINDS \
                or not isinstance(event["operation_id"], str) \
                or not re.fullmatch(r"[0-9a-f]{64}", event["operation_id"]) \
                or not isinstance(event["payload"], dict) \
                or event["previous_hash"] != previous \
                or not isinstance(claimed, str) \
                or claimed != _sha(body):
            raise SessionBlocked(
                "SESSION_CORRUPT", f"session event {index} hash chain is invalid")
        previous = claimed
    return value


def _append_event(journal, kind, session_id, operation_id, instant, payload):
    if len(journal["events"]) >= MAX_EVENTS:
        raise SessionBlocked("SESSION_CAPACITY", "session event bound is exhausted")
    previous = journal["events"][-1]["event_hash"] if journal["events"] else None
    journal["events"].append(
        _event(kind, session_id, operation_id, instant, payload, previous))


def _validate_handler_result(value):
    required = {
        "status", "code", "success", "metrics", "evidence_ids",
        "reversible_action_ids",
    }
    optional_id_lists = {
        "applied_memory_ids", "verified_memory_ids", "rejected_memory_ids",
    }
    optional_structures = {
        "preference_observations", "artifact_usage", "usage", "user_message"}
    allowed = required | optional_id_lists | optional_structures
    if not isinstance(value, dict) or set(value) - allowed or not required.issubset(value):
        raise SessionBlocked(
            "HANDLER_RESULT_INVALID", "handler result fields are unknown or missing")
    if value["status"] not in {"completed", "blocked"}:
        raise SessionBlocked("HANDLER_RESULT_INVALID", "handler status is invalid")
    if not isinstance(value["code"], str) or not SAFE_ID_RE.fullmatch(value["code"]):
        raise SessionBlocked("HANDLER_RESULT_INVALID", "handler code is invalid")
    if type(value["success"]) is not bool:
        raise SessionBlocked("HANDLER_RESULT_INVALID", "handler success is invalid")
    if not isinstance(value["metrics"], dict) or not all(
            isinstance(key, str) and SAFE_ID_RE.fullmatch(key)
            and type(metric) in (int, float)
            for key, metric in value["metrics"].items()):
        raise SessionBlocked("HANDLER_RESULT_INVALID", "handler metrics are invalid")
    for field in ("evidence_ids", "reversible_action_ids"):
        if not isinstance(value[field], list) or not all(
                isinstance(item, str) and SAFE_ID_RE.fullmatch(item)
                for item in value[field]):
            raise SessionBlocked("HANDLER_RESULT_INVALID", f"handler {field} is invalid")
    normalized = dict(value)
    for field in optional_id_lists:
        identifiers = value.get(field, [])
        if not isinstance(identifiers, list) \
                or len(identifiers) != len(set(identifiers)):
            raise SessionBlocked("HANDLER_RESULT_INVALID", f"{field} is invalid")
        for item in identifiers:
            try:
                if str(uuid.UUID(item)) != item:
                    raise ValueError
            except (ValueError, TypeError, AttributeError) as exc:
                raise SessionBlocked(
                    "HANDLER_RESULT_INVALID",
                    f"{field} must contain canonical UUIDs") from exc
        normalized[field] = identifiers
    observations = value.get("preference_observations", [])
    if not isinstance(observations, list) or len(observations) > 16:
        raise SessionBlocked("HANDLER_RESULT_INVALID", "preference observations are invalid")
    normalized_observations = []
    for observation in observations:
        if not isinstance(observation, dict) or set(observation) - {"key", "value", "subject"} \
                or not {"key", "value"}.issubset(observation) \
                or observation["key"] not in loom_preferences.KEYS \
                or not isinstance(observation["value"], str) \
                or not observation["value"] or len(observation["value"]) > 80 \
                or ("subject" in observation and (
                    not isinstance(observation["subject"], str)
                    or not SAFE_ID_RE.fullmatch(observation["subject"]))):
            raise SessionBlocked("HANDLER_RESULT_INVALID", "preference observation is invalid")
        normalized_observations.append(dict(observation))
    normalized["preference_observations"] = normalized_observations
    artifact_usage = value.get("artifact_usage", [])
    if not isinstance(artifact_usage, list) or len(artifact_usage) > 64:
        raise SessionBlocked("HANDLER_RESULT_INVALID", "artifact usage is invalid")
    normalized_usage = []
    for usage in artifact_usage:
        if not isinstance(usage, dict) or set(usage) != {
                "artifact_id", "opened", "cited", "work_order_used", "prevented_defect"} \
                or not isinstance(usage["artifact_id"], str) \
                or not SAFE_ID_RE.fullmatch(usage["artifact_id"]) \
                or any(type(usage[name]) is not bool for name in (
                    "opened", "cited", "work_order_used", "prevented_defect")):
            raise SessionBlocked("HANDLER_RESULT_INVALID", "artifact usage entry is invalid")
        normalized_usage.append(dict(usage))
    normalized["artifact_usage"] = normalized_usage
    user_message = value.get("user_message", "")
    if not isinstance(user_message, str) or len(user_message) > 1000:
        raise SessionBlocked("HANDLER_RESULT_INVALID", "user message is invalid")
    normalized["user_message"] = user_message
    try:
        normalized["usage"] = loom_performance.normalize_usage(value.get("usage"))
    except loom_performance.PerformanceError as exc:
        raise SessionBlocked("HANDLER_RESULT_INVALID", str(exc)) from exc
    if set(normalized["verified_memory_ids"]) & set(normalized["rejected_memory_ids"]) \
            or set(normalized["applied_memory_ids"]) & (
                set(normalized["verified_memory_ids"])
                | set(normalized["rejected_memory_ids"])):
        raise SessionBlocked(
            "HANDLER_RESULT_INVALID", "memory result roles must be disjoint")
    return json.loads(json.dumps(normalized, allow_nan=False))


@dataclass(frozen=True)
class SessionContext:
    session_id: str
    operation_id: str
    invocation_id: str
    project_id: str
    intent: str
    prepared: loom_runtime.PreparedInvocation
    selected_memory: tuple
    selected_preferences: tuple
    session_journal: str
    request_text: str

    def environment(self):
        """Return the minimal capability passed to lifecycle subprocesses."""
        return {
            "LOOM_SESSION_JOURNAL": self.session_journal,
            "LOOM_SESSION_ID": self.session_id,
            "LOOM_SESSION_OPERATION_ID": self.operation_id,
            "LOOM_SESSION_DOMAIN": self.prepared.domains[0],
        }


@dataclass(frozen=True)
class SessionReceipt:
    schema_version: int
    session_id: str
    operation_id: str
    invocation_id: str
    project_id: str
    intent: str
    status: str
    code: str
    repeated: bool
    reconciled_session_id: str | None
    selected_memory_ids: tuple
    selected_preference_ids: tuple
    outcome_ids: tuple
    adaptation_receipts: tuple
    improvement_evidence_ids: tuple
    tier: str
    domains: tuple
    reversible_action_ids: tuple
    archived_count: int
    uncertainty_codes: tuple
    owner_input_required: bool
    user_message: str
    usage: MappingProxyType
    event_count: int
    world_fingerprint: str
    started_at: str
    completed_at: str
    receipt_hash: str

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "operation_id": self.operation_id,
            "invocation_id": self.invocation_id,
            "project_id": self.project_id,
            "intent": self.intent,
            "status": self.status,
            "code": self.code,
            "repeated": self.repeated,
            "reconciled_session_id": self.reconciled_session_id,
            "selected_memory_ids": list(self.selected_memory_ids),
            "selected_preference_ids": list(self.selected_preference_ids),
            "outcome_ids": list(self.outcome_ids),
            "adaptation_receipts": list(self.adaptation_receipts),
            "improvement_evidence_ids": list(self.improvement_evidence_ids),
            "tier": self.tier,
            "domains": list(self.domains),
            "reversible_action_ids": list(self.reversible_action_ids),
            "archived_count": self.archived_count,
            "uncertainty_codes": list(self.uncertainty_codes),
            "owner_input_required": self.owner_input_required,
            "user_message": self.user_message,
            "usage": _thaw(self.usage),
            "event_count": self.event_count,
            "world_fingerprint": self.world_fingerprint,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "receipt_hash": self.receipt_hash,
        }

    def owner_view(self):
        return loom_transparency.render_compact_receipt(
            loom_transparency.compact_receipt(self.to_dict()))

    def explain(self):
        return loom_transparency.explain_receipt(self.to_dict())


def _receipt_hash(value):
    body = dict(value)
    body.pop("receipt_hash", None)
    body.pop("repeated", None)
    return _sha(body)


def _transition_count(value):
    """Count context removed from active use without treating unrelated metrics as archives."""
    if isinstance(value, dict):
        return sum(
            (int(item) if key in {"archived", "dormant", "stale"}
             and type(item) is int and item >= 0 else _transition_count(item))
            for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return sum(_transition_count(item) for item in value)
    return 0


def _latest_sealed_receipt(journal):
    """Return the latest trustworthy receipt, excluding the session being built."""
    for event in reversed(journal.get("events", [])):
        if event.get("kind") != "session-receipt-sealed":
            continue
        payload = event.get("payload")
        receipt = payload.get("receipt") if isinstance(payload, dict) else None
        if isinstance(receipt, dict):
            return receipt
    return None


def _receipt_from_data(value, *, repeated):
    fields = {
        "schema_version", "session_id", "operation_id", "invocation_id",
        "project_id", "intent", "status", "code", "repeated",
        "reconciled_session_id", "selected_memory_ids", "outcome_ids",
        "selected_preference_ids", "adaptation_receipts",
        "improvement_evidence_ids",
        "tier", "domains", "reversible_action_ids", "archived_count",
        "uncertainty_codes", "owner_input_required", "user_message", "usage",
        "event_count", "world_fingerprint", "started_at", "completed_at",
        "receipt_hash",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("status") not in RECEIPT_STATUSES \
            or value.get("receipt_hash") != _receipt_hash(value):
        raise SessionBlocked("SESSION_CORRUPT", "sealed session receipt is invalid")
    data = json.loads(json.dumps(value))
    data["repeated"] = bool(repeated)
    data["selected_memory_ids"] = tuple(data["selected_memory_ids"])
    data["selected_preference_ids"] = tuple(data["selected_preference_ids"])
    data["outcome_ids"] = tuple(data["outcome_ids"])
    data["adaptation_receipts"] = tuple(data["adaptation_receipts"])
    data["improvement_evidence_ids"] = tuple(data["improvement_evidence_ids"])
    data["domains"] = tuple(data["domains"])
    data["reversible_action_ids"] = tuple(data["reversible_action_ids"])
    data["uncertainty_codes"] = tuple(data["uncertainty_codes"])
    data["usage"] = _freeze(data["usage"])
    return SessionReceipt(**data)


def _operation_identity(prepared):
    operation_id = _sha({
        "project_id": prepared.project_id,
        "request_hash": prepared.request_hash,
        "survey_hash": prepared.survey_hash,
        "intent": prepared.intent,
        "domains": list(prepared.domains),
    })
    return operation_id, str(uuid.uuid5(uuid.UUID(prepared.instance_id), operation_id))


@dataclass(frozen=True)
class OpenSession:
    prepared: loom_runtime.PreparedInvocation
    session_id: str
    operation_id: str
    journal_path: str
    started_at: str
    terminal_receipt: SessionReceipt | None

    def environment(self):
        return {
            "LOOM_SESSION_JOURNAL": self.journal_path,
            "LOOM_SESSION_ID": self.session_id,
            "LOOM_SESSION_OPERATION_ID": self.operation_id,
            "LOOM_SESSION_DOMAIN": self.prepared.domains[0],
        }


class NoopMemoryAdapter:
    """Explicit no-profile adapter for tests and disabled-profile operation."""

    def housekeeping(self, _context):
        return {"code": "memory-disabled"}

    def select(self, _context):
        return []

    def select_preferences(self, _context):
        return []

    def record_outcome(self, _context, _result):
        return []

    def compact(self, _context):
        return {"code": "memory-disabled"}


class LocalMemoryAdapter:
    """Bounded adapter over Loom's instance-scoped local memory store."""

    def __init__(self, *, owner_home, instance_id, max_chars=None):
        loom_runtime._canonical_uuid(instance_id, "instance_id")
        root = Path(owner_home)
        if not root.is_absolute():
            raise SessionBlocked("SESSION_HOME_REQUIRED", "owner_home must be absolute")
        if max_chars is not None and (
                type(max_chars) is not int or not 256 <= max_chars <= 4096):
            raise SessionError("memory max_chars ceiling must be between 256 and 4096")
        loom_memory.validate_instance(root, instance_id)
        self.owner_home = root
        self.instance_id = instance_id
        self.max_chars = max_chars
        self.learning = loom_learning.LearningEngine(root, instance_id)
        self.preferences = loom_preferences.PreferenceEngine(root, instance_id)
        self.planning = loom_planning.PlanningOptimizer(root, instance_id)
        self.actions = loom_transparency.ActionLedger(root, instance_id)
        self.improvement = loom_improvement.ImprovementTracker(root, instance_id)

    def housekeeping(self, _context):
        lifecycle = loom_memory.maintain_lifecycle(
            self.owner_home, self.instance_id)
        memory = loom_memory.compact(self.owner_home, self.instance_id)
        learning = self.learning.housekeeping()
        preferences = self.preferences.housekeeping()
        return {"lifecycle": lifecycle, "memory": memory, "learning": learning,
                "preferences": preferences}

    def select(self, context):
        policy = loom_performance.adaptive_memory_budget(
            tier=context.prepared.route_contract["tier"], intent=context.intent,
            domain_count=len(context.prepared.domains))
        budget = min(policy["max_chars"], self.max_chars or policy["max_chars"])
        project_id = context.project_id if policy["include_project_history"] else None
        hints = []
        per_domain_chars = max(256, min(800, max(256, budget) // max(
            1, len(context.prepared.domains))))
        for domain in context.prepared.domains:
            result = self.learning.rehydrate_domain(
                domain=domain,
                project_id=project_id, max_records=1,
                max_chars=max(1600, per_domain_chars))
            hints.extend(result["capsule"])
        hint_chars = sum(len(json.dumps(item, ensure_ascii=False)) + 1 for item in hints)
        active = loom_memory.select(
            self.owner_home,
            self.instance_id,
            domain=list(context.prepared.domains),
            project_id=project_id,
            max_chars=max(1, max(2048, budget) - hint_chars),
        )
        return loom_performance.memory_capsule(
            active + hints, max_chars=budget,
            max_records=policy["max_records"])

    def select_preferences(self, context):
        risk_class = {"S": "low", "M": "medium", "L": "high"}[
            context.prepared.route_contract["tier"]]
        selected = self.preferences.select(
            domain=context.prepared.domains[0], task_class=context.intent,
            risk_class=risk_class)
        by_key = {item["key"]: item for item in selected}
        key_map = {
            "report_style": "report_detail",
            "decision_batching": "decision_batch_size",
            "autonomy_default": "autonomy",
            "stack_preference": "stack",
        }
        for record in context.selected_memory:
            if not isinstance(record, dict) or record.get("category") != "preference" \
                    or record.get("provenance") != "stated":
                continue
            key = key_map.get(record.get("preference_key"))
            if key is None:
                continue
            by_key[key] = {
                "id": record["id"], "key": key,
                "effective_value": record["preference_value"],
                "effective_source": "stated", "stated_confidence": 1.0,
                "inferred_confidence": by_key.get(key, {}).get(
                    "inferred_confidence", 0.0),
                "domain": record.get("domain"),
                "task_class": context.intent if key == "autonomy" else None,
                "risk_class": risk_class if key == "autonomy" else None,
                "subject": None,
                "retired_values": by_key.get(key, {}).get("retired_values", []),
            }
        return sorted(by_key.values(), key=lambda item: (item["key"], item["id"]))

    def record_outcome(self, context, result):
        if context.intent in {"why", "status", "undo", "forget"}:
            return {"outcome_ids": [], "adaptation_receipts": [],
                    "improvement_evidence_ids": [],
                    "reversible_action_ids": result.get("reversible_action_ids", [])}
        outcome_id = str(uuid.uuid5(
            uuid.UUID(self.instance_id),
            f"{context.operation_id}:confidence"))
        outcome = loom_memory.record_outcome(
            self.owner_home,
            self.instance_id,
            metric="confidence",
            predicted=float(context.prepared.route_contract["confidence"]),
            actual=1.0 if result["success"] else 0.0,
            domain=context.prepared.domains[0],
            project_id=context.project_id,
            outcome_id=outcome_id,
        )
        evidence = list(result["evidence_ids"]) or [
            "session-" + context.operation_id[:16]]
        self.learning.capture(
            kind="prediction-outcome", scope="project",
            signal="confidence-error", decision_target="confidence-calibration",
            evidence_ids=evidence, domain=context.prepared.domains[0],
            project_id=context.project_id,
            predicted=float(context.prepared.route_contract["confidence"]),
            actual=1.0 if result["success"] else 0.0)
        self.learning.capture(
            kind="routing-outcome", scope="project",
            signal="route-succeeded" if result["success"] else "route-escalated",
            decision_target="routing-strategy", evidence_ids=evidence,
            domain=context.prepared.domains[0], project_id=context.project_id,
            actual=1.0 if result["success"] else 0.0)
        outcome_ids = [outcome["id"]]
        metrics = result["metrics"]
        domain = context.prepared.domains[0]
        calibration_error = abs(
            float(context.prepared.route_contract["confidence"])
            - (1.0 if result["success"] else 0.0))
        measurements = [
            ("prediction-calibration-error", calibration_error, domain),
            ("prediction-calibration-error", calibration_error, "general"),
        ]
        metric_map = {
            "rework-observed": "rework-rate",
            "verification-escape": "verification-escape-rate",
            "incorrect-tier": "incorrect-tier-rate",
            "planning-overhead-ratio": "planning-overhead-ratio",
            "human-decision-round-trips": "human-decision-round-trips",
            "artifact-unused": "unused-artifact-rate",
            "wo-reopen": "wo-reopen-rate",
            "drift-caught-before-execution": "drift-caught-before-execution-rate",
            "release-rollback": "release-rollback-rate",
        }
        for handler_metric, proof_metric in metric_map.items():
            if handler_metric in metrics:
                measurements.append((proof_metric, float(metrics[handler_metric]), domain))
        selected_ids = {item.get("id") for item in context.selected_memory
                        if isinstance(item, dict)}
        applied_ids = result.get("applied_memory_ids", [])
        verified_ids = result.get("verified_memory_ids", [])
        rejected_ids = result.get("rejected_memory_ids", [])
        if any(item not in selected_ids for item in (
                applied_ids + verified_ids + rejected_ids)):
            raise loom_memory.MemoryError(
                "handler referenced memory that was not selected")
        for record_id in verified_ids:
            self.learning.record_verification(record_id, verified=True)
        for record_id in rejected_ids:
            self.learning.record_verification(record_id, verified=False)
        harmful = any(float(metrics.get(key, 0)) > 0 for key in (
            "rework-observed", "verification-escape", "guidance-wasted-work"))
        application_outcome = "hurt" if harmful else (
            "helped" if result["success"] else "neutral")
        if applied_ids:
            measurements.extend([
                ("memory-help-rate", 1.0 if application_outcome == "helped" else 0.0,
                 domain),
                ("memory-hurt-rate", 1.0 if application_outcome == "hurt" else 0.0,
                 domain),
            ])
        for record_id in applied_ids:
            loom_memory.record_application(
                self.owner_home, self.instance_id, record_id,
                outcome=application_outcome, project_id=context.project_id)
        if "effort-estimate" in metrics and "effort-actual" in metrics:
            effort_id = str(uuid.uuid5(
                uuid.UUID(self.instance_id), f"{context.operation_id}:effort-estimate"))
            effort = loom_memory.record_outcome(
                self.owner_home, self.instance_id, metric="effort-estimate",
                predicted=float(metrics["effort-estimate"]),
                actual=float(metrics["effort-actual"]),
                domain=context.prepared.domains[0], project_id=context.project_id,
                outcome_id=effort_id)
            outcome_ids.append(effort["id"])
            self.learning.capture(
                kind="effort-outcome", scope="project", signal="effort-error",
                decision_target="effort-calibration", evidence_ids=evidence,
                domain=context.prepared.domains[0], project_id=context.project_id,
                predicted=float(metrics["effort-estimate"]),
                actual=float(metrics["effort-actual"]))
        automatic_signals = {
            "rework-observed": ("rework", "rework-observed", "effort-calibration"),
            "verification-escape": (
                "verification-escape", "verification-escape", "verification-strategy"),
            "assumption-caught": (
                "assumption-outcome", "assumption-caught", "assumption-strategy"),
            "assumption-missed": (
                "assumption-outcome", "assumption-missed", "assumption-strategy"),
            "unpredicted-failure": (
                "unpredicted-failure", "unexpected-failure", "routing-strategy"),
            "artifact-unused": (
                "artifact-utility", "artifact-unused", "artifact-selection"),
            "artifact-consumed": (
                "artifact-utility", "artifact-consumed", "artifact-selection"),
            "question-rejected": (
                "question-response", "question-rejected", "question-batching"),
            "decision-delegated": (
                "decision-delegation", "decision-delegated", "delegation-strategy"),
            "verification-caught-defect": (
                "verification-catch", "verification-caught-defect",
                "verification-strategy"),
            "guidance-wasted-work": (
                "guidance-waste", "guidance-wasted-work", "guidance-selection"),
            "project-completed": (
                "lifecycle-outcome", "project-completed", "routing-strategy"),
        }
        project_completed = result["success"] and context.intent == "close"
        for metric, (kind, signal, target) in automatic_signals.items():
            observed = float(metrics.get(metric, 0)) > 0
            if metric == "project-completed":
                observed = observed or project_completed
            if observed:
                self.learning.capture(
                    kind=kind, scope="project", signal=signal,
                    decision_target=target, evidence_ids=evidence,
                    domain=context.prepared.domains[0], project_id=context.project_id,
                    actual=(1.0 if metric == "project-completed" and project_completed
                            else min(1.0, float(metrics[metric]))))
        if project_completed or float(metrics.get("project-completed", 0)) > 0:
            self.learning.close_project(context.project_id)
        adaptation_receipts = []
        reversible_action_ids = []
        risk_class = {"S": "low", "M": "medium", "L": "high"}[
            context.prepared.route_contract["tier"]]
        for index, observation in enumerate(result.get("preference_observations", [])):
            kwargs = {}
            if observation["key"] == "stack":
                kwargs["domain"] = context.prepared.domains[0]
            elif observation["key"] == "autonomy":
                kwargs.update(task_class=context.intent, risk_class=risk_class)
            elif observation["key"] == "concern":
                kwargs["subject"] = observation.get("subject")
            receipt = self.preferences.observe(
                key=observation["key"], value=observation["value"], source="observed",
                project_id=context.project_id,
                evidence_id=f"session-{context.operation_id[:16]}-{index}", **kwargs)
            if receipt["material_change"]:
                adaptation_receipts.append(receipt["message"])
                action_id = f"adapt-{context.operation_id[:20]}-{index}"
                self.actions.record(
                    action_id=action_id, kind="preference",
                    target={
                        "key": observation["key"],
                        "domain": kwargs.get("domain"),
                        "task_class": kwargs.get("task_class"),
                        "risk_class": kwargs.get("risk_class"),
                        "subject": kwargs.get("subject"),
                    },
                    evidence_ids=[f"session-{context.operation_id[:16]}-{index}"])
                reversible_action_ids.append(action_id)
        if result.get("artifact_usage"):
            self.planning.record_usage_batch(
                domain=context.prepared.domains[0], project_id=context.project_id,
                usages=result["artifact_usage"])
        proof_batch = []
        for index, (metric, value, measurement_domain) in enumerate(measurements):
            evidence_id = (
                f"session-{context.operation_id[:20]}-{index}-{metric}")
            proof_batch.append({
                "metric": metric, "value": value, "domain": measurement_domain,
                "project_id": context.project_id, "evidence_id": evidence_id,
                "recorded_at": context.prepared.prepared_at,
            })
        proof_result = self.improvement.record_observations_batch(proof_batch)
        return {"outcome_ids": outcome_ids,
                "adaptation_receipts": adaptation_receipts,
                "improvement_evidence_ids": [
                    item["evidence_id"] for item in proof_batch][
                        :proof_result["added"]],
                "reversible_action_ids": reversible_action_ids}

    def compact(self, _context):
        return loom_memory.compact(self.owner_home, self.instance_id)

    def undo_latest(self):
        return self.actions.undo_latest(self.preferences)

    def profile_summary(self):
        return loom_transparency.profile_summary(
            self.owner_home, self.instance_id, max_chars=1200)

    def forget(self, text, selected):
        return loom_transparency.forget_memory(
            self.owner_home, self.instance_id, text, selected)


def validate_active_session(journal_path, session_id, operation_id, *, project_id=None):
    """Validate a currently open session capability without trusting environment prose."""
    try:
        uuid.UUID(str(session_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SessionBlocked("SESSION_IDENTITY_INVALID", "session id is invalid") from exc
    if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{64}", operation_id):
        raise SessionBlocked("SESSION_IDENTITY_INVALID", "operation id is invalid")
    path = Path(journal_path)
    if not path.is_absolute():
        raise SessionBlocked("SESSION_IDENTITY_INVALID", "session journal must be absolute")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except SessionBlocked:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SessionBlocked("SESSION_IDENTITY_INVALID", "session journal is unavailable") from exc
    if not isinstance(raw, dict):
        raise SessionBlocked("SESSION_IDENTITY_INVALID", "session journal is invalid")
    actual_project = raw.get("project_id")
    journal = _load_journal(path, raw.get("instance_id"), actual_project)
    if project_id is not None and actual_project != project_id:
        raise SessionBlocked("SESSION_IDENTITY_INVALID", "session belongs to another project")
    matching = [event for event in journal["events"]
                if event["session_id"] == session_id
                and event["operation_id"] == operation_id]
    if not matching or matching[0]["kind"] != "session-opened" \
            or matching[-1]["kind"] not in {"session-opened", "session-reconciled"}:
        raise SessionBlocked("SESSION_NOT_ACTIVE", "session is not currently active")
    return {"session_id": session_id, "operation_id": operation_id,
            "project_id": actual_project, "instance_id": raw["instance_id"]}


class SessionController:
    """One public controller that prepares, dispatches, and seals an invocation."""

    def __init__(self, *, owner_home, instance_id, handlers, memory):
        loom_runtime._canonical_uuid(instance_id, "instance_id")
        if owner_home is None:
            raise SessionBlocked("SESSION_HOME_REQUIRED", "owner_home must be explicit")
        root = Path(owner_home)
        if not root.is_absolute():
            raise SessionBlocked("SESSION_HOME_REQUIRED", "owner_home must be absolute")
        if not isinstance(handlers, dict) or not all(
                intent in loom_runtime.INTENTS and callable(handler)
                for intent, handler in handlers.items()):
            raise SessionError("handlers must map supported intents to callables")
        self.owner_home = root
        self.instance_id = instance_id
        self.handlers = dict(handlers)
        self.memory = memory

    def _journal_path(self, project_id):
        return (self.owner_home / "instances" / self.instance_id / "runtime" /
                "projects" / project_id / JOURNAL_FILE)

    def open(self, request, *, invocation_id, cwd, explicit_target=None,
             explicit_config=None, now=None):
        """Open an authenticated host-agent action without sealing a false result."""
        instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
        prepared = loom_runtime.prepare_invocation(
            request, instance_id=self.instance_id, invocation_id=invocation_id,
            cwd=cwd, explicit_target=explicit_target, explicit_config=explicit_config,
            owner_home=self.owner_home, now=instant)
        path = self._journal_path(prepared.project_id)
        operation_id, session_id = _operation_identity(prepared)
        with _SessionFileLock(path.with_name(".session.lock")):
            journal = _load_journal(path, self.instance_id, prepared.project_id)
            for event in reversed(journal["events"]):
                if event["kind"] == "session-receipt-sealed" \
                        and event["operation_id"] == operation_id:
                    receipt = _receipt_from_data(
                        event["payload"].get("receipt"), repeated=True)
                    return OpenSession(
                        prepared, session_id, operation_id, str(path),
                        receipt.started_at, receipt)
            prior = [event for event in journal["events"]
                     if event["operation_id"] == operation_id]
            if prior:
                if prior[-1]["kind"] == "session-interrupted":
                    _append_event(
                        journal, "session-reconciled", session_id, operation_id,
                        instant, {"prior_event_hash": prior[-1]["event_hash"]})
                started = next(event["recorded_at"] for event in prior
                               if event["kind"] == "session-opened")
            else:
                started = _format_time(instant)
                _append_event(journal, "session-opened", session_id, operation_id, instant, {
                    "invocation_id": invocation_id,
                    "request_hash": prepared.request_hash,
                    "world_fingerprint": prepared.world_fingerprint,
                    "intent": prepared.intent,
                    "domains": list(prepared.domains),
                })
            _atomic_json(path, journal)
        return OpenSession(
            prepared, session_id, operation_id, str(path), started, None)

    def interrupt(self, open_session, *, code, now=None):
        """Close an open delegated action as interrupted, idempotently."""
        if not isinstance(open_session, OpenSession) \
                or not isinstance(code, str) or not SAFE_ID_RE.fullmatch(code):
            raise SessionError("interrupt requires an open session and safe code")
        instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
        path = Path(open_session.journal_path)
        with _SessionFileLock(path.with_name(".session.lock")):
            journal = _load_journal(
                path, self.instance_id, open_session.prepared.project_id)
            matching = [event for event in journal["events"]
                        if event["operation_id"] == open_session.operation_id]
            if not matching:
                raise SessionBlocked("SESSION_NOT_ACTIVE", "session is unavailable")
            if matching[-1]["kind"] in {"session-opened", "session-reconciled"}:
                _append_event(
                    journal, "session-interrupted", open_session.session_id,
                    open_session.operation_id, instant, {"code": code})
                _atomic_json(path, journal)
            return {"status": "interrupted", "code": code,
                    "session_id": open_session.session_id}

    def run(self, request, *, invocation_id, cwd, explicit_target=None,
            explicit_config=None, now=None, continue_open=False, prepared=None):
        instant = loom_runtime._parse_time(now or dt.datetime.now(dt.timezone.utc))
        if prepared is None:
            prepared = loom_runtime.prepare_invocation(
                request,
                instance_id=self.instance_id,
                invocation_id=invocation_id,
                cwd=cwd,
                explicit_target=explicit_target,
                explicit_config=explicit_config,
                owner_home=self.owner_home,
                now=instant,
            )
        else:
            if not continue_open or not isinstance(
                    prepared, loom_runtime.PreparedInvocation):
                raise SessionError(
                    "sealed preparation may only continue an open session")
            normalized = " ".join(request.split())
            if prepared.instance_id != self.instance_id \
                    or prepared.invocation_id != invocation_id \
                    or prepared.request_hash != loom_runtime._sha(normalized):
                raise SessionBlocked(
                    "SEALED_PREPARATION_MISMATCH",
                    "sealed preparation does not match this session request")
        path = self._journal_path(prepared.project_id)
        lock_path = path.with_name(".session.lock")
        with _SessionFileLock(lock_path):
            return self._run_locked(
                prepared, invocation_id, instant, path, request,
                continue_open=continue_open)

    def _run_locked(self, prepared, invocation_id, instant, path, request,
                    *, continue_open=False):
        operation_id, session_id = _operation_identity(prepared)
        journal = _load_journal(path, self.instance_id, prepared.project_id)
        for event in reversed(journal["events"]):
            if event["kind"] == "session-receipt-sealed" \
                    and event["operation_id"] == operation_id:
                return _receipt_from_data(
                    event["payload"].get("receipt"), repeated=True)
        prior = [event for event in journal["events"]
                 if event["operation_id"] == operation_id]
        reconciled_session_id = None
        if prior:
            if continue_open and prior[-1]["kind"] in {
                    "session-opened", "session-reconciled"}:
                pass
            elif prior[-1]["kind"] != "session-interrupted":
                reconciled_session_id = session_id
                _append_event(
                    journal, "session-interrupted", session_id, operation_id, instant,
                    {"code": "prior-run-ended-without-terminal"})
            if not (continue_open and prior[-1]["kind"] in {
                    "session-opened", "session-reconciled"}):
                reconciled_session_id = session_id
                interrupted_hash = journal["events"][-1]["event_hash"]
                _append_event(
                    journal, "session-reconciled", session_id, operation_id, instant,
                    {"prior_event_hash": interrupted_hash})
            started = next(
                event["recorded_at"] for event in prior
                if event["kind"] == "session-opened")
        else:
            started = _format_time(instant)
            _append_event(journal, "session-opened", session_id, operation_id, instant, {
                "invocation_id": invocation_id,
                "request_hash": prepared.request_hash,
                "world_fingerprint": prepared.world_fingerprint,
                "intent": prepared.intent,
                "domains": list(prepared.domains),
            })
        _atomic_json(path, journal)

        provisional = SessionContext(
            session_id=session_id,
            operation_id=operation_id,
            invocation_id=invocation_id,
            project_id=prepared.project_id,
            intent=prepared.intent,
            prepared=prepared,
            selected_memory=(),
            selected_preferences=(),
            session_journal=str(path),
            request_text=request,
        )
        try:
            housekeeping_result = self.memory.housekeeping(provisional)
            selected = tuple(self.memory.select(provisional))
            selection_context = SessionContext(
                session_id=session_id,
                operation_id=operation_id,
                invocation_id=invocation_id,
                project_id=prepared.project_id,
                intent=prepared.intent,
                prepared=prepared,
                selected_memory=selected,
                selected_preferences=(),
                session_journal=str(path),
                request_text=request,
            )
            preference_selector = getattr(self.memory, "select_preferences", None)
            preferences = tuple(preference_selector(selection_context)) \
                if preference_selector is not None else ()
            context = SessionContext(
                session_id=session_id,
                operation_id=operation_id,
                invocation_id=invocation_id,
                project_id=prepared.project_id,
                intent=prepared.intent,
                prepared=prepared,
                selected_memory=selected,
                selected_preferences=preferences,
                session_journal=str(path),
                request_text=request,
            )
            handler = self.handlers.get(prepared.intent)
            if prepared.route_contract["blocked"]:
                result = {
                    "status": "blocked", "code": prepared.route_contract["code"].lower(),
                    "success": False, "metrics": {}, "evidence_ids": [],
                    "reversible_action_ids": [],
                }
            elif handler is None and prepared.intent in {"why", "status", "undo", "forget"}:
                result = _validate_handler_result(
                    self._builtin_transparency(context, journal))
            elif handler is None:
                result = {
                    "status": "blocked", "code": "handler-unavailable",
                    "success": False, "metrics": {}, "evidence_ids": [],
                    "reversible_action_ids": [],
                }
            else:
                result = _validate_handler_result(handler(context))
            if "usage" not in result:
                result["usage"] = loom_performance.normalize_usage(None)
            memory_result = self.memory.record_outcome(context, result)
            if isinstance(memory_result, dict):
                outcome_ids = tuple(memory_result.get("outcome_ids", []))
                adaptation_receipts = tuple(memory_result.get("adaptation_receipts", []))
                improvement_evidence_ids = tuple(
                    memory_result.get("improvement_evidence_ids", []))
            else:
                outcome_ids = tuple(memory_result)
                adaptation_receipts = ()
                improvement_evidence_ids = ()
            compact_result = self.memory.compact(context)
        except Exception as exc:
            _append_event(
                journal, "session-interrupted", session_id, operation_id, instant,
                {"code": "handler-or-housekeeping-failed"})
            _atomic_json(path, journal)
            raise SessionInterrupted(
                "HANDLER_INTERRUPTED",
                "session did not close; the next invocation will reconcile it") from exc
        completed = _format_time(instant)
        receipt_data = {
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id,
            "operation_id": operation_id,
            "invocation_id": invocation_id,
            "project_id": prepared.project_id,
            "intent": prepared.intent,
            "status": result["status"],
            "code": result["code"],
            "repeated": False,
            "reconciled_session_id": reconciled_session_id,
            "selected_memory_ids": [
                item.get("id") for item in selected
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ],
            "selected_preference_ids": [
                item.get("id") for item in preferences
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ],
            "outcome_ids": list(outcome_ids),
            "adaptation_receipts": list(adaptation_receipts),
            "improvement_evidence_ids": list(improvement_evidence_ids),
            "tier": prepared.route_contract["tier"],
            "domains": list(prepared.domains),
            "reversible_action_ids": list(dict.fromkeys(
                result.get("reversible_action_ids", [])
                + (memory_result.get("reversible_action_ids", [])
                   if isinstance(memory_result, dict) else []))),
            "archived_count": _transition_count(
                {"housekeeping": housekeeping_result, "compaction": compact_result}),
            "uncertainty_codes": ([prepared.route_contract["code"].lower()]
                                    if prepared.route_contract["needs_owner"] else []),
            "owner_input_required": prepared.route_contract["needs_owner"],
            "user_message": result.get("user_message", ""),
            "usage": result["usage"],
            "event_count": len(journal["events"]) + 1,
            "world_fingerprint": prepared.world_fingerprint,
            "started_at": started,
            "completed_at": completed,
        }
        receipt_data["receipt_hash"] = _receipt_hash(receipt_data)
        _append_event(
            journal, "session-receipt-sealed", session_id, operation_id, instant,
            {"receipt": receipt_data, "result": result})
        _atomic_json(path, journal)
        return _receipt_from_data(receipt_data, repeated=False)

    def _builtin_transparency(self, context, journal):
        base = {"status": "completed", "code": f"{context.intent}-complete",
                "success": True, "metrics": {}, "evidence_ids": [],
                "reversible_action_ids": []}
        if context.intent == "status":
            if re.search(r"remember about me|remembered preferences", context.request_text, re.I):
                selector = getattr(self.memory, "profile_summary", None)
                if selector is None:
                    return {**base, "status": "blocked", "code": "profile-disabled",
                            "success": False, "user_message": "Owner memory is disabled."}
                return {**base, "user_message": selector()}
            prior = _latest_sealed_receipt(journal)
            message = ("No prior Loom run exists for this project." if prior is None
                       else loom_transparency.render_compact_receipt(
                           loom_transparency.compact_receipt(prior)))
            return {**base, "user_message": message}
        if context.intent == "why":
            prior = _latest_sealed_receipt(journal)
            if prior is None:
                return {**base, "status": "blocked", "code": "no-prior-decision",
                        "success": False, "user_message": "No prior decision exists to explain."}
            return {**base, "user_message": loom_transparency.explain_receipt(prior)}
        if context.intent == "undo":
            undo = getattr(self.memory, "undo_latest", None)
            if undo is None:
                return {**base, "status": "blocked", "code": "adaptation-disabled",
                        "success": False, "user_message": "No reversible adaptation is available."}
            try:
                result = undo()
            except (loom_transparency.TransparencyError,
                    loom_preferences.PreferenceError) as exc:
                return {**base, "status": "blocked", "code": "nothing-to-undo",
                        "success": False, "user_message": str(exc)}
            return {**base, "user_message": result["message"]}
        forgetter = getattr(self.memory, "forget", None)
        if forgetter is None:
            return {**base, "status": "blocked", "code": "profile-disabled",
                    "success": False, "user_message": "Owner memory is disabled."}
        try:
            result = forgetter(context.request_text, context.selected_memory)
        except loom_transparency.TransparencyError as exc:
            return {**base, "status": "blocked", "code": "memory-reference-unclear",
                    "success": False, "user_message": str(exc)}
        return {**base, "user_message": result["message"]}
