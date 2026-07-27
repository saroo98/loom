#!/usr/bin/env python3
"""Durable write-ahead envelope for risky operations and typed sidecars."""

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import uuid
from pathlib import Path

import loom_reliability


MAX_EVENTS = 128
PHASES = {
    "created", "started", "effect", "passed", "failed", "crashed",
    "timed-out", "cancelled", "incomplete", "reconciled",
}
TERMINAL = {"passed", "failed", "crashed", "timed-out", "cancelled", "reconciled"}
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
OPERATION_NAMESPACE = uuid.UUID("3e8bbd4b-9f77-58f2-a42d-36f09dd25750")


class EnvelopeError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _stamp(value=None):
    instant = value or dt.datetime.now(dt.timezone.utc)
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise EnvelopeError("operation event time must be timezone-aware")
    return instant.astimezone(dt.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def _event(*, sequence, phase, previous_digest, side_effect_boundary,
           state_may_have_changed, primary_failure, secondary_failures,
           cleanup_disposition, terminal_state, now):
    body = {
        "sequence": sequence,
        "phase": phase,
        "recorded_at": _stamp(now),
        "previous_digest": previous_digest,
        "side_effect_boundary": side_effect_boundary,
        "state_may_have_changed": state_may_have_changed,
        "primary_failure": primary_failure,
        "secondary_failures": list(secondary_failures),
        "cleanup_disposition": cleanup_disposition,
        "terminal_state": terminal_state,
    }
    body["event_digest"] = _hash(body)
    return body


def _validate_event(event, *, sequence, previous):
    fields = {
        "sequence", "phase", "recorded_at", "previous_digest",
        "side_effect_boundary", "state_may_have_changed", "primary_failure",
        "secondary_failures", "cleanup_disposition", "terminal_state",
        "event_digest",
    }
    if not isinstance(event, dict) or set(event) != fields \
            or event.get("sequence") != sequence \
            or event.get("phase") not in PHASES \
            or event.get("previous_digest") != previous \
            or event.get("event_digest") != _hash({
                key: item for key, item in event.items() if key != "event_digest"}) \
            or type(event.get("state_may_have_changed")) is not bool \
            or not isinstance(event.get("secondary_failures"), list) \
            or any(not isinstance(item, str) or not item or len(item) > 240
                   for item in event["secondary_failures"]) \
            or event.get("cleanup_disposition") not in {
                "not-started", "not-needed", "completed", "preserved",
                "quarantined", "failed"} \
            or event.get("terminal_state") not in {None, *TERMINAL}:
        raise EnvelopeError("operation event is invalid")
    if event["phase"] in TERMINAL \
            and event["terminal_state"] != event["phase"] \
            or event["phase"] not in TERMINAL and event["terminal_state"] is not None:
        raise EnvelopeError("operation terminal state is inconsistent")
    if event["primary_failure"] is not None and (
            not isinstance(event["primary_failure"], str)
            or not event["primary_failure"] or len(event["primary_failure"]) > 240):
        raise EnvelopeError("operation primary failure is invalid")
    try:
        dt.datetime.fromisoformat(event["recorded_at"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnvelopeError("operation event timestamp is invalid") from exc
    return event["event_digest"]


def validate(value):
    fields = {
        "schema_version", "operation_id", "operation_class", "subject_digest",
        "typed_sidecar", "created_at", "durability_scope", "events",
        "envelope_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 2 \
            or not isinstance(value.get("operation_class"), str) \
            or SAFE_NAME.fullmatch(value["operation_class"]) is None \
            or not DIGEST.fullmatch(str(value.get("subject_digest", ""))) \
            or not isinstance(value.get("events"), list) \
            or not 1 <= len(value["events"]) <= MAX_EVENTS \
            or value.get("envelope_sha256") != _hash({
                key: item for key, item in value.items() if key != "envelope_sha256"}):
        raise EnvelopeError("operation envelope is invalid")
    try:
        if str(uuid.UUID(value["operation_id"])) != value["operation_id"]:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise EnvelopeError("operation identity is invalid") from exc
    sidecar = value.get("typed_sidecar")
    if not isinstance(sidecar, dict) or set(sidecar) != {
            "type", "id", "contract_digest", "final_digest"} \
            or not isinstance(sidecar["type"], str) \
            or SAFE_NAME.fullmatch(sidecar["type"]) is None \
            or not isinstance(sidecar["id"], str) or not sidecar["id"] \
            or len(sidecar["id"]) > 128 \
            or not DIGEST.fullmatch(sidecar["contract_digest"]) \
            or (sidecar["final_digest"] is not None
                and not DIGEST.fullmatch(str(sidecar["final_digest"]))):
        raise EnvelopeError("operation sidecar identity is invalid")
    if value.get("durability_scope") not in {
            "process-crash-confirmed", "power-loss-confirmed",
            "power-loss-unverified"}:
        raise EnvelopeError("operation durability scope is invalid")
    previous = "0" * 64
    for sequence, event in enumerate(value["events"]):
        previous = _validate_event(event, sequence=sequence, previous=previous)
    phases = [event["phase"] for event in value["events"]]
    if phases[0] != "created" \
            or ("started" in phases and phases.index("started") != 1) \
            or any(phase in TERMINAL for phase in phases[:-1]):
        raise EnvelopeError("operation phase sequence is invalid")
    return value


def _write(path, value):
    value["envelope_sha256"] = _hash({
        key: item for key, item in value.items() if key != "envelope_sha256"})
    validate(value)
    loom_reliability.atomic_write_json(path, value)
    return json.loads(json.dumps(value))


def begin(directory, *, operation_class, subject_digest, sidecar_type,
          sidecar_id, sidecar_digest, now=None, operation_id=None):
    directory = Path(directory)
    if not directory.is_absolute():
        raise EnvelopeError("operation journal directory must be absolute")
    if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
        raise EnvelopeError("operation journal directory is unsafe")
    directory.mkdir(parents=True, exist_ok=True)
    identifier = str(uuid.uuid4()) if operation_id is None else str(operation_id)
    try:
        if str(uuid.UUID(identifier)) != identifier:
            raise ValueError
    except ValueError as exc:
        raise EnvelopeError("operation identity is invalid") from exc
    path = directory / f"{identifier}.json"
    if path.exists():
        raise EnvelopeError("operation identity already exists")
    created = _stamp(now)
    value = {
        "schema_version": 2,
        "operation_id": identifier,
        "operation_class": operation_class,
        "subject_digest": subject_digest,
        "typed_sidecar": {
            "type": sidecar_type, "id": sidecar_id,
            "contract_digest": sidecar_digest, "final_digest": None,
        },
        "created_at": created,
        "durability_scope": (
            "process-crash-confirmed" if os.name == "nt"
            else "power-loss-confirmed"),
        "events": [_event(
            sequence=0, phase="created", previous_digest="0" * 64,
            side_effect_boundary="before-first-effect",
            state_may_have_changed=False, primary_failure=None,
            secondary_failures=[], cleanup_disposition="not-started",
            terminal_state=None, now=now)],
        "envelope_sha256": "",
    }
    return path, _write(path, value)


def begin_or_reuse(directory, *, operation_class, subject_digest, sidecar_type,
                   sidecar_id, sidecar_digest, now=None):
    """Reuse one exact unchanged-world operation; changed subjects get new identities."""
    identity = str(uuid.uuid5(
        OPERATION_NAMESPACE,
        _canonical({
            "operation_class": operation_class,
            "subject_digest": subject_digest,
            "sidecar_type": sidecar_type,
            "sidecar_id": sidecar_id,
            "sidecar_digest": sidecar_digest,
        }).decode("ascii")))
    path = Path(directory) / f"{identity}.json"
    if path.exists():
        value = read(path)
        expected = {
            "operation_id": identity,
            "operation_class": operation_class,
            "subject_digest": subject_digest,
            "typed_sidecar": {
                "type": sidecar_type, "id": sidecar_id,
                "contract_digest": sidecar_digest, "final_digest": None,
            },
        }
        if any(value[key] != item for key, item in expected.items()):
            raise EnvelopeError("reused operation identity has conflicting semantics")
        return path, value, True
    path, value = begin(
        directory, operation_class=operation_class,
        subject_digest=subject_digest, sidecar_type=sidecar_type,
        sidecar_id=sidecar_id, sidecar_digest=sidecar_digest,
        now=now, operation_id=identity)
    return path, value, False


def incomplete(directory, *, limit=256):
    """Return validated nonterminal envelopes in deterministic order."""
    directory = Path(directory)
    if not directory.is_absolute() or not directory.exists() \
            or directory.is_symlink() or not directory.is_dir():
        raise EnvelopeError("operation journal directory is unsafe")
    entries = sorted(directory.iterdir(), key=lambda item: item.name)
    if len(entries) > limit:
        raise EnvelopeError("operation journal exceeds its inspection bound")
    pending = []
    for path in entries:
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise EnvelopeError("operation journal contains an unsafe entry")
        value = read(path)
        if value["events"][-1]["phase"] not in TERMINAL:
            pending.append((path, value))
    return pending


def read(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"operation envelope is unreadable: {exc}") from exc
    return validate(value)


def transition(path, *, phase, side_effect_boundary, state_may_have_changed,
               primary_failure=None, secondary_failures=(),
               cleanup_disposition="not-needed", final_sidecar_digest=None,
               now=None):
    value = read(path)
    if phase not in PHASES or value["events"][-1]["phase"] in TERMINAL:
        raise EnvelopeError("operation transition is not allowed")
    previous_phase = value["events"][-1]["phase"]
    if phase == "started" and previous_phase != "created" \
            or phase == "effect" and previous_phase not in {"started", "effect"} \
            or phase == "incomplete" and previous_phase not in {
                "started", "effect"} \
            or phase == "reconciled" and previous_phase != "incomplete" \
            or phase in TERMINAL - {"reconciled"} and previous_phase not in {
                "started", "effect", "incomplete"}:
        raise EnvelopeError("operation transition violates phase order")
    candidate = _event(
        sequence=len(value["events"]), phase=phase,
        previous_digest=value["events"][-1]["event_digest"],
        side_effect_boundary=side_effect_boundary,
        state_may_have_changed=state_may_have_changed,
        primary_failure=primary_failure,
        secondary_failures=secondary_failures,
        cleanup_disposition=cleanup_disposition,
        terminal_state=phase if phase in TERMINAL else None, now=now)
    if len(value["events"]) >= MAX_EVENTS:
        raise EnvelopeError("operation envelope exceeds its event bound")
    value["events"].append(candidate)
    if final_sidecar_digest is not None:
        if phase not in TERMINAL or not isinstance(final_sidecar_digest, str) \
                or DIGEST.fullmatch(final_sidecar_digest) is None:
            raise EnvelopeError("operation final sidecar digest is invalid")
        value["typed_sidecar"]["final_digest"] = final_sidecar_digest
    return _write(path, value)


def reconcile_incomplete(path, *, subject_digest, reconciler, now=None):
    value = read(path)
    if value["subject_digest"] != subject_digest:
        raise EnvelopeError("incomplete operation subject changed")
    if value["events"][-1]["phase"] in TERMINAL:
        return value
    transition(
        path, phase="incomplete", side_effect_boundary="reconciliation-required",
        state_may_have_changed=True, cleanup_disposition="preserved", now=now)
    outcome = reconciler(read(path))
    if not isinstance(outcome, dict) or set(outcome) != {
            "state_may_have_changed", "cleanup_disposition",
            "secondary_failures"}:
        raise EnvelopeError("operation reconciler returned an invalid outcome")
    return transition(
        path, phase="reconciled", side_effect_boundary="reconciliation-complete",
        state_may_have_changed=outcome["state_may_have_changed"],
        secondary_failures=outcome["secondary_failures"],
        cleanup_disposition=outcome["cleanup_disposition"], now=now)


def run_supervised(*, operation_class, command, cwd, timeout, environment=None,
                   allowed_roots=(), protected_roots=(), capabilities=(),
                   cancel_requested=None, max_transcript_bytes=256 * 1024,
                   capture_output=False, journal_root=None):
    """Run a contained subprocess with a durable envelope before process start."""
    import loom_operation_supervisor

    cwd = Path(cwd).resolve()
    if journal_root is None:
        identity = hashlib.sha256(str(cwd).encode("utf-8")).hexdigest()[:24]
        journal_root = Path(tempfile.gettempdir()).resolve() / \
            "loom-operation-journal" / identity
    journal_root = Path(journal_root).resolve()
    operation_id = str(uuid.uuid4())
    contract = {
        "operation_class": operation_class,
        "command": list(command),
        "cwd": str(cwd),
        "timeout": float(timeout),
        "environment_keys": sorted((environment or {}).keys()),
        "allowed_roots": sorted(str(Path(item).resolve()) for item in allowed_roots),
        "protected_roots": sorted(
            str(Path(item).resolve()) for item in protected_roots),
        "capabilities": sorted(set(capabilities)),
    }
    contract_digest = _hash(contract)
    path, _value = begin(
        journal_root, operation_class=operation_class,
        subject_digest=contract_digest,
        sidecar_type="operation-supervisor-receipt",
        sidecar_id=f"{operation_id}.json",
        sidecar_digest=contract_digest,
        operation_id=operation_id)
    transition(
        path, phase="started", side_effect_boundary="before-process-start",
        state_may_have_changed=False)
    transition(
        path, phase="effect", side_effect_boundary="process-start-authorized",
        state_may_have_changed=True)
    try:
        result = loom_operation_supervisor.run(
            operation_class=operation_class, command=command, cwd=cwd,
            timeout=timeout, environment=environment, allowed_roots=allowed_roots,
            protected_roots=protected_roots, capabilities=capabilities,
            cancel_requested=cancel_requested,
            max_transcript_bytes=max_transcript_bytes,
            capture_output=capture_output, operation_id=operation_id)
        receipt = result[0] if capture_output else result
        failure = receipt.get("primary_failure")
        phase = {
            "cancelled": "cancelled",
            "timed-out": "timed-out",
        }.get(failure, "passed" if receipt.get("status") == "passed" else "failed")
        transition(
            path, phase=phase,
            side_effect_boundary="supervisor-receipt-committed",
            state_may_have_changed=True, primary_failure=failure,
            secondary_failures=receipt.get("secondary_failures", ()),
            cleanup_disposition=(
                "completed" if receipt.get("survivors_confirmed_zero")
                else "failed"),
            final_sidecar_digest=receipt["receipt_sha256"])
        return result
    except BaseException as exc:
        try:
            current = read(path)
            if current["events"][-1]["phase"] not in TERMINAL:
                transition(
                    path, phase="failed",
                    side_effect_boundary="supervisor-failed-without-receipt",
                    state_may_have_changed=True,
                    primary_failure=type(exc).__name__[:120],
                    cleanup_disposition="preserved")
        finally:
            raise
