#!/usr/bin/env python3
"""Owner-facing Proofline projections with a closed privacy firewall."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import loom_message
import loom_proofline
import loom_proofline_completion
import loom_reliability


TRUST_CARD_SCHEMA_VERSION = 1
FLIGHT_RECORDER_SCHEMA_VERSION = 1
BUNDLE_SCHEMA_VERSION = 1
REPLAY_SCHEMA_VERSION = 1
MAX_FLIGHT_EVENTS = 2048
PUBLIC_FILES = (
    "public/completion-report.json",
    "public/flight-recorder.json",
    "public/trust-card.json",
)
PRIVATE_FILES = ("private/references.json",)
BUNDLE_FILES = frozenset((*PUBLIC_FILES, *PRIVATE_FILES, "manifest.json"))


class ProofUXError(ValueError):
    pass


def _read_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProofUXError(f"{label} is unreadable: {exc}") from exc


def _file_row(root, relative, visibility):
    path = root / relative
    data = path.read_bytes()
    return {
        "path": relative,
        "visibility": visibility,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _safe_receipt(receipt):
    required = {
        "receipt_hash", "operation_id", "intent", "status", "code",
        "completed_at", "owner_message", "selected_memory_ids",
        "selected_preference_ids",
    }
    if not isinstance(receipt, dict) or any(key not in receipt for key in required) \
            or not isinstance(receipt["owner_message"], dict):
        raise ProofUXError("sealed receipt fields are unavailable")
    loom_message.validate(receipt["owner_message"])
    if any(not isinstance(receipt[key], str) or not receipt[key]
           for key in ("receipt_hash", "operation_id", "intent", "status",
                       "code", "completed_at")):
        raise ProofUXError("sealed receipt identity is invalid")
    return receipt


def build_trust_card(receipt, completion_report):
    receipt = _safe_receipt(receipt)
    loom_proofline_completion.validate_report(completion_report)
    message = receipt["owner_message"]
    body = {
        "schema_version": TRUST_CARD_SCHEMA_VERSION,
        "receipt_id": message["receipt_id"],
        "receipt_sha256": receipt["receipt_hash"],
        "state": message["state"],
        "consequence": message["consequence"],
        "verification": message["verification"],
        "freshness": message["freshness"],
        "changes_made": message["changes_made"],
        "undo_status": message["undo_status"],
        "summary": message["summary"],
        "recommendation": message["recommendation"] or message["next_action"],
        "next_action": message["next_action"],
        "result_path": message["result_path"],
        "proofline_report_sha256": completion_report["report_sha256"],
        "proofline_gate": completion_report["gate"]["state"],
        "details_available": True,
    }
    value = {**body, "card_sha256": loom_proofline.digest(body)}
    validate_trust_card(value)
    return value


def validate_trust_card(value):
    fields = {
        "schema_version", "receipt_id", "receipt_sha256", "state",
        "consequence", "verification", "freshness", "changes_made",
        "undo_status", "summary", "recommendation", "next_action",
        "result_path", "proofline_report_sha256", "proofline_gate",
        "details_available", "card_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != TRUST_CARD_SCHEMA_VERSION \
            or value.get("details_available") is not True \
            or value.get("proofline_gate") not in {"passed", "failed", "advisory"} \
            or any(not isinstance(value.get(key), str) or not value[key]
                   for key in ("receipt_id", "receipt_sha256", "state",
                               "consequence", "verification", "freshness",
                               "undo_status", "summary", "recommendation",
                               "next_action", "proofline_report_sha256")) \
            or (value.get("result_path") is not None
                and (not isinstance(value["result_path"], str)
                     or loom_message.SAFE_RESULT_PATH.fullmatch(
                         value["result_path"]) is None)):
        raise ProofUXError("Trust Card is invalid")
    body = dict(value)
    observed = body.pop("card_sha256", None)
    if observed != loom_proofline.digest(body):
        raise ProofUXError("Trust Card digest changed")
    return value


def append_flight_event(existing, receipt):
    receipt = _safe_receipt(receipt)
    if existing is None:
        events = []
    else:
        validate_flight_recorder(existing)
        events = list(existing["events"])
    message = receipt["owner_message"]
    row = {
        "receipt_id": message["receipt_id"],
        "receipt_sha256": receipt["receipt_hash"],
        "completed_at": receipt["completed_at"],
        "intent": receipt["intent"],
        "status": receipt["status"],
        "summary": message["summary"],
        "verification": message["verification"],
        "freshness": message["freshness"],
        "changes_made": message["changes_made"],
        "undo_status": message["undo_status"],
        "result_path": message["result_path"],
    }
    events = [item for item in events if item["receipt_id"] != row["receipt_id"]]
    events.append(row)
    events = sorted(events, key=lambda item: (
        item["completed_at"], item["receipt_id"]))[-MAX_FLIGHT_EVENTS:]
    body = {
        "schema_version": FLIGHT_RECORDER_SCHEMA_VERSION,
        "events": events,
        "privacy": {
            "memory_bodies": "excluded",
            "raw_transcripts": "excluded",
            "owner_request_bodies": "excluded",
        },
    }
    value = {**body, "recorder_sha256": loom_proofline.digest(body)}
    validate_flight_recorder(value)
    return value


def validate_flight_recorder(value):
    fields = {"schema_version", "events", "privacy", "recorder_sha256"}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != FLIGHT_RECORDER_SCHEMA_VERSION \
            or not isinstance(value.get("events"), list) \
            or len(value["events"]) > MAX_FLIGHT_EVENTS \
            or value.get("privacy") != {
                "memory_bodies": "excluded",
                "raw_transcripts": "excluded",
                "owner_request_bodies": "excluded",
            }:
        raise ProofUXError("Flight Recorder is invalid")
    receipt_ids = []
    for row in value["events"]:
        required = {
            "receipt_id", "receipt_sha256", "completed_at", "intent",
            "status", "summary", "verification", "freshness",
            "changes_made", "undo_status", "result_path",
        }
        if not isinstance(row, dict) or set(row) != required \
                or any(not isinstance(row[key], str) or not row[key]
                       for key in required - {"changes_made", "result_path"}) \
                or (row["changes_made"] is not None
                    and type(row["changes_made"]) is not bool) \
                or (row["result_path"] is not None
                    and loom_message.SAFE_RESULT_PATH.fullmatch(
                        row["result_path"]) is None):
            raise ProofUXError("Flight Recorder event is invalid")
        receipt_ids.append(row["receipt_id"])
    if len(receipt_ids) != len(set(receipt_ids)):
        raise ProofUXError("Flight Recorder contains duplicate receipts")
    body = dict(value)
    observed = body.pop("recorder_sha256", None)
    if observed != loom_proofline.digest(body):
        raise ProofUXError("Flight Recorder digest changed")
    return value


def _private_references(receipt):
    return {
        "schema_version": 1,
        "receipt_sha256": receipt["receipt_hash"],
        "selected_memory_count": len(receipt["selected_memory_ids"]),
        "selected_preference_count": len(receipt["selected_preference_ids"]),
        "memory_bodies_included": False,
        "raw_transcripts_included": False,
        "owner_request_bodies_included": False,
    }


def _write_bundle(bundle, *, trust_card, completion_report, flight, receipt):
    public = bundle / "public"
    private = bundle / "private"
    public.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    loom_reliability.atomic_write_json(public / "trust-card.json", trust_card)
    loom_reliability.atomic_write_json(
        public / "completion-report.json", completion_report)
    loom_reliability.atomic_write_json(public / "flight-recorder.json", flight)
    loom_reliability.atomic_write_json(
        private / "references.json", _private_references(receipt))
    rows = [
        *(_file_row(bundle, path, "public") for path in PUBLIC_FILES),
        *(_file_row(bundle, path, "private-reference") for path in PRIVATE_FILES),
    ]
    body = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_id": "proof-" + receipt["receipt_hash"][:24],
        "receipt_sha256": receipt["receipt_hash"],
        "proofline_report_sha256": completion_report["report_sha256"],
        "files": sorted(rows, key=lambda item: item["path"]),
        "privacy_firewall": {
            "allowlisted_files_only": True,
            "memory_bodies": "excluded",
            "raw_transcripts": "excluded",
            "owner_request_bodies": "excluded",
        },
    }
    manifest = {**body, "manifest_sha256": loom_proofline.digest(body)}
    loom_reliability.atomic_write_json(bundle / "manifest.json", manifest)
    validate_bundle(bundle)
    return manifest


def validate_bundle(bundle):
    bundle = Path(bundle)
    actual = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*") if path.is_file()
    }
    if actual != BUNDLE_FILES:
        raise ProofUXError("Proof Bundle contains a file outside its privacy firewall")
    manifest = _read_json(bundle / "manifest.json", "Proof Bundle manifest")
    fields = {
        "schema_version", "bundle_id", "receipt_sha256",
        "proofline_report_sha256", "files", "privacy_firewall",
        "manifest_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != fields \
            or manifest.get("schema_version") != BUNDLE_SCHEMA_VERSION \
            or manifest.get("privacy_firewall") != {
                "allowlisted_files_only": True,
                "memory_bodies": "excluded",
                "raw_transcripts": "excluded",
                "owner_request_bodies": "excluded",
            }:
        raise ProofUXError("Proof Bundle manifest is invalid")
    expected_rows = sorted([
        *(_file_row(bundle, path, "public") for path in PUBLIC_FILES),
        *(_file_row(bundle, path, "private-reference") for path in PRIVATE_FILES),
    ], key=lambda item: item["path"])
    if manifest["files"] != expected_rows:
        raise ProofUXError("Proof Bundle file digest changed")
    body = dict(manifest)
    observed = body.pop("manifest_sha256", None)
    if observed != loom_proofline.digest(body):
        raise ProofUXError("Proof Bundle manifest digest changed")
    return manifest


def record_receipt(pack, receipt):
    pack = Path(pack)
    proofline = pack / "proofline"
    completion = _read_json(
        proofline / "completion-report.json", "Proofline completion report")
    loom_proofline_completion.validate_report(completion)
    recorder_path = proofline / "flight-recorder.json"
    existing = _read_json(recorder_path, "Flight Recorder") \
        if recorder_path.is_file() else None
    flight = append_flight_event(existing, receipt)
    trust_card = build_trust_card(receipt, completion)
    loom_reliability.atomic_write_json(proofline / "trust-card.json", trust_card)
    loom_reliability.atomic_write_json(recorder_path, flight)
    _write_bundle(
        proofline / "proof-bundle", trust_card=trust_card,
        completion_report=completion, flight=flight, receipt=receipt)
    return {
        "trust_card": trust_card,
        "flight_recorder": flight,
        "bundle": validate_bundle(proofline / "proof-bundle"),
    }


def replay(bundle, current_completion_report):
    manifest = validate_bundle(bundle)
    current = current_completion_report
    loom_proofline_completion.validate_report(current)
    historical = _read_json(
        Path(bundle) / "public" / "completion-report.json",
        "historical Proofline completion report")
    loom_proofline_completion.validate_report(historical)
    state = (
        "current" if current["report_sha256"] == historical["report_sha256"]
        else "stale")
    body = {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "bundle_id": manifest["bundle_id"],
        "historical_report_sha256": historical["report_sha256"],
        "current_report_sha256": current["report_sha256"],
        "freshness": state,
        "commands_executed": 0,
        "historical_authority_granted": False,
        "authority_effect": "none",
    }
    return {**body, "replay_sha256": loom_proofline.digest(body)}
