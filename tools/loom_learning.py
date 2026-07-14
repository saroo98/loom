#!/usr/bin/env python3
"""Typed, bounded, per-install automatic learning for Loom (stdlib only)."""

import datetime as dt
import hashlib
import json
import math
import re
import uuid
from pathlib import Path

import loom_memory


SCHEMA_VERSION = 1
MAX_EVENTS = 1024
MAX_CANDIDATES = 256
MAX_CANDIDATE_EVIDENCE = 64
MAX_EVIDENCE_PROJECTS = 16
EVENT_KINDS = {
    "prediction-outcome", "effort-outcome", "rework", "verification-escape",
    "routing-outcome", "assumption-outcome", "unpredicted-failure",
    "artifact-utility", "question-response", "decision-delegation",
    "verification-catch", "guidance-waste", "lifecycle-outcome",
}
SCOPES = {"global", "domain", "project"}
POLARITIES = {"supports", "contradicts"}
DECISION_TARGETS = {
    "confidence-calibration", "effort-calibration", "routing-strategy",
    "verification-strategy", "assumption-strategy", "artifact-selection",
    "question-batching", "delegation-strategy", "guidance-selection",
}
SIGNALS = {
    "confidence-error", "effort-error", "rework-observed",
    "verification-escape", "route-succeeded", "route-escalated",
    "assumption-caught", "assumption-missed", "unexpected-failure",
    "artifact-consumed", "artifact-unused", "question-rejected",
    "decision-delegated", "verification-caught-defect", "guidance-wasted-work",
    "gate-passed", "work-order-closed", "project-completed",
}
PROHIBITED_INFERENCE_TARGETS = {
    "hard-stop", "privacy-tolerance", "spending-authority",
    "destructive-operation-permission", "security-risk-appetite",
}
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PROJECT_ID = re.compile(r"^p-[0-9a-f]{32}$")
EVENT_FIELDS = {
    "kind", "scope", "signal", "decision_target", "evidence_ids", "domain",
    "project_id", "predicted", "actual", "polarity", "schema_version", "id",
    "instance_id", "recorded_at",
}
CANDIDATE_FIELDS = {
    "scope", "category", "domain", "project_id", "signal", "decision_target",
    "id", "status", "supports", "contradicts", "evidence_count", "evidence_ids",
    "evidence_projects", "confidence", "created_at", "last_evidence_at",
    "expires_at", "future_decision", "admitted_memory_id",
}


class LearningError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LearningError(f"learning store duplicates key {key!r}")
        value[key] = item
    return value


def _now(value=None):
    if value is None:
        instant = dt.datetime.now(dt.timezone.utc)
    elif isinstance(value, str):
        try:
            instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LearningError("recorded_at must be an ISO-8601 timestamp") from exc
    else:
        instant = value
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise LearningError("recorded_at must be timezone-aware")
    return instant.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat() \
        .replace("+00:00", "Z")


class LearningEngine:
    """Small public interface over typed event capture and admission state."""

    def __init__(self, owner_home, instance_id):
        self.home = Path(owner_home)
        if not self.home.is_absolute():
            raise LearningError("owner_home must be absolute")
        try:
            loom_memory.validate_instance(self.home, instance_id)
        except loom_memory.MemoryError as exc:
            raise LearningError(str(exc)) from exc
        self.instance_id = instance_id
        self.directory = self.home / "instances" / instance_id
        self.path = self.directory / "learning-events.json"
        self.candidate_path = self.directory / "learning-candidates.json"

    def _read(self):
        if not self.path.exists():
            return {"schema_version": SCHEMA_VERSION,
                    "instance_id": self.instance_id, "total_count": 0, "events": []}
        try:
            value = json.loads(
                self.path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
        except (OSError, ValueError, json.JSONDecodeError, loom_memory.MemoryError) as exc:
            raise LearningError(f"learning event store is invalid: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "total_count", "events"} \
                or value["schema_version"] != SCHEMA_VERSION \
                or value["instance_id"] != self.instance_id \
                or not isinstance(value["events"], list) \
                or len(value["events"]) > MAX_EVENTS:
            raise LearningError("learning event store contract is invalid")
        for event in value["events"]:
            self._validate_event(event)
        return value

    def _validate_event(self, event):
        if not isinstance(event, dict) or set(event) != EVENT_FIELDS \
                or event.get("schema_version") != SCHEMA_VERSION \
                or event.get("instance_id") != self.instance_id \
                or event.get("kind") not in EVENT_KINDS \
                or event.get("scope") not in SCOPES \
                or event.get("signal") not in SIGNALS \
                or event.get("decision_target") not in DECISION_TARGETS \
                or event.get("polarity") not in POLARITIES:
            raise LearningError("learning event contract is invalid")
        try:
            uuid.UUID(event["id"])
            _now(event["recorded_at"])
        except (ValueError, TypeError, AttributeError, LearningError) as exc:
            raise LearningError("learning event identity is invalid") from exc
        evidence = event.get("evidence_ids")
        if not isinstance(evidence, list) or not evidence or len(evidence) > 32 \
                or len(evidence) != len(set(evidence)) or not all(
                    isinstance(item, str) and re.fullmatch(r"e-[0-9a-f]{24}", item)
                    for item in evidence):
            raise LearningError("learning event evidence is invalid")
        domain, project = event.get("domain"), event.get("project_id")
        scope_valid = (
            event["scope"] == "global" and domain is None and project is None
            or event["scope"] == "domain" and isinstance(domain, str)
            and SAFE_ID.fullmatch(domain) and project is None
            or event["scope"] == "project" and isinstance(domain, str)
            and SAFE_ID.fullmatch(domain) and isinstance(project, str)
            and PROJECT_ID.fullmatch(project)
        )
        metrics_valid = all(value is None or (
            type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1)
            for value in (event.get("predicted"), event.get("actual")))
        if not scope_valid or not metrics_valid:
            raise LearningError("learning event scope or metrics are invalid")
        identity = {key: event[key] for key in (
            "kind", "scope", "signal", "decision_target", "evidence_ids", "domain",
            "project_id", "predicted", "actual", "polarity")}
        expected = str(uuid.uuid5(uuid.UUID(self.instance_id), _digest(identity)))
        if event["id"] != expected:
            raise LearningError("learning event was modified after capture")

    def events(self):
        return json.loads(json.dumps(self._read()["events"]))

    def _read_candidates(self):
        if not self.candidate_path.exists():
            return {"schema_version": SCHEMA_VERSION, "instance_id": self.instance_id,
                    "candidates": []}
        try:
            value = json.loads(self.candidate_path.read_text(encoding="utf-8"),
                               object_pairs_hook=_strict_object)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise LearningError(f"learning candidate store is invalid: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "candidates"} \
                or value["schema_version"] != SCHEMA_VERSION \
                or value["instance_id"] != self.instance_id \
                or not isinstance(value["candidates"], list) \
                or len(value["candidates"]) > MAX_CANDIDATES:
            raise LearningError("learning candidate store contract is invalid")
        for candidate in value["candidates"]:
            if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_FIELDS \
                    or candidate.get("status") not in {
                        "candidate", "active", "dormant", "stale", "archived",
                        "forgotten", "superseded"} \
                    or candidate.get("scope") not in SCOPES \
                    or candidate.get("future_decision") not in DECISION_TARGETS \
                    or not isinstance(candidate.get("evidence_ids"), list) \
                    or len(candidate["evidence_ids"]) > MAX_CANDIDATE_EVIDENCE \
                    or not isinstance(candidate.get("evidence_projects"), list) \
                    or len(candidate["evidence_projects"]) > MAX_EVIDENCE_PROJECTS:
                raise LearningError("learning candidate contract is invalid")
        return value

    def candidates(self):
        return json.loads(json.dumps(self._read_candidates()["candidates"]))

    def housekeeping(self, *, now=None):
        instant = dt.datetime.fromisoformat(_now(now).replace("Z", "+00:00"))
        expired = 0
        with loom_memory.FileLock(self.directory / ".learning.lock"):
            store = self._read_candidates()
            for candidate in store["candidates"]:
                deadline = dt.datetime.fromisoformat(
                    candidate["expires_at"].replace("Z", "+00:00"))
                if candidate["status"] == "candidate" and deadline < instant:
                    candidate["status"] = "archived"
                    expired += 1
                if candidate["status"] == "active" \
                        and candidate.get("admitted_memory_id"):
                    memory = loom_memory.inspect_record(
                        self.home, self.instance_id,
                        candidate["admitted_memory_id"])
                    if memory is None:
                        raise LearningError(
                            "active candidate references missing admitted memory")
                    candidate["status"] = memory["status"]
            loom_memory._atomic_json(self.candidate_path, store)
        return {"expired": expired, "pending_candidates": sum(
            item["status"] == "candidate" for item in store["candidates"])}

    def close_project(self, project_id, *, now=None):
        result = loom_memory.close_project(
            self.home, self.instance_id, project_id, now=now)
        with loom_memory.FileLock(self.directory / ".learning.lock"):
            store = self._read_candidates()
            transitioned = 0
            for candidate in store["candidates"]:
                if candidate.get("project_id") == project_id \
                        and candidate.get("status") in {"candidate", "active"}:
                    candidate["status"] = "archived"
                    transitioned += 1
            loom_memory._atomic_json(self.candidate_path, store)
        result["candidates_archived"] = transitioned
        return result

    def rehydrate_domain(self, *, domain, project_id=None, max_records=3,
                         max_chars=1600, now=None):
        result = loom_memory.rehydrate_domain(
            self.home, self.instance_id, domain=domain, project_id=project_id,
            max_records=max_records, max_chars=max_chars, now=now)
        changed = set(result["reactivated_ids"] + result["verification_required_ids"]
                      + result["dormant_review_ids"])
        if changed:
            with loom_memory.FileLock(self.directory / ".learning.lock"):
                store = self._read_candidates()
                for candidate in store["candidates"]:
                    if candidate.get("admitted_memory_id") in changed:
                        memory = loom_memory.inspect_record(
                            self.home, self.instance_id,
                            candidate["admitted_memory_id"])
                        candidate["status"] = memory["status"]
                loom_memory._atomic_json(self.candidate_path, store)
        return result

    def record_verification(self, record_id, *, verified, verify_by=None, now=None):
        record = loom_memory.record_verification(
            self.home, self.instance_id, record_id, verified=verified,
            verify_by=verify_by, now=now)
        with loom_memory.FileLock(self.directory / ".learning.lock"):
            store = self._read_candidates()
            for candidate in store["candidates"]:
                if candidate.get("admitted_memory_id") == record_id:
                    candidate["status"] = record["status"]
            loom_memory._atomic_json(self.candidate_path, store)
        return record

    @staticmethod
    def _admission_contract(event):
        signal = event["signal"]
        if signal in {"decision-delegated", "question-rejected"}:
            return ("global", "process", None, None, 3, 2)
        if signal == "confidence-error":
            return ("global", "calibration", None, None, 3, 2)
        if signal in {"effort-error", "route-succeeded", "route-escalated",
                      "verification-caught-defect", "guidance-wasted-work"}:
            return ("domain", "domain", event["domain"], None, 3, 1)
        return ("project", "process", event["domain"], event["project_id"], 2, 1)

    def _consider(self, event):
        scope, category, domain, project_id, threshold, project_threshold = \
            self._admission_contract(event)
        key_data = {
            "scope": scope, "category": category, "domain": domain,
            "project_id": project_id, "signal": event["signal"],
            "decision_target": event["decision_target"],
        }
        candidate_id = str(uuid.uuid5(
            uuid.UUID(self.instance_id), "candidate:" + _digest(key_data)))
        lock = self.directory / ".learning.lock"
        with loom_memory.FileLock(lock):
            store = self._read_candidates()
            candidate = next((item for item in store["candidates"]
                              if item["id"] == candidate_id), None)
            if candidate is None:
                candidate = dict(key_data)
                candidate.update({
                    "id": candidate_id, "status": "candidate",
                    "supports": 0, "contradicts": 0, "evidence_count": 0,
                    "evidence_ids": [], "evidence_projects": [],
                    "confidence": 0.0, "created_at": event["recorded_at"],
                    "last_evidence_at": event["recorded_at"],
                    "expires_at": _now(dt.datetime.fromisoformat(
                        event["recorded_at"].replace("Z", "+00:00"))
                        + dt.timedelta(days=14)),
                    "future_decision": event["decision_target"],
                    "admitted_memory_id": None,
                })
                store["candidates"].append(candidate)
            new_evidence = [item for item in event["evidence_ids"]
                            if item not in candidate["evidence_ids"]]
            remaining = MAX_CANDIDATE_EVIDENCE - len(candidate["evidence_ids"])
            if remaining <= 0 and new_evidence and candidate["status"] == "candidate":
                candidate["status"] = "archived"
            new_evidence = new_evidence[:max(0, remaining)]
            if new_evidence:
                candidate[event["polarity"]] += len(new_evidence)
                candidate["evidence_ids"] = sorted(set(
                    candidate["evidence_ids"] + new_evidence))
                if event["project_id"]:
                    candidate["evidence_projects"] = sorted(set(
                        candidate["evidence_projects"] + [event["project_id"]]))[
                            -MAX_EVIDENCE_PROJECTS:]
                candidate["evidence_count"] = len(candidate["evidence_ids"])
                total = candidate["supports"] + candidate["contradicts"]
                candidate["confidence"] = candidate["supports"] / total
                candidate["last_evidence_at"] = event["recorded_at"]
            can_admit = (
                candidate["status"] == "candidate"
                and candidate["supports"] >= threshold
                and len(candidate["evidence_projects"]) >= project_threshold
                and candidate["contradicts"] == 0
                and candidate["confidence"] >= 0.75
            )
            if can_admit:
                statement = (
                    f"When deciding {candidate['future_decision']}, account for "
                    f"the observed signal {candidate['signal']}."
                )
                memory = next((record for record in loom_memory.read_store(
                    self.home, self.instance_id)["records"]
                    if record.get("status") == "active"
                    and record.get("scope") == scope
                    and record.get("category") == category
                    and record.get("domain") == domain
                    and record.get("project_id") == project_id
                    and record.get("statement") == statement), None)
                if memory is None:
                    memory = loom_memory.admit_learning(
                        self.home, self.instance_id, scope=scope, category=category,
                        signal=candidate["signal"],
                        future_decision=candidate["future_decision"],
                        evidence_count=candidate["evidence_count"], domain=domain,
                        project_id=project_id, confidence=candidate["confidence"],
                        evidence_projects=candidate["evidence_projects"])
                candidate["status"] = "active"
                candidate["admitted_memory_id"] = memory["id"]
            store["candidates"] = store["candidates"][-MAX_CANDIDATES:]
            loom_memory._atomic_json(self.candidate_path, store)

    def capture(self, *, kind, scope, signal, decision_target, evidence_ids,
                domain=None, project_id=None, predicted=None, actual=None,
                polarity="supports", recorded_at=None):
        if kind not in EVENT_KINDS or scope not in SCOPES or signal not in SIGNALS \
                or decision_target not in DECISION_TARGETS \
                or polarity not in POLARITIES:
            raise LearningError("learning event uses uncontrolled vocabulary")
        if decision_target in PROHIBITED_INFERENCE_TARGETS:
            raise LearningError("prohibited authority or safety preference cannot be inferred")
        if scope == "global" and (domain is not None or project_id is not None):
            raise LearningError("global evidence cannot carry project or domain identity")
        if scope == "domain" and (not isinstance(domain, str)
                                  or not SAFE_ID.fullmatch(domain)
                                  or project_id is not None):
            raise LearningError("domain evidence requires exactly one safe domain")
        if scope == "project" and (not isinstance(domain, str)
                                   or not SAFE_ID.fullmatch(domain)
                                   or not isinstance(project_id, str)
                                   or not PROJECT_ID.fullmatch(project_id)):
            raise LearningError("project evidence requires domain and project identity")
        if not isinstance(evidence_ids, (list, tuple)) or not evidence_ids \
                or len(evidence_ids) > 32 or not all(
                    isinstance(item, str) and SAFE_ID.fullmatch(item)
                    for item in evidence_ids):
            raise LearningError("learning requires controlled evidence identifiers")
        values = []
        for value in (predicted, actual):
            if value is not None and (type(value) not in (int, float)
                                      or not math.isfinite(value)
                                      or not 0 <= float(value) <= 1):
                raise LearningError("learning metrics must be finite values in [0, 1]")
            values.append(None if value is None else float(value))
        identity = {
            "kind": kind, "scope": scope, "signal": signal,
            "decision_target": decision_target,
            "evidence_ids": sorted({
                "e-" + hashlib.sha256(item.encode("utf-8")).hexdigest()[:24]
                for item in evidence_ids}), "domain": domain,
            "project_id": project_id, "predicted": values[0], "actual": values[1],
            "polarity": polarity,
        }
        event = dict(identity)
        event.update({
            "schema_version": SCHEMA_VERSION,
            "id": str(uuid.uuid5(uuid.UUID(self.instance_id), _digest(identity))),
            "instance_id": self.instance_id,
            "recorded_at": _now(recorded_at),
        })
        with loom_memory.FileLock(self.directory / ".lock"):
            store = self._read()
            existing = next((item for item in store["events"]
                             if item["id"] == event["id"]), None)
            if existing is not None:
                event = existing
            else:
                store["total_count"] += 1
                store["events"] = (store["events"] + [event])[-MAX_EVENTS:]
                loom_memory._atomic_json(self.path, store)
        self._consider(event)
        return json.loads(json.dumps(event))

    def improvement_report(self, *, metric, domain="general"):
        report = loom_memory.learning_report(
            self.home, self.instance_id, metric=metric, domain=domain)
        report["claim"] = (
            "improved" if report["improved"] is True else
            "regressed" if report["improved"] is False else "insufficient-evidence")
        return report
