#!/usr/bin/env python3
"""Scoped, evidence-based owner preference evolution for Loom (stdlib only)."""

import argparse
import datetime as dt
import json
import re
import sys
import uuid
from pathlib import Path

import loom_memory


SCHEMA_VERSION = 1
MAX_PREFERENCES = 128
MAX_OBSERVATIONS = 32
MAX_HISTORY = 8
INFERENCE_WINDOW_DAYS = 120
RETIRE_AFTER_DAYS = 180
SAFE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PROJECT = re.compile(r"^p-[0-9a-f]{32}$")
KEYS = {
    "autonomy", "decision_batch_size", "report_detail",
    "verification_expectation", "stack", "concern",
}
ENUM_VALUES = {
    "autonomy": {"A0", "A1", "A2", "A3"},
    "decision_batch_size": {"one-at-a-time", "small-batch", "gate-batch", "all-at-once"},
    "report_detail": {"concise", "balanced", "detailed"},
    "verification_expectation": {"focused", "standard", "exhaustive"},
    "concern": {"care", "dismiss"},
}
HIGH_CONSEQUENCE = {("autonomy", "A2"), ("autonomy", "A3")}


class PreferenceError(RuntimeError):
    pass


def _instant(value=None):
    if value is None:
        parsed = dt.datetime.now(dt.timezone.utc)
    elif isinstance(value, dt.datetime):
        parsed = value
    else:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise PreferenceError("observed_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise PreferenceError("observed_at must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0)


def _stamp(value=None):
    return _instant(value).isoformat().replace("+00:00", "Z")


def _copy(value):
    return json.loads(json.dumps(value))


class PreferenceEngine:
    """One bounded interface for observing, correcting, selecting, and retiring preferences."""

    def __init__(self, owner_home, instance_id):
        self.home = Path(owner_home)
        if not self.home.is_absolute():
            raise PreferenceError("owner_home must be absolute")
        try:
            loom_memory.validate_instance(self.home, instance_id)
        except loom_memory.MemoryError as exc:
            raise PreferenceError(str(exc)) from exc
        self.instance_id = instance_id
        self.directory = self.home / "instances" / instance_id
        self.path = self.directory / "preference-evolution.json"
        self.lock = self.directory / ".preferences.lock"

    def _empty(self):
        return {"schema_version": SCHEMA_VERSION, "instance_id": self.instance_id,
                "total_observations": 0, "preferences": []}

    def _read(self):
        if not self.path.exists():
            return self._empty()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PreferenceError(f"preference store is invalid: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "total_observations", "preferences"} \
                or value["schema_version"] != SCHEMA_VERSION \
                or value["instance_id"] != self.instance_id \
                or not isinstance(value["preferences"], list) \
                or len(value["preferences"]) > MAX_PREFERENCES:
            raise PreferenceError("preference store contract is invalid")
        for record in value["preferences"]:
            self._validate_record(record)
        return value

    @staticmethod
    def _validate_record(record):
        required = {
            "id", "key", "domain", "task_class", "risk_class", "subject",
            "stated", "inferred", "effective_value", "effective_source", "pending_value",
            "status", "observations", "observation_count", "retired_values", "history",
            "updated_at",
        }
        if not isinstance(record, dict) or set(record) != required \
                or record.get("key") not in KEYS \
                or record.get("status") not in {"active", "pending-confirmation", "retired"} \
                or not isinstance(record.get("observations"), list) \
                or len(record["observations"]) > MAX_OBSERVATIONS \
                or not isinstance(record.get("history"), list) \
                or len(record["history"]) > MAX_HISTORY:
            raise PreferenceError("preference record contract is invalid")
        try:
            uuid.UUID(record["id"])
            _instant(record["updated_at"])
        except (ValueError, TypeError, AttributeError, PreferenceError) as exc:
            raise PreferenceError("preference record identity is invalid") from exc
        for observation in record["observations"]:
            if not isinstance(observation, dict) or set(observation) != {
                    "value", "source", "project_id", "evidence_id", "observed_at"} \
                    or observation["source"] not in {"stated", "observed"} \
                    or not isinstance(observation["value"], str) \
                    or not isinstance(observation["evidence_id"], str) \
                    or not SAFE.fullmatch(observation["evidence_id"]):
                raise PreferenceError("preference observation contract is invalid")
            if observation["source"] == "observed" and (
                    not isinstance(observation["project_id"], str)
                    or not PROJECT.fullmatch(observation["project_id"])):
                raise PreferenceError("preference observation contract is invalid")
            if observation["source"] == "stated" and observation["project_id"] is not None:
                raise PreferenceError("preference observation contract is invalid")
            _instant(observation["observed_at"])
        if record["observation_count"] < len(record["observations"]):
            raise PreferenceError("preference observation contract is invalid")
        if record["stated"] is not None and (
                not isinstance(record["stated"], dict)
                or set(record["stated"]) != {"value", "confidence", "observed_at"}
                or record["stated"]["confidence"] != 1.0):
            raise PreferenceError("stated preference contract is invalid")
        if record["inferred"] is not None and (
                not isinstance(record["inferred"], dict)
                or set(record["inferred"]) != {"value", "confidence", "supports",
                    "contradicts", "project_count", "last_observed"}
                or not 0 <= record["inferred"]["confidence"] <= 1):
            raise PreferenceError("inferred preference contract is invalid")

    def _write(self, store):
        store["preferences"] = store["preferences"][-MAX_PREFERENCES:]
        loom_memory._atomic_json(self.path, store)

    def _slot(self, key, *, domain=None, task_class=None, risk_class=None, subject=None):
        if key not in KEYS:
            raise PreferenceError(f"unsupported preference key: {key}")
        for name, value in (("domain", domain), ("task_class", task_class),
                            ("risk_class", risk_class), ("subject", subject)):
            if value is not None and (not isinstance(value, str) or not SAFE.fullmatch(value)):
                raise PreferenceError(f"{name} must be a safe identifier")
        if key == "stack" and domain is None:
            raise PreferenceError("stack preference requires a domain")
        if key == "autonomy" and (task_class is None or risk_class not in {"low", "medium", "high"}):
            raise PreferenceError("autonomy preference requires task_class and risk_class")
        if key == "concern" and subject is None:
            raise PreferenceError("concern preference requires a subject")
        if key not in {"stack"} and domain is not None:
            raise PreferenceError(f"{key} cannot carry a domain")
        if key != "autonomy" and (task_class is not None or risk_class is not None):
            raise PreferenceError(f"{key} cannot carry task or risk class")
        if key != "concern" and subject is not None:
            raise PreferenceError(f"{key} cannot carry a subject")
        raw = json.dumps([key, domain, task_class, risk_class, subject], separators=(",", ":"))
        identifier = str(uuid.uuid5(uuid.UUID(self.instance_id), "preference:" + raw))
        return {"id": identifier, "key": key, "domain": domain,
                "task_class": task_class, "risk_class": risk_class, "subject": subject}

    @staticmethod
    def _value(key, value):
        if not isinstance(value, str) or not value or len(value) > 80:
            raise PreferenceError("preference value must be a short string")
        if key in ENUM_VALUES and value not in ENUM_VALUES[key]:
            raise PreferenceError(f"unsupported {key} value")
        if key == "stack" and not SAFE.fullmatch(value):
            raise PreferenceError("stack value must be a safe identifier")
        return value

    @staticmethod
    def _snapshot(record):
        return {key: _copy(record[key]) for key in (
            "stated", "inferred", "effective_value", "effective_source",
            "pending_value", "status", "retired_values", "updated_at")}

    @staticmethod
    def _receipt(record, old, *, action, requires_confirmation=False):
        new = record.get("effective_value")
        material = old != new or requires_confirmation
        if requires_confirmation:
            message = (f"Proposed {record['key']}={record['pending_value']}; confirmation "
                       "is required before this high-consequence change applies.")
        elif material:
            message = f"Adapted {record['key']}: {old or 'unset'} -> {new or 'retired'}."
        else:
            message = f"No material {record['key']} change."
        return {"preference_id": record["id"], "action": action,
                "material_change": material, "requires_confirmation": requires_confirmation,
                "message": message}

    def observe(self, *, key, value, source, evidence_id, project_id=None,
                domain=None, task_class=None, risk_class=None, subject=None,
                observed_at=None):
        slot = self._slot(key, domain=domain, task_class=task_class,
                          risk_class=risk_class, subject=subject)
        value = self._value(key, value)
        if source not in {"stated", "observed"}:
            raise PreferenceError("source must be stated or observed")
        if not isinstance(evidence_id, str) or not SAFE.fullmatch(evidence_id):
            raise PreferenceError("evidence_id must be a safe identifier")
        if source == "observed" and (not isinstance(project_id, str)
                                      or not PROJECT.fullmatch(project_id)):
            raise PreferenceError("observed preference requires a project id")
        if source == "stated" and project_id is not None:
            raise PreferenceError("stated preference cannot be attributed to a project")
        instant = _instant(observed_at)
        stamp = _stamp(instant)
        with loom_memory.FileLock(self.lock):
            store = self._read()
            record = next((item for item in store["preferences"] if item["id"] == slot["id"]), None)
            if record is None:
                record = dict(slot)
                record.update({"stated": None, "inferred": None, "effective_value": None,
                    "effective_source": None, "pending_value": None, "status": "retired",
                    "observations": [], "observation_count": 0, "retired_values": [],
                    "history": [], "updated_at": stamp})
                store["preferences"].append(record)
            if any(item["evidence_id"] == evidence_id for item in record["observations"]):
                return self._receipt(record, record["effective_value"], action="duplicate")
            old = record["effective_value"]
            record["history"].append(self._snapshot(record))
            record["history"] = record["history"][-MAX_HISTORY:]
            record["observations"].append({"value": value, "source": source,
                "project_id": project_id, "evidence_id": evidence_id, "observed_at": stamp})
            record["observations"] = record["observations"][-MAX_OBSERVATIONS:]
            record["observation_count"] += 1
            store["total_observations"] += 1
            requires_confirmation = False
            if source == "stated":
                record["stated"] = {"value": value, "confidence": 1.0, "observed_at": stamp}
                record["effective_value"] = value
                record["effective_source"] = "stated"
                record["pending_value"] = None
                record["status"] = "active"
            else:
                cutoff = instant - dt.timedelta(days=INFERENCE_WINDOW_DAYS)
                recent = [item for item in record["observations"]
                          if item["source"] == "observed"
                          and _instant(item["observed_at"]) >= cutoff]
                counts = {}
                projects = {}
                for item in recent:
                    counts[item["value"]] = counts.get(item["value"], 0) + 1
                    projects.setdefault(item["value"], set()).add(item["project_id"])
                candidate = max(counts, key=lambda item: (counts[item], item), default=None)
                total = len(recent)
                confidence = counts.get(candidate, 0) / total if total else 0.0
                qualified = candidate is not None and counts[candidate] >= 3 \
                    and len(projects[candidate]) >= 2 and confidence >= 0.75
                previous_inferred = record["inferred"]["value"] if record["inferred"] else None
                if qualified:
                    record["inferred"] = {"value": candidate, "confidence": round(confidence, 4),
                        "supports": counts[candidate], "contradicts": total - counts[candidate],
                        "project_count": len(projects[candidate]), "last_observed": stamp}
                    if previous_inferred and previous_inferred != candidate \
                            and previous_inferred not in record["retired_values"]:
                        record["retired_values"].append(previous_inferred)
                    if record["stated"] is None:
                        if (key, candidate) in HIGH_CONSEQUENCE \
                                and record["effective_value"] != candidate:
                            record["pending_value"] = candidate
                            record["status"] = "pending-confirmation"
                            requires_confirmation = True
                        else:
                            record["effective_value"] = candidate
                            record["effective_source"] = "inferred"
                            record["pending_value"] = None
                            record["status"] = "active"
                elif record["stated"] is None and record["inferred"] is not None:
                    prior = record["inferred"]["value"]
                    prior_confidence = counts.get(prior, 0) / total if total else 0.0
                    record["inferred"]["confidence"] = round(prior_confidence, 4)
                    if prior_confidence < 0.5:
                        if prior not in record["retired_values"]:
                            record["retired_values"].append(prior)
                        record["inferred"] = None
                        record["effective_value"] = None
                        record["effective_source"] = None
                        record["pending_value"] = None
                        record["status"] = "retired"
            record["retired_values"] = record["retired_values"][-16:]
            record["updated_at"] = stamp
            self._write(store)
            return self._receipt(record, old, action="observe",
                                 requires_confirmation=requires_confirmation)

    def confirm(self, preference_id, *, observed_at=None):
        with loom_memory.FileLock(self.lock):
            store = self._read()
            record = next((item for item in store["preferences"]
                           if item["id"] == preference_id), None)
            if record is None or record["pending_value"] is None:
                raise PreferenceError("preference has no pending change")
            old = record["effective_value"]
            record["history"].append(self._snapshot(record))
            record["history"] = record["history"][-MAX_HISTORY:]
            record["effective_value"] = record["pending_value"]
            record["effective_source"] = "inferred-confirmed"
            record["pending_value"] = None
            record["status"] = "active"
            record["updated_at"] = _stamp(observed_at)
            self._write(store)
            return self._receipt(record, old, action="confirm")

    def undo(self, *, key, domain=None, task_class=None, risk_class=None,
             subject=None, observed_at=None):
        slot = self._slot(key, domain=domain, task_class=task_class,
                          risk_class=risk_class, subject=subject)
        with loom_memory.FileLock(self.lock):
            store = self._read()
            record = next((item for item in store["preferences"] if item["id"] == slot["id"]), None)
            if record is None or not record["history"]:
                raise PreferenceError("preference has no change to undo")
            old = record["effective_value"]
            snapshot = record["history"].pop()
            for name, value in snapshot.items():
                record[name] = value
            record["updated_at"] = _stamp(observed_at)
            self._write(store)
            return self._receipt(record, old, action="undo")

    def correct(self, text, *, observed_at=None):
        normalized = " ".join(str(text).strip().lower().split())
        report = re.fullmatch(r"prefer (concise|balanced|detailed) reports?", normalized)
        if report:
            return self.observe(key="report_detail", value=report.group(1), source="stated",
                evidence_id="stated-" + uuid.uuid4().hex[:16], observed_at=observed_at)
        undo = re.fullmatch(r"undo my (report detail|decision batch size|verification expectation) preference", normalized)
        if undo:
            key = {"report detail": "report_detail", "decision batch size": "decision_batch_size",
                   "verification expectation": "verification_expectation"}[undo.group(1)]
            return self.undo(key=key, observed_at=observed_at)
        raise PreferenceError("unsupported correction; use a controlled preference phrase")

    def housekeeping(self, *, now=None):
        instant = _instant(now)
        retired = 0
        with loom_memory.FileLock(self.lock):
            store = self._read()
            for record in store["preferences"]:
                inferred = record["inferred"]
                if record["stated"] is None and inferred is not None \
                        and _instant(inferred["last_observed"]) \
                        < instant - dt.timedelta(days=RETIRE_AFTER_DAYS):
                    value = inferred["value"]
                    if value not in record["retired_values"]:
                        record["retired_values"].append(value)
                    record["inferred"] = None
                    record["effective_value"] = None
                    record["effective_source"] = None
                    record["pending_value"] = None
                    record["status"] = "retired"
                    record["updated_at"] = _stamp(instant)
                    retired += 1
            self._write(store)
        return {"retired_inferred": retired}

    def select(self, *, domain=None, task_class=None, risk_class=None):
        selected = []
        for record in self._read()["preferences"]:
            if record["status"] != "active" or record["effective_value"] is None:
                continue
            if record["key"] == "stack" and record["domain"] != domain:
                continue
            if record["key"] == "autonomy" and (
                    record["task_class"] != task_class or record["risk_class"] != risk_class):
                continue
            stated_confidence = record["stated"]["confidence"] if record["stated"] else 0.0
            inferred_confidence = record["inferred"]["confidence"] if record["inferred"] else 0.0
            selected.append({"id": record["id"], "key": record["key"],
                "effective_value": record["effective_value"],
                "effective_source": record["effective_source"],
                "stated_confidence": stated_confidence,
                "inferred_confidence": inferred_confidence,
                "domain": record["domain"], "task_class": record["task_class"],
                "risk_class": record["risk_class"], "subject": record["subject"],
                "retired_values": list(record["retired_values"])})
        return sorted(selected, key=lambda item: (item["key"], item["id"]))

    def inspect(self):
        return _copy(self._read()["preferences"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", required=True)
    parser.add_argument("--instance", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    view = sub.add_parser("view")
    view.add_argument("--domain")
    correct = sub.add_parser("correct")
    correct.add_argument("text")
    confirm = sub.add_parser("confirm")
    confirm.add_argument("preference_id")
    args = parser.parse_args(argv)
    try:
        engine = PreferenceEngine(Path(args.home), args.instance)
        if args.command == "view":
            result = engine.select(domain=args.domain)
        elif args.command == "correct":
            result = engine.correct(args.text)
        else:
            result = engine.confirm(args.preference_id)
        print(json.dumps({"status": "ok", "result": result}, sort_keys=True))
        return 0
    except PreferenceError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
