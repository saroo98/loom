#!/usr/bin/env python3
"""Bounded, domain-exact evidence for claims that Loom improves work."""

import datetime as dt
import hashlib
import json
import math
import re
import uuid
from pathlib import Path

import loom_memory


SCHEMA_VERSION = 1
WINDOW = 8
MIN_LONGITUDINAL_SAMPLES = WINDOW * 2
MIN_REPLAY_PAIRS = 8
REGRESSION_DELTA = 0.05
MAX_ACTIVE_RECORDS = 512
MAX_BATCH_RECORDS = 2048
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
METRICS = {
    "prediction-calibration-error": "lower",
    "rework-rate": "lower",
    "verification-escape-rate": "lower",
    "incorrect-tier-rate": "lower",
    "planning-overhead-ratio": "lower",
    "human-decision-round-trips": "lower",
    "unused-artifact-rate": "lower",
    "wo-reopen-rate": "lower",
    "drift-caught-before-execution-rate": "higher",
    "release-rollback-rate": "lower",
    "memory-help-rate": "higher",
    "memory-hurt-rate": "lower",
}
UNBOUNDED_METRICS = {"human-decision-round-trips"}
RECORD_FIELDS = {
    "schema_version", "id", "instance_id", "kind", "metric", "value",
    "domain", "cohort", "project_id", "evidence_id", "replay_id", "recorded_at",
}


class ImprovementError(RuntimeError):
    pass


def _stamp(value=None):
    if value is None:
        parsed = dt.datetime.now(dt.timezone.utc)
    else:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ImprovementError("recorded_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ImprovementError("recorded_at must be timezone-aware")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _mean(values):
    return round(math.fsum(values) / len(values), 12) if values else None


def _digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _partition_key(kind, metric, domain):
    return f"{kind}:{metric}:{domain}"


def _sample(record):
    return {"value": record["value"], "evidence_id": record["evidence_id"],
            "recorded_at": record["recorded_at"]}


def _valid_value(metric, value):
    return not isinstance(value, bool) and isinstance(value, (int, float)) \
        and math.isfinite(float(value)) and float(value) >= 0 \
        and (metric in UNBOUNDED_METRICS or float(value) <= 1)


class ImprovementTracker:
    """Record controlled measurements and produce exact-domain comparative reports."""

    def __init__(self, owner_home, instance_id):
        self.home = Path(owner_home)
        if not self.home.is_absolute():
            raise ImprovementError("owner_home must be absolute")
        try:
            findings = loom_memory.validate_instance(self.home, instance_id)
        except loom_memory.MemoryError as exc:
            raise ImprovementError(str(exc)) from exc
        if findings:
            raise ImprovementError("owner instance is invalid: " + "; ".join(findings))
        self.instance_id = instance_id
        self.directory = self.home / "instances" / instance_id
        self.path = self.directory / "improvement-evidence.json"
        self.lock = self.directory / ".improvement.lock"

    def _empty(self):
        return {"schema_version": SCHEMA_VERSION, "instance_id": self.instance_id,
                "total_count": 0, "records": [], "partitions": {}}

    def _read(self):
        if not self.path.is_file():
            return self._empty()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ImprovementError(f"improvement evidence is unreadable: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "total_count", "records", "partitions"} \
                or value["schema_version"] != SCHEMA_VERSION \
                or value["instance_id"] != self.instance_id \
                or isinstance(value["total_count"], bool) \
                or not isinstance(value["total_count"], int) \
                or not isinstance(value["records"], list) \
                or len(value["records"]) > MAX_ACTIVE_RECORDS \
                or not isinstance(value["partitions"], dict) \
                or value["total_count"] < len(value["records"]):
            raise ImprovementError("improvement evidence contract is invalid")
        for record in value["records"]:
            self._validate_record(record)
        for key, partition in value["partitions"].items():
            self._validate_partition(key, partition)
        return value

    def _validate_partition(self, key, partition):
        if not isinstance(partition, dict) or partition.get("kind") not in {
                "observation", "replay"} or partition.get("metric") not in METRICS \
                or not isinstance(partition.get("domain"), str) \
                or not ID_RE.fullmatch(partition["domain"]) \
                or key != _partition_key(
                    partition["kind"], partition["metric"], partition["domain"]):
            raise ImprovementError("improvement partition is invalid")
        if partition["kind"] == "observation":
            if set(partition) != {"kind", "metric", "domain", "sample_count",
                                  "first_samples", "recent_samples"} \
                    or not isinstance(partition["sample_count"], int) \
                    or partition["sample_count"] < 1 \
                    or not isinstance(partition["first_samples"], list) \
                    or not isinstance(partition["recent_samples"], list) \
                    or len(partition["first_samples"]) > WINDOW \
                    or len(partition["recent_samples"]) > WINDOW:
                raise ImprovementError("observation partition is invalid")
            samples = partition["first_samples"] + partition["recent_samples"]
            for sample in samples:
                if not isinstance(sample, dict) or set(sample) != {
                        "value", "evidence_id", "recorded_at"} \
                        or not _valid_value(partition["metric"], sample["value"]) \
                        or not isinstance(sample["evidence_id"], str) \
                        or not EVIDENCE_RE.fullmatch(sample["evidence_id"]):
                    raise ImprovementError("observation partition sample is invalid")
                _stamp(sample["recorded_at"])
        else:
            if set(partition) != {"kind", "metric", "domain", "pair_count",
                                  "recent_pairs"} \
                    or not isinstance(partition["pair_count"], int) \
                    or partition["pair_count"] < 1 \
                    or not isinstance(partition["recent_pairs"], list) \
                    or len(partition["recent_pairs"]) > MIN_REPLAY_PAIRS:
                raise ImprovementError("replay partition is invalid")
            seen = set()
            for pair in partition["recent_pairs"]:
                if not isinstance(pair, dict) or set(pair) != {
                        "replay_id", "enabled", "disabled"} \
                        or pair["replay_id"] in seen:
                    raise ImprovementError("replay partition pair is invalid")
                seen.add(pair["replay_id"])
                for cohort in ("enabled", "disabled"):
                    item = pair[cohort]
                    if not isinstance(item, dict) or set(item) != {
                            "value", "evidence_id"} \
                            or not _valid_value(partition["metric"], item["value"]):
                        raise ImprovementError("replay partition value is invalid")

    @staticmethod
    def _update_observation_partition(store, record):
        key = _partition_key("observation", record["metric"], record["domain"])
        partition = store["partitions"].get(key)
        if partition is None:
            partition = {"kind": "observation", "metric": record["metric"],
                         "domain": record["domain"], "sample_count": 0,
                         "first_samples": [], "recent_samples": []}
            store["partitions"][key] = partition
        sample = _sample(record)
        partition["sample_count"] += 1
        if len(partition["first_samples"]) < WINDOW:
            partition["first_samples"].append(sample)
        partition["recent_samples"] = (
            partition["recent_samples"] + [sample])[-WINDOW:]

    @staticmethod
    def _update_replay_partition(store, records):
        enabled = next(item for item in records if item["cohort"] == "enabled")
        disabled = next(item for item in records if item["cohort"] == "disabled")
        key = _partition_key("replay", enabled["metric"], enabled["domain"])
        partition = store["partitions"].get(key)
        if partition is None:
            partition = {"kind": "replay", "metric": enabled["metric"],
                         "domain": enabled["domain"], "pair_count": 0,
                         "recent_pairs": []}
            store["partitions"][key] = partition
        pair = {"replay_id": enabled["replay_id"],
                "enabled": {"value": enabled["value"],
                            "evidence_id": enabled["evidence_id"]},
                "disabled": {"value": disabled["value"],
                             "evidence_id": disabled["evidence_id"]}}
        partition["pair_count"] += 1
        partition["recent_pairs"] = (
            partition["recent_pairs"] + [pair])[-MIN_REPLAY_PAIRS:]

    def _write(self, store):
        store["records"] = store["records"][-MAX_ACTIVE_RECORDS:]
        loom_memory._atomic_json(self.path, store)

    def _validate_record(self, record):
        if not isinstance(record, dict) or set(record) != RECORD_FIELDS \
                or record.get("schema_version") != SCHEMA_VERSION \
                or record.get("instance_id") != self.instance_id \
                or record.get("kind") not in {"observation", "replay"} \
                or record.get("metric") not in METRICS \
                or record.get("cohort") not in {"enabled", "disabled"} \
                or not isinstance(record.get("domain"), str) \
                or not ID_RE.fullmatch(record["domain"]) \
                or not isinstance(record.get("evidence_id"), str) \
                or not EVIDENCE_RE.fullmatch(record["evidence_id"]):
            raise ImprovementError("improvement evidence record is invalid")
        try:
            if str(uuid.UUID(record["id"])) != record["id"]:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as exc:
            raise ImprovementError("improvement evidence identity is invalid") from exc
        value = record.get("value")
        if not _valid_value(record["metric"], value):
            raise ImprovementError("improvement measurement is outside its metric contract")
        project_id = record.get("project_id")
        if project_id is not None and (
                not isinstance(project_id, str)
                or not loom_memory.PROJECT_ID_RE.fullmatch(project_id)):
            raise ImprovementError("improvement project identity is invalid")
        if record["kind"] == "observation" and record.get("replay_id") is not None:
            raise ImprovementError("ordinary observation cannot carry replay identity")
        if record["kind"] == "replay" and (
                not isinstance(record.get("replay_id"), str)
                or not EVIDENCE_RE.fullmatch(record["replay_id"])):
            raise ImprovementError("replay evidence requires a safe replay identity")
        _stamp(record.get("recorded_at"))

    def record_observation(self, *, metric, value, domain, project_id, evidence_id,
                           recorded_at=None):
        if metric not in METRICS:
            raise ImprovementError("unsupported improvement metric")
        if not isinstance(domain, str) or not ID_RE.fullmatch(domain):
            raise ImprovementError("measurement requires one exact domain")
        record = {
            "schema_version": SCHEMA_VERSION,
            "id": str(uuid.uuid5(uuid.UUID(self.instance_id),
                                 f"improvement:observation:{evidence_id}")),
            "instance_id": self.instance_id,
            "kind": "observation",
            "metric": metric,
            "value": value,
            "domain": domain,
            "cohort": "enabled",
            "project_id": project_id,
            "evidence_id": evidence_id,
            "replay_id": None,
            "recorded_at": _stamp(recorded_at),
        }
        self._validate_record(record)
        with loom_memory.FileLock(self.lock):
            store = self._read()
            existing = next((item for item in store["records"]
                             if item["id"] == record["id"]), None)
            if existing is not None:
                comparable = {key: value for key, value in record.items()
                              if key != "recorded_at"}
                if any(existing[key] != value for key, value in comparable.items()):
                    raise ImprovementError("evidence identity is bound to another measurement")
                return json.loads(json.dumps(existing))
            store["records"].append(record)
            store["total_count"] += 1
            self._update_observation_partition(store, record)
            self._write(store)
        return json.loads(json.dumps(record))

    def record_observations_batch(self, observations):
        if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_BATCH_RECORDS:
            raise ImprovementError("observation batch exceeds its bound")
        records = []
        seen_ids = set()
        for item in observations:
            if not isinstance(item, dict) or set(item) != {
                    "metric", "value", "domain", "project_id", "evidence_id",
                    "recorded_at"}:
                raise ImprovementError("observation batch entry is invalid")
            metric, domain, evidence_id = (
                item["metric"], item["domain"], item["evidence_id"])
            if metric not in METRICS or not isinstance(domain, str) \
                    or not ID_RE.fullmatch(domain):
                raise ImprovementError("observation batch entry is invalid")
            record = {
                "schema_version": SCHEMA_VERSION,
                "id": str(uuid.uuid5(uuid.UUID(self.instance_id),
                                     f"improvement:observation:{evidence_id}")),
                "instance_id": self.instance_id, "kind": "observation",
                "metric": metric, "value": item["value"], "domain": domain,
                "cohort": "enabled", "project_id": item["project_id"],
                "evidence_id": evidence_id, "replay_id": None,
                "recorded_at": _stamp(item["recorded_at"]),
            }
            self._validate_record(record)
            if record["id"] in seen_ids:
                raise ImprovementError("observation batch repeats evidence identity")
            seen_ids.add(record["id"])
            records.append(record)
        with loom_memory.FileLock(self.lock):
            store = self._read()
            active = {item["id"]: item for item in store["records"]}
            additions = []
            for record in records:
                existing = active.get(record["id"])
                if existing is not None:
                    comparable = {key: value for key, value in record.items()
                                  if key != "recorded_at"}
                    if any(existing[key] != value for key, value in comparable.items()):
                        raise ImprovementError(
                            "evidence identity is bound to another measurement")
                    continue
                additions.append(record)
            for record in additions:
                store["records"].append(record)
                store["total_count"] += 1
                self._update_observation_partition(store, record)
            self._write(store)
        return {"added": len(additions), "total_count": store["total_count"]}

    def record_replay_pair(self, *, metric, domain, replay_id, enabled_value,
                           disabled_value, project_id, evidence_ids, recorded_at=None):
        if metric not in METRICS:
            raise ImprovementError("unsupported improvement metric")
        if not isinstance(domain, str) or not ID_RE.fullmatch(domain):
            raise ImprovementError("replay requires one exact domain")
        if not isinstance(replay_id, str) or not EVIDENCE_RE.fullmatch(replay_id) \
                or not isinstance(evidence_ids, list) or len(evidence_ids) != 2 \
                or not all(isinstance(item, str) and EVIDENCE_RE.fullmatch(item)
                           for item in evidence_ids):
            raise ImprovementError("replay pair requires exact controlled evidence")
        stamp = _stamp(recorded_at)
        records = []
        for cohort, value, evidence_id in (
                ("enabled", enabled_value, evidence_ids[0]),
                ("disabled", disabled_value, evidence_ids[1])):
            record = {
                "schema_version": SCHEMA_VERSION,
                "id": str(uuid.uuid5(
                    uuid.UUID(self.instance_id),
                    f"improvement:replay:{metric}:{domain}:{replay_id}:{cohort}")),
                "instance_id": self.instance_id,
                "kind": "replay",
                "metric": metric,
                "value": value,
                "domain": domain,
                "cohort": cohort,
                "project_id": project_id,
                "evidence_id": evidence_id,
                "replay_id": replay_id,
                "recorded_at": stamp,
            }
            self._validate_record(record)
            records.append(record)
        with loom_memory.FileLock(self.lock):
            store = self._read()
            existing = [item for item in store["records"]
                        if item["id"] in {record["id"] for record in records}]
            if existing:
                if len(existing) != 2:
                    raise ImprovementError("replay pair is incomplete; evidence is corrupt")
                by_id = {item["id"]: item for item in existing}
                for record in records:
                    comparable = {key: value for key, value in record.items()
                                  if key != "recorded_at"}
                    if any(by_id[record["id"]][key] != value
                           for key, value in comparable.items()):
                        raise ImprovementError(
                            "replay identity is bound to another measurement")
                return json.loads(json.dumps(existing))
            store["records"].extend(records)
            store["total_count"] += 2
            self._update_replay_partition(store, records)
            self._write(store)
        return json.loads(json.dumps(records))

    def status(self):
        store = self._read()
        return {"total_count": store["total_count"],
                "active_record_count": len(store["records"]),
                "active_record_bound": MAX_ACTIVE_RECORDS,
                "compacted_record_count": store["total_count"] - len(store["records"]),
                "partition_count": len(store["partitions"])}

    def report(self, *, metric, domain):
        if metric not in METRICS:
            raise ImprovementError("unsupported improvement metric")
        if not isinstance(domain, str) or not ID_RE.fullmatch(domain):
            raise ImprovementError("improvement reports require one exact domain")
        store = self._read()
        observation_partition = store["partitions"].get(
            _partition_key("observation", metric, domain))
        sample_count = (observation_partition["sample_count"]
                        if observation_partition else 0)
        if sample_count < MIN_LONGITUDINAL_SAMPLES:
            longitudinal = {
                "status": "insufficient-evidence", "sample_count": sample_count,
                "required_sample_count": MIN_LONGITUDINAL_SAMPLES,
                "early_sample_count": min(sample_count, WINDOW),
                "recent_sample_count": min(max(0, sample_count - WINDOW), WINDOW),
                "early_mean": None, "recent_mean": None,
            }
        else:
            early = [float(item["value"])
                     for item in observation_partition["first_samples"]]
            recent = [float(item["value"])
                      for item in observation_partition["recent_samples"]]
            early_mean, recent_mean = _mean(early), _mean(recent)
            improvement_delta = (early_mean - recent_mean
                                 if METRICS[metric] == "lower"
                                 else recent_mean - early_mean)
            if improvement_delta > 0:
                status = "improved"
            elif improvement_delta <= -REGRESSION_DELTA:
                status = "regressed"
            else:
                status = "no-change"
            longitudinal = {
                "status": status,
                "sample_count": sample_count,
                "required_sample_count": MIN_LONGITUDINAL_SAMPLES,
                "early_sample_count": len(early), "recent_sample_count": len(recent),
                "early_mean": early_mean, "recent_mean": recent_mean,
                "improvement_delta": improvement_delta,
            }
        replay_partition = store["partitions"].get(
            _partition_key("replay", metric, domain))
        pair_count = replay_partition["pair_count"] if replay_partition else 0
        recent_pairs = replay_partition["recent_pairs"] if replay_partition else []
        if pair_count < MIN_REPLAY_PAIRS:
            replay = {"status": "insufficient-evidence",
                      "pair_count": pair_count,
                      "required_pair_count": MIN_REPLAY_PAIRS,
                      "enabled_mean": None, "disabled_mean": None}
        else:
            enabled_mean = _mean([float(pair["enabled"]["value"])
                                  for pair in recent_pairs])
            disabled_mean = _mean([float(pair["disabled"]["value"])
                                   for pair in recent_pairs])
            replay_improved = (enabled_mean < disabled_mean
                               if METRICS[metric] == "lower"
                               else enabled_mean > disabled_mean)
            replay = {"status": "improved" if replay_improved else "not-improved",
                      "pair_count": pair_count,
                      "required_pair_count": MIN_REPLAY_PAIRS,
                      "enabled_mean": enabled_mean, "disabled_mean": disabled_mean}
        claim_allowed = longitudinal["status"] == "improved" \
            and replay["status"] == "improved"
        if claim_allowed:
            claim_status = "improved"
        elif longitudinal["status"] == "insufficient-evidence":
            claim_status = "insufficient-longitudinal-evidence"
        elif replay["status"] == "insufficient-evidence":
            claim_status = "insufficient-replay"
        else:
            claim_status = "not-improved"
        return {
            "schema_version": SCHEMA_VERSION,
            "metric": metric,
            "direction": METRICS[metric],
            "domain": domain,
            "scope": "general-calibration" if domain == "general" else "exact-domain",
            "longitudinal": longitudinal,
            "replay": replay,
            "improvement_claim_allowed": claim_allowed,
            "claim_status": claim_status,
            "regression_alarm": longitudinal["status"] == "regressed",
        }

    def audit_bundle(self, *, metric, domain):
        claim = self.report(metric=metric, domain=domain)
        store = self._read()
        observation_partition = store["partitions"].get(
            _partition_key("observation", metric, domain))
        replay_partition = store["partitions"].get(
            _partition_key("replay", metric, domain))
        evidence = {
            "longitudinal": {
                "sample_count": (observation_partition["sample_count"]
                                 if observation_partition else 0),
                "early": (json.loads(json.dumps(
                    observation_partition["first_samples"]))
                    if observation_partition else []),
                "recent": (json.loads(json.dumps(
                    observation_partition["recent_samples"]))
                    if observation_partition else []),
            },
            "replay_pairs": (json.loads(json.dumps(replay_partition["recent_pairs"]))
                             if replay_partition else []),
            "replay_pair_count": (replay_partition["pair_count"]
                                  if replay_partition else 0),
        }
        sealed = {
            "metric": metric, "domain": domain, "direction": METRICS[metric],
            "thresholds": {
                "window": WINDOW,
                "minimum_longitudinal_samples": MIN_LONGITUDINAL_SAMPLES,
                "minimum_replay_pairs": MIN_REPLAY_PAIRS,
                "regression_delta": REGRESSION_DELTA,
            },
            "evidence": evidence,
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "instance_id": self.instance_id,
            **sealed,
            "evidence_sha256": _digest(sealed),
            "claim": claim,
        }
