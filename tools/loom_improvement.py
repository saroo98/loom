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
STORE_SCHEMA_VERSION = 2
WINDOW = 8
MIN_LONGITUDINAL_SAMPLES = WINDOW * 2
MIN_REPLAY_PAIRS = 8
REGRESSION_DELTA = 0.05
MAX_ACTIVE_RECORDS = 512
MAX_BATCH_RECORDS = 2048
MAX_PARTITIONS = 128
MAX_EVIDENCE_IDS = 8192
MAX_STORE_BYTES = 4 * 1024 * 1024
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
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


def _evidence_key(record):
    return hashlib.sha256(record["evidence_id"].encode("utf-8")).hexdigest()


def _measurement_hash(record):
    return _digest({key: value for key, value in record.items()
                    if key not in {"id", "recorded_at"}})


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
        return {"schema_version": STORE_SCHEMA_VERSION,
                "instance_id": self.instance_id, "total_count": 0,
                "records": [], "partitions": {}, "evidence_index": {},
                "evicted_partition_count": 0, "legacy_reset_count": 0}

    def _read(self):
        if not self.path.is_file():
            return self._empty()
        try:
            raw = self.path.read_bytes()
            if len(raw) > MAX_STORE_BYTES:
                raise ImprovementError("improvement evidence exceeds its byte capacity")
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ImprovementError(f"improvement evidence is unreadable: {exc}") from exc
        legacy_fields = {
            "schema_version", "instance_id", "total_count", "records", "partitions"}
        if isinstance(value, dict) and set(value) == legacy_fields \
                and value.get("schema_version") == SCHEMA_VERSION \
                and value.get("instance_id") == self.instance_id \
                and type(value.get("total_count")) is int \
                and value["total_count"] >= 0:
            reset = self._empty()
            reset["legacy_reset_count"] = value["total_count"]
            return reset
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "total_count", "records", "partitions",
                "evidence_index", "evicted_partition_count", "legacy_reset_count"} \
                or value["schema_version"] != STORE_SCHEMA_VERSION \
                or value["instance_id"] != self.instance_id \
                or isinstance(value["total_count"], bool) \
                or not isinstance(value["total_count"], int) \
                or not isinstance(value["records"], list) \
                or len(value["records"]) > MAX_ACTIVE_RECORDS \
                or not isinstance(value["partitions"], dict) \
                or len(value["partitions"]) > MAX_PARTITIONS \
                or not isinstance(value["evidence_index"], dict) \
                or len(value["evidence_index"]) > MAX_EVIDENCE_IDS \
                or value["total_count"] != len(value["evidence_index"]) \
                or value["total_count"] < len(value["records"]) \
                or type(value["evicted_partition_count"]) is not int \
                or value["evicted_partition_count"] < 0 \
                or type(value["legacy_reset_count"]) is not int \
                or value["legacy_reset_count"] < 0:
            raise ImprovementError("improvement evidence contract is invalid")
        if any(not isinstance(key, str) or not DIGEST_RE.fullmatch(key)
               or not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest)
               for key, digest in value["evidence_index"].items()):
            raise ImprovementError("improvement evidence identity index is invalid")
        for record in value["records"]:
            self._validate_record(record)
            if value["evidence_index"].get(_evidence_key(record)) \
                    != _measurement_hash(record):
                raise ImprovementError("improvement evidence identity index is inconsistent")
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
                                  "first_samples", "recent_samples", "last_recorded_at"} \
                    or not isinstance(partition["sample_count"], int) \
                    or partition["sample_count"] < 1 \
                    or not isinstance(partition["first_samples"], list) \
                    or not isinstance(partition["recent_samples"], list) \
                    or len(partition["first_samples"]) > WINDOW \
                    or len(partition["recent_samples"]) > WINDOW:
                raise ImprovementError("observation partition is invalid")
            _stamp(partition["last_recorded_at"])
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
                                  "recent_pairs", "last_recorded_at"} \
                    or not isinstance(partition["pair_count"], int) \
                    or partition["pair_count"] < 1 \
                    or not isinstance(partition["recent_pairs"], list) \
                    or len(partition["recent_pairs"]) > MIN_REPLAY_PAIRS:
                raise ImprovementError("replay partition is invalid")
            _stamp(partition["last_recorded_at"])
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
    def _ensure_partition_capacity(store, key):
        if key in store["partitions"] or len(store["partitions"]) < MAX_PARTITIONS:
            return
        victim = min(
            store["partitions"],
            key=lambda item: (
                1 if store["partitions"][item]["domain"] == "general" else 0,
                store["partitions"][item]["last_recorded_at"], item))
        del store["partitions"][victim]
        store["evicted_partition_count"] += 1

    @classmethod
    def _update_observation_partition(cls, store, record):
        key = _partition_key("observation", record["metric"], record["domain"])
        partition = store["partitions"].get(key)
        if partition is None:
            cls._ensure_partition_capacity(store, key)
            partition = {"kind": "observation", "metric": record["metric"],
                         "domain": record["domain"], "sample_count": 0,
                         "first_samples": [], "recent_samples": [],
                         "last_recorded_at": record["recorded_at"]}
            store["partitions"][key] = partition
        sample = _sample(record)
        partition["sample_count"] += 1
        if len(partition["first_samples"]) < WINDOW:
            partition["first_samples"].append(sample)
        partition["recent_samples"] = (
            partition["recent_samples"] + [sample])[-WINDOW:]
        partition["last_recorded_at"] = record["recorded_at"]

    @classmethod
    def _update_replay_partition(cls, store, records):
        enabled = next(item for item in records if item["cohort"] == "enabled")
        disabled = next(item for item in records if item["cohort"] == "disabled")
        key = _partition_key("replay", enabled["metric"], enabled["domain"])
        partition = store["partitions"].get(key)
        if partition is None:
            cls._ensure_partition_capacity(store, key)
            partition = {"kind": "replay", "metric": enabled["metric"],
                         "domain": enabled["domain"], "pair_count": 0,
                         "recent_pairs": [],
                         "last_recorded_at": enabled["recorded_at"]}
            store["partitions"][key] = partition
        pair = {"replay_id": enabled["replay_id"],
                "enabled": {"value": enabled["value"],
                            "evidence_id": enabled["evidence_id"]},
                "disabled": {"value": disabled["value"],
                             "evidence_id": disabled["evidence_id"]}}
        partition["pair_count"] += 1
        partition["recent_pairs"] = (
            partition["recent_pairs"] + [pair])[-MIN_REPLAY_PAIRS:]
        partition["last_recorded_at"] = enabled["recorded_at"]

    def _write(self, store):
        store["records"] = store["records"][-MAX_ACTIVE_RECORDS:]
        raw = (json.dumps(store, indent=2, sort_keys=True, ensure_ascii=False)
               + "\n").encode("utf-8")
        if len(raw) > MAX_STORE_BYTES:
            raise ImprovementError("improvement evidence exceeds its byte capacity")
        loom_memory._atomic_json(self.path, store)

    @staticmethod
    def _identity_additions(store, records):
        additions, pending = [], {}
        for record in records:
            key, digest = _evidence_key(record), _measurement_hash(record)
            prior = store["evidence_index"].get(key)
            if prior is not None:
                if prior != digest:
                    raise ImprovementError(
                        "evidence identity is bound to another measurement")
                continue
            if key in pending:
                if pending[key] != digest:
                    raise ImprovementError(
                        "evidence identity is bound to another measurement")
                continue
            pending[key] = digest
            additions.append(record)
        if len(store["evidence_index"]) + len(pending) > MAX_EVIDENCE_IDS:
            raise ImprovementError("improvement evidence identity capacity is exhausted")
        return additions, pending

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
            additions, pending = self._identity_additions(store, [record])
            if not additions:
                return json.loads(json.dumps(record))
            store["records"].extend(additions)
            store["evidence_index"].update(pending)
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
            additions, pending = self._identity_additions(store, records)
            for record in additions:
                store["records"].append(record)
                store["total_count"] += 1
                self._update_observation_partition(store, record)
            store["evidence_index"].update(pending)
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
                           for item in evidence_ids) \
                or len(set(evidence_ids)) != 2:
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
            additions, pending = self._identity_additions(store, records)
            if not additions:
                return json.loads(json.dumps(records))
            if len(additions) != 2:
                raise ImprovementError("replay pair is incomplete; evidence is corrupt")
            store["records"].extend(additions)
            store["evidence_index"].update(pending)
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
                "partition_count": len(store["partitions"]),
                "partition_bound": MAX_PARTITIONS,
                "evicted_partition_count": store["evicted_partition_count"],
                "evidence_identity_count": len(store["evidence_index"]),
                "evidence_identity_bound": MAX_EVIDENCE_IDS,
                "byte_size": self.path.stat().st_size if self.path.is_file() else 0,
                "byte_bound": MAX_STORE_BYTES,
                "legacy_reset_count": store["legacy_reset_count"]}

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
        local_improvement_observed = longitudinal["status"] == "improved" \
            and replay["status"] == "improved"
        if local_improvement_observed:
            claim_status = "requires-independent-attestation"
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
            "local_improvement_observed": local_improvement_observed,
            "attestation_status": "local-unattested",
            "improvement_claim_allowed": False,
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
